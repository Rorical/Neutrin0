//! Finalized chunk statements and the chunk proofs a certificate ratifies
//! (design 08).

extern crate alloc;

use alloc::vec::Vec;
use neutrin0_consensus_types::FinalityCert;
use neutrin0_consensus_types::history_proof::ChunkReceiptStatement;
use neutrin0_primitives::{ChunkId, Hash};
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_storage::Database;

use super::{PreparedConsensusChunk, chunk_public_inputs};
use crate::{Engine, FinalizeError};

impl<DB: Database> Engine<DB> {
    /// The consensus statement of finalized chunk `chunk_id` under the
    /// certificate committed by `finality_cert_hash`, or `None` without its
    /// stored boundaries. Only the certificate commitment depends on which
    /// valid certificate finalized the chunk; boundaries, History and the
    /// chunk commitment do not (design 08).
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn chunk_statement_under(
        &self,
        chunk_id: ChunkId,
        finality_cert_hash: Hash,
    ) -> Result<
        Option<neutrin0_consensus_types::history_proof::ConsensusStatement>,
        crate::StoreError<DB::Error>,
    > {
        let Some(next) = chunk_id.checked_add(1) else {
            return Ok(None);
        };
        let chunk = match self.store().chunk_statement(chunk_id)? {
            Some(statement) => statement.chunk,
            None => match self.store().historical_chunk(chunk_id)? {
                Some(record) => chunk_public_inputs(&record.chunk),
                None => return Ok(None),
            },
        };
        let (Some(start), Some(end)) = (
            self.store().consensus_boundary(chunk_id)?,
            self.store().consensus_boundary(next)?,
        ) else {
            return Ok(None);
        };
        Ok(Some(
            neutrin0_consensus_types::history_proof::ConsensusStatement {
                chain: self.chain_binding(),
                start,
                end,
                chunk,
                finality_cert_hash,
            },
        ))
    }

    /// Install `certificate` in `prepared` with the chunk proof it ratifies:
    /// the finalized statement of the ratified chunk crediting the named
    /// prover and, when held, the proof with that statement key (design 08).
    ///
    /// # Errors
    /// Returns an invalid witness when the ratified chunk's finalized
    /// statement is missing or does not produce the named key.
    pub fn install_finality_certificate<P: ProofSystem>(
        &self,
        prepared: &mut PreparedConsensusChunk<P>,
        certificate: FinalityCert,
    ) -> Result<(), FinalizeError<DB::Error>> {
        let mut statements = Vec::new();
        let mut proofs = Vec::new();
        for entry in &certificate.proposal.ratified_chunk_proofs {
            let statement = ChunkReceiptStatement {
                statement: self
                    .chunk_statement_under(entry.chunk_id, entry.finality_cert_hash)?
                    .ok_or(ProofError::InvalidWitness)?,
                chunk_prover_address: entry.prover_address,
            };
            if statement.statement_key() != entry.statement_key {
                return Err(ProofError::PublicInputMismatch.into());
            }
            statements.push(statement);
            if proofs.len() + 1 == statements.len()
                && let Some(held) = self
                    .store()
                    .chunk_receipts(entry.chunk_id)?
                    .into_iter()
                    .find(|receipt| receipt.statement_key == entry.statement_key)
            {
                proofs.push(
                    borsh::from_slice(&held.proof.proof_bytes)
                        .map_err(|_| ProofError::MalformedProof)?,
                );
            }
        }
        prepared.witness.finality_cert = certificate;
        prepared.witness.ratified = statements;
        prepared.ratified = proofs;
        Ok(())
    }
}
