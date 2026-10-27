//! Verification and finalization of peer-supplied complete chunk proofs.

use core::fmt;

use crate::full_chunk::PreparedConsensusChunk;
use neutrin0_consensus_types::ChunkProof;
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_prover_chunk::consensus::validate_consensus_with_context;
use neutrin0_storage::Database;

use super::{ImportChunkProofOutcome, ImportError};
use crate::engine::Engine;

impl<DB: Database> Engine<DB> {
    /// Verify and finalize a peer-supplied complete chunk proof.
    ///
    /// Reconstructs the trusted candidate context, validates the mandatory
    /// certificate and statement, verifies the backend receipt, then atomically
    /// persists and installs the next consensus boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError::InvalidChunkProof`] when the envelope and
    /// public inputs disagree or verification fails, [`ImportError::Codec`]
    /// when the backend proof bytes fail to decode, or
    /// [`ImportError::Store`] on persistence failure.
    pub fn import_chunk_proof<PS: ProofSystem>(
        &mut self,
        proof: &ChunkProof,
        proof_system: &PS,
    ) -> Result<ImportChunkProofOutcome, ImportError<DB::Error>>
    where
        DB::Error: fmt::Debug + fmt::Display,
    {
        self.import_chunk_proof_inner(proof, proof_system, None)
    }

    /// Verify complete chunk finality and atomically select its branch with
    /// replayed state when the peer finalized a different unfinalized fork.
    ///
    /// # Errors
    /// Returns proof, replay or storage errors without changing finality.
    pub fn import_chunk_proof_with_dry_run<PS: ProofSystem>(
        &mut self,
        proof: &ChunkProof,
        proof_system: &PS,
        executor: &dyn ErasedBlockExecutor,
    ) -> Result<ImportChunkProofOutcome, ImportError<DB::Error>>
    where
        DB::Error: fmt::Debug + fmt::Display,
    {
        self.import_chunk_proof_inner(proof, proof_system, Some(executor))
    }

    /// The statement another proof of an already finalized chunk must
    /// commit, or `None` when the proof needs nothing: its chunk is ratified
    /// already or its statement is held. The proof may name another valid
    /// certificate of the same chunk: it verifies against the stored
    /// boundaries and chunk commitment under its own certificate commitment,
    /// and the chunk Guest that produced it validated that certificate.
    ///
    /// # Errors
    /// Returns a mismatching artifact or storage failures.
    pub fn alternative_chunk_statement(
        &self,
        proof: &ChunkProof,
    ) -> Result<
        Option<neutrin0_consensus_types::history_proof::ChunkReceiptStatement>,
        ImportError<DB::Error>,
    > {
        let Some(statement) = self.chunk_statement_under(
            proof.chunk_id,
            neutrin0_consensus_types::evidence::commitment(&proof.finality_cert),
        )?
        else {
            return Ok(None);
        };
        if proof.public_inputs != statement.chunk
            || proof.chunk_hash
                != neutrin0_prover_chunk::consensus::as_chunk(&statement.chunk).hash()
            || proof.finality_cert.chunk_id != proof.chunk_id
            || proof.finality_cert.chunk_hash != proof.chunk_hash
        {
            return Err(ImportError::InvalidChunkProof(
                neutrin0_proof_system::ProofError::PublicInputMismatch,
            ));
        }
        // A certificate of chunk `N` ratifies chunk `N - 1`, so once chunk
        // `N - 1` is finalized every proof below `N - 2` (and below the
        // specification's first chunk) has been ratified already.
        let ratified = self
            .finalized_next_chunk_id()
            .saturating_sub(2)
            .max(self.chain_spec().first_chunk());
        let receipt_statement = neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
            statement,
            chunk_prover_address: proof.prover_address,
        };
        let statement_key = receipt_statement.statement_key();
        if proof.chunk_id < ratified
            || self
                .store()
                .chunk_receipts(proof.chunk_id)?
                .iter()
                .any(|receipt| receipt.statement_key == statement_key)
        {
            return Ok(None);
        }
        Ok(Some(receipt_statement))
    }

    /// Verify and retain another valid proof of an already finalized chunk
    /// for ratification (design 08), under
    /// [`Self::alternative_chunk_statement`]. Returns whether the proof is
    /// new.
    ///
    /// # Errors
    /// Returns a mismatching artifact, an invalid proof or storage failures.
    pub fn import_alternative_chunk_proof<PS: ProofSystem>(
        &mut self,
        proof: &ChunkProof,
        proof_system: &PS,
    ) -> Result<bool, ImportError<DB::Error>> {
        let Some(receipt_statement) = self.alternative_chunk_statement(proof)? else {
            return Ok(false);
        };
        let statement_key = receipt_statement.statement_key();
        let backend_proof: PS::ChunkProof =
            borsh::from_slice(&proof.proof_bytes).map_err(ImportError::Codec)?;
        proof_system
            .verify_consensus_chunk(&backend_proof, &receipt_statement)
            .map_err(ImportError::InvalidChunkProof)?;
        let preferred = self.prover_address().ok();
        let max = self.max_receipts_per_block();
        let first_verified_slot = self.local_slot();
        self.store_mut().put_chunk_receipt(
            crate::store::StoredChunkReceipt {
                proof: proof.clone(),
                statement_key,
                first_verified_slot,
            },
            preferred,
            max,
        )?;
        Ok(true)
    }

    /// Whether `proof`'s finality certificate carries a valid quorum of its
    /// chunk's committee.
    fn certificate_is_authentic(&self, proof: &ChunkProof) -> bool {
        let chunk = neutrin0_prover_chunk::consensus::as_chunk(&proof.public_inputs);
        self.accountability_context(chunk.chunk_id)
            .is_ok_and(|(validators, seed)| {
                neutrin0_prover_chunk::finality::verify_finality_using(
                    self.consensus_domain(),
                    &self.chain_spec().consensus,
                    &validators,
                    &seed,
                    &chunk,
                    &proof.finality_cert,
                    &mut *self.bls_verifier.borrow_mut(),
                )
                .is_ok()
            })
    }

    fn import_chunk_proof_inner<PS: ProofSystem>(
        &mut self,
        proof: &ChunkProof,
        proof_system: &PS,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<ImportChunkProofOutcome, ImportError<DB::Error>>
    where
        DB::Error: fmt::Debug + fmt::Display,
    {
        if self.store().get_chunk_proof(proof.chunk_id)?.as_ref() == Some(proof) {
            return Ok(ImportChunkProofOutcome {
                chunk_id: proof.chunk_id,
                end_height: proof.public_inputs.end_height,
                chunk_hash: proof.chunk_hash,
            });
        }
        let prepared = self.prepared_imported_chunk(proof, proof_system)?;
        let validated = validate_consensus_with_context(&prepared.witness)
            .map_err(|error| ImportError::ChunkWitness(format!("consensus: {error:?}")))?;
        let statement = &validated.statement;
        if proof.chunk_id != statement.chunk.chunk_id
            || proof.public_inputs != statement.chunk
            || proof.chunk_hash
                != neutrin0_prover_chunk::consensus::as_chunk(&statement.chunk).hash()
        {
            return Err(ImportError::InvalidChunkProof(
                neutrin0_proof_system::ProofError::PublicInputMismatch,
            ));
        }
        let backend_proof = decoded_chunk_receipt::<PS, DB::Error>(proof_system, proof)?;
        let finalized = self
            .commit_imported_consensus_chunk(
                &prepared.witness,
                &backend_proof,
                proof_system,
                executor,
                validated,
            )
            .map_err(|error| match error {
                crate::FinalizeError::Replay(error) => error,
                crate::FinalizeError::Engine(crate::EngineError::Store(error)) => {
                    ImportError::Store(error)
                }
                crate::FinalizeError::Backend(error) => ImportError::InvalidChunkProof(error),
                _ => ImportError::InvalidChunkProof(
                    neutrin0_proof_system::ProofError::BackendRejected,
                ),
            })?;
        Ok(ImportChunkProofOutcome {
            chunk_id: finalized.chunk.chunk_id,
            end_height: finalized.chunk.end_height,
            chunk_hash: finalized.chunk_hash,
        })
    }

    /// Prepare the chunk on the branch `proof` names with the certificate's
    /// receipts and ratified statements installed. A verified certificate's
    /// named receipts are kept once they arrive, however many other receipts
    /// their blocks have.
    fn prepared_imported_chunk<PS: ProofSystem>(
        &mut self,
        proof: &ChunkProof,
        proof_system: &PS,
    ) -> Result<PreparedConsensusChunk<PS>, ImportError<DB::Error>>
    where
        DB::Error: fmt::Debug + fmt::Display,
    {
        let prepared = self.prepare_consensus_chunk_on_branch(
            proof.chunk_id,
            proof.public_inputs.end_block_hash,
            Some(&proof.finality_cert.proposal.receipt_keys()),
            proof_system,
        );
        let mut prepared = match prepared {
            Ok(prepared) => prepared,
            Err(crate::FinalizeError::MissingBlockReceipt {
                hash,
                statement_key,
            }) => {
                // A verified certificate's named receipts are kept once they
                // arrive, however many other receipts their blocks have.
                if self.certificate_is_authentic(proof) {
                    self.await_receipts(
                        crate::receipts::CERTIFIED_SLOT,
                        &proof.finality_cert.proposal,
                    );
                }
                return Err(ImportError::MissingBlockReceipt {
                    hash,
                    statement_key,
                });
            }
            Err(other) => return Err(ImportError::ChunkWitness(format!("preparation: {other}"))),
        };
        self.install_finality_certificate(&mut prepared, proof.finality_cert.clone())
            .map_err(|error| ImportError::ChunkWitness(format!("certificate: {error}")))?;
        Ok(prepared)
    }
}

/// The backend proof of `proof`, which must credit exactly the runtime
/// account its envelope names.
fn decoded_chunk_receipt<PS: ProofSystem, E>(
    proof_system: &PS,
    proof: &ChunkProof,
) -> Result<PS::ChunkProof, ImportError<E>> {
    let backend_proof: PS::ChunkProof =
        borsh::from_slice(&proof.proof_bytes).map_err(ImportError::Codec)?;
    if proof_system
        .chunk_prover_address(&backend_proof)
        .map_err(ImportError::InvalidChunkProof)?
        != proof.prover_address
        || !neutrin0_primitives::is_runtime_account(&proof.prover_address)
    {
        return Err(ImportError::InvalidChunkProof(
            neutrin0_proof_system::ProofError::PublicInputMismatch,
        ));
    }
    Ok(backend_proof)
}
