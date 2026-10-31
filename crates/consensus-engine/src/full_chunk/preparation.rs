//! Owned consensus inputs: receipt and signature checks need no engine lock.

extern crate alloc;

use alloc::vec::Vec;
use neutrin0_consensus_types::{BlockProof, Header};
use neutrin0_primitives::ChainSpec;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_prover_chunk::{
    body::ConsensusBody,
    consensus::{ConsensusWitness, validate_candidate},
    execution::{ExecutionContext, ProvenBlock},
    history::HistoryWitness,
};
use neutrin0_runtime_abi::StateWitness;

use super::{BranchWitness, PreparedConsensusChunk, witness::unfilled_finality_cert};
use crate::FinalizeError;

/// Owned sources selected under the engine lock, without trusting a live read
/// handle as a database snapshot. Verification does not mutate the engine.
pub struct PendingConsensusChunk {
    pub(super) expected_chunk: Option<Hash>,
    pub(super) chain_spec: ChainSpec,
    pub(super) context: ExecutionContext,
    pub(super) seed: Hash,
    pub(super) blocks: Vec<(Header, BlockProof)>,
    pub(super) bodies: Vec<ConsensusBody>,
    pub(super) post_state: StateWitness,
    pub(super) sanctions: neutrin0_trie::Trie,
    pub(super) history: HistoryWitness,
}

impl PendingConsensusChunk {
    /// Verify the selected receipts and candidate without holding the engine.
    ///
    /// # Errors
    /// Rejects an unavailable backend, malformed proof or invalid candidate.
    pub fn prepare<P: ProofSystem, E>(
        self,
        proof_system: &P,
    ) -> Result<PreparedConsensusChunk<P>, FinalizeError<E>> {
        let expected_chunk = self.expected_chunk;
        let (witness, proofs) = self.witness(proof_system)?;
        let candidate = validate_candidate(&witness).map_err(|_| ProofError::InvalidWitness)?;
        if expected_chunk.is_some_and(|hash| {
            neutrin0_prover_chunk::consensus::as_chunk(&candidate.execution.chunk).hash() != hash
        }) {
            return Err(ProofError::PublicInputMismatch.into());
        }
        Ok(PreparedConsensusChunk {
            witness,
            candidate,
            proofs,
            ratified: Vec::new(),
        })
    }

    pub(crate) fn witness<P: ProofSystem, E>(
        self,
        proof_system: &P,
    ) -> Result<BranchWitness<P>, FinalizeError<E>> {
        let guests = proof_system.programs().ok_or(ProofError::Unsupported)?;
        if guests.chunk != self.chain_spec.genesis_chunk
            || !proof_system.can_prove(&neutrin0_consensus_types::history_proof::GuestPrograms {
                execution: self.context.programs.execution,
                chunk: guests.chunk,
            })
        {
            return Err(ProofError::Unsupported.into());
        }
        let mut blocks = Vec::new();
        let mut proofs = Vec::new();
        for (header, wire) in self.blocks {
            let proof = borsh::from_slice(&wire.proof_bytes)?;
            let statement = proof_system.verify_block_statement(&proof, &wire.public_inputs)?;
            if statement.prover_address != wire.prover_address
                || crate::prove::statement_key(&statement) != wire.statement_key
            {
                return Err(ProofError::PublicInputMismatch.into());
            }
            blocks.push(ProvenBlock {
                header,
                public_inputs: wire.public_inputs,
                output: statement.output,
                prover_address: statement.prover_address,
            });
            proofs.push(proof);
        }
        // Only content-addressed paths are read here. Missing retained nodes
        // fail closed; the commit path separately rechecks the trusted boundary.
        let identity_sanctions = super::sanctions::sanctions_witness::<E>(
            &self.sanctions,
            &self.context,
            &self.post_state,
            &blocks,
        )
        .map_err(|_| ProofError::InvalidWitness)?;
        let chunk_id = self.context.chunk_id;
        Ok((
            ConsensusWitness {
                chain_spec: self.chain_spec,
                context: self.context,
                seed: self.seed,
                blocks,
                bodies: self.bodies,
                post_state: self.post_state,
                identity_sanctions,
                history: self.history,
                finality_cert: unfilled_finality_cert(chunk_id),
                facts: Vec::new(),
                ratified: Vec::new(),
            },
            proofs,
        ))
    }
}
