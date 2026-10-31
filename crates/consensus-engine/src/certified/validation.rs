//! Receipt-checked, owned native certification validated outside engine locks.

use super::{CertifiedExecution, ValidatedExecutionChunk};
use crate::full_chunk::{ConsensusState, PreparedConsensusChunk};
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_prover_chunk::{
    consensus::{
        ConsensusWitness, ValidatedConsensus, context_boundary, validate_consensus_with_context,
    },
    history::HistoricalChunk,
};

impl ValidatedExecutionChunk {
    /// Authenticate every receipt and the full native certificate. The returned
    /// value owns its exact witness; only the engine can commit it after checking
    /// the live trusted sources. No engine access is needed during validation.
    ///
    /// # Errors
    /// Rejects malformed receipts or invalid consensus.
    pub fn validate<P: ProofSystem>(
        prepared: &PreparedConsensusChunk<P>,
        proof_system: &P,
    ) -> Result<Self, ProofError> {
        if prepared.proofs.len() != prepared.witness.blocks.len()
            || !prepared.witness.facts.is_empty()
        {
            return Err(ProofError::InvalidWitness);
        }
        for (proof, block) in prepared.proofs.iter().zip(&prepared.witness.blocks) {
            if proof_system.verify_block_statement(proof, &block.public_inputs)?
                != block.statement()
            {
                return Err(ProofError::PublicInputMismatch);
            }
        }
        let (certified, validated) = validate_certificate(&prepared.witness, 0)?;
        Ok(Self {
            certified,
            validated,
        })
    }
}

pub(super) fn validate_certificate(
    witness: &ConsensusWitness,
    certified_at_secs: u64,
) -> Result<(CertifiedExecution, ValidatedConsensus), ProofError> {
    let context = &witness.context;
    let seed = witness.seed;
    let history = &witness.history;
    let validated =
        validate_consensus_with_context(witness).map_err(|_| ProofError::InvalidWitness)?;
    let record = HistoricalChunk {
        runtime_code_hash: context.programs.runtime_code_hash,
        block_guest_vk_digest: context.programs.execution.block,
        start_boundary: validated.statement.start.commitment(),
        chunk: neutrin0_prover_chunk::consensus::as_chunk(&validated.statement.chunk),
        validators: context.active_validators.clone(),
        seed,
        finality: witness.finality_cert.clone(),
    };
    let mut frontier = history.frontier.clone();
    let root = frontier
        .append(commitment(&record.evidence_context()))
        .ok_or(ProofError::InvalidWitness)?;
    let end = validated.statement.end;
    if root != end.history_root
        || context_boundary(&validated.next_context, end.seed)
            .map_err(|_| ProofError::InvalidWitness)?
            != end
    {
        return Err(ProofError::PublicInputMismatch);
    }
    let certified = CertifiedExecution {
        witness: witness.clone(),
        record,
        certified_at_secs,
        state: ConsensusState {
            boundary: end,
            next_context: validated.next_context.clone(),
            next_seed: end.seed,
            frontier,
        },
    };
    Ok((certified, validated))
}
