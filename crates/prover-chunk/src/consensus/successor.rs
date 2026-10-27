//! The successor a validated candidate determines before any certificate.

use alloc::vec::Vec;
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::history_proof::ConsensusBoundary;
use neutrin0_primitives::Hash;

use super::candidate::{CandidateParts, validate_candidate_using};
use super::finalized::hybrid_verifier;
use super::{
    ConsensusError, ConsensusWitness, ValidatedCandidate, as_chunk, boundary_with_validators,
};
use crate::{
    execution::{ExecutionContext, ExecutionStatement},
    rotation::ConsensusRecords,
};

/// Validate a candidate and derive its successor exactly as the guest does.
/// Voters run the derivation too: a candidate whose successor cannot be
/// derived could otherwise be certified and never proven.
pub(super) fn validate_with_successor(
    input: &ConsensusWitness,
) -> Result<(ValidatedCandidate, Successor), ConsensusError> {
    let mut verifier = hybrid_verifier(input)?;
    let CandidateParts {
        candidate,
        mut records,
        ..
    } = validate_candidate_using(input, &mut verifier)?;
    if !verifier.finish() {
        return Err(ConsensusError::Proposer);
    }
    let successor = derive_successor(
        input,
        &candidate.execution,
        candidate.next_validators.clone(),
        (candidate.participation, candidate.proving),
        &mut records,
    )?;
    Ok((candidate, successor))
}

/// The successor a validated candidate determines without its certificate.
pub(super) struct Successor {
    pub(super) start: ConsensusBoundary,
    pub(super) end: ConsensusBoundary,
    pub(super) next_context: ExecutionContext,
    pub(super) frontier: neutrin0_consensus_types::history::HistoryFrontier,
}

/// Derive the outgoing boundary and next execution context of a validated
/// candidate. `reports` are the participation and proving commitments its
/// carrier selected (design 08).
pub(super) fn derive_successor(
    input: &ConsensusWitness,
    execution: &ExecutionStatement,
    next_validators: Vec<neutrin0_primitives::Validator>,
    reports: (Hash, Hash),
    records: &mut ConsensusRecords,
) -> Result<Successor, ConsensusError> {
    let (participation, proving) = reports;
    let context = &input.context;
    let chunk = as_chunk(&execution.chunk);
    let vrfs: Vec<_> = input
        .blocks
        .iter()
        .map(|block| block.header.vrf_proof)
        .collect();
    let start = boundary_with_validators(
        context,
        input.seed,
        execution.chunk.active_validator_set_root,
    )?;
    // The leaf commits this chunk's start boundary, so any later history root
    // authenticates that boundary as an ancestor (design 13).
    let historical = neutrin0_consensus_types::evidence::EvidenceContext {
        chunk_id: chunk.chunk_id,
        chunk_hash: chunk.hash(),
        end_height: chunk.end_height,
        validators_root: chunk.active_validator_set_root,
        seed: input.seed,
        source_block_guest_vk_digest: context.programs.execution.block,
        source_runtime_code_hash: context.programs.runtime_code_hash,
        start_boundary: start.commitment(),
    };
    let mut frontier = input.history.frontier.clone();
    let history_root = frontier
        .append(commitment(&historical))
        .ok_or(ConsensusError::Context)?;
    let next_chunk_id = context
        .chunk_id
        .checked_add(1)
        .ok_or(ConsensusError::Context)?;
    // A scheduled upgrade in the authenticated post-state switches the program
    // set at this boundary; otherwise the current set stays in force.
    let next_programs = records
        .next_programs(context.programs, next_chunk_id)
        .map_err(|_| ConsensusError::Rotation)?;
    // A scheduled hard fork travels in every boundary up to its count, where
    // this chain ends (design 20).
    let next_fork = records
        .next_fork(next_chunk_id)
        .map_err(|_| ConsensusError::Rotation)?;
    let next_seed = neutrin0_vrf::fold_seed(&input.seed, &vrfs);
    let next_context = ExecutionContext {
        seed: next_seed,
        chunk_id: next_chunk_id,
        parent_block_hash: execution.chunk.end_block_hash,
        pre_state_root: execution.chunk.end_state_root,
        parent_slot: input
            .blocks
            .last()
            .ok_or(ConsensusError::Context)?
            .header
            .slot,
        active_validators: next_validators,
        identity_sanctions_root: execution.chunk.next_identity_sanctions_root,
        history_root,
        chain_id: context.chain_id,
        chain_spec_hash: context.chain_spec_hash,
        chunk_size: context.chunk_size,
        vm_code_hash: next_programs.runtime_code_hash,
        programs: next_programs,
        participation,
        proving,
        fork: next_fork,
    };
    let end = boundary_with_validators(
        &next_context,
        next_seed,
        execution.chunk.next_validator_set_root,
    )?;
    Ok(Successor {
        start,
        end,
        next_context,
        frontier,
    })
}

/// The boundary and context a proven candidate hands its successor (design 08).
///
/// It exists before any certificate. Successor blocks may be produced under
/// it; the certificate that finalizes the candidate yields the same values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedSuccessor {
    /// The candidate's chunk hash.
    pub chunk_hash: Hash,
    /// The candidate's outgoing boundary.
    pub end: ConsensusBoundary,
    /// The successor's execution context.
    pub next_context: ExecutionContext,
    /// The History frontier after appending the candidate's record.
    pub frontier: neutrin0_consensus_types::history::HistoryFrontier,
}

/// Project the successor of a candidate whose receipts are all held.
///
/// # Errors
/// Returns the candidate validation failure.
pub fn project_successor(input: &ConsensusWitness) -> Result<ProjectedSuccessor, ConsensusError> {
    let (
        candidate,
        Successor {
            end,
            next_context,
            frontier,
            ..
        },
    ) = validate_with_successor(input)?;
    Ok(ProjectedSuccessor {
        chunk_hash: as_chunk(&candidate.execution.chunk).hash(),
        end,
        next_context,
        frontier,
    })
}
