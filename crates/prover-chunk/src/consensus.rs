//! Composition of execution, proposer, finality and validator-transition checks.
//!
//! Historical membership is opened against the
//! incoming context and extended into the next chunk's authenticated context.
//! Block-proven runtime offence markers own sanction replay protection.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
/// Re-exported so the Chunk Guest commits it without a direct dependency.
pub use neutrin0_consensus_types::history_proof::ChunkReceiptStatement;
use neutrin0_consensus_types::history_proof::ConsensusStatement;
use neutrin0_consensus_types::history_proof::{ChainBinding, ConsensusBoundary, ProgramSet};
use neutrin0_consensus_types::participation::NO_PARTICIPATION;
use neutrin0_consensus_types::{Body, Chunk, ChunkProofPublicInputs};
use neutrin0_primitives::{ChainSpec, Hash, Seed, merkle_root_from_hashes};
use neutrin0_runtime_abi::StateWitness;

use crate::{
    body::ConsensusBody,
    execution::{ExecutionContext, ExecutionStatement, ProvenBlock},
    history::{HistoryError, HistoryWitness},
};
use neutrin0_consensus_types::evidence::commitment;

mod candidate;
#[cfg(test)]
mod compact_participation_tests;
mod finalized;
mod successor;

pub use candidate::verify_participation_vote_using;
pub use finalized::{fact_coverage, validate_consensus_using, validate_consensus_with_context};
use successor::validate_with_successor;
pub use successor::{ProjectedSuccessor, project_successor};

/// Witness for a chunk whose inner execution proofs are verified separately.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
///
/// Every Guest identity is read from authenticated data: the Fact Guest and the
/// chunk Guest (which verifies the ratified proof recursively) from the
/// specification, the evidence and Block Guests from the incoming context's
/// program set.
pub struct ConsensusWitness {
    /// Trusted chain configuration, committed by the execution context.
    pub chain_spec: ChainSpec,
    /// Incoming context. Its commitment must be checked by the verifier.
    pub context: ExecutionContext,
    /// Latest authenticated finalized randomness seed.
    pub seed: Seed,
    /// Blocks in strictly increasing canonical height order.
    pub blocks: Vec<ProvenBlock>,
    /// Compact bodies in block order; ordinary transactions are omitted.
    pub bodies: Vec<ConsensusBody>,
    /// Trie witness for post-chunk validator records.
    pub post_state: StateWitness,
    /// Openings in the consensus-owned permanent BLS identity sanctions trie.
    pub identity_sanctions: StateWitness,
    /// Authenticated append frontier and referenced historical records.
    pub history: HistoryWitness,
    /// Both BFT phases, signing the derived chunk commitment.
    pub finality_cert: neutrin0_consensus_types::FinalityCert,
    /// Recursively authenticated fact statements covering some or all of the
    /// signature checks below. The guest verifies each receipt under the
    /// specification's Fact Guest; uncovered checks fall back to in-circuit BLS.
    pub facts: Vec<crate::facts::FactStatement>,
    /// Public values of the chunk proof the certificate ratifies: the previous
    /// chunk's, exactly one after chunk zero (design 08). The guest verifies
    /// each recursively under the pinned chunk program.
    pub ratified: Vec<ChunkReceiptStatement>,
}

/// Native result retaining the full context outside the compact public statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedConsensus {
    /// Exact fixed-size values committed by the Chunk Guest.
    pub statement: ConsensusStatement,
    /// Complete next active set used by ordinary node execution.
    pub next_context: ExecutionContext,
}

/// Construct the canonical execution context from a validated chain specification
/// and the program set every node trusts at genesis.
pub fn genesis_context(spec: &ChainSpec, programs: ProgramSet) -> ExecutionContext {
    genesis_context_with_hash(spec, spec.hash(), programs)
}

/// [`genesis_context`] with `chain_spec_hash == spec.hash()` already computed.
pub(super) fn genesis_context_with_hash(
    spec: &ChainSpec,
    chain_spec_hash: Hash,
    programs: ProgramSet,
) -> ExecutionContext {
    ExecutionContext {
        seed: spec.genesis_seed,
        chain_id: spec.chain_id,
        chain_spec_hash,
        chunk_id: 0,
        chunk_size: spec.consensus.chunk_size,
        parent_block_hash: spec.genesis_block_hash,
        pre_state_root: spec.genesis_state_root,
        parent_slot: 0,
        vm_code_hash: programs.runtime_code_hash,
        programs,
        participation: NO_PARTICIPATION,
        proving: neutrin0_consensus_types::proving::NO_PROVING,
        active_validators: spec.initial_validators.clone(),
        identity_sanctions_root: neutrin0_primitives::ZERO_HASH,
        history_root: neutrin0_consensus_types::history::empty_history_root(),
        fork: None,
    }
}

/// Compact a complete execution context without losing any authenticated field.
pub fn context_boundary(
    context: &ExecutionContext,
    seed: Seed,
) -> Result<ConsensusBoundary, ConsensusError> {
    boundary_with_validators(context, seed, commitment(&context.active_validators))
}

pub(super) fn boundary_with_validators(
    context: &ExecutionContext,
    seed: Seed,
    validators_root: Hash,
) -> Result<ConsensusBoundary, ConsensusError> {
    if context.seed != seed {
        return Err(ConsensusError::Context);
    }
    Ok(ConsensusBoundary {
        next_chunk_id: context.chunk_id,
        height: context
            .chunk_id
            .checked_mul(context.chunk_size)
            .ok_or(ConsensusError::Context)?,
        block_hash: context.parent_block_hash,
        state_root: context.pre_state_root,
        slot: context.parent_slot,
        validators_root,
        identity_sanctions_root: context.identity_sanctions_root,
        seed,
        history_root: context.history_root,
        programs: context.programs,
        participation: context.participation,
        proving: context.proving,
        fork: context.fork,
    })
}

/// Failure while constructing a guest consensus statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsensusError {
    /// Chain configuration or genesis anchor mismatch.
    Context,
    /// Execution statement or cross-block binding failed.
    Execution,
    /// Body commitment, timestamp or gas limit is inconsistent with its
    /// header or the chain specification.
    Header,
    /// Proposer signature, VRF or stake threshold failed.
    Proposer,
    /// Validator transition or its state witness failed.
    Rotation,
    /// Finality certificate failed.
    Finality,
    /// Historical authorization or replay protection failed.
    History(HistoryError),
}

/// Compose every consensus check without a host-trust bypass.
///
/// Inner SP1 proofs must be verified by the guest using the exact block outputs
/// and key in this witness. This function alone does not establish execution.
pub fn validate_consensus(input: &ConsensusWitness) -> Result<ConsensusStatement, ConsensusError> {
    Ok(validate_consensus_with_context(input)?.statement)
}

/// Upper bound on fact statements a chunk witness may carry.
pub const MAX_CONSENSUS_FACT_STATEMENTS: usize = 64;

/// Largest encoded chunk witness the chunk Guest accepts.
///
/// Every other limit the Guest applies is a rule of [`validate_consensus`],
/// which nodes run natively; this one bounds the proving input itself.
pub const MAX_CHUNK_WITNESS_BYTES: usize = 64 * 1024 * 1024;

/// Room a candidate witness keeps within [`MAX_CHUNK_WITNESS_BYTES`].
///
/// It holds what the witness gains after the vote: its finality certificate,
/// the fact statements and the ratified chunk statement.
const POST_VOTE_WITNESS_BYTES: usize =
    neutrin0_consensus_types::signed_artifacts::MAX_SIGNED_ARTIFACT_BYTES + 1024 * 1024;

/// Whether the chunk Guest can accept `candidate` once complete.
///
/// The certificate, fact statements and ratified statement are attached after
/// the vote. Voters check this with [`validate_candidate`] before voting, so
/// no certified chunk is unprovable for its size; a native/Guest disagreement
/// on any rule is an implementation bug, repaired by hard fork.
#[must_use]
pub fn provable_candidate(candidate: &ConsensusWitness) -> bool {
    borsh::object_length(candidate)
        .is_ok_and(|bytes| bytes.saturating_add(POST_VOTE_WITNESS_BYTES) <= MAX_CHUNK_WITNESS_BYTES)
}

/// Consensus-valid candidate before collecting the finality certificate.
/// This is not a proof or a finalized statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedCandidate {
    /// Chunk fields to be signed by BFT.
    pub execution: ExecutionStatement,
    /// Validator transition authenticated against the exact chunk-end state.
    pub next_validators: Vec<neutrin0_primitives::Validator>,
    /// Commitment of the participation report this chunk consumed: the
    /// carrier's, or the start boundary's in chunk zero (design 08).
    pub participation: Hash,
    /// Commitment of the proving report this chunk consumed (design 08).
    pub proving: Hash,
}

/// Validate a candidate before voting: everything the guest checks except
/// finality, which only [`validate_consensus`], the guest's entry point,
/// checks.
pub fn validate_candidate(input: &ConsensusWitness) -> Result<ValidatedCandidate, ConsensusError> {
    Ok(validate_with_successor(input)?.0)
}

/// Validate a successor using the preceding authenticated statement as anchor.
/// The preceding statement must itself have been proven or locally verified.
pub fn validate_successor(
    previous: &ConsensusStatement,
    input: &ConsensusWitness,
) -> Result<ConsensusStatement, ConsensusError> {
    if context_boundary(&input.context, input.seed)? != previous.end
        || ChainBinding::new(&input.chain_spec) != previous.chain
    {
        return Err(ConsensusError::Context);
    }
    validate_consensus(input)
}

/// Recover the canonical chunk signed by both BFT phases.
pub const fn as_chunk(pi: &ChunkProofPublicInputs) -> Chunk {
    Chunk {
        chunk_id: pi.chunk_id,
        start_height: pi.start_height,
        end_height: pi.end_height,
        start_state_root: pi.start_state_root,
        end_state_root: pi.end_state_root,
        start_block_hash: pi.start_block_hash,
        end_block_hash: pi.end_block_hash,
        block_hash_root: pi.block_hash_root,
        block_proof_root: pi.block_proof_root,
        vrf_proof_root: pi.vrf_proof_root,
        active_validator_set_root: pi.active_validator_set_root,
        next_validator_set_root: pi.next_validator_set_root,
        next_identity_sanctions_root: pi.next_identity_sanctions_root,
        da_root: pi.da_root,
    }
}

/// Canonical full-body DA commitment used by headers and fraud verification.
pub fn body_da_root(body: &Body) -> Hash {
    neutrin0_primitives::da_root_from_lane_roots([
        (
            u32::try_from(body.transactions.len()).expect("body lane length fits borsh"),
            neutrin0_primitives::transactions_root_of_blobs(&body.transactions),
        ),
        (
            neutrin0_consensus_types::participation::vote_lane_count(&body.participation_acks),
            neutrin0_consensus_types::participation::vote_lane_root(&body.participation_acks),
        ),
        lane_root(
            &body
                .programs
                .iter()
                .map(neutrin0_consensus_types::ProgramPiece::descriptor)
                .collect::<Vec<_>>(),
        ),
        lane_root(body.participation.as_slice()),
    ])
}

fn lane_root<T: neutrin0_consensus_types::hashing::Committed>(lane: &[T]) -> (u32, Hash) {
    (
        u32::try_from(lane.len()).expect("body lane length fits borsh"),
        merkle_root_from_hashes(lane.iter().map(commitment).collect()),
    )
}
