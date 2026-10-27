//! The last executed block's environment, kept for historical call simulation.
//!
//! A block input without transactions is mostly its consensus set and the
//! reports it consumed, tens of kilobytes that change only at a chunk boundary
//! and at the chunk's carrier. Blocks therefore rewrite only their own small
//! facts and leave that larger part to a separate record they rewrite when it
//! changes, so a light block's writes and witness stay small.

use crate::state::{read_record, write_record};
use alloc::{string::String, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::{
    evidence::EvidenceAnchor, participation::ParticipationReport, proving::ProvingReport,
    runtime::ConsensusExecutionContext,
};
use neutrin0_primitives::Hash;
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_core::StateBackend;

/// Key of the last executed block's [`BlockEnvironment`].
pub const ENVIRONMENT_KEY: &[u8] = b"evm:environment";

/// Key of the last executed block's [`ChunkEnvironment`].
pub const CHUNK_ENVIRONMENT_KEY: &[u8] = b"evm:environment:chunk";

/// The facts of one block input that change from block to block.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct BlockEnvironment {
    /// Consensus facts of the block.
    pub context: ConsensusExecutionContext,
    /// Evidence admission anchor of the block.
    pub evidence_anchor: EvidenceAnchor,
    /// Chain identifier.
    pub chain_id: u64,
    /// Height of the block.
    pub block_height: u64,
    /// Gas limit of the block.
    pub block_gas_limit: u64,
    /// Runtime account of the block's proposer.
    pub proposer_address: Hash,
    /// Whether the block consumed carried reports. With the chunk it tells
    /// when the [`ChunkEnvironment`] changes.
    pub reports: bool,
}

/// The facts of one block input that hold for a chunk, or from its carrier on.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ChunkEnvironment {
    /// Consensus set of the chunk.
    pub active_validators: Vec<neutrin0_primitives::Validator>,
    /// Participation report the block consumed, from the chunk's carrier on.
    pub participation: Option<ParticipationReport>,
    /// Proving report the block consumed, from the chunk's carrier on.
    pub proving: Option<ProvingReport>,
}

/// Split `input` into its two environment records.
#[must_use]
pub fn records(input: &RuntimeBlockInput) -> (BlockEnvironment, ChunkEnvironment) {
    (
        BlockEnvironment {
            context: input.context,
            evidence_anchor: input.evidence_anchor,
            chain_id: input.chain_id,
            block_height: input.block_height,
            block_gas_limit: input.block_gas_limit,
            proposer_address: input.proposer_address,
            reports: input.participation.is_some(),
        },
        ChunkEnvironment {
            active_validators: input.active_validators.clone(),
            participation: input.participation.clone(),
            proving: input.proving.clone(),
        },
    )
}

/// Store `input` as the last executed block's environment.
///
/// The chunk record is written only when `previous`, the prior block's
/// environment, does not share its chunk and carried-report state: within one
/// chunk on one branch the consensus set is fixed and the carrier's reports
/// repeat.
pub fn store<B: StateBackend>(
    state: &mut B,
    input: &RuntimeBlockInput,
    previous: Option<&BlockEnvironment>,
) {
    let (block, chunk) = records(input);
    if previous.is_none_or(|previous| {
        previous.evidence_anchor.chunk_id != block.evidence_anchor.chunk_id
            || previous.reports != block.reports
    }) {
        write_record(state, CHUNK_ENVIRONMENT_KEY, &chunk);
    }
    write_record(state, ENVIRONMENT_KEY, &block);
}

/// The last executed block's environment as a block input without
/// transactions, if any block was executed.
///
/// # Errors
/// Returns a record that does not decode canonically, or a block record
/// without its chunk record.
pub fn load<B: StateBackend>(state: &mut B) -> Result<Option<RuntimeBlockInput>, String> {
    let Some(block) = read_record::<BlockEnvironment, _>(state, ENVIRONMENT_KEY)? else {
        return Ok(None);
    };
    let chunk: ChunkEnvironment = read_record(state, CHUNK_ENVIRONMENT_KEY)?
        .ok_or("block environment without its chunk record")?;
    Ok(Some(RuntimeBlockInput {
        active_validators: chunk.active_validators,
        participation_acks: Vec::new(),
        program_pieces: Vec::new(),
        context: block.context,
        evidence_anchor: block.evidence_anchor,
        chain_id: block.chain_id,
        block_height: block.block_height,
        block_gas_limit: block.block_gas_limit,
        proposer_address: block.proposer_address,
        participation: chunk.participation,
        proving: chunk.proving,
        transactions: Vec::new(),
    }))
}
