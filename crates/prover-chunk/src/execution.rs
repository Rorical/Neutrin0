//! Header and execution bindings for recursive block-proof aggregation.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::{BlockProofPublicInputs, ChunkProofPublicInputs, Header};
use neutrin0_primitives::{
    Hash, Validator, blake3_256, merkle_root_from_hashes, merkle_root_of_hashes,
};
use neutrin0_runtime_abi::RuntimeBlockOutput;

/// Project a signed header and trusted incoming boundary into runtime context.
pub fn runtime_context(
    header: &Header,
    finalized: neutrin0_consensus_types::history_proof::ConsensusBoundary,
) -> neutrin0_consensus_types::runtime::ConsensusExecutionContext {
    neutrin0_consensus_types::runtime::ConsensusExecutionContext {
        slot: header.slot,
        timestamp: header.timestamp,
        parent_block_hash: header.parent_hash,
        proposer_vrf_output: neutrin0_vrf::proof_output(&header.vrf_proof),
        finalized,
    }
}

/// Inputs authenticated by the caller's previous checkpoint and chain spec.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ExecutionContext {
    /// Finalized seed authenticated by the incoming boundary.
    pub seed: neutrin0_primitives::Seed,
    /// Chain ID required in every inner statement.
    pub chain_id: u64,
    /// Chain specification commitment.
    pub chain_spec_hash: Hash,
    /// Chunk being proven.
    pub chunk_id: u64,
    /// Number of canonical blocks per chunk.
    pub chunk_size: u64,
    /// Header immediately before this chunk.
    pub parent_block_hash: Hash,
    /// State root immediately before this chunk.
    pub pre_state_root: Hash,
    /// Slot of the preceding block.
    pub parent_slot: u64,
    /// Runtime artifact executing this chunk; equals `programs.runtime_code_hash`.
    pub vm_code_hash: Hash,
    /// Complete program set active for this chunk (design 20).
    pub programs: neutrin0_consensus_types::history_proof::ProgramSet,
    /// Latest participation report consumed before this chunk's start boundary.
    /// This chunk selects its new previous-chunk report in its first block;
    /// the selection does not depend on the current finality certificate.
    pub participation: Hash,
    /// Latest proving report consumed before this chunk's start boundary,
    /// derived from the same carried certificate (design 08).
    pub proving: Hash,
    /// Authenticated consensus validator set for this chunk.
    pub active_validators: Vec<Validator>,
    /// Permanent identity-sanctions trie authenticated by the incoming boundary.
    pub identity_sanctions_root: Hash,
    /// Commitment to finalized historical consensus records.
    pub history_root: Hash,
    /// Hard fork scheduled by the state before this chunk; the chain proves
    /// no chunk from its count on (design 20).
    pub fork: Option<neutrin0_primitives::ScheduledFork>,
}

/// One complete header and the statement authenticated by its inner proof.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ProvenBlock {
    /// Canonical header preimage, including its proposer signature.
    pub header: Header,
    /// Wire block inputs, also used for the engine's proof-root commitment.
    pub public_inputs: BlockProofPublicInputs,
    /// Exact runtime statement the guest must authenticate by SP1 recursion.
    pub output: RuntimeBlockOutput,
    /// Attribution the receipt commits next to the statement (design 08).
    pub prover_address: Hash,
}

impl ProvenBlock {
    /// The receipt's complete public values.
    #[must_use]
    pub fn statement(&self) -> neutrin0_runtime_abi::BlockReceiptStatement {
        neutrin0_runtime_abi::BlockReceiptStatement {
            output: self.output.clone(),
            prover_address: self.prover_address,
        }
    }
}

/// Native execution candidate used to derive the compact consensus statement.
/// This alone establishes neither recursive proof validity nor finality.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ExecutionStatement {
    /// Canonical chunk commitment fields.
    pub chunk: ChunkProofPublicInputs,
}

/// A malformed or inconsistent aggregate execution statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    /// Empty, truncated, overflowing or otherwise invalid chunk range.
    Range,
    /// Header/public-input or public-input/inner-proof binding failed.
    BlockBinding,
    /// Parent hash, height, slot or state-root continuity failed.
    Continuity,
    /// Proposer is absent, slashed or has zero stake.
    Proposer,
}

use neutrin0_consensus_types::evidence::commitment;

/// The execution-input commitment of `output` (design 08): what the header's
/// `inputs_root` must equal.
#[must_use]
pub fn output_inputs_root(output: &RuntimeBlockOutput) -> neutrin0_primitives::Hash {
    neutrin0_consensus_types::runtime::execution_inputs_root(
        &output.context,
        output.participation,
        output.participation_acks,
        output.proving,
        output.program_pieces,
        &output.accountability.anchor,
    )
}

/// Whether a recursively authenticated block output commits exactly the
/// wire public inputs' chain, height, roots, gas, proposer, runtime fields and
/// declared execution inputs.
#[must_use]
#[allow(clippy::suspicious_operation_groupings)] // Wire fields deliberately differ from STF names.
pub fn output_binds(output: &RuntimeBlockOutput, pi: &BlockProofPublicInputs) -> bool {
    output_inputs_root(output) == pi.inputs_root
        && output.context == *pi.context
        && output.chain_id == pi.chain_id
        && output.block_height == pi.height
        && output.pre_state_root == pi.state_root_before
        && output.post_state_root == pi.state_root_after
        && output.transactions_root == pi.transactions_root
        && output.receipts_root == pi.receipt_root
        && output.gas_used == pi.gas_used
        && output.block_gas_limit == pi.gas_limit
        && output.proposer_address == pi.proposer_address
        && output.consensus_candidates_root == pi.runtime_extra
}

/// Validate all execution bindings and derive the aggregate commitment.
///
/// This function does not replace SP1 inner-proof verification, BLS signature
/// verification or validation of the incoming context's trust anchor.
pub fn validate_execution(
    context: &ExecutionContext,
    blocks: &[ProvenBlock],
) -> Result<ExecutionStatement, ExecutionError> {
    validate_execution_with_hashes(context, blocks).map(|(statement, _)| statement)
}

/// [`validate_execution`] that also returns each block's header hash, in order.
pub(crate) fn validate_execution_with_hashes(
    context: &ExecutionContext,
    blocks: &[ProvenBlock],
) -> Result<(ExecutionStatement, Vec<Hash>), ExecutionError> {
    let count = u64::try_from(blocks.len()).map_err(|_| ExecutionError::Range)?;
    if count == 0 || count != context.chunk_size {
        return Err(ExecutionError::Range);
    }
    let start_height = context
        .chunk_id
        .checked_mul(context.chunk_size)
        .and_then(|height| height.checked_add(1))
        .ok_or(ExecutionError::Range)?;
    let end_height = start_height
        .checked_add(count - 1)
        .ok_or(ExecutionError::Range)?;
    // All blocks in this chunk consume the same authenticated finalized
    // boundary. Hash its full validator vector once, rather than once per block.
    let incoming = crate::consensus::context_boundary(context, context.seed)
        .map_err(|_| ExecutionError::BlockBinding)?;
    let mut parent = context.parent_block_hash;
    let mut state = context.pre_state_root;
    let mut slot = context.parent_slot;
    let mut hashes = Vec::with_capacity(blocks.len());
    let mut proof_leaves = Vec::with_capacity(blocks.len());
    let mut vrf_leaves = Vec::with_capacity(blocks.len());
    let mut da_leaves = Vec::with_capacity(blocks.len());
    for (offset, block) in blocks.iter().enumerate() {
        let header = &block.header;
        let height = start_height + u64::try_from(offset).map_err(|_| ExecutionError::Range)?;
        let hash = verify_block_binding(context, &incoming, block, height, (parent, state, slot))?;
        hashes.push(hash);
        // Match Engine::wire_proof_leaf_bytes exactly, rather than hashing
        // SP1's SHA-256 public-values digest into a different commitment.
        proof_leaves.push(commitment(&block.public_inputs));
        vrf_leaves.push(blake3_256(&header.vrf_proof));
        da_leaves.push(blake3_256(&header.da_root));
        parent = hash;
        state = header.state_root;
        slot = header.slot;
    }
    let start_block_hash = *hashes.first().ok_or(ExecutionError::Range)?;
    let last = blocks.last().ok_or(ExecutionError::Range)?;
    let statement = ExecutionStatement {
        chunk: ChunkProofPublicInputs {
            chunk_id: context.chunk_id,
            start_height,
            end_height,
            start_state_root: context.pre_state_root,
            end_state_root: state,
            start_block_hash,
            end_block_hash: parent,
            block_hash_root: merkle_root_of_hashes(&hashes),
            block_proof_root: merkle_root_from_hashes(proof_leaves),
            vrf_proof_root: merkle_root_from_hashes(vrf_leaves),
            active_validator_set_root: incoming.validators_root,
            // The full consensus transition replaces this runtime commitment
            // with the derived consensus active-set root before finality.
            next_validator_set_root: last.output.consensus_candidates_root,
            // Candidate validation derives the independently authenticated update.
            next_identity_sanctions_root: context.identity_sanctions_root,
            da_root: merkle_root_from_hashes(da_leaves),
        },
    };
    Ok((statement, hashes))
}

/// Bind one block to its predecessor `(parent, state, slot)`, its seated
/// proposer and the exact public inputs its receipt must carry; returns the
/// header hash.
#[allow(clippy::suspicious_operation_groupings)] // Wire fields deliberately differ from STF names.
fn verify_block_binding(
    context: &ExecutionContext,
    incoming: &neutrin0_consensus_types::history_proof::ConsensusBoundary,
    block: &ProvenBlock,
    height: u64,
    (parent, state, slot): (Hash, Hash, u64),
) -> Result<Hash, ExecutionError> {
    let header = &block.header;
    let pi = &block.public_inputs;
    let output = &block.output;
    let hash = header.hash();
    if header.parent_hash != parent
        || header.height != height
        || header.slot <= slot
        || output.pre_state_root != state
    {
        return Err(ExecutionError::Continuity);
    }
    let proposer = usize::try_from(header.proposer_index)
        .ok()
        .and_then(|index| context.active_validators.get(index))
        .filter(|validator| crate::finality::is_active(validator))
        .ok_or(ExecutionError::Proposer)?;
    let expected = BlockProofPublicInputs {
        context: runtime_context(header, *incoming).into(),
        chain_id: context.chain_id,
        height,
        parent_block_hash: parent,
        block_hash: hash,
        state_root_before: state,
        state_root_after: header.state_root,
        transactions_root: header.transactions_root,
        receipt_root: header.receipts_root,
        da_root: header.da_root,
        vm_code_hash: context.vm_code_hash,
        block_program: context.programs.execution.block,
        gas_used: header.gas_used,
        gas_limit: header.gas_limit,
        proposer_address: proposer.withdrawal_credentials,
        runtime_extra: header.runtime_extra,
        inputs_root: header.inputs_root,
    };
    if *pi != expected || !output_binds(output, pi) || output.gas_used > output.block_gas_limit {
        return Err(ExecutionError::BlockBinding);
    }
    Ok(hash)
}
