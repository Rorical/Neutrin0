//! Block receipts and the public inputs they bind.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{BlockHash, ChainId, Hash, Height, StateRoot};

use crate::{history_proof, runtime};

/// Public inputs committed by a single block proof.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct BlockProofPublicInputs {
    /// Consensus execution environment authenticated by the containing chunk.
    pub context: alloc::boxed::Box<runtime::ConsensusExecutionContext>,
    /// Chain identifier preventing cross-chain proof replay.
    pub chain_id: ChainId,
    /// Canonical block height.
    pub height: Height,
    /// Hash of the parent block header.
    pub parent_block_hash: BlockHash,
    /// Hash of this block header.
    pub block_hash: BlockHash,
    /// State root the runtime extended.
    pub state_root_before: StateRoot,
    /// State root committed by the runtime after `execute_block`.
    pub state_root_after: StateRoot,
    /// Merkle root of the included transactions, in canonical order.
    pub transactions_root: Hash,
    /// Merkle root of the receipts emitted by the runtime.
    pub receipt_root: Hash,
    /// Data-availability commitment for this block.
    pub da_root: Hash,
    /// BLAKE3 of the WASM runtime artifact bytes.
    pub vm_code_hash: Hash,
    /// Block Guest expected to have produced this proof: the block program
    /// of the chunk boundary the block executes under (design 20). The
    /// verifier checks the receipt's verifying key against it.
    pub block_program: history_proof::VkDigest,
    /// Sum of per-transaction gas the runtime charged inside the block.
    /// Cross-checked against `header.gas_used` so a malicious prover
    /// cannot understate the block's gas consumption.
    pub gas_used: u64,
    /// Block-level gas ceiling the runtime executed under. Cross-checked
    /// against `header.gas_limit` so the proof's STF input cannot
    /// declare a different limit than the header committed to.
    pub gas_limit: u64,
    /// Runtime account that received this block's accumulated fees.
    /// Bound to `active_validator_set[header.proposer_index].withdrawal_credentials`
    /// so a malicious prover cannot redirect fees to a different
    /// address than consensus committed to.
    pub proposer_address: Hash,
    /// Runtime-emitted commitment carried in `header.runtime_extra`: the
    /// canonical `validator_set_root`. The SP1 Guest commits the same value
    /// as `RuntimeBlockOutput.validator_set_root` and the verifier
    /// cross-checks the two are equal, so a malicious prover cannot
    /// rewrite the consensus active set in the proven state without
    /// the runtime catching the disagreement.
    pub runtime_extra: Hash,
    /// The header's execution-input commitment (design 08); the output must
    /// reproduce it.
    pub inputs_root: Hash,
}

/// A retained block receipt: the backend proof bytes with the envelope the
/// node derived for them and the attribution the proof commits (design 08).
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct BlockProof {
    /// Block height proven by this artifact.
    pub height: Height,
    /// Block hash proven by this artifact.
    pub block_hash: BlockHash,
    /// Public inputs the backend proof binds.
    pub public_inputs: BlockProofPublicInputs,
    /// Backend-defined proof bytes.
    pub proof_bytes: Vec<u8>,
    /// Runtime account the receipt names for payment, read from its verified
    /// public values.
    pub prover_address: Hash,
    /// Commitment of the receipt's complete public values: the same for every
    /// proof of one statement, distinct for every attribution.
    pub statement_key: Hash,
}
