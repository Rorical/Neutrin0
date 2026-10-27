//! Runtime-independent execution wire contract.

use alloc::{boxed::Box, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::{
    evidence::{EvidenceAnchor, EvidenceSubmission},
    participation::ParticipationReport,
};
use neutrin0_primitives::{Hash, StateRoot};

/// Canonical transaction envelope shared by every runtime.
/// User payloads are opaque to the host and consensus.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum RuntimeTransaction {
    /// Runtime-defined user transaction bytes.
    User(Vec<u8>),
    /// Framework evidence admission; all admissions precede user transactions.
    SubmitEvidence(Box<EvidenceSubmission>),
}

pub use neutrin0_consensus_types::runtime::ExecutionArtifacts;

/// WASM execution result; SP1 commits the common output and recomputes its artifacts.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct RuntimeBlockResult {
    /// Consensus-facing statement.
    pub output: RuntimeBlockOutput,
    /// Data bound by `output.receipts_root`.
    pub artifacts: ExecutionArtifacts,
}

/// Block execution input used by WASM, native adapters and the block Guest.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct RuntimeBlockInput {
    /// Consensus-derived execution environment; never supplied by a user transaction.
    pub context: neutrin0_consensus_types::runtime::ConsensusExecutionContext,
    /// Incoming active committee; its canonical commitment must match the boundary.
    pub active_validators: Vec<neutrin0_primitives::Validator>,
    /// Authenticated incoming consensus and execution-program context.
    pub evidence_anchor: EvidenceAnchor,
    /// Numeric chain identifier; the anchor also binds the complete specification.
    pub chain_id: u64,
    /// Header-authenticated execution height.
    pub block_height: u64,
    /// Header-authenticated resource limit.
    pub block_gas_limit: u64,
    /// Consensus withdrawal identity receiving runtime-defined proposer fees.
    pub proposer_address: Hash,
    /// Certified participation of the preceding chunk.
    pub participation: Option<ParticipationReport>,
    /// Certified proving report of the preceding chunk, consumed with the
    /// participation report (design 08).
    pub proving: Option<neutrin0_consensus_types::proving::ProvingReport>,
    /// Canonical positive participation derived from committed historical votes.
    pub participation_acks:
        Vec<neutrin0_consensus_types::participation::ParticipationAcknowledgement>,
    /// References of the body's program-lane pieces, in lane order; the chunk
    /// Guest authenticates them against the lane descriptors (design 20).
    pub program_pieces: Vec<neutrin0_consensus_types::ProgramPieceRef>,
    /// Exact ordered canonical transaction envelopes.
    pub transactions: Vec<RuntimeTransaction>,
}

/// Transaction count authenticated by the block and reused by compact chunk DA.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct TransactionSummary {
    /// All input envelopes, including transactions rejected by execution.
    pub transaction_count: u32,
}

pub use neutrin0_consensus_types::runtime::{AccountabilityOutput, Sanction};

/// The public values of a block receipt (design 08): the runtime's block
/// statement and the account the prover names for the receipt.
///
/// `prover_address` is chosen by the prover and accepted by every verifier at
/// any value; it is attribution for payment, never part of the transition.
/// Two receipts of one block with different attribution are two statements,
/// and the statement key, the commitment of these bytes, is what retention and
/// selection compare.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct BlockReceiptStatement {
    /// Exact block statement the runtime committed.
    pub output: RuntimeBlockOutput,
    /// Runtime account paid for this receipt.
    pub prover_address: Hash,
}

impl neutrin0_consensus_types::hashing::Committed for BlockReceiptStatement {
    const COMMITMENT_TAG: neutrin0_primitives::DomainTag =
        neutrin0_primitives::DOMAIN_BLOCK_STATEMENT;
}

/// Common block statement committed by every runtime's SP1 Guest.
///
/// The host checks its execution bindings; chunks authenticate its exact bytes
/// recursively and consume the candidate and accountability commitments.
/// Account layout, user transaction decoding, fees and receipt contents belong
/// to the runtime and do not change this statement's shape.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct RuntimeBlockOutput {
    /// Exact execution environment consumed by the proven transition.
    pub context: neutrin0_consensus_types::runtime::ConsensusExecutionContext,
    /// Block-proven evidence authorization, admissions and mandatory deductions.
    pub accountability: AccountabilityOutput,
    /// Chain identifier the STF executed under.  The consensus engine
    /// wires this into `BlockProofPublicInputs.chain_id` so a proof
    /// from chain A cannot be replayed as a proof on chain B (the
    /// committed value would not match the verifier's expected
    /// chain_id).
    pub chain_id: u64,
    /// Height of the block being executed.  Bound to
    /// `BlockProofPublicInputs.height` so a malicious prover cannot
    /// supply a forged `block_height` to the STF (e.g. to mature
    /// withdrawals early — the STF uses `block_height` for the
    /// `DEFAULT_UNBONDING_DELAY_BLOCKS` clock).
    pub block_height: u64,
    /// Block-level gas ceiling the STF executed under.  Bound to
    /// `BlockProofPublicInputs.gas_limit` so a malicious prover
    /// cannot raise the ceiling beyond what the header committed
    /// to (which would let gas-hogging transactions pass).
    pub block_gas_limit: u64,
    /// Runtime account credited with this block's accumulated fees.
    /// Bound to `BlockProofPublicInputs.proposer_address` so a
    /// malicious prover cannot redirect fees to a different
    /// address than the consensus header committed to.
    pub proposer_address: Hash,
    /// Commitment of the [`ParticipationReport`] this block consumed. A block
    /// before its chunk's carrier consumes none and commits the start
    /// boundary's, which is
    /// [`NO_PARTICIPATION`](neutrin0_consensus_types::participation::NO_PARTICIPATION)
    /// until a report is consumed. The Chunk Guest binds the carrier and later
    /// blocks to the report derived from the carried certificate (design 08).
    pub participation: neutrin0_primitives::Hash,
    /// Commitment of the proving report this block consumed or inherited
    /// (design 08).
    pub proving: neutrin0_primitives::Hash,
    /// Commitment of the positive participation records consumed by execution.
    pub participation_acks: neutrin0_primitives::Hash,
    /// Commitment of the program-lane references consumed by execution.
    pub program_pieces: neutrin0_primitives::Hash,
    /// Counted, tagged root over the borsh-encoded forms of the common
    /// transaction envelopes, `neutrin0_primitives::transactions_root_of_blobs`.
    /// Bound to
    /// `BlockProofPublicInputs.transactions_root` (= the body's
    /// `transactions_root` lane), so a malicious prover cannot feed
    /// the guest a transaction list that diverges from the one
    /// gossiped in the body (for example to forge `post_state_root` with a
    /// fake mint).
    pub transactions_root: StateRoot,
    /// Block-proven transaction count authenticating the omitted DA lane.
    pub transaction_summary: TransactionSummary,
    /// State root before this block.
    pub pre_state_root: StateRoot,
    /// State root after this block.
    pub post_state_root: StateRoot,
    /// Number of included transactions that executed successfully.
    pub applied: u32,
    /// Number of included transactions that reverted or halted. A skipped
    /// transaction (undecodable, invalid or over the gas limit) counts in
    /// neither field.
    pub failed: u32,
    /// Canonical commitment to the fixed consensus candidate record after
    /// execution. The consensus engine wires this into
    /// `header.runtime_extra` so the next block's chunk BFT uses the
    /// updated stake distribution.
    pub consensus_candidates_root: StateRoot,
    /// Total runtime-defined gas consumed, including failed execution and sanctions
    /// in this block. The consensus engine wires this into
    /// `header.gas_used` and `BlockProofPublicInputs.gas_used`, so the
    /// SP1 proof binds the same value the header committed to.
    pub gas_used: u64,
    /// Runtime-defined commitment over the block's receipts.
    /// The consensus engine wires this into
    /// `header.receipts_root` and `BlockProofPublicInputs.receipt_root`
    /// so the SP1 proof commits to the same digest.
    pub receipts_root: StateRoot,
}
