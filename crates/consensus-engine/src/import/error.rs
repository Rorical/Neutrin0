//! Failures while importing peer blocks, receipts and chunk proofs.

use core::fmt;

use neutrin0_consensus_vrf::VrfError;
use neutrin0_primitives::{BlockHash, ChunkId, Height, Slot, StateRoot};
use neutrin0_proof_system::ProofError;

use super::{
    HISTORY_UNAVAILABLE, MAX_CLOCK_DRIFT_SECS, PARTICIPATION_UNAVAILABLE, PROGRAMS_UNAVAILABLE,
};
use crate::body::BodyRoots;
use crate::signature::SignatureError;
use crate::store::StoreError;

/// Failures while importing a peer-supplied block or complete chunk proof.
#[derive(Debug)]
pub enum ImportError<E> {
    /// Header height is not `head + 1`.
    HeightMismatch {
        /// Expected height (local head + 1).
        expected: Height,
        /// Actual height in the imported header.
        actual: Height,
    },
    /// Header's `parent_hash` does not match the local head.
    ParentMismatch {
        /// Local head hash.
        expected: BlockHash,
        /// Parent hash in the imported header.
        actual: BlockHash,
    },
    /// Header proposer BLS signature failed to verify.
    HeaderSignature(SignatureError),
    /// Header proposer VRF claim failed to verify.
    HeaderVrf(VrfError),
    /// Header `gas_limit` differs from the chain specification's. The
    /// runtime executes under the header's limit, so a proposer free to pick
    /// it could make block gas bound nothing.
    GasLimitMismatch {
        /// `genesis_gas_limit` of the chain specification.
        expected: u64,
        /// Limit carried by the imported header.
        actual: u64,
    },
    /// Header slot does not strictly follow its parent's slot. The chunk
    /// Guest requires strictly increasing slots, so such a block could never
    /// be proven.
    SlotNotIncreasing {
        /// Slot of the parent header.
        parent_slot: Slot,
        /// Slot of the imported header.
        slot: Slot,
    },
    /// Header slot has not started on the local wall clock, beyond
    /// [`MAX_CLOCK_DRIFT_SECS`] of tolerance. A grinding proposer
    /// would otherwise move the head to a far-future slot and stall every
    /// honest producer until that slot arrives. Not proof of misbehaviour: a
    /// local clock running behind sees honest blocks this way, so the block
    /// may be imported again once its slot has started.
    FutureSlot {
        /// Slot of the imported header.
        slot: Slot,
        /// Scheduled start of that slot.
        slot_start: u64,
        /// Local wall-clock time.
        now: u64,
    },
    /// Header `timestamp` is not exactly the start of its slot.
    ///
    /// Chain time is the slot schedule, so a proposer can neither backdate
    /// nor postdate a block and lock later producers out of increasing time.
    HeaderTimestampMismatch {
        /// Timestamp on the imported header.
        actual: u64,
        /// Start of the header's slot.
        expected: u64,
    },
    /// The header failed against a successor context this node only projected.
    ///
    /// Another candidate of the open chunk may still win and give the header
    /// a different committee or seed, so this is not a verdict on it.
    ProjectedContext(Box<Self>),
    /// Execution contradicts the header while the writes reproduce its root.
    ///
    /// Proof-following nodes accept such a candidate, so this is not a gossip
    /// verdict: no receipt can prove it, and a contradicting receipt becomes
    /// an invalid execution claim.
    ExecutionDiverges(Box<Self>),
    /// A valid receipt credits a value that is not a runtime account; the
    /// runtime could never pay it.
    NonRuntimeProver {
        /// Hash of the block the receipt proves.
        hash: BlockHash,
    },
    /// Checked execution returned a runtime validator commitment different
    /// from the header's `runtime_extra`.
    HeaderRuntimeExtraMismatch {
        /// Value committed by the imported header.
        expected: [u8; 32],
        /// Value returned by the local executor.
        actual: [u8; 32],
    },
    /// Re-executing the block against the parent's state trie
    /// produced a different post-state root than the header claims.
    /// Surfaced by executor-equipped import or branch replay before that
    /// scratch state is published as the materialized head.
    StateRootMismatch {
        /// Value carried by the imported header.
        expected: StateRoot,
        /// Value the local executor produced re-running the body.
        computed: StateRoot,
    },
    /// The header declares other execution inputs than the block consumes on
    /// its branch (design 08). No receipt can prove such a header, and its
    /// state would escape an invalid execution claim, so no node admits it.
    InputsRootMismatch {
        /// Value carried by the imported header.
        declared: [u8; 32],
        /// Value derived from the branch's boundary, reports and votes.
        expected: [u8; 32],
    },
    /// Re-executing the block produced a different `receipts_root`
    /// than the header claims. Companion to
    /// [`Self::StateRootMismatch`].
    ReceiptsRootMismatch {
        /// Value carried by the imported header.
        expected: [u8; 32],
        /// Value the local executor produced re-running the body.
        computed: [u8; 32],
    },
    /// Re-executing the block produced a different `gas_used` than
    /// the header claims. Companion to [`Self::StateRootMismatch`].
    GasUsedMismatch {
        /// Value carried by the imported header.
        expected: u64,
        /// Value the local executor produced re-running the body.
        computed: u64,
    },
    /// The dry-run executor itself failed (trap, codec error, etc.).
    /// The block is rejected because the local node could not
    /// independently verify the proposer's claim; the SP1 proof
    /// path is the canonical authority but we refuse to advance
    /// the head against an unverifiable claim.
    DryRunFailed(String),
    /// A peer block cannot be judged: this engine has no executor to
    /// re-execute it and does not follow receipts. A node configuration
    /// fault, never a verdict on the block.
    ExecutorRequired,
    /// Reorg materialisation refused because the lowest common
    /// ancestor of the current head and the new fork-choice head
    /// is below the finalised height. The engine never retracts
    /// finalised history, so a fork-choice
    /// head that would require crossing the finalised line is
    /// rejected and the materialised head stays put.
    ReorgPastFinalized {
        /// Height of the lowest common ancestor we would have
        /// reorged back to.
        lca_height: Height,
        /// End height of the latest finalized chunk. The LCA must be at
        /// least this height.
        finalized_height: Height,
    },
    /// A branch would discard a durable certificate used by successor execution.
    ReorgPastCertified {
        /// Height of the proposed branch's common ancestor.
        lca_height: Height,
        /// End height of the certified execution dependency.
        certified_height: Height,
    },
    /// Block proof references a block header that is not stored locally.
    UnknownBlock(BlockHash),
    /// The program-artifact lane violates its piece count or size bounds.
    ProgramPieces,
    /// Body lane roots derived from the supplied body do not match the header.
    BodyRootsMismatch {
        /// Roots committed in the header.
        header: Box<BodyRoots>,
        /// Roots re-derived from the body.
        computed: Box<BodyRoots>,
    },
    /// An embedded vote targets a chunk outside the preceding eight finalized chunks.
    HistoricalVoteOutsideWindow {
        /// Chunk containing the imported block.
        chunk_id: ChunkId,
        /// Historical chunk claimed by the embedded vote.
        referenced_chunk: ChunkId,
    },
    /// Stored header's parent is required to reconstruct proof public inputs.
    MissingParentHeader {
        /// Parent hash that should have been present.
        parent_hash: BlockHash,
    },
    /// Block proof envelope does not match the stored canonical header.
    BlockProofEnvelopeMismatch {
        /// Hash the proof should have covered.
        expected_hash: BlockHash,
        /// Hash carried by the proof envelope.
        actual_hash: BlockHash,
        /// Height the proof should have covered.
        expected_height: Height,
        /// Height carried by the proof envelope.
        actual_height: Height,
    },
    /// Block proof's public inputs do not match the stored canonical header.
    BlockProofPublicInputsMismatch {
        /// Block hash whose proof inputs were inconsistent.
        hash: BlockHash,
    },
    /// A verified receipt executed different body-selected participation inputs.
    /// This is not an objective cryptographic proof rejection or block invalidity.
    BlockProofContextMismatch {
        /// Block hash whose retained body selected different execution context.
        hash: BlockHash,
    },
    /// A supplied state diff names another block, pre-state or post-state
    /// than the verified receipt, or is not canonically ordered. The diff is
    /// an unauthenticated transport artifact: fetch it from another peer.
    StateDiffMismatch {
        /// Block hash the diff should have covered.
        hash: BlockHash,
    },
    /// Applying the supplied state diff to the exact pre-state did not
    /// reproduce the post-state root the verified receipt binds.
    StateDiffRootMismatch {
        /// Root committed by the header and receipt.
        expected: StateRoot,
        /// Root the diff produced.
        computed: StateRoot,
    },
    /// A diff write addresses a key the state trie cannot hold.
    StateDiffMalformed,
    /// A candidate lies beyond the bounded pending chain: more than two
    /// chunks above the finalized head (design 08).
    PendingChainBound {
        /// Height of the refused candidate.
        height: Height,
        /// Highest height the pending chain may reach right now.
        limit: Height,
    },
    /// The proposer already published another candidate for this slot
    /// (design 08 case 13): the signed headers are a double proposal, and only
    /// a receipt admits the second candidate.
    SlotAlreadyProposed {
        /// Slot of both candidates.
        slot: neutrin0_primitives::Slot,
        /// The candidate this node already holds.
        existing: BlockHash,
    },
    /// As many unproven candidates as the pending chain has heights already
    /// wait above finality; a new one waits for receipts or finality.
    CandidateBound {
        /// Unproven candidates this node keeps at most.
        limit: usize,
    },
    /// Receipt-diff branch replay met a proven block without a retained diff.
    MissingStateDiff(BlockHash),
    /// The certificate names a receipt this node does not hold yet (design
    /// 08); the proof is retried once the receipt arrives.
    MissingBlockReceipt {
        /// Block whose receipt is named.
        hash: BlockHash,
        /// Statement key of the named receipt.
        statement_key: neutrin0_primitives::Hash,
    },
    /// Backend proof bytes failed to decode under the active backend.
    Codec(borsh::io::Error),
    /// Block proof verification rejected the proof.
    InvalidBlockProof(ProofError),
    /// Chunk proof verification rejected the proof.
    InvalidChunkProof(ProofError),
    /// The local witness a chunk proof must match could not be built, took
    /// no certificate or failed consensus validation; the message names the
    /// step and its cause.
    ChunkWitness(String),
    /// Underlying chain store / database error.
    Store(StoreError<E>),
}

impl<E> ImportError<E> {
    /// Whether checked execution produced other results than the header
    /// claims.
    #[must_use]
    pub const fn is_execution_divergence(&self) -> bool {
        matches!(
            self,
            Self::StateRootMismatch { .. }
                | Self::HeaderRuntimeExtraMismatch { .. }
                | Self::ReceiptsRootMismatch { .. }
                | Self::GasUsedMismatch { .. }
        )
    }

    /// `true` when the block could not be checked only because this node has
    /// not finalized the chunk its execution context depends on. The block is
    /// not known to be invalid; import it again after catching up.
    #[must_use]
    pub fn awaits_local_finality(&self) -> bool {
        matches!(
            self,
            Self::DryRunFailed(reason)
                if reason == PROGRAMS_UNAVAILABLE
                    || reason == PARTICIPATION_UNAVAILABLE
                    || reason == HISTORY_UNAVAILABLE
        )
    }
}

impl<E> From<StoreError<E>> for ImportError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Store(value)
    }
}

impl<E> From<borsh::io::Error> for ImportError<E> {
    fn from(value: borsh::io::Error) -> Self {
        Self::Codec(value)
    }
}

impl<E: fmt::Debug + fmt::Display> fmt::Display for ImportError<E> {
    #[allow(clippy::too_many_lines)] // One arm per variant; the table is intentionally flat.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeightMismatch { expected, actual } => {
                write!(
                    f,
                    "header height {actual} does not extend local head + 1 = {expected}"
                )
            }
            Self::ParentMismatch { expected, actual } => {
                write!(
                    f,
                    "header parent_hash {actual:?} does not match local head hash {expected:?}"
                )
            }
            Self::HeaderSignature(err) => write!(f, "header signature rejected: {err}"),
            Self::HeaderVrf(err) => write!(f, "header VRF claim rejected: {err}"),
            Self::GasLimitMismatch { expected, actual } => write!(
                f,
                "header gas_limit {actual} differs from the chain gas limit {expected}"
            ),
            Self::SlotNotIncreasing { parent_slot, slot } => write!(
                f,
                "header slot {slot} does not follow parent slot {parent_slot}"
            ),
            Self::FutureSlot {
                slot,
                slot_start,
                now,
            } => write!(
                f,
                "header slot {slot} starts at {slot_start}, after local time {now} plus {MAX_CLOCK_DRIFT_SECS}s"
            ),
            Self::HeaderTimestampMismatch { actual, expected } => write!(
                f,
                "header timestamp {actual} is not its slot start {expected}"
            ),
            Self::ProjectedContext(inner) => write!(
                f,
                "header does not match this node's projected successor context: {inner}"
            ),
            Self::ExecutionDiverges(inner) => write!(
                f,
                "execution contradicts the header while its writes reproduce the root: {inner}"
            ),
            Self::NonRuntimeProver { hash } => write!(
                f,
                "receipt of block {hash:?} credits a value that is not a runtime account"
            ),
            Self::HeaderRuntimeExtraMismatch { expected, actual } => write!(
                f,
                "header runtime_extra {actual:?} does not match executed runtime commitment {expected:?}"
            ),
            Self::StateRootMismatch { expected, computed } => write!(
                f,
                "dry-run state_root {computed:?} does not match header state_root {expected:?}",
            ),
            Self::InputsRootMismatch { declared, expected } => write!(
                f,
                "header inputs_root {declared:?} differs from the consumed inputs {expected:?}",
            ),
            Self::ReceiptsRootMismatch { expected, computed } => write!(
                f,
                "dry-run receipts_root {computed:?} does not match header receipts_root {expected:?}",
            ),
            Self::GasUsedMismatch { expected, computed } => write!(
                f,
                "dry-run gas_used {computed} does not match header gas_used {expected}",
            ),
            Self::DryRunFailed(msg) => write!(f, "dry-run executor failed: {msg}"),
            Self::ExecutorRequired => {
                f.write_str("peer import needs an executor or receipt following")
            }
            Self::ReorgPastFinalized {
                lca_height,
                finalized_height,
            } => write!(
                f,
                "reorg refused: lowest common ancestor at height {lca_height} \
                 is below finalised height {finalized_height}",
            ),
            Self::ReorgPastCertified {
                lca_height,
                certified_height,
            } => write!(
                f,
                "reorg refused: common ancestor at height {lca_height} is below certified execution height {certified_height}"
            ),
            Self::UnknownBlock(hash) => write!(f, "block proof targets unknown block {hash:?}"),
            Self::ProgramPieces => write!(f, "block body program lane exceeds its bounds"),
            Self::BodyRootsMismatch { header, computed } => write!(
                f,
                "block body roots mismatch: header {header:?}, computed {computed:?}"
            ),
            Self::HistoricalVoteOutsideWindow {
                chunk_id,
                referenced_chunk,
            } => write!(
                f,
                "embedded vote for chunk {referenced_chunk} is outside chunk {chunk_id}'s history window"
            ),
            Self::MissingParentHeader { parent_hash } => {
                write!(f, "parent header {parent_hash:?} is missing")
            }
            Self::BlockProofEnvelopeMismatch {
                expected_hash,
                actual_hash,
                expected_height,
                actual_height,
            } => write!(
                f,
                "block proof envelope ({actual_height}, {actual_hash:?}) does not match canonical ({expected_height}, {expected_hash:?})"
            ),
            Self::BlockProofPublicInputsMismatch { hash } => {
                write!(
                    f,
                    "block proof for {hash:?} does not match canonical public inputs"
                )
            }
            Self::BlockProofContextMismatch { hash } => write!(
                f,
                "verified block receipt for {hash:?} differs from body-selected execution context"
            ),
            Self::StateDiffMismatch { hash } => write!(
                f,
                "state diff for {hash:?} does not match the verified receipt or is not canonical"
            ),
            Self::StateDiffRootMismatch { expected, computed } => write!(
                f,
                "state diff produced root {computed:?}, receipt commits {expected:?}"
            ),
            Self::StateDiffMalformed => f.write_str("state diff addresses an invalid state key"),
            Self::PendingChainBound { height, limit } => write!(
                f,
                "candidate at height {height} exceeds the pending chain bound {limit}"
            ),
            Self::SlotAlreadyProposed { slot, existing } => write!(
                f,
                "slot {slot} already has the proposer's candidate {existing:?}"
            ),
            Self::CandidateBound { limit } => {
                write!(f, "{limit} unproven candidates already wait above finality")
            }
            Self::MissingStateDiff(hash) => {
                write!(f, "branch block {hash:?} has no retained state diff")
            }
            Self::MissingBlockReceipt {
                hash,
                statement_key,
            } => write!(
                f,
                "receipt {statement_key:?} of block {hash:?} is not held locally"
            ),
            Self::Codec(err) => write!(f, "borsh decode of backend proof failed: {err}"),
            Self::InvalidBlockProof(err) => {
                write!(f, "block proof verification rejected: {err:?}")
            }
            Self::InvalidChunkProof(err) => {
                write!(f, "chunk proof verification rejected: {err:?}")
            }
            Self::ChunkWitness(reason) => write!(f, "chunk proof witness rejected: {reason}"),
            Self::Store(err) => write!(f, "store error: {err}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for ImportError<E> {}
