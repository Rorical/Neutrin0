//! Values the driver and a [`SyncBackend`](super::SyncBackend) exchange:
//! backend errors, import results and sync targets.

use neutrin0_primitives::{BlockHash, CheckpointIndex, ChunkId, Hash, Height, StateRoot};
use thiserror::Error;

/// Evidence-gossip verdict separates invalid receipts from local sync/cache limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceProofAcceptance {
    /// Authenticated and persisted for admission.
    Accepted,
    /// Local history is unavailable, evidence is stale, or the cache is full.
    Deferred,
    /// The submitted receipt or statement is invalid.
    Rejected,
}

/// Sequential sync range bounded by the previous complete consensus proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsensusSyncTarget {
    /// Chunk awaiting proof-gated finalization.
    pub chunk_id: ChunkId,
    /// First height to fetch when establishing a peer's branch.
    pub start_height: Height,
    /// Last height of this chunk.
    pub end_height: Height,
}

/// Errors a backend can surface to the driver.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum SyncBackendError {
    /// Peer-supplied data failed verification.
    #[error("peer data rejected: {0}")]
    Rejected(String),
    /// Backend storage failed.
    #[error("storage error: {0}")]
    Storage(String),
    /// Request parameters are invalid or exceed supported query bounds.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// Backend was asked for data it does not yet have.
    #[error("not available: {0}")]
    NotAvailable(String),
    /// This provider deliberately pruned the requested history; try another provider.
    #[error(
        "data pruned; retained chunks start at {retained_from_chunk}, blocks at {retained_from_height}"
    )]
    Pruned {
        /// Earliest complete retained chunk.
        retained_from_chunk: ChunkId,
        /// Earliest complete retained block payload.
        retained_from_height: Height,
    },
    /// Peer data could not be imported because the local chain is
    /// missing an earlier link.
    ///
    /// Distinct from [`Self::Rejected`] so the driver can reset the
    /// complete-chunk cursor instead of treating the message
    /// as malicious. Surfaced by `verify_and_import_proven_blocks`
    /// when the publication's parent is not known locally.
    #[error("local chain is behind peer: {0}")]
    ChainBehind(String),
}

/// Result of a light client accepting a History proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointsImported {
    /// Chunk count at the accepted endpoint.
    pub new_finalized_index: CheckpointIndex,
    /// Checkpoint hash of the accepted endpoint.
    pub new_finalized_hash: [u8; 32],
    /// State root at the endpoint.
    pub new_finalized_state_root: StateRoot,
    /// Block height at the endpoint.
    pub new_finalized_height: Height,
    /// Block hash at the endpoint.
    pub new_finalized_block_hash: BlockHash,
}

/// Result of importing a batch of headers / blocks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeadersImported {
    /// Highest header height now stored locally.
    pub new_head_height: Height,
    /// Hash of the new head.
    pub new_head_hash: BlockHash,
    /// Slot of the new head.
    pub new_head_slot: u64,
}

/// Result of importing block receipts (design 08).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReceiptsImported {
    /// Heights whose block became proven by this batch, in import order.
    pub proven: Vec<Height>,
    /// Receipts kept for the orphan window because their block is unknown.
    pub buffered: usize,
    /// Proposer receipts newly retained for blocks another receipt already
    /// proved; selection prefers them, so they are relayed.
    pub relayed: usize,
}

/// Artifacts a deferred leader proposal names that this node does not hold
/// (design 08, voter rules 1 and 4).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProposalArtifacts {
    /// Blocks of the proposal's range whose named receipt is missing.
    pub receipts: Vec<BlockHash>,
    /// Ratified chunks whose named proof is missing, with its statement key.
    pub chunk_proofs: Vec<(ChunkId, Hash)>,
}

impl ProposalArtifacts {
    /// Whether nothing named is missing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.receipts.is_empty() && self.chunk_proofs.is_empty()
    }
}

/// Result of importing trie nodes during a snapshot bootstrap's state download.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateProgress {
    /// `true` once the target state root is fully reconstructed locally.
    pub root_complete: bool,
    /// Exact pending node/value hashes and offsets discovered from verified nodes.
    pub next_items: Vec<neutrin0_consensus_types::bootstrap::StateItem>,
}

/// Result of importing a single chunk proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChunkProofImported {
    /// Chunk id covered by the imported proof.
    pub chunk_id: ChunkId,
    /// Last block height covered by the chunk.
    pub end_height: Height,
}
