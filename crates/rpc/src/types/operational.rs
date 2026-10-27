//! Read-only observations for operator clients.

use super::HashHex;
use serde::{Deserialize, Serialize};

/// A local observation; this is not a consensus certificate or readiness verdict.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Independent operational observations, not exclusive lifecycle states."
)]
pub struct DiagnosticsJson {
    /// Locally authenticated complete chain specification hash.
    pub chain_spec_hash: HashHex,
    /// Number of blocks per complete consensus chunk.
    pub chunk_size: u64,
    /// Specification unbonding delay in blocks; it fixes the lead an upgrade
    /// needs between enactment and activation.
    pub unbonding_delay_blocks: u64,
    /// Whether this node is a proof-only light client.
    pub proof_only: bool,
    /// Authenticated snapshot installation is unfinished.
    pub bootstrap_pending: bool,
    /// The proof-only trust anchor has expired, if applicable.
    pub trust_anchor_expired: bool,
    /// Two verified History proofs disagree and the light client halted until
    /// a new trusted checkpoint is configured.
    pub history_conflict: bool,
    /// The data filesystem is below its free-space quota; production and new
    /// candidate imports are paused.
    pub storage_pressure: bool,
    /// Sync-driver observations; absent when no driver is attached.
    pub sync: Option<SyncProgressJson>,
    /// Bounded live BFT sessions; absent committee data is not an empty committee.
    /// The local identity, its seat and its votes are on the management socket.
    pub bft_sessions: Option<Vec<BftSessionJson>>,
    /// Proof scheduler occupancy; sampled counters can change independently.
    pub proof_work: Vec<ProofWorkJson>,
    /// Queued block-proof jobs, before scheduler admission.
    pub queued_block_proofs: u64,
}

/// Current driver phase and bounded synchronization cursors.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncProgressJson {
    /// Current activity, such as `following`, `full_chunk`, or `stalled`.
    pub phase: String,
    /// Number of connected peers.
    pub peers: u64,
    /// Whether known synchronization work remains unfinished.
    pub syncing: bool,
    /// Waiting for a useful first-peer handshake.
    pub awaiting_first_peer: bool,
    /// FSM's height cursor (zero when that phase has no height cursor).
    pub cursor_height: u64,
    /// FSM's height target (zero when that phase has no height target).
    pub target_height: u64,
    /// Authenticated sequential full-chunk target height, when known.
    pub full_chunk_target_height: Option<u64>,
    /// Next block height and chunk cursor for sequential full-chunk sync.
    pub full_chunk_cursors: [u64; 2],
    /// Snapshot bootstrap's target chunk count.
    pub bootstrap_target_chunks: u64,
    /// Snapshot entries still outstanding.
    pub bootstrap_pending_items: u64,
}

/// One live BFT round. Stake values are observations, not fresh quorum verification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Independent consensus phase observations."
)]
pub struct BftSessionJson {
    /// Chunk under vote.
    pub chunk_id: u64,
    /// Current round.
    pub round: u32,
    /// Total, value prevote, value precommit, nil prevote, and nil precommit
    /// stake, in wei.
    pub stake: [super::Wei; 5],
    /// Engine observed a prevote quorum.
    pub prevote_quorum: bool,
    /// Engine observed a precommit quorum.
    pub precommit_quorum: bool,
}

/// Occupancy of one proof stage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProofWorkJson {
    /// Fixed stage name.
    pub stage: String,
    /// Calls waiting for scheduler admission.
    pub waiting: u64,
    /// Calls holding a proving permit.
    pub running: u64,
}
