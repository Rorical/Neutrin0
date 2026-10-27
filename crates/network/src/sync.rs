//! Sync state machine implementing `docs/design/21-networking.md`
//! §"Sync state machine".
//!
//! ```text
//!     Light: Init → HistoryFetch → Following
//!     Full:  Init → Following (the driver's complete-chunk sync catches up)
//!     Archive: as Full, from providers whose retention covers the chunk.
//! ```
//!
//! [`SyncMachine`] is a **pure state machine**: it owns no I/O, performs no
//! verification, and persists nothing. The driver — typically the consensus
//! engine in `node` mode — translates [`SyncCommand`]s emitted by the FSM
//! into [`crate::service::NetworkCommand`]s (and gossip subscriptions), runs
//! the corresponding verification + storage, then notifies the FSM with the
//! resulting [`SyncEvent`].
//!
//! Separating the FSM from its execution lets us unit-test every transition
//! against synthetic events without spinning up libp2p or rocksdb.

use crate::service::HostGroup;
use crate::{
    rpc::{self, RpcProtocol},
    topic::Topic,
};
use libp2p::PeerId;
pub use neutrin0_light_client::sampling::SamplingPolicy;
use neutrin0_primitives::{BlockHash, CheckpointIndex, ChunkId, Hash, Height, Slot, StateRoot};
use std::collections::{BTreeMap, VecDeque};

mod events;
mod light;

pub use events::{SyncCommand, SyncEvent};

/// Sync goal selected at startup.
///
/// Defines which states the FSM walks before reaching [`SyncState::Following`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncMode {
    /// `Init → HistoryFetch → Following`.
    ///
    /// The light client accepts the latest History proof, a finalized chunk
    /// receipt proving its chain from genesis, for an endpoint that a quorum
    /// of sampled peers advertise identically. It does not download block
    /// bodies or state.
    LightClient,
    /// `Init → Following`. The driver's complete-chunk sync (or a snapshot
    /// bootstrap) catches up outside this machine, which only selects the
    /// moment to subscribe.
    Snap,
    /// Same as [`SyncMode::Snap`]; archives retain what they import and take
    /// it from providers whose advertised retention covers it.
    Archive,
}

/// Live sync state.
///
/// Each backfilling state carries `in_flight` so the driver can suppress
/// duplicate RPCs while a previous batch is being verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncState {
    /// Waiting for the first peer handshake.
    Init,
    /// Fetching the History proof of a newer endpoint that a quorum of
    /// sampled peers advertise.
    HistoryFetch {
        /// Chunk count at the locally authenticated endpoint.
        local_finalized_index: CheckpointIndex,
        /// Chunk count advertised at the chosen peer endpoint.
        target_index: CheckpointIndex,
        /// True while a `HistoryProof` RPC is in flight.
        in_flight: bool,
    },
    /// Live gossip subscriber. Pending sync requests are quiesced.
    Following,
    /// Permanent failure; the driver must reset before any further
    /// transitions are accepted.
    Stalled {
        /// Operator-readable reason.
        reason: SyncStallReason,
    },
}

/// Reason the sync machine became [`SyncState::Stalled`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncStallReason {
    /// Two verified History proofs end at different endpoints with one chunk
    /// count. The light client stops until an operator configures a new
    /// trusted checkpoint.
    HistoryConflict,
}

/// Local view of chain progress at the moment the FSM was constructed.
///
/// The FSM does not mutate this directly — the driver updates it via
/// [`SyncEvent::CheckpointsAdvanced`] / [`SyncEvent::HeadersAdvanced`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LocalProgress {
    /// Local chain id; peers reporting a mismatch are rejected.
    pub chain_id: u64,
    /// Canonical hash of the local chain spec.
    pub chain_spec_hash: Hash,
    /// Latest complete chunk finalized locally, or the last chunk a light
    /// client's accepted History proof covers.
    pub finalized_chunk_id: Option<ChunkId>,
    /// Hash of the latest finalized chunk, or zero at genesis.
    pub finalized_chunk_hash: Hash,
    /// Checkpoint hash of the boundary that chunk ends in.
    pub checkpoint_hash: Hash,
    /// State root at that boundary.
    pub finalized_state_root: StateRoot,
    /// Block hash at that boundary.
    pub finalized_block_hash: BlockHash,
    /// Block height at that boundary.
    pub finalized_height: Height,
    /// Highest authenticated head height (light clients need not store its header).
    pub head_height: Height,
    /// Hash of the local head block.
    pub head_block_hash: BlockHash,
    /// Slot of the local head block.
    pub head_slot: Slot,
    /// Highest height for which a block proof has been imported.
    pub proven_height: Height,
}

impl LocalProgress {
    /// Chunk count of the local finalized (or accepted) endpoint.
    #[must_use]
    pub fn finalized_chunks(&self) -> CheckpointIndex {
        self.finalized_chunk_id.map_or(0, |id| id.saturating_add(1))
    }
}

/// The sync state machine.
///
/// Construct with [`SyncMachine::new`], feed events with
/// [`SyncMachine::on_event`], and drain emitted commands from the returned
/// vector.
#[derive(Clone, Debug)]
pub struct SyncMachine {
    mode: SyncMode,
    state: SyncState,
    progress: LocalProgress,
    sync_peer: Option<PeerStatus>,
    light_sampling: SamplingPolicy,
    /// Latest status of each of the most recently heard distinct hosts, oldest
    /// first, at most `light_sampling.peers`.
    samples: VecDeque<PeerStatus>,
    /// The host each connected peer reached this node from, when known.
    peer_hosts: BTreeMap<PeerId, HostGroup>,
}

/// Snapshot of a peer's last reported status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerStatus {
    peer: PeerId,
    /// The peer's host when it sent the status; identities sharing one
    /// count as one light-client sample.
    host: Option<HostGroup>,
    status: rpc::Status,
}

impl SyncMachine {
    /// Construct a new sync machine in [`SyncState::Init`].
    #[must_use]
    pub const fn new(mode: SyncMode, progress: LocalProgress) -> Self {
        Self {
            mode,
            state: SyncState::Init,
            progress,
            sync_peer: None,
            light_sampling: SamplingPolicy::DEFAULT,
            samples: VecDeque::new(),
            peer_hosts: BTreeMap::new(),
        }
    }

    /// Override how many distinct peers a light client samples and how many
    /// must advertise an endpoint identically. The caller validates it.
    #[must_use]
    pub const fn with_light_sampling(mut self, policy: SamplingPolicy) -> Self {
        self.light_sampling = policy;
        self
    }

    /// Selected synchronization role.
    #[must_use]
    pub const fn mode(&self) -> SyncMode {
        self.mode
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> &SyncState {
        &self.state
    }

    /// Current local progress snapshot.
    #[must_use]
    pub const fn progress(&self) -> &LocalProgress {
        &self.progress
    }

    /// Refresh canonical cursors only after a backend atomically installs a checkpoint.
    pub const fn refresh_local_progress(&mut self, progress: LocalProgress) {
        self.progress = progress;
    }

    /// Selected sync peer, if any.
    #[must_use]
    pub fn sync_peer(&self) -> Option<PeerId> {
        self.sync_peer.map(|p| p.peer)
    }

    /// Apply an event and return the commands to execute.
    ///
    /// Returning an empty vector is normal — many events advance state
    /// without immediately requesting more data.
    pub fn on_event(&mut self, event: SyncEvent) -> Vec<SyncCommand> {
        match event {
            SyncEvent::Reset => self.reset(),
            SyncEvent::PeerConnected(peer) => self.on_peer_connected(peer),
            SyncEvent::PeerHost { peer, host } => {
                self.peer_hosts.insert(peer, host);
                Vec::new()
            }
            SyncEvent::PeerDisconnected(peer) => self.on_peer_disconnected(peer),
            SyncEvent::PeerStatus { peer, status } => self.on_peer_status(peer, &status),
            SyncEvent::CheckpointsAdvanced {
                new_finalized_index,
                new_finalized_hash,
                new_finalized_state_root,
                new_finalized_height,
                new_finalized_block_hash,
            } => self.on_checkpoints_advanced(
                new_finalized_index,
                new_finalized_hash,
                new_finalized_state_root,
                new_finalized_height,
                new_finalized_block_hash,
            ),
            SyncEvent::HeadersAdvanced {
                new_head_height,
                new_head_hash,
                new_head_slot,
            } => self.on_headers_advanced(new_head_height, new_head_hash, new_head_slot),
            SyncEvent::HistoryConflict => self.on_history_conflict(),
            SyncEvent::SampleRejected(peer) => self.on_sample_rejected(peer),
            SyncEvent::RpcFailed { protocol, peer } => self.on_rpc_failed(protocol, peer),
        }
    }

    // --- Event handlers ------------------------------------------------------

    fn reset(&mut self) -> Vec<SyncCommand> {
        self.state = SyncState::Init;
        self.sync_peer = None;
        self.samples.clear();
        Vec::new()
    }

    #[allow(clippy::unused_self)] // kept on `&self` for API symmetry with other handlers
    fn on_peer_connected(&self, peer: PeerId) -> Vec<SyncCommand> {
        // Always handshake newly-connected peers, regardless of state.
        vec![SyncCommand::RequestStatus(peer)]
    }

    fn on_peer_disconnected(&mut self, peer: PeerId) -> Vec<SyncCommand> {
        self.peer_hosts.remove(&peer);
        // A light client keeps what a departed peer advertised: the window
        // is the last distinct peers heard, and any provider can serve the
        // agreed endpoint, which the proof's checkpoint hash identifies.
        if self.sync_peer.is_some_and(|s| s.peer == peer) {
            if self.mode == SyncMode::LightClient
                && let SyncState::HistoryFetch { in_flight, .. } = &mut self.state
            {
                *in_flight = false;
            } else {
                self.sync_peer = None;
                self.state = SyncState::Init;
            }
        }
        Vec::new()
    }

    fn on_peer_status(&mut self, peer: PeerId, status: &rpc::Status) -> Vec<SyncCommand> {
        // Wrong chain/spec → ignore the peer (could become a Stall condition
        // once we count all peers, but with one-peer-at-a-time semantics a
        // single mismatch is not fatal).
        if status.chain_id != self.progress.chain_id
            || status.chain_spec_hash != self.progress.chain_spec_hash
        {
            return Vec::new();
        }
        if self.mode == SyncMode::LightClient {
            return self.on_light_status(peer, status);
        }

        let is_ahead = status.finalized_chunks() > self.progress.finalized_chunks()
            || status.head_height > self.progress.head_height;
        if !is_ahead {
            return Vec::new();
        }

        // Adopt this peer as the sync target.
        self.sync_peer = Some(PeerStatus {
            peer,
            host: self.peer_hosts.get(&peer).copied(),
            status: *status,
        });

        match self.state {
            SyncState::Init => self.enter_following(),
            _ => Vec::new(),
        }
    }

    /// Record whether the current backfill state has a request outstanding.
    const fn set_in_flight(&mut self, outstanding: bool) {
        if let SyncState::HistoryFetch { in_flight, .. } = &mut self.state {
            *in_flight = outstanding;
        }
    }

    const fn on_headers_advanced(
        &mut self,
        new_head_height: Height,
        new_head_hash: BlockHash,
        new_head_slot: Slot,
    ) -> Vec<SyncCommand> {
        self.progress.head_height = new_head_height;
        self.progress.head_block_hash = new_head_hash;
        self.progress.head_slot = new_head_slot;
        Vec::new()
    }

    fn enter_following(&mut self) -> Vec<SyncCommand> {
        self.state = SyncState::Following;
        let mut cmds: Vec<SyncCommand> = match self.mode {
            SyncMode::LightClient => vec![SyncCommand::Subscribe(Topic::Checkpoints)],
            SyncMode::Snap | SyncMode::Archive => {
                Topic::all_default().map(SyncCommand::Subscribe).collect()
            }
        };
        cmds.push(SyncCommand::EnterFollowing);
        cmds
    }

    fn on_rpc_failed(&mut self, protocol: RpcProtocol, peer: PeerId) -> Vec<SyncCommand> {
        if self.mode == SyncMode::LightClient
            && protocol == RpcProtocol::HistoryProof
            && self.sync_peer.is_none_or(|target| target.peer != peer)
        {
            return Vec::new();
        }
        // The history fetch waits for a fresh notification instead of retrying.
        if matches!(self.state, SyncState::HistoryFetch { .. })
            && protocol == RpcProtocol::HistoryProof
        {
            self.set_in_flight(false);
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests;
