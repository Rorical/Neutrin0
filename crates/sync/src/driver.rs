//! Async driver loop that bridges the libp2p [`NetworkService`] with the
//! sync [`SyncMachine`].
//!
//! `SyncDriver` owns:
//! - the [`SyncMachine`] state machine,
//! - an [`mpsc::Sender<NetworkCommand>`] used to drive the network,
//! - an [`mpsc::Receiver<NetworkEvent>`] consuming inbound events, and
//! - an [`Arc<dyn SyncBackend>`] performing verification and persistence
//!   (read for serving RPCs, write for importing peer data).
//!
//! For every outbound RPC the driver spawns a short task that awaits the
//! `oneshot` result and forwards it to an internal channel, so the main
//! `select!` loop remains purely event-driven.
//!
//! [`NetworkService`]: neutrin0_network::service::NetworkService

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::time::Duration;

use neutrin0_network::rpc::Status;
use neutrin0_network::service::{NetworkCommand, NetworkEvent};
use neutrin0_network::sync::{SyncMachine, SyncMode, SyncState};
use neutrin0_primitives::Height;
use tokio::sync::mpsc;

use crate::backend::SyncBackend;
use crate::metrics::Phase;

mod availability;
mod bft;
mod bootstrap;
mod candidates;
mod events;
mod full_chunk;
mod gossip;
mod handshake;
mod history;
mod inbound;
mod metadata;
mod outbound;
mod programs;
mod providers;
mod reporter_paths;
mod run;
#[cfg(test)]
mod status_tests;
mod transactions;

use history::{HistoryRequest, HistoryTarget};
use outbound::{OutboundEnvelope, OutboundOutcome};

/// Construction-time options for [`SyncDriver`].
#[derive(Clone, Copy, Debug)]
pub struct SyncDriverConfig {
    /// Sync mode passed into the underlying [`SyncMachine`].
    pub mode: SyncMode,
    /// Maximum outstanding outbound RPC responses tracked at once.
    pub outbound_buffer: usize,
    /// How many distinct peers a light client samples and how many must
    /// advertise an endpoint identically before it is fetched.
    pub light_sampling: neutrin0_network::sync::SamplingPolicy,
}

impl Default for SyncDriverConfig {
    fn default() -> Self {
        Self {
            mode: SyncMode::Snap,
            outbound_buffer: 256,
            light_sampling: neutrin0_network::sync::SamplingPolicy::DEFAULT,
        }
    }
}

/// Retain disconnected provider identities until the next availability event,
/// while bounding memory even if distinct peers continuously churn.
const HISTORY_PROVIDER_ATTEMPT_LIMIT: usize = 256;

/// Cadence of the retry tick driving availability, round recovery and
/// complete-chunk status polling.
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Untrusted ahead-of-context hints may refresh at most four connected
/// providers per retry interval. They never reset active authenticated work.
#[derive(Default)]
struct AheadHints {
    window: Option<tokio::time::Instant>,
    count: usize,
    peers: BTreeMap<neutrin0_network::PeerId, tokio::time::Instant>,
}

impl AheadHints {
    fn allow(&mut self, peer: neutrin0_network::PeerId, now: tokio::time::Instant) -> bool {
        self.peers
            .retain(|_, time| now.saturating_duration_since(*time) < RETRY_INTERVAL);
        if self
            .window
            .is_none_or(|start| now.saturating_duration_since(start) >= RETRY_INTERVAL)
        {
            self.window = Some(now);
            self.count = 0;
        }
        if self.count >= 4 || self.peers.contains_key(&peer) || self.peers.len() >= 256 {
            return false;
        }
        self.count += 1;
        self.peers.insert(peer, now);
        true
    }
}

/// Live sync summary shared with observers outside the driver task, such as
/// the `system_health` RPC. Cloning shares the same underlying counters.
#[derive(Clone, Debug)]
pub struct SyncStatus(Arc<SyncStatusInner>);

/// Independently sampled synchronization progress for local operator views.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncProgress {
    /// Current fixed activity label.
    pub phase: &'static str,
    /// FSM height cursor.
    pub cursor_height: u64,
    /// FSM target height.
    pub target_height: u64,
    /// Sequential full-chunk target height, when authenticated and available.
    pub full_chunk_target_height: Option<u64>,
    /// Next block height and chunk cursor for sequential full-chunk sync.
    pub full_chunk_cursors: [u64; 2],
    /// Snapshot bootstrap target chunk count.
    pub bootstrap_target_chunks: u64,
    /// Outstanding snapshot items.
    pub bootstrap_pending_items: u64,
}

#[derive(Debug)]
struct SyncStatusInner {
    peers: AtomicU64,
    syncing: AtomicBool,
    awaiting_first_peer: AtomicBool,
    metrics: crate::metrics::SyncMetrics,
}

impl Default for SyncStatus {
    /// Before the driver publishes anything the node has no peers and has
    /// not reached [`SyncState::Following`], so it reports as syncing.
    fn default() -> Self {
        Self(Arc::new(SyncStatusInner {
            peers: AtomicU64::new(0),
            syncing: AtomicBool::new(true),
            awaiting_first_peer: AtomicBool::new(true),
            metrics: crate::metrics::SyncMetrics::default(),
        }))
    }
}

impl SyncStatus {
    /// Current activity and progress, sampled independently from live counters.
    pub fn operator_progress(&self) -> SyncProgress {
        self.0.metrics.operator_progress()
    }
    /// Number of currently connected libp2p peers.
    #[must_use]
    pub fn peer_count(&self) -> u64 {
        self.0.peers.load(Ordering::Relaxed)
    }

    /// `true` while bootstrap or known sync targets remain incomplete.
    /// Sequential full sync compares authenticated local progress with its
    /// download targets instead of relying on an idle FSM. Unknown targets
    /// and a [`SyncState::Stalled`] driver remain syncing.
    #[must_use]
    pub fn is_syncing(&self) -> bool {
        self.0.syncing.load(Ordering::Relaxed)
    }

    /// `true` while the sync FSM is in [`SyncState::Init`] and neither
    /// sequential full sync nor bootstrap has established a target. This means
    /// waiting for a useful handshake rather than working on known backfill.
    /// The value is initially `true` and may become `true` again after a reset;
    /// it does not record whether this process has ever had a connected peer.
    /// Operators can use this with a zero-peer policy for an intentionally
    /// isolated development network without exempting backfill or stalled sync.
    #[must_use]
    pub fn awaiting_first_peer(&self) -> bool {
        self.0.awaiting_first_peer.load(Ordering::Relaxed)
    }

    /// Append fixed-label sync and bootstrap metrics. Cloned status handles
    /// observe the driver's event counters and latest progress snapshot.
    pub fn render_metrics(&self, out: &mut String) {
        self.0.metrics.render(out);
    }

    #[cfg(test)]
    fn publish(&self, peers: usize, state: &SyncState) {
        self.publish_observation(
            peers,
            !matches!(state, SyncState::Following),
            matches!(state, SyncState::Init),
        );
    }

    fn publish_observation(&self, peers: usize, syncing: bool, awaiting_peer: bool) {
        self.0
            .awaiting_first_peer
            .store(awaiting_peer, Ordering::Relaxed);
        self.0
            .peers
            .store(u64::try_from(peers).unwrap_or(u64::MAX), Ordering::Relaxed);
        self.0.syncing.store(syncing, Ordering::Relaxed);
    }
}

/// The engine-side bridge between the libp2p network service and the sync
/// state machine.
pub struct SyncDriver {
    full_chunks: full_chunk::FullChunkSync,
    bootstrap: bootstrap::BootstrapSync,
    candidates: candidates::CandidateSync,
    bft: bft::BftSync,
    availability: availability::AvailabilitySync,
    transactions: transactions::TransactionSync,
    programs: programs::ProgramSync,
    reporter_paths: reporter_paths::ReporterPathSync,
    peer_metadata: BTreeMap<neutrin0_network::PeerId, neutrin0_network::rpc::Metadata>,
    history_retry_at: tokio::time::Instant,
    fsm: SyncMachine,
    /// Observer-facing summary refreshed on every loop iteration.
    status: SyncStatus,
    backend: Arc<dyn SyncBackend>,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: mpsc::Receiver<NetworkEvent>,
    event_backlog: VecDeque<NetworkEvent>,
    outbound_rx: mpsc::Receiver<OutboundEnvelope>,
    outbound_tx: mpsc::Sender<OutboundEnvelope>,
    outbound_bytes: Arc<tokio::sync::Semaphore>,
    outbound_control_bytes: Arc<tokio::sync::Semaphore>,
    outbound_control_slots: Arc<tokio::sync::Semaphore>,
    outbound_slots: Arc<tokio::sync::Semaphore>,
    /// Inbound data queries served concurrently off this task.
    inbound_slots: Arc<tokio::sync::Semaphore>,
    /// One query slot per connected peer, so no peer holds more than one of
    /// the shared slots.
    inbound_peer_slots: BTreeMap<neutrin0_network::PeerId, Arc<tokio::sync::Semaphore>>,
    /// Connected providers used by bounded gossip hints and periodic status polling.
    connected_peers: BTreeSet<neutrin0_network::PeerId>,
    ahead_hints: AheadHints,
    /// Latest availability event. Its sequence preserves a notice that races with
    /// an older pending request's eventual unavailable response.
    history_announcement: Option<(u64, neutrin0_network::PeerId)>,
    /// Providers attempted for the current exact anchored endpoint and
    /// availability round.
    history_attempts: BTreeSet<neutrin0_network::PeerId>,
    history_attempt_target: Option<HistoryTarget>,
    /// Only this request may advance state or release the in-flight slot.
    active_history_request: Option<HistoryRequest>,
    next_history_nonce: u64,
    /// Compatible in-flight status updates, capped at the provider-round limit.
    deferred_history_status: BTreeMap<neutrin0_network::PeerId, neutrin0_network::rpc::Status>,
    deferred_history_cursor: Option<neutrin0_network::PeerId>,
    /// Conflict sides being fetched, and those already verified.
    conflict_checks: BTreeMap<HistoryTarget, bool>,
}

impl SyncDriver {
    /// Construct a new driver. The caller is responsible for spawning the
    /// network service that owns the other end of the supplied channels.
    pub fn new(
        config: SyncDriverConfig,
        backend: Arc<dyn SyncBackend>,
        local_progress: neutrin0_network::sync::LocalProgress,
        cmd_tx: mpsc::Sender<NetworkCommand>,
        event_rx: mpsc::Receiver<NetworkEvent>,
    ) -> Self {
        let (outbound_tx, outbound_rx) = mpsc::channel(config.outbound_buffer);
        let fsm = SyncMachine::new(config.mode, local_progress)
            .with_light_sampling(config.light_sampling);
        Self {
            full_chunks: full_chunk::FullChunkSync::default(),
            bootstrap: bootstrap::BootstrapSync::default(),
            candidates: candidates::CandidateSync::default(),
            bft: bft::BftSync::default(),
            availability: availability::AvailabilitySync::default(),
            transactions: transactions::TransactionSync::default(),
            programs: programs::ProgramSync::default(),
            reporter_paths: reporter_paths::ReporterPathSync::default(),
            peer_metadata: BTreeMap::new(),
            history_retry_at: tokio::time::Instant::now() + Duration::from_secs(30),
            fsm,
            status: SyncStatus::default(),
            backend,
            cmd_tx,
            event_rx,
            event_backlog: VecDeque::new(),
            outbound_rx,
            outbound_tx,
            outbound_bytes: Arc::new(tokio::sync::Semaphore::new(128 * 1024)),
            outbound_control_bytes: Arc::new(tokio::sync::Semaphore::new(64)),
            outbound_control_slots: Arc::new(tokio::sync::Semaphore::new(64)),
            outbound_slots: Arc::new(tokio::sync::Semaphore::new(16)),
            inbound_slots: Arc::new(tokio::sync::Semaphore::new(events::INBOUND_QUERY_SLOTS)),
            inbound_peer_slots: BTreeMap::new(),
            connected_peers: BTreeSet::new(),
            ahead_hints: AheadHints::default(),
            history_announcement: None,
            history_attempts: BTreeSet::new(),
            history_attempt_target: None,
            active_history_request: None,
            next_history_nonce: 0,
            deferred_history_status: BTreeMap::new(),
            deferred_history_cursor: None,
            conflict_checks: BTreeMap::new(),
        }
    }

    /// Inspect the underlying [`SyncMachine`] (chiefly for tests and
    /// metrics).
    #[must_use]
    pub const fn fsm(&self) -> &SyncMachine {
        &self.fsm
    }

    /// Shared handle reporting peer count and sync progress. Remains valid
    /// after the driver is moved into its task.
    #[must_use]
    pub fn status(&self) -> SyncStatus {
        self.status.clone()
    }

    fn metrics(&self) -> &crate::metrics::SyncMetrics {
        &self.status.0.metrics
    }

    pub(super) async fn publish_status(&mut self) {
        let fsm_phase = self.metrics().publish_fsm(self.fsm.state());
        full_chunk::publish_metrics(self);
        let bootstrap_syncing = bootstrap::is_syncing(self);
        let full_chunk_syncing = if self.full_chunks.enabled {
            let (local, target) = full_chunk::observe_local(self).await;
            if let Some(local) = &local {
                self.metrics().publish_progress(local);
            }
            self.metrics()
                .publish_full_availability(local.is_some(), target.as_ref());
            Some(full_chunk::is_syncing(
                self,
                local.as_ref(),
                target.as_ref(),
            ))
        } else {
            self.metrics()
                .publish_non_full_progress(self.fsm.progress());
            None
        };
        let syncing = bootstrap_syncing
            || full_chunk_syncing
                .unwrap_or_else(|| !matches!(self.fsm.state(), SyncState::Following));
        let awaiting_peer = !bootstrap_syncing
            && full_chunk_syncing.is_none()
            && matches!(self.fsm.state(), SyncState::Init);
        self.status
            .publish_observation(self.connected_peers.len(), syncing, awaiting_peer);
        let bootstrap_kind = bootstrap::active_kind(self);
        self.metrics()
            .publish_bootstrap(bootstrap_kind.is_some(), bootstrap_syncing);
        self.metrics().publish_phase(Phase::select(
            fsm_phase,
            bootstrap_kind,
            bootstrap_syncing,
            full_chunk_syncing,
        ));
    }
}

/// Whether two status handshakes describe the same chain and chain spec.
fn same_chain(a: &Status, b: &Status) -> bool {
    a.chain_id == b.chain_id && a.chain_spec_hash == b.chain_spec_hash
}

/// One bounded download page from `start` through at most `last`
/// (`start <= last`): the requested entry count and the page's last height.
fn page(start: Height, last: Height, max_entries: u64) -> (u64, Height) {
    let count = (last - start + 1).min(max_entries);
    (count, start + count - 1)
}
