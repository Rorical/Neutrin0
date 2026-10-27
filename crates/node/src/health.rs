//! Operational readiness sampled independently of HTTP requests.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::HealthConfig;
use crate::metrics::{MetricsSnapshot, MetricsSource, SNAPSHOT_INTERVAL};

/// A missing sampler heartbeat must not leave a stale healthy response cached.
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
enum Lifecycle {
    Starting,
    Running,
    Stopping,
    Failed,
}

struct State {
    lifecycle: Lifecycle,
    snapshot: Option<MetricsSnapshot>,
    sampled_at: Option<Instant>,
    finalized_chunks: u64,
    last_progress: Instant,
}

/// Shared bounded health state; no scrape takes the engine lock.
#[expect(
    clippy::redundant_pub_crate,
    reason = "health state is internal even if its module later becomes public"
)]
pub(crate) struct NodeHealth {
    min_peers: u64,
    stall_timeout: Duration,
    state: Mutex<State>,
}

/// Why the node is or is not ready, in exposition order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "readiness reasons are an internal HTTP adapter interface"
)]
pub(crate) enum ReadinessReason {
    Starting,
    Stopping,
    CriticalTaskFailed,
    HealthSampleStale,
    BootstrapPending,
    TrustAnchorExpired,
    HistoryConflict,
    StoragePressure,
    InsufficientPeers,
    Syncing,
    FinalityStalled,
    Ok,
    HealthSamplePending,
}

impl ReadinessReason {
    pub(crate) const ALL: [Self; 13] = [
        Self::Starting,
        Self::Stopping,
        Self::CriticalTaskFailed,
        Self::HealthSampleStale,
        Self::BootstrapPending,
        Self::TrustAnchorExpired,
        Self::HistoryConflict,
        Self::StoragePressure,
        Self::InsufficientPeers,
        Self::Syncing,
        Self::FinalityStalled,
        Self::Ok,
        Self::HealthSamplePending,
    ];

    /// Fixed label used in HTTP bodies and the readiness gauge.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Stopping => "stopping",
            Self::CriticalTaskFailed => "critical_task_failed",
            Self::HealthSampleStale => "health_sample_stale",
            Self::BootstrapPending => "bootstrap_pending",
            Self::TrustAnchorExpired => "trust_anchor_expired",
            Self::HistoryConflict => "history_conflict",
            Self::StoragePressure => "storage_pressure",
            Self::InsufficientPeers => "insufficient_peers",
            Self::Syncing => "syncing",
            Self::FinalityStalled => "finality_stalled",
            Self::Ok => "ok",
            Self::HealthSamplePending => "health_sample_pending",
        }
    }
}

/// Status returned by the HTTP endpoints and exported as gauges.
#[expect(
    clippy::redundant_pub_crate,
    reason = "health responses are an internal HTTP adapter interface"
)]
pub(crate) struct HealthStatus {
    pub live: bool,
    pub ready: bool,
    pub reason: ReadinessReason,
    pub finality_age: Duration,
    pub stall_timeout: Duration,
    pub sample_age: Option<Duration>,
}

impl NodeHealth {
    pub(crate) fn new(config: &HealthConfig, slot_seconds: u64, chunk_size: u64) -> Self {
        let default_timeout = slot_seconds
            .saturating_mul(chunk_size)
            .saturating_mul(3)
            .max(1800);
        Self {
            min_peers: u64::try_from(config.min_peers).unwrap_or(u64::MAX),
            stall_timeout: Duration::from_secs(
                config
                    .finality_stall_timeout_secs
                    .unwrap_or(default_timeout),
            ),
            state: Mutex::new(State {
                lifecycle: Lifecycle::Starting,
                snapshot: None,
                sampled_at: None,
                finalized_chunks: 0,
                last_progress: Instant::now(),
            }),
        }
    }

    pub(crate) fn mark_running(&self) {
        let mut state = self.state.lock().expect("health state poisoned");
        state.lifecycle = Lifecycle::Running;
        // Expensive prover setup is outside the live finality grace period.
        state.last_progress = Instant::now();
    }

    pub(crate) fn mark_stopping(&self) {
        self.state.lock().expect("health state poisoned").lifecycle = Lifecycle::Stopping;
    }

    pub(crate) fn mark_failed(&self) {
        self.state.lock().expect("health state poisoned").lifecycle = Lifecycle::Failed;
    }

    pub(crate) async fn monitor(self: Arc<Self>, source: Arc<dyn MetricsSource>) {
        let mut interval = tokio::time::interval(SNAPSHOT_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let source = Arc::clone(&source);
            // Engine sampling takes synchronous locks; keep HTTP and signal
            // handling schedulable while an import holds one of those locks.
            let snapshot = tokio::task::spawn_blocking(move || source.snapshot())
                .await
                .expect("health sampler panicked");
            self.sample_at(snapshot, Instant::now());
        }
    }

    fn sample_at(&self, snapshot: MetricsSnapshot, now: Instant) {
        let mut state = self.state.lock().expect("health state poisoned");
        if state.snapshot.is_none() || snapshot.finalized_chunks > state.finalized_chunks {
            state.last_progress = now;
            state.finalized_chunks = snapshot.finalized_chunks;
        }
        state.snapshot = Some(snapshot);
        state.sampled_at = Some(now);
    }

    #[cfg(test)]
    pub(crate) fn sample_for_test(&self, snapshot: MetricsSnapshot) {
        self.sample_at(snapshot, Instant::now());
    }

    pub(crate) fn snapshot(&self) -> MetricsSnapshot {
        self.state
            .lock()
            .expect("health state poisoned")
            .snapshot
            .clone()
            .unwrap_or_default()
    }

    pub(crate) fn status(&self) -> HealthStatus {
        self.status_at(Instant::now())
    }

    fn status_at(&self, now: Instant) -> HealthStatus {
        let state = self.state.lock().expect("health state poisoned");
        let finality_age = now.saturating_duration_since(state.last_progress);
        let reason = match state.lifecycle {
            Lifecycle::Starting => ReadinessReason::Starting,
            Lifecycle::Stopping => ReadinessReason::Stopping,
            Lifecycle::Failed => ReadinessReason::CriticalTaskFailed,
            Lifecycle::Running => match (&state.snapshot, state.sampled_at) {
                (Some(snapshot), Some(sampled_at)) => {
                    if now.saturating_duration_since(sampled_at) > SAMPLE_TIMEOUT {
                        ReadinessReason::HealthSampleStale
                    } else if snapshot.bootstrap_pending {
                        ReadinessReason::BootstrapPending
                    } else if snapshot.trust_anchor_expired {
                        ReadinessReason::TrustAnchorExpired
                    } else if snapshot.history_conflict {
                        ReadinessReason::HistoryConflict
                    } else if snapshot.storage_pressure {
                        ReadinessReason::StoragePressure
                    } else if snapshot.peers < self.min_peers {
                        ReadinessReason::InsufficientPeers
                    } else if snapshot.syncing
                        && !(self.min_peers == 0
                            && snapshot.peers == 0
                            && snapshot.sync_awaiting_peer)
                    {
                        ReadinessReason::Syncing
                    } else if finality_age >= self.stall_timeout {
                        ReadinessReason::FinalityStalled
                    } else {
                        ReadinessReason::Ok
                    }
                }
                _ => ReadinessReason::HealthSamplePending,
            },
        };
        HealthStatus {
            live: matches!(state.lifecycle, Lifecycle::Running)
                && !matches!(
                    reason,
                    ReadinessReason::HealthSampleStale | ReadinessReason::HealthSamplePending
                ),
            ready: reason == ReadinessReason::Ok,
            reason,
            finality_age,
            stall_timeout: self.stall_timeout,
            sample_age: state.sampled_at.map(|at| now.saturating_duration_since(at)),
        }
    }
}

#[cfg(test)]
mod tests;
