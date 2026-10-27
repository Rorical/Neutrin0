//! Fixed-label measurements for sync and authenticated bootstrap progress.

use crate::{SyncBackendError, backend::ConsensusSyncTarget};
use neutrin0_network::{LocalProgress, SyncStallReason, SyncState};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

mod render;
#[cfg(test)]
mod tests;

const PHASES: [&str; 8] = [
    "init",
    "history_fetch",
    "following",
    "stalled",
    "bootstrap_history",
    "bootstrap_state",
    "full_chunk",
    "bootstrap_waiting",
];

/// Current sync activity; discriminants index `PHASES`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Init,
    HistoryFetch,
    Following,
    Stalled,
    BootstrapHistory,
    BootstrapState,
    FullChunk,
    BootstrapWaiting,
}

impl Phase {
    /// Bootstrap work outranks sequential full-chunk sync, which outranks the FSM.
    pub(crate) const fn select(
        fsm: Self,
        bootstrap: Option<BootstrapKind>,
        bootstrap_syncing: bool,
        full_chunk_syncing: Option<bool>,
    ) -> Self {
        match (bootstrap, full_chunk_syncing) {
            (Some(BootstrapKind::History), _) => Self::BootstrapHistory,
            (Some(BootstrapKind::State), _) => Self::BootstrapState,
            (None, _) if bootstrap_syncing => Self::BootstrapWaiting,
            (None, Some(_)) if matches!(fsm, Self::Stalled) => Self::Stalled,
            (None, Some(true)) => Self::FullChunk,
            (None, Some(false)) => Self::Following,
            (None, None) => fsm,
        }
    }
}

/// Slots of `RESULTS` assigned without a backend error.
const RESULT_OK: usize = 0;
const RESULT_PRUNED: usize = 5;
const RESULT_TRANSPORT: usize = 7;
const RESULT_CANCELLED: usize = 8;
const RESULTS: [&str; 9] = [
    "ok",
    "rejected",
    "storage",
    "invalid_request",
    "not_available",
    "pruned",
    "chain_behind",
    "transport",
    "cancelled",
];
const BOOTSTRAP_KINDS: [&str; 2] = ["history", "state"];
const FULL_CHUNK_KINDS: [&str; 2] = ["blocks", "finality"];

#[derive(Clone, Copy)]
pub(crate) enum BootstrapKind {
    History,
    State,
}
impl BootstrapKind {
    const fn index(self) -> usize {
        match self {
            Self::History => 0,
            Self::State => 1,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum FullChunkKind {
    Blocks,
    Finality,
}
impl FullChunkKind {
    const fn index(self) -> usize {
        match self {
            Self::Blocks => 0,
            Self::Finality => 1,
        }
    }
}

const fn backend_result(error: &SyncBackendError) -> usize {
    match error {
        SyncBackendError::Rejected(_) => 1,
        SyncBackendError::Storage(_) => 2,
        SyncBackendError::InvalidRequest(_) => 3,
        SyncBackendError::NotAvailable(_) => 4,
        SyncBackendError::Pruned { .. } => 5,
        SyncBackendError::ChainBehind(_) => 6,
    }
}

/// Shared sync measurements with fixed phase, unit, operation and outcome labels.
/// Heights, chunk counts and provider hints are gauge values, never labels.
#[derive(Debug, Default)]
pub struct SyncMetrics {
    phase: AtomicUsize,
    fsm_target_height: AtomicU64,
    fsm_cursor_height: AtomicU64,
    fsm_target_chunks: AtomicU64,
    fsm_cursor_chunks: AtomicU64,
    fsm_inflight: AtomicU64,
    stalled_reason: AtomicUsize,
    progress: [AtomicU64; 3],
    progress_available: AtomicU64,
    full_chunk_target_available: AtomicU64,
    full_chunk_consensus_target: [AtomicU64; 3],
    bootstrap_inflight: AtomicU64,
    bootstrap_waiting: AtomicU64,
    bootstrap_pending_items: AtomicU64,
    bootstrap_target_chunks: AtomicU64,
    bootstrap_requests: [AtomicU64; 2],
    bootstrap_results: [[AtomicU64; RESULTS.len()]; 2],
    bootstrap_errors: [AtomicU64; RESULTS.len()],
    bootstrap_state_entries: AtomicU64,
    bootstrap_installs: AtomicU64,
    full_chunk_enabled: AtomicU64,
    observation_failures: [AtomicU64; 2],
    full_chunk_inflight: AtomicU64,
    full_chunk_cursors: [AtomicU64; 2],
    full_chunk_target_height: AtomicU64,
    full_chunk_requests: [AtomicU64; 2],
    full_chunk_results: [[AtomicU64; RESULTS.len()]; 2],
}

/// Local observations whose query failures are counted.
#[derive(Clone, Copy)]
pub(crate) enum Observation {
    LocalProgress,
    ConsensusTarget,
}

impl SyncMetrics {
    pub(crate) fn operator_progress(&self) -> crate::driver::SyncProgress {
        crate::driver::SyncProgress {
            phase: PHASES[self.phase.load(Ordering::Relaxed)],
            cursor_height: self.fsm_cursor_height.load(Ordering::Relaxed),
            target_height: self.fsm_target_height.load(Ordering::Relaxed),
            full_chunk_target_height: (self.full_chunk_target_available.load(Ordering::Relaxed)
                != 0)
                .then(|| self.full_chunk_target_height.load(Ordering::Relaxed)),
            full_chunk_cursors: core::array::from_fn(|index| {
                self.full_chunk_cursors[index].load(Ordering::Relaxed)
            }),
            bootstrap_target_chunks: self.bootstrap_target_chunks.load(Ordering::Relaxed),
            bootstrap_pending_items: self.bootstrap_pending_items.load(Ordering::Relaxed),
        }
    }
    /// Publish FSM cursors and return the FSM's own phase for [`Phase::select`].
    pub(crate) fn publish_fsm(&self, state: &SyncState) -> Phase {
        let (phase, cursor_height, target_height, cursor_chunks, target_chunks, inflight, reason) =
            match state {
                SyncState::Init => (Phase::Init, 0, 0, 0, 0, false, 0),
                SyncState::HistoryFetch {
                    local_finalized_index,
                    target_index,
                    in_flight,
                } => (
                    Phase::HistoryFetch,
                    0,
                    0,
                    *local_finalized_index,
                    *target_index,
                    *in_flight,
                    0,
                ),
                SyncState::Following => (Phase::Following, 0, 0, 0, 0, false, 0),
                SyncState::Stalled { reason } => (
                    Phase::Stalled,
                    0,
                    0,
                    0,
                    0,
                    false,
                    match reason {
                        SyncStallReason::HistoryConflict => 1,
                    },
                ),
            };
        self.fsm_cursor_height
            .store(cursor_height, Ordering::Relaxed);
        self.fsm_target_height
            .store(target_height, Ordering::Relaxed);
        self.fsm_cursor_chunks
            .store(cursor_chunks, Ordering::Relaxed);
        self.fsm_target_chunks
            .store(target_chunks, Ordering::Relaxed);
        self.fsm_inflight
            .store(u64::from(inflight), Ordering::Relaxed);
        self.stalled_reason.store(reason, Ordering::Relaxed);
        phase
    }

    pub(crate) fn publish_phase(&self, phase: Phase) {
        self.phase.store(phase as usize, Ordering::Relaxed);
    }

    pub(crate) fn publish_progress(&self, progress: &LocalProgress) {
        for (value, metric) in [
            progress.head_height,
            progress.proven_height,
            progress.finalized_chunks(),
        ]
        .into_iter()
        .zip(&self.progress)
        {
            metric.store(value, Ordering::Relaxed);
        }
        self.progress_available.store(1, Ordering::Relaxed);
    }

    pub(crate) fn publish_full_availability(
        &self,
        progress_known: bool,
        target: Option<&ConsensusSyncTarget>,
    ) {
        if let Some(target) = target {
            for (value, metric) in [target.chunk_id, target.start_height, target.end_height]
                .into_iter()
                .zip(&self.full_chunk_consensus_target)
            {
                metric.store(value, Ordering::Relaxed);
            }
        }
        self.progress_available
            .store(u64::from(progress_known), Ordering::Relaxed);
        self.full_chunk_target_available
            .store(u64::from(target.is_some()), Ordering::Relaxed);
    }

    pub(crate) fn publish_non_full_progress(&self, progress: &LocalProgress) {
        self.publish_progress(progress);
        self.full_chunk_target_available.store(0, Ordering::Relaxed);
    }

    pub(crate) fn publish_full_chunk(
        &self,
        enabled: bool,
        inflight: bool,
        cursors: [u64; 2],
        target_height: u64,
    ) {
        self.full_chunk_enabled
            .store(u64::from(enabled), Ordering::Relaxed);
        self.full_chunk_inflight
            .store(u64::from(inflight), Ordering::Relaxed);
        for (value, metric) in cursors.into_iter().zip(&self.full_chunk_cursors) {
            metric.store(value, Ordering::Relaxed);
        }
        self.full_chunk_target_height
            .store(target_height, Ordering::Relaxed);
    }

    pub(crate) fn publish_bootstrap(&self, inflight: bool, syncing: bool) {
        self.bootstrap_inflight
            .store(u64::from(inflight), Ordering::Relaxed);
        self.bootstrap_waiting
            .store(u64::from(syncing && !inflight), Ordering::Relaxed);
    }

    pub(crate) fn bootstrap_target(&self, chunks: u64) {
        self.bootstrap_target_chunks
            .store(chunks, Ordering::Relaxed);
    }
    pub(crate) fn bootstrap_pending(&self, items: usize) {
        self.bootstrap_pending_items
            .store(u64::try_from(items).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
    pub(crate) fn bootstrap_request(&self, kind: BootstrapKind) {
        self.bootstrap_requests[kind.index()].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn bootstrap_cancelled(&self, kind: BootstrapKind) {
        self.bootstrap_results[kind.index()][RESULT_CANCELLED].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn bootstrap_transport_error(&self, kind: BootstrapKind) {
        self.bootstrap_results[kind.index()][RESULT_TRANSPORT].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn bootstrap_error(&self, error: &SyncBackendError) {
        self.bootstrap_errors[backend_result(error)].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn bootstrap_result<T>(
        &self,
        kind: BootstrapKind,
        result: &Result<T, SyncBackendError>,
    ) {
        let outcome = result.as_ref().err().map_or(RESULT_OK, backend_result);
        self.bootstrap_results[kind.index()][outcome].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn bootstrap_state_entries(&self, entries: usize) {
        self.bootstrap_state_entries.fetch_add(
            u64::try_from(entries).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }
    pub(crate) fn bootstrap_installed(&self) {
        self.bootstrap_installs.fetch_add(1, Ordering::Relaxed);
        self.bootstrap_pending_items.store(0, Ordering::Relaxed);
    }

    pub(crate) fn observation_error(&self, observation: Observation) {
        self.observation_failures[observation as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn full_chunk_request(&self, kind: FullChunkKind) {
        self.full_chunk_requests[kind.index()].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn full_chunk_cancelled(&self, kind: FullChunkKind) {
        self.full_chunk_results[kind.index()][RESULT_CANCELLED].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn full_chunk_pruned(&self, kind: FullChunkKind) {
        self.full_chunk_results[kind.index()][RESULT_PRUNED].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn full_chunk_transport_error(&self, kind: FullChunkKind) {
        self.full_chunk_results[kind.index()][RESULT_TRANSPORT].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn full_chunk_result<T>(
        &self,
        kind: FullChunkKind,
        result: &Result<T, SyncBackendError>,
    ) {
        let outcome = result.as_ref().err().map_or(RESULT_OK, backend_result);
        self.full_chunk_results[kind.index()][outcome].fetch_add(1, Ordering::Relaxed);
    }
}
