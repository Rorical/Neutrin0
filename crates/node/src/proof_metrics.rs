//! Fixed-cardinality proving, admission and queue metrics.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::metrics::{LatencyHistogram, StageMetrics, counter, family, gauge, labeled, loads};
use crate::proving_budget::ProvingPriority;

/// Optional early-fact groups queued before producers drop new work.
pub(crate) const FACT_QUEUE_CAPACITY: usize = 8;

/// A fixed proving stage. Peer identities and proof hashes never become labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofStage {
    /// Block execution proof.
    Block,
    /// Complete consensus chunk proof.
    Chunk,
    /// Optional early cryptographic facts.
    Fact,
    /// Objective offence proof.
    Evidence,
    /// Local authenticated Guest setup.
    ProgramSetup,
}

impl ProofStage {
    /// Every supported label, including idle stages.
    pub const ALL: [Self; 5] = [
        Self::Block,
        Self::Chunk,
        Self::Fact,
        Self::Evidence,
        Self::ProgramSetup,
    ];

    /// Fixed Prometheus label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Chunk => "chunk",
            Self::Fact => "fact",
            Self::Evidence => "evidence",
            Self::ProgramSetup => "program_setup",
        }
    }

    /// Fixed scheduler priority label.
    #[must_use]
    pub const fn priority_label(self) -> &'static str {
        self.priority().label()
    }

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Block => 0,
            Self::Chunk => 1,
            Self::Fact => 2,
            Self::Evidence => 3,
            Self::ProgramSetup => 4,
        }
    }

    pub(crate) const fn priority(self) -> ProvingPriority {
        match self {
            Self::Block | Self::Chunk => ProvingPriority::Critical,
            Self::Fact | Self::Evidence | Self::ProgramSetup => ProvingPriority::Normal,
        }
    }

    fn labels(self) -> String {
        format!(
            "stage=\"{}\",priority=\"{}\"",
            self.label(),
            self.priority_label()
        )
    }
}

#[derive(Debug, Default)]
struct WaitHistogram {
    admitted: AtomicU64,
    cancelled: AtomicU64,
    latency: LatencyHistogram,
}

impl WaitHistogram {
    fn observe(&self, duration: Duration, admitted: bool) {
        if admitted {
            self.admitted.fetch_add(1, Ordering::Relaxed);
        } else {
            self.cancelled.fetch_add(1, Ordering::Relaxed);
        }
        self.latency.observe(duration);
    }

    fn render(&self, out: &mut String, labels: &str) {
        let _ = writeln!(
            out,
            "neutrin0_proving_wait_total{{{labels},outcome=\"admitted\"}} {}",
            self.admitted.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "neutrin0_proving_wait_total{{{labels},outcome=\"cancelled\"}} {}",
            self.cancelled.load(Ordering::Relaxed)
        );
        self.latency
            .render(out, "neutrin0_proving_wait_seconds", labels);
    }
}

/// Actual shared permit occupancy, distinct from launched blocking tasks.
#[derive(Debug, Default)]
pub struct BudgetMetrics {
    capacity: AtomicU64,
    inflight: [AtomicU64; ProofStage::ALL.len()],
    waiters: [AtomicU64; ProofStage::ALL.len()],
    waits: [WaitHistogram; ProofStage::ALL.len()],
}

impl BudgetMetrics {
    pub(crate) fn set_capacity(&self, capacity: usize) {
        self.capacity.store(
            u64::try_from(capacity).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }
    pub(crate) fn queued(&self, stage: ProofStage) {
        self.waiters[stage.index()].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn admitted(&self, stage: ProofStage, wait: Duration) {
        self.waiters[stage.index()].fetch_sub(1, Ordering::Relaxed);
        self.inflight[stage.index()].fetch_add(1, Ordering::Relaxed);
        self.waits[stage.index()].observe(wait, true);
    }
    pub(crate) fn cancelled(&self, stage: ProofStage, wait: Duration) {
        self.waiters[stage.index()].fetch_sub(1, Ordering::Relaxed);
        self.waits[stage.index()].observe(wait, false);
    }
    pub(crate) fn released(&self, stage: ProofStage) {
        self.inflight[stage.index()].fetch_sub(1, Ordering::Relaxed);
    }
    /// Admitted proof calls currently holding a permit for `stage`.
    pub(crate) fn inflight(&self, stage: ProofStage) -> u64 {
        self.inflight[stage.index()].load(Ordering::Relaxed)
    }

    /// Calls awaiting admission for the selected stage.
    pub(crate) fn waiting(&self, stage: ProofStage) -> u64 {
        self.waiters[stage.index()].load(Ordering::Relaxed)
    }

    fn render(&self, out: &mut String) {
        gauge(
            out,
            "neutrin0_proving_capacity",
            "Shared proof permit capacity.",
            self.capacity.load(Ordering::Relaxed),
        );
        family(
            out,
            "neutrin0_proving_inflight",
            "Actual admitted proof calls by stage and priority.",
            "gauge",
        );
        family(
            out,
            "neutrin0_proving_waiters",
            "Calls awaiting a shared permit.",
            "gauge",
        );
        family(
            out,
            "neutrin0_proving_wait_total",
            "Completed permit waits by outcome.",
            "counter",
        );
        family(
            out,
            "neutrin0_proving_wait_seconds",
            "Time waiting for a shared proof permit.",
            "histogram",
        );
        for stage in ProofStage::ALL {
            let labels = stage.labels();
            let _ = writeln!(
                out,
                "neutrin0_proving_inflight{{{labels}}} {}",
                self.inflight(stage)
            );
            let _ = writeln!(
                out,
                "neutrin0_proving_waiters{{{labels}}} {}",
                self.waiters[stage.index()].load(Ordering::Relaxed)
            );
            self.waits[stage.index()].render(out, &labels);
        }
    }
}

#[derive(Debug, Default)]
struct BacklogState {
    jobs: AtomicU64,
    items: AtomicU64,
}

/// Queue occupancy released when an entry is consumed or discarded.
#[derive(Clone, Debug, Default)]
pub struct BacklogMetrics(Arc<BacklogState>);

impl BacklogMetrics {
    pub(crate) fn track(&self, items: usize) -> BacklogGuard {
        let items = u64::try_from(items).unwrap_or(u64::MAX);
        self.0.jobs.fetch_add(1, Ordering::Relaxed);
        self.0.items.fetch_add(items, Ordering::Relaxed);
        BacklogGuard {
            state: Arc::clone(&self.0),
            items,
        }
    }
    fn render(&self, out: &mut String, name: &str) {
        gauge(
            out,
            &format!("{name}_pending"),
            "Undispatched jobs.",
            self.0.jobs.load(Ordering::Relaxed),
        );
        gauge(
            out,
            &format!("{name}_items_pending"),
            "Items in undispatched jobs.",
            self.0.items.load(Ordering::Relaxed),
        );
    }
}

pub(crate) struct BacklogGuard {
    state: Arc<BacklogState>,
    items: u64,
}
impl Drop for BacklogGuard {
    fn drop(&mut self) {
        self.state.jobs.fetch_sub(1, Ordering::Relaxed);
        self.state.items.fetch_sub(self.items, Ordering::Relaxed);
    }
}

/// Proof pipeline outcomes, backlogs and resource admission.
#[derive(Debug, Default)]
pub struct ProofMetrics {
    /// Authenticated program setup attempts and latency.
    pub program_setups: StageMetrics,
    /// Early fact prover calls (including failures and panics).
    pub fact_proofs: StageMetrics,
    /// Evidence batch prover calls (including split retries).
    pub evidence_proofs: StageMetrics,
    /// Actual incoming evidence receipt verification calls.
    pub evidence_verification: StageMetrics,
    /// Shared admission budget.
    pub budget: BudgetMetrics,
    /// Queued early-fact groups and individual requests.
    pub fact_backlog: BacklogMetrics,
    /// Queued evidence batches and individual claims.
    pub evidence_backlog: BacklogMetrics,
    /// Prepared chunk jobs not yet started by a blocking worker.
    pub chunk_backlog: BacklogMetrics,
    /// Quorum wakeups coalesced while one chunk proof is outstanding.
    pub chunk_busy: AtomicU64,
    /// Optional fact groups discarded because the queue is full.
    pub fact_dropped_full: AtomicU64,
    /// Optional fact groups discarded because the receiver has closed.
    pub fact_dropped_closed: AtomicU64,
    /// Optional fact groups exceeding the encoding limit.
    pub fact_dropped_oversize: AtomicU64,
    /// Evidence wakeups coalesced while an existing batch is in progress.
    pub evidence_busy: AtomicU64,
    evidence_outcomes: [AtomicU64; 3],
    local_evidence_outcomes: [AtomicU64; 4],
    fact_coverage: Mutex<Option<(u64, u64)>>,
}

impl ProofMetrics {
    pub(crate) fn local_evidence_outcome(
        &self,
        outcome: neutrin0_sync::EvidenceProofAcceptance,
        fresh: bool,
    ) {
        let index = match outcome {
            neutrin0_sync::EvidenceProofAcceptance::Accepted if fresh => 0,
            neutrin0_sync::EvidenceProofAcceptance::Accepted => 1,
            neutrin0_sync::EvidenceProofAcceptance::Rejected => 2,
            neutrin0_sync::EvidenceProofAcceptance::Deferred => 3,
        };
        self.local_evidence_outcomes[index].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn evidence_outcome(&self, outcome: neutrin0_sync::EvidenceProofAcceptance) {
        let index = match outcome {
            neutrin0_sync::EvidenceProofAcceptance::Accepted => 0,
            neutrin0_sync::EvidenceProofAcceptance::Rejected => 1,
            neutrin0_sync::EvidenceProofAcceptance::Deferred => 2,
        };
        self.evidence_outcomes[index].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn set_fact_coverage(&self, covered: u64, total: u64) {
        *self.fact_coverage.lock().expect("fact coverage metrics") = Some((covered, total));
    }

    /// Coherent coverage of unique requests in the latest successful local chunk proof.
    #[must_use]
    pub fn fact_coverage(&self) -> Option<(u64, u64)> {
        *self.fact_coverage.lock().expect("fact coverage metrics")
    }

    /// Render bounded labels and every idle stage.
    pub fn render(&self, out: &mut String) {
        self.program_setups
            .render(out, "neutrin0_program_setup", "Authenticated program setup");
        self.fact_proofs
            .render(out, "neutrin0_fact_proof", "Fact proof");
        self.evidence_proofs
            .render(out, "neutrin0_evidence_proof", "Evidence proof");
        self.evidence_verification.render(
            out,
            "neutrin0_evidence_verify",
            "Incoming evidence verification",
        );
        self.budget.render(out);
        self.fact_backlog.render(out, "neutrin0_fact_queue");
        self.evidence_backlog.render(out, "neutrin0_evidence_queue");
        self.chunk_backlog.render(out, "neutrin0_chunk_queue");
        gauge(
            out,
            "neutrin0_fact_queue_capacity",
            "Optional early-fact group queue capacity.",
            FACT_QUEUE_CAPACITY,
        );
        counter(
            out,
            "neutrin0_chunk_worker_busy_total",
            "Quorum wakeups coalesced into an outstanding chunk proof.",
            self.chunk_busy.load(Ordering::Relaxed),
        );
        self.render_outcomes(out);
    }

    fn render_outcomes(&self, out: &mut String) {
        labeled(
            out,
            "neutrin0_evidence_report_import_total",
            "Incoming report admission attempts, independent of receipt verification.",
            "counter",
            "outcome",
            ["accepted", "rejected", "deferred"]
                .into_iter()
                .zip(loads(&self.evidence_outcomes)),
        );
        labeled(
            out,
            "neutrin0_evidence_local_install_total",
            "Locally proven receipt installation attempts.",
            "counter",
            "outcome",
            ["inserted", "existing", "rejected", "deferred"]
                .into_iter()
                .zip(loads(&self.local_evidence_outcomes)),
        );
        labeled(
            out,
            "neutrin0_fact_queue_dropped_total",
            "Optional fact groups not enqueued by reason.",
            "counter",
            "reason",
            [
                ("full", &self.fact_dropped_full),
                ("closed", &self.fact_dropped_closed),
                ("oversize", &self.fact_dropped_oversize),
            ]
            .map(|(reason, value)| (reason, value.load(Ordering::Relaxed))),
        );
        counter(
            out,
            "neutrin0_evidence_worker_busy_total",
            "Wakeups coalesced into an existing evidence worker.",
            self.evidence_busy.load(Ordering::Relaxed),
        );
    }
}

#[cfg(test)]
mod tests;
