//! Shared proof capacity with reserved foreground capacity and priority admission.

use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex},
    time::Instant,
};

use crate::metrics::NodeMetrics;
use crate::proof_metrics::ProofStage;
use neutrin0_runtime_host::backend::{
    SubmissionGate, SubmissionGuard, SubmissionObserver, SubmissionPriority, SubmissionRequest,
};

struct NativeStageObserver {
    metrics: Arc<NodeMetrics>,
    stage: ProofStage,
}

struct CpuStageAdmission {
    budget: Arc<ProvingBudget>,
    stage: ProofStage,
}

impl neutrin0_runtime_host::backend::NativeAdmission for CpuStageAdmission {
    fn acquire(&self) -> Box<dyn neutrin0_runtime_host::backend::NativeLease> {
        Box::new(self.budget.acquire(self.stage))
    }
}

impl SubmissionObserver for NativeStageObserver {
    fn queued(&self) {
        self.metrics.proof_pipeline.budget.queued(self.stage);
    }
    fn admitted(&self, wait: std::time::Duration) {
        self.metrics
            .proof_pipeline
            .budget
            .admitted(self.stage, wait);
    }
    fn released(&self) {
        self.metrics.proof_pipeline.budget.released(self.stage);
    }
    fn cancelled(&self, wait: std::time::Duration) {
        self.metrics
            .proof_pipeline
            .budget
            .cancelled(self.stage, wait);
    }
}

/// Admission priority for expensive proving work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "The scheduler is shared inside this crate and is not a public node API"
)]
pub(crate) enum ProvingPriority {
    /// Block and chunk proofs required to keep finality moving.
    Critical,
    /// Fact and evidence proofs that feed execution.
    Normal,
}

impl ProvingPriority {
    const fn index(self) -> usize {
        match self {
            Self::Critical => 0,
            Self::Normal => 1,
        }
    }

    /// Fixed Prometheus label.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Normal => "normal",
        }
    }
}

struct State {
    capacity: usize,
    active: usize,
    next_ticket: u64,
    waiting: [VecDeque<u64>; 2],
}

impl State {
    fn can_admit(&self, priority: ProvingPriority, ticket: u64) -> bool {
        let index = priority.index();
        self.active < self.capacity
            && self.waiting[index].front() == Some(&ticket)
            && self.waiting[..index].iter().all(VecDeque::is_empty)
    }
}

/// Process-local proving budget shared by all proof pipelines of a node.
///
/// Priority applies when admitting new work; an active prover is never aborted.
/// Waiters of the same priority enter in arrival order.
#[expect(
    clippy::redundant_pub_crate,
    reason = "The scheduler is shared inside this crate and is not a public node API"
)]
pub(crate) struct ProvingBudget {
    state: Mutex<State>,
    changed: Condvar,
    metrics: Arc<NodeMetrics>,
    device: Option<Arc<SubmissionGate>>,
    native_admission: bool,
    block_backlog: tokio::sync::watch::Sender<bool>,
}

impl ProvingBudget {
    /// Create a budget, clamping its capacity to the supported range `1..=64`.
    #[cfg(test)]
    pub(crate) fn new(capacity: usize) -> Self {
        Self::with_metrics(capacity, Arc::new(NodeMetrics::default()))
    }

    #[cfg(test)]
    pub(crate) fn with_metrics(capacity: usize, metrics: Arc<NodeMetrics>) -> Self {
        Self::with_device(capacity, metrics, None)
    }

    #[cfg(test)]
    pub(crate) fn with_device(
        capacity: usize,
        metrics: Arc<NodeMetrics>,
        device: Option<u32>,
    ) -> Self {
        Self::with_backend(capacity, metrics, device, true)
    }

    pub(crate) fn with_backend(
        capacity: usize,
        metrics: Arc<NodeMetrics>,
        device: Option<u32>,
        native_admission: bool,
    ) -> Self {
        let gate = device.map(|device| {
            neutrin0_runtime_host::backend::cuda_submission_gate(device)
                .expect("registered CUDA gate")
        });
        let capacity = if gate.is_some() { 1 } else { capacity };
        let capacity = capacity.clamp(1, 64);
        metrics.proof_pipeline.budget.set_capacity(capacity);
        Self {
            state: Mutex::new(State {
                capacity,
                active: 0,
                next_ticket: 0,
                waiting: core::array::from_fn(|_| VecDeque::new()),
            }),
            changed: Condvar::new(),
            metrics,
            device: gate,
            native_admission,
            block_backlog: tokio::sync::watch::channel(false).0,
        }
    }

    /// Keep optional precomputation behind the whole producer queue, including
    /// the gap between one native call returning and the next job launching.
    pub(crate) fn set_block_backlog(&self, jobs: usize) {
        self.block_backlog.send_replace(jobs != 0);
    }

    /// Wait without holding a proving permit or blocking an executor thread.
    pub(crate) async fn wait_for_block_proofs(&self) {
        self.block_backlog
            .subscribe()
            .wait_for(|busy| !*busy)
            .await
            .expect("proving budget retains its backlog sender");
    }

    /// Adjust admission capacity without interrupting already running proofs.
    pub(crate) fn set_capacity(&self, capacity: usize) {
        let capacity = if self.device.is_some() {
            1
        } else {
            capacity.clamp(1, 64)
        };
        self.state.lock().expect("proving budget").capacity = capacity;
        self.metrics.proof_pipeline.budget.set_capacity(capacity);
        self.changed.notify_all();
    }

    /// Reserve a FIFO position. Dropping an unconsumed request cancels it.
    pub(crate) fn request(self: &Arc<Self>, stage: ProofStage) -> ProvingRequest {
        let priority = stage.priority();
        let started = Instant::now();
        if let Some(gate) = &self.device {
            self.metrics.proof_pipeline.budget.queued(stage);
            return ProvingRequest {
                budget: Arc::clone(self),
                stage,
                ticket: 0,
                started,
                waiting: true,
                native: Some(gate.request(submission_priority(stage))),
            };
        }
        let mut scheduler = self.state.lock().expect("proving budget");
        let ticket = scheduler.next_ticket;
        scheduler.next_ticket = ticket.checked_add(1).expect("proving ticket overflow");
        scheduler.waiting[priority.index()].push_back(ticket);
        self.metrics.proof_pipeline.budget.queued(stage);
        drop(scheduler);
        self.changed.notify_all();
        ProvingRequest {
            budget: Arc::clone(self),
            stage,
            ticket,
            started,
            waiting: true,
            native: None,
        }
    }

    /// Acquire on a blocking worker, outside engine locks. One permit covers
    /// one native prover call; running native calls retain it during shutdown.
    pub(crate) fn acquire(self: &Arc<Self>, stage: ProofStage) -> ProvingPermit {
        self.request(stage).wait()
    }

    /// Run one native prover call for `stage` under a permit, timing it in the
    /// stage's metrics. The permit is released after the call returns or unwinds.
    pub(crate) fn prove<T, E>(
        self: &Arc<Self>,
        stage: ProofStage,
        attempt: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        if self.native_admission && stage.priority() == ProvingPriority::Normal {
            // Fact/Evidence batches contain multiple native calls. Each host
            // submit acquires the device separately so Critical work can enter
            // between them; never hold the GPU while waiting on fact flight.
            if self.device.is_some() {
                return self.observe_native(stage, attempt);
            }
            return self.admit_local_native(stage, attempt);
        }
        let permit = self.acquire(stage);
        permit.run(|| self.metrics.proof_stage(stage).time(attempt))
    }

    /// Setup consumes capacity only at its native leaf, after single-flight
    /// cache and installation checks, so a waiting cache hit holds no slot.
    pub(crate) fn setup<T, E>(
        self: &Arc<Self>,
        attempt: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        if !self.native_admission {
            self.prove(ProofStage::ProgramSetup, attempt)
        } else if self.device.is_some() {
            self.observe_native(ProofStage::ProgramSetup, attempt)
        } else {
            self.admit_local_native(ProofStage::ProgramSetup, attempt)
        }
    }

    fn admit_local_native<T, E>(
        self: &Arc<Self>,
        stage: ProofStage,
        attempt: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let admission = Arc::new(CpuStageAdmission {
            budget: Arc::clone(self),
            stage,
        });
        neutrin0_runtime_host::backend::with_native_admission(admission, || {
            neutrin0_runtime_host::backend::with_submission_priority(
                submission_priority(stage),
                || self.metrics.proof_stage(stage).time(attempt),
            )
        })
    }

    fn observe_native<T, E>(
        &self,
        stage: ProofStage,
        attempt: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let observer = Arc::new(NativeStageObserver {
            metrics: Arc::clone(&self.metrics),
            stage,
        });
        neutrin0_runtime_host::backend::with_submission_observer(observer, || {
            neutrin0_runtime_host::backend::with_submission_priority(
                submission_priority(stage),
                || self.metrics.proof_stage(stage).time(attempt),
            )
        })
    }
}

#[expect(
    clippy::redundant_pub_crate,
    reason = "FIFO admission requests remain internal to the node scheduler."
)]
pub(crate) struct ProvingRequest {
    budget: Arc<ProvingBudget>,
    stage: ProofStage,
    ticket: u64,
    started: Instant,
    waiting: bool,
    native: Option<SubmissionRequest>,
}

impl ProvingRequest {
    pub(crate) fn wait(self) -> ProvingPermit {
        self.wait_if(|| true).expect("uncancelled proving request")
    }

    /// Recheck queued work without holding resource locks. A cancellation only
    /// removes its queue position and never interrupts an admitted native call.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "The guard is handed to the condition variable and released explicitly on every path."
    )]
    pub(crate) fn wait_if(mut self, mut ready: impl FnMut() -> bool) -> Option<ProvingPermit> {
        if let Some(request) = self.native.take() {
            let guard = request.wait_if(ready)?;
            self.waiting = false;
            self.budget
                .metrics
                .proof_pipeline
                .budget
                .admitted(self.stage, self.started.elapsed());
            return Some(ProvingPermit {
                budget: Arc::clone(&self.budget),
                stage: self.stage,
                native: Some(guard),
            });
        }
        let priority = self.stage.priority();
        let mut state = loop {
            if !ready() {
                return None;
            }
            let state = self.budget.state.lock().expect("proving budget");
            if state.can_admit(priority, self.ticket) {
                break state;
            }
            let (state, _) = self
                .budget
                .changed
                .wait_timeout(state, std::time::Duration::from_millis(250))
                .expect("proving budget");
            drop(state);
        };
        state.waiting[priority.index()].pop_front();
        state.active += 1;
        self.waiting = false;
        self.budget
            .metrics
            .proof_pipeline
            .budget
            .admitted(self.stage, self.started.elapsed());
        drop(state);
        self.budget.changed.notify_all();
        Some(ProvingPermit {
            budget: Arc::clone(&self.budget),
            stage: self.stage,
            native: None,
        })
    }
}

impl Drop for ProvingRequest {
    fn drop(&mut self) {
        if self.waiting {
            if self.budget.device.is_some() {
                self.budget
                    .metrics
                    .proof_pipeline
                    .budget
                    .cancelled(self.stage, self.started.elapsed());
                return;
            }
            let mut state = self.budget.state.lock().expect("proving budget");
            state.waiting[self.stage.priority().index()].retain(|ticket| *ticket != self.ticket);
            self.budget
                .metrics
                .proof_pipeline
                .budget
                .cancelled(self.stage, self.started.elapsed());
            drop(state);
            self.budget.changed.notify_all();
        }
    }
}

/// A single active proof; dropping it wakes waiting workers immediately.
#[expect(
    clippy::redundant_pub_crate,
    reason = "The scheduler is shared inside this crate and is not a public node API"
)]
pub(crate) struct ProvingPermit {
    budget: Arc<ProvingBudget>,
    stage: ProofStage,
    native: Option<SubmissionGuard>,
}

impl ProvingPermit {
    pub(crate) fn run<T>(&self, work: impl FnOnce() -> T) -> T {
        match &self.native {
            Some(guard) => guard.run(work),
            None => neutrin0_runtime_host::backend::with_submission_priority(
                submission_priority(self.stage),
                work,
            ),
        }
    }
}

const fn submission_priority(stage: ProofStage) -> SubmissionPriority {
    match stage.priority() {
        ProvingPriority::Critical => SubmissionPriority::Critical,
        ProvingPriority::Normal => SubmissionPriority::Normal,
    }
}

impl Drop for ProvingPermit {
    fn drop(&mut self) {
        if self.native.is_some() {
            self.budget
                .metrics
                .proof_pipeline
                .budget
                .released(self.stage);
            return;
        }
        let mut state = self.budget.state.lock().expect("proving budget");
        state.active -= 1;
        self.budget
            .metrics
            .proof_pipeline
            .budget
            .released(self.stage);
        drop(state);
        self.budget.changed.notify_all();
    }
}

#[cfg(test)]
mod tests;
