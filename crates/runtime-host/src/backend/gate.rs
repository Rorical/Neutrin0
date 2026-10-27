//! One-at-a-time native submission gate with priority and FIFO admission.

use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex},
};

use super::{RESERVED, SubmissionPriority, with_submission_priority};

#[derive(Default)]
pub(super) struct SubmissionState {
    pub(super) active: bool,
    pub(super) ticket: u64,
    pub(super) waiting: [VecDeque<u64>; 2],
}

/// One native submission at a time, with priority and FIFO admission.
/// Running work is never cancelled or preempted.
#[derive(Default)]
pub struct SubmissionGate {
    pub(super) state: Mutex<SubmissionState>,
    pub(super) changed: Condvar,
}

impl SubmissionGate {
    /// Reserve a queue position without waiting. Dropping it cancels admission.
    /// # Panics
    /// Panics if the gate is poisoned or its monotonic ticket counter is exhausted.
    pub fn request(self: &Arc<Self>, priority: SubmissionPriority) -> SubmissionRequest {
        let mut state = self.state.lock().expect("submission gate");
        let ticket = state.ticket;
        state.ticket = ticket.checked_add(1).expect("submission ticket exhaustion");
        state.waiting[priority.index()].push_back(ticket);
        drop(state);
        self.changed.notify_all();
        SubmissionRequest {
            gate: Arc::clone(self),
            priority,
            ticket,
            waiting: true,
        }
    }

    /// Acquire a native submission on a blocking worker.
    /// # Panics
    /// Panics if the gate is poisoned or its ticket counter is exhausted.
    pub fn acquire(self: &Arc<Self>, priority: SubmissionPriority) -> SubmissionGuard {
        self.request(priority).wait()
    }
}

/// A cancellable FIFO position in a submission gate.
#[must_use = "Dropping the request cancels its queue position."]
pub struct SubmissionRequest {
    gate: Arc<SubmissionGate>,
    priority: SubmissionPriority,
    ticket: u64,
    waiting: bool,
}

impl SubmissionRequest {
    /// Cancel queued work when its caller no longer needs it. The predicate is
    /// evaluated without the gate lock; admitted native calls are never revoked.
    /// Readiness is rechecked at least every 250 ms while another call is active.
    /// # Panics
    /// Panics if the gate is poisoned.
    #[allow(
        clippy::significant_drop_tightening,
        reason = "The guard is handed to the condition variable and released explicitly on every path."
    )]
    pub fn wait_if(mut self, mut ready: impl FnMut() -> bool) -> Option<SubmissionGuard> {
        let index = self.priority.index();
        loop {
            if !ready() {
                return None;
            }
            let mut state = self.gate.state.lock().expect("submission gate");
            if !state.active
                && state.waiting[index].front() == Some(&self.ticket)
                && state.waiting[..index].iter().all(VecDeque::is_empty)
            {
                state.waiting[index].pop_front();
                state.active = true;
                self.waiting = false;
                drop(state);
                return Some(SubmissionGuard {
                    gate: Arc::clone(&self.gate),
                    priority: self.priority,
                });
            }
            let (state, _) = self
                .gate
                .changed
                .wait_timeout(state, std::time::Duration::from_millis(250))
                .expect("submission gate");
            drop(state);
        }
    }

    /// Wait for admission without holding any consensus or registry lock.
    /// # Panics
    /// Panics if the gate is poisoned.
    pub fn wait(mut self) -> SubmissionGuard {
        let index = self.priority.index();
        let mut state = self.gate.state.lock().expect("submission gate");
        while state.active
            || state.waiting[index].front() != Some(&self.ticket)
            || state.waiting[..index].iter().any(|queue| !queue.is_empty())
        {
            state = self.gate.changed.wait(state).expect("submission gate");
        }
        state.waiting[index].pop_front();
        state.active = true;
        self.waiting = false;
        drop(state);
        SubmissionGuard {
            gate: Arc::clone(&self.gate),
            priority: self.priority,
        }
    }
}

impl Drop for SubmissionRequest {
    fn drop(&mut self) {
        if self.waiting {
            self.gate.state.lock().expect("submission gate").waiting[self.priority.index()]
                .retain(|ticket| *ticket != self.ticket);
            self.gate.changed.notify_all();
        }
    }
}

/// An admitted submission, retained until its native call returns.
#[must_use = "Keep the guard until the native call returns."]
pub struct SubmissionGuard {
    gate: Arc<SubmissionGate>,
    priority: SubmissionPriority,
}

impl SubmissionGuard {
    /// Run synchronous work under this reservation. Nested host wrappers reuse it.
    pub fn run<T>(&self, work: impl FnOnce() -> T) -> T {
        struct Restore(Option<usize>);
        impl Drop for Restore {
            fn drop(&mut self) {
                RESERVED.with(|value| value.set(self.0));
            }
        }
        let identity = Arc::as_ptr(&self.gate) as usize;
        let _restore = Restore(RESERVED.with(|value| value.replace(Some(identity))));
        with_submission_priority(self.priority, work)
    }
}

impl Drop for SubmissionGuard {
    fn drop(&mut self) {
        self.gate.state.lock().expect("submission gate").active = false;
        self.gate.changed.notify_all();
    }
}
