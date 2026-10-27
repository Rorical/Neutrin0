//! Bounded event-driven blocking work queue used by local block proving.

#![allow(clippy::redundant_pub_crate)]

use neutrin0_primitives::Hash;
use std::collections::{BTreeSet, VecDeque};
use tokio::task::{JoinError, JoinSet};

pub(crate) struct ProofQueue<J, O> {
    pending: VecDeque<(Hash, J)>,
    known: BTreeSet<Hash>,
    running: JoinSet<(Hash, Result<O, JoinError>)>,
    concurrency: usize,
    capacity: usize,
}

impl<J: Send + 'static, O: Send + 'static> ProofQueue<J, O> {
    pub(crate) fn new(concurrency: usize, capacity: usize) -> Self {
        assert!(concurrency > 0 && capacity >= concurrency);
        Self {
            pending: VecDeque::new(),
            known: BTreeSet::new(),
            running: JoinSet::new(),
            concurrency,
            capacity,
        }
    }

    pub(crate) fn available(&self) -> usize {
        self.capacity - self.known.len()
    }
    pub(crate) fn contains(&self, hash: &Hash) -> bool {
        self.known.contains(hash)
    }
    /// Jobs waiting for a worker.
    pub(crate) fn pending(&self) -> usize {
        self.pending.len()
    }
    /// Jobs currently proving.
    pub(crate) fn running(&self) -> usize {
        self.running.len()
    }
    pub(crate) fn is_running(&self) -> bool {
        !self.running.is_empty()
    }

    pub(crate) fn push(&mut self, hash: Hash, job: J) -> bool {
        if self.available() == 0 || !self.known.insert(hash) {
            return false;
        }
        self.pending.push_back((hash, job));
        true
    }

    pub(crate) fn retain_pending(&mut self, keep: impl Fn(&Hash) -> bool) {
        self.pending.retain(|(hash, _)| {
            if keep(hash) {
                true
            } else {
                self.known.remove(hash);
                false
            }
        });
    }

    pub(crate) fn start(&mut self, work: impl Fn(J) -> O + Clone + Send + 'static) {
        while self.running.len() < self.concurrency {
            let Some((hash, job)) = self.pending.pop_front() else {
                break;
            };
            let work = work.clone();
            self.running
                .spawn(async move { (hash, tokio::task::spawn_blocking(move || work(job)).await) });
        }
    }

    pub(crate) async fn completed(&mut self) -> (Hash, Result<O, JoinError>) {
        // The wrapper cannot panic: panics in the blocking prover are returned
        // as an error with the original hash, releasing its capacity for retry.
        let (hash, result) = self
            .running
            .join_next()
            .await
            .expect("queue has running work")
            .expect("prover wrapper cannot panic");
        self.known.remove(&hash);
        (hash, result)
    }
}

#[cfg(test)]
mod tests;
