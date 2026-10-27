//! Own and observe node workers, including workers started by the backend.

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

use tokio::task::{AbortHandle, Id, JoinSet};

#[derive(Debug, Eq, PartialEq)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "Task failures are shared by private runner and backend modules."
)]
pub(crate) struct TaskFailure {
    pub(crate) name: &'static str,
    pub(crate) reason: String,
}

struct TaskInfo {
    name: &'static str,
    critical: bool,
}

#[derive(Default)]
struct Registry {
    tasks: JoinSet<Result<(), String>>,
    names: HashMap<Id, TaskInfo>,
    wake: Option<Waker>,
    closing: bool,
    cleanup: Vec<Box<dyn FnOnce() + Send>>,
}

type Joined = Result<(Id, Result<(), String>), tokio::task::JoinError>;

impl Registry {
    /// Join the next finished task and release its registration.
    fn poll_joined(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<(Option<TaskInfo>, Joined)>> {
        self.tasks.poll_join_next_with_id(cx).map(|joined| {
            joined.map(|result| {
                let id = match &result {
                    Ok((id, _)) => *id,
                    Err(error) => error.id(),
                };
                (self.names.remove(&id), result)
            })
        })
    }
}

/// Clones register workers with the runner's owner; they never extend its life.
#[derive(Clone)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "Worker registration is shared by private runner and backend modules."
)]
pub(crate) struct TaskSpawner(Arc<Mutex<Registry>>);

impl TaskSpawner {
    pub(crate) fn render_metrics(&self, out: &mut String) {
        const WORKERS: [&str; 15] = [
            "network",
            "sync",
            "producer",
            "bft-clock",
            "consensus-notifications",
            "history",
            "facts",
            "metrics",
            "health-monitor",
            "rpc",
            "management",
            "consensus-proof",
            "evidence",
            "program-restore",
            "program-install",
        ];
        // The final slot counts every unlisted worker name.
        let mut counts = [0_usize; WORKERS.len() + 1];
        for task in self
            .0
            .lock()
            .expect("task registry poisoned")
            .names
            .values()
        {
            let index = WORKERS
                .iter()
                .position(|worker| *worker == task.name)
                .unwrap_or(WORKERS.len());
            counts[index] += 1;
        }
        crate::metrics::labeled(
            out,
            "neutrin0_worker_tasks",
            "Registered tasks, including completed tasks awaiting supervision.",
            "gauge",
            "worker",
            WORKERS.into_iter().chain(["other"]).zip(counts),
        );
    }

    pub(crate) fn spawn_critical(
        &self,
        name: &'static str,
        future: impl Future<Output = Result<(), String>> + Send + 'static,
    ) -> Option<AbortHandle> {
        self.spawn(name, true, future)
    }

    pub(crate) fn spawn_job(
        &self,
        name: &'static str,
        future: impl Future<Output = Result<(), String>> + Send + 'static,
    ) -> Option<AbortHandle> {
        self.spawn(name, false, future)
    }

    fn spawn(
        &self,
        name: &'static str,
        critical: bool,
        future: impl Future<Output = Result<(), String>> + Send + 'static,
    ) -> Option<AbortHandle> {
        let mut registry = self.0.lock().expect("task registry poisoned");
        if registry.closing {
            return None;
        }
        let handle = registry.tasks.spawn(future);
        registry
            .names
            .insert(handle.id(), TaskInfo { name, critical });
        let wake = registry.wake.take();
        drop(registry);
        if let Some(wake) = wake {
            wake.wake();
        }
        Some(handle)
    }
}

/// The runner is the sole owner. Dropping it stops every registered task.
#[expect(
    clippy::redundant_pub_crate,
    reason = "The task owner is an internal node lifecycle interface."
)]
pub(crate) struct TaskSupervisor {
    spawner: TaskSpawner,
}

impl TaskSupervisor {
    pub(crate) fn new() -> Self {
        Self {
            spawner: TaskSpawner(Arc::new(Mutex::new(Registry::default()))),
        }
    }

    pub(crate) fn spawner(&self) -> TaskSpawner {
        self.spawner.clone()
    }

    /// Cleanup hooks stop services with their own task ownership, such as RPC.
    pub(crate) fn on_shutdown(&self, cleanup: impl FnOnce() + Send + 'static) {
        self.spawner
            .0
            .lock()
            .expect("task registry poisoned")
            .cleanup
            .push(Box::new(cleanup));
    }

    pub(crate) async fn next_failure(&self) -> TaskFailure {
        loop {
            let (info, result) = poll_fn(|cx| {
                let mut registry = self.spawner.0.lock().expect("task registry poisoned");
                match registry.poll_joined(cx) {
                    Poll::Ready(Some((info, result))) => {
                        Poll::Ready((info.expect("registered task name"), result))
                    }
                    Poll::Ready(None) | Poll::Pending => {
                        registry.wake = Some(cx.waker().clone());
                        Poll::Pending
                    }
                }
            })
            .await;
            let reason = match result {
                Ok((_, Ok(()))) if !info.critical => continue,
                Ok((_, Ok(()))) => "returned unexpectedly".to_owned(),
                Ok((_, Err(error))) => error,
                Err(error) => error.to_string(),
            };
            return TaskFailure {
                name: info.name,
                reason,
            };
        }
    }

    pub(crate) fn close(&self) {
        let mut registry = self.spawner.0.lock().expect("task registry poisoned");
        registry.closing = true;
        registry.tasks.abort_all();
        let cleanup = std::mem::take(&mut registry.cleanup);
        drop(registry);
        for cleanup in cleanup {
            cleanup();
        }
    }

    pub(crate) async fn shutdown(&self) {
        self.close();
        loop {
            let done = poll_fn(|cx| {
                let mut registry = self.spawner.0.lock().expect("task registry poisoned");
                registry.poll_joined(cx).map(|joined| joined.is_none())
            })
            .await;
            if done {
                break;
            }
        }
    }
}

impl Drop for TaskSupervisor {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests;
