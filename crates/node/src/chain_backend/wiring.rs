//! Handles the runner installs on the backend and the counters it reads back.

use std::sync::Arc;

use neutrin0_primitives::ChainId;
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_storage::Database;
use neutrin0_sync::SyncStatus;

use super::{ChainBackend, cloned};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(crate) fn set_task_spawner(&self, spawner: crate::supervision::TaskSpawner) {
        *self
            .background_tasks
            .lock()
            .expect("background tasks mutex") = Some(spawner);
    }

    /// Register `future` with the runner's supervisor, or spawn it on the
    /// current runtime when no supervisor is installed. A `critical` worker
    /// must never return; a job may complete.
    pub(super) fn spawn_supervised(
        &self,
        name: &'static str,
        critical: bool,
        future: impl core::future::Future<Output = ()> + Send + 'static,
    ) {
        if let Some(spawner) = cloned(&self.background_tasks) {
            let task = async move {
                future.await;
                Ok(())
            };
            let _ = if critical {
                spawner.spawn_critical(name, task)
            } else {
                spawner.spawn_job(name, task)
            };
        } else if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(future);
        }
    }

    /// Install the artifact store; the node binary roots it under the data
    /// directory so accepted artifacts survive restarts.
    pub fn set_program_store(&self, store: crate::programs::ProgramStore) {
        *self
            .programs
            .lock()
            .expect("ChainBackend program store poisoned") = Arc::new(store);
        self.configure_program_loader();
    }

    pub(crate) fn program_store(&self) -> Arc<crate::programs::ProgramStore> {
        Arc::clone(
            &self
                .programs
                .lock()
                .expect("ChainBackend program store poisoned"),
        )
    }

    /// Install the dynamic-runtime [`ErasedBlockExecutor`] the
    /// producer hands to [`Engine::try_produce_block`](neutrin0_consensus_engine::Engine::try_produce_block).
    ///
    /// The node binary calls this with a
    /// [`neutrin0_runtime_host::WasmExecutor`] at startup. Tests
    /// that exercise gossip / BFT but never call
    /// [`Self::try_produce_block`] can leave this unset.
    pub fn set_block_executor<X>(&self, executor: X)
    where
        X: ErasedBlockExecutor + 'static,
    {
        *self
            .block_executor
            .lock()
            .expect("ChainBackend block_executor poisoned") = Some(Arc::new(
            crate::execution_metrics::MeteredExecutor::new(executor, Arc::clone(&self.metrics)),
        ));
        self.configure_program_loader();
    }

    /// Install the sync driver's status handle so RPC health reflects the
    /// live peer count and sync progress.
    pub fn set_sync_status(&self, status: SyncStatus) {
        *self
            .sync_status
            .lock()
            .expect("ChainBackend sync_status poisoned") = Some(status);
    }

    /// Counters updated by the proving and production paths.
    #[must_use]
    pub const fn metrics(&self) -> &Arc<crate::metrics::NodeMetrics> {
        &self.metrics
    }

    pub(crate) fn rpc_metrics(&self) -> Arc<neutrin0_rpc::metrics::RpcMetrics> {
        Arc::clone(&self.rpc_metrics)
    }

    pub(crate) fn set_network_metrics(
        &self,
        metrics: Arc<neutrin0_network::metrics::NetworkMetrics>,
    ) {
        *self.network_metrics.lock().expect("network metrics") = Some(metrics);
    }

    pub(crate) fn set_metrics_data_path(&self, path: std::path::PathBuf) {
        self.process_metrics
            .lock()
            .expect("process metrics")
            .set_path(path);
    }

    /// Flag the storage guard raises below the free-space quota.
    pub(crate) fn storage_pressure_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.storage_pressure)
    }

    /// The data filesystem is below its free-space quota: no production and
    /// no new peer candidates until pruning or the operator frees space.
    #[must_use]
    pub fn storage_pressure(&self) -> bool {
        self.storage_pressure
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn set_local_peer_id(&self, peer_id: String) {
        *self.local_peer_id.lock().expect("local peer id") = Some(peer_id);
    }

    /// Installed sync status handle, if a driver has published one.
    #[must_use]
    pub fn sync_status(&self) -> Option<SyncStatus> {
        cloned(&self.sync_status)
    }

    /// Local chain id; convenience helper for the node binary.
    pub fn chain_id(&self) -> ChainId {
        self.with_engine(|e| e.chain_spec().chain_id)
    }
}
