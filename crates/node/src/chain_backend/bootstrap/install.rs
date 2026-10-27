//! The one durable publication of a completely downloaded snapshot.

use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem, VerifiedHistory};
use neutrin0_prover_chunk::history::HistoricalOpening;
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;

use super::{
    AuthenticatedBootstrap, ChainBackend, Check, Pending, authenticate, rejected, storage_error,
};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(in crate::chain_backend) async fn finish_bootstrap(&self) -> Result<(), SyncBackendError> {
        let _installation = self.bootstrap_install.lock().await;
        self.finish_bootstrap_locked().await
    }

    async fn finish_bootstrap_locked(&self) -> Result<(), SyncBackendError> {
        let (pending, future) = self.pending_installation()?;
        let _program_pins = self.pin_bootstrap_programs(&pending.data)?;
        // Publish source authority before cold artifact authentication or reload;
        // reconciliation is serialized with scope registration.
        self.sync_programs();
        // Verification and anchor expiry are repeated immediately before
        // atomic installation; staleness was judged when the manifest was
        // admitted.
        let (history, recent) = self.authenticate_installation(&pending, future).await?;
        let end = *pending.data.history.end();
        let root = end.state_root;
        // Streamed into the state store; a target that changes meanwhile
        // supersedes the finished installation when it installs its own.
        self.install_downloaded_state(&[root, end.identity_sanctions_root])?;
        self.install_bootstrap_programs(root, &pending.data).await?;
        let executor = self.block_executor_snapshot();
        self.publish_bootstrap(&pending, history, &recent, executor.as_deref())?;
        self.after_chunk_finality();
        Ok(())
    }

    /// The admitted manifest to install and its future-drift allowance.
    fn pending_installation(&self) -> Result<(Pending, u64), SyncBackendError> {
        let guard = self.bootstrap.lock().expect("bootstrap runtime");
        let runtime = guard
            .as_ref()
            .ok_or_else(|| SyncBackendError::NotAvailable("bootstrap is disabled".into()))?;
        let snapshot = (
            runtime.pending.clone().ok_or_else(|| {
                SyncBackendError::NotAvailable("bootstrap has no pending snapshot".into())
            })?,
            runtime.max_future_drift_secs,
        );
        drop(guard);
        Ok(snapshot)
    }

    /// Verify the manifest's proof and opening again on a blocking worker.
    async fn authenticate_installation(
        &self,
        pending: &Pending,
        future: u64,
    ) -> Result<AuthenticatedBootstrap, SyncBackendError> {
        let verifier = std::sync::Arc::clone(&self.proof_system);
        let spec = self.with_engine(|engine| engine.chain_spec().clone());
        let candidate = pending.clone();
        tokio::task::spawn_blocking(move || {
            authenticate(
                verifier.as_ref(),
                &spec,
                &candidate,
                future,
                Check::Installation,
            )
        })
        .await
        .map_err(storage_error)?
    }

    /// Adopt the installed state as the new finalized boundary in one engine
    /// lock hold, unless the pending target changed meanwhile.
    fn publish_bootstrap(
        &self,
        pending: &Pending,
        history: VerifiedHistory,
        recent: &[HistoricalOpening],
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<(), SyncBackendError> {
        let _lifecycle = self
            .program_lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.with_engine_mut(|engine| {
            if self
                .bootstrap
                .lock()
                .expect("bootstrap runtime")
                .as_ref()
                .and_then(|runtime| runtime.pending.as_ref())
                != Some(pending)
            {
                return Err(SyncBackendError::ChainBehind(
                    "bootstrap target changed during installation".into(),
                ));
            }
            engine
                .install_bootstrap(
                    history,
                    pending.anchor.as_ref(),
                    pending.origin,
                    &pending.data.anchor_header,
                    &pending.data.validators,
                    &pending.data.frontier,
                    recent,
                    executor,
                )
                .map_err(rejected)?;
            // A reporter keeps its evidence across the jump; say what it
            // could not observe and which paths wait for a refresh.
            if let (Ok(gaps), Ok(dormant)) =
                (engine.reporter_gaps(), engine.reporter_dormant_chunks())
                && let Some(&(from, to)) = gaps.last()
            {
                tracing::warn!(
                    from,
                    to,
                    dormant = dormant.len(),
                    "reporter bootstrap skipped unobserved chunks; dormant paths refresh from peers"
                );
            }
            self.reset_block_verdicts();
            // Bootstrap stays available: a later one starts from this endpoint.
            if let Some(runtime) = self.bootstrap.lock().expect("bootstrap runtime").as_mut() {
                runtime.pending = None;
                runtime.fetching = false;
            }
            Ok(())
        })
    }
}
