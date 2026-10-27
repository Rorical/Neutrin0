//! Admitting a manifest and keeping its resumable download durable.

use neutrin0_consensus_types::bootstrap::BootstrapData;
use neutrin0_consensus_types::history_proof::{AnchorOpening, Checkpoint};
use neutrin0_light_client::LightClient;
use neutrin0_proof_system::{ProofSystem, verify_history_proof};
use neutrin0_storage::{Batch, Column, Database};
use neutrin0_sync::{StateProgress, SyncBackendError};

use super::{
    BootstrapRuntime, ChainBackend, Check, PENDING_KEY, Pending, authenticate, rejected,
    storage_error,
};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Discard only temporary snapshot objects, and any installation nothing
    /// adopted, when bootstrap is disabled.
    pub(crate) fn discard_bootstrap_download(&self) -> Result<(), String> {
        let _lifecycle = self
            .program_lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.finish_interrupted_install()
            .map_err(|error| error.to_string())?;
        self.with_engine_mut(|engine| {
            engine.store_mut().release_state_install()?;
            let mut batch = Batch::new();
            batch.delete(Column::Meta, PENDING_KEY);
            engine.store_mut().write_observed_batch(batch, true)
        })
        .map_err(|error| error.to_string())?;
        // Summaries, progress and staged objects all share this prefix.
        self.clear_rows(neutrin0_consensus_engine::store::pointers::STATE_DOWNLOAD)
            .map_err(|error| error.to_string())?;
        *self.bootstrap.lock().map_err(|error| error.to_string())? = None;
        Ok(())
    }

    /// Configure full/validator bootstrap from locally selected trust and restore downloads.
    pub fn initialize_bootstrap(
        &self,
        config: &crate::config::BootstrapConfig,
    ) -> Result<(), String> {
        if !config.enabled {
            return self.discard_bootstrap_download();
        }
        let (spec, domain) = self.history_profile()?;
        let saved_pending = self.recover_bootstrap_download(&spec)?;
        let configured = match (&config.trusted_checkpoint_path, config.trusted_at) {
            (Some(path), Some(time)) => {
                let bytes = crate::config::read_trusted_checkpoint(path)
                    .map_err(|error| error.to_string())?
                    .ok_or("bootstrap trusted checkpoint exceeds size limit")?;
                let checkpoint =
                    borsh::from_slice::<Checkpoint>(&bytes).map_err(|error| error.to_string())?;
                if checkpoint.chain != domain.chain {
                    return Err("bootstrap origin has a different chain binding".into());
                }
                Some((checkpoint, time))
            }
            (None, None) => None,
            _ => {
                return Err(
                    "bootstrap trusted_checkpoint_path and trusted_at must accompany each other"
                        .into(),
                );
            }
        };
        let (origin, trusted_at) = self.local_trust_origin(domain.chain, configured.as_ref())?;
        LightClient::new(&spec, origin, trusted_at, config.max_future_drift_secs)
            .map_err(|error| error.to_string())?;
        // A download begun under other trust, or one that no longer
        // authenticates (its anchor expired while the node was off), is
        // dropped and started again rather than refusing to start.
        let pending = match saved_pending {
            Some(pending) => {
                let still_trusted = if pending.origin != origin || pending.trusted_at != trusted_at
                {
                    Err("bootstrap trust origin changed during download".to_owned())
                } else {
                    self.authenticate_pending(&pending, config.max_future_drift_secs)
                        .map(|_| ())
                        .map_err(|error| error.to_string())
                };
                match still_trusted {
                    Ok(()) => Some(pending),
                    Err(reason) => {
                        tracing::warn!(%reason, "discarding the pending snapshot download");
                        self.discard_bootstrap_download()?;
                        None
                    }
                }
            }
            None => None,
        };
        // Finish any interrupted manifest replacement, and drop downloads no
        // manifest still needs.
        let roots = pending.as_ref().map_or_else(Vec::new, |pending| {
            let end = pending.data.history.end();
            vec![end.state_root, end.identity_sanctions_root]
        });
        self.retain_state_downloads(&roots)
            .map_err(|error| error.to_string())?;
        let fetching = pending.is_some()
            || self.with_engine(|engine| {
                engine.finalized_next_chunk_id() == 0 && origin.boundary.next_chunk_id != 0
            });
        let _lifecycle = self
            .program_lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *self.bootstrap.lock().map_err(|error| error.to_string())? = Some(BootstrapRuntime {
            chain: domain.chain,
            configured,
            max_future_drift_secs: config.max_future_drift_secs,
            fetching,
            pending,
        });
        Ok(())
    }

    fn recover_bootstrap_download(
        &self,
        spec: &neutrin0_primitives::ChainSpec,
    ) -> Result<Option<Pending>, String> {
        let mut saved_pending = self
            .with_engine(|engine| engine.store().db().get(Column::Meta, PENDING_KEY))
            .map_err(|error| error.to_string())?
            .map(|bytes| {
                if bytes.len() > 32 * 1024 * 1024 {
                    return Err("oversized pending bootstrap".to_owned());
                }
                borsh::from_slice::<Pending>(&bytes).map_err(|error| error.to_string())
            })
            .transpose()?;
        if let Some(pending) = &saved_pending {
            let end = *pending.data.history.end();
            let installed = self.with_engine(|engine| -> Result<bool, String> {
                Ok(engine
                    .store()
                    .bootstrap_source_floor()
                    .map_err(|error| error.to_string())?
                    == end.next_chunk_id
                    && engine
                        .canonical_boundary(end.next_chunk_id)
                        .map_err(|error| error.to_string())?
                        == end
                    && engine
                        .latest_history_proof()
                        .map_err(|error| error.to_string())?
                        .as_ref()
                        == Some(&pending.data.history))
            })?;
            if installed {
                verify_history_proof(
                    self.proof_system.as_ref(),
                    spec,
                    pending.data.history.clone(),
                )
                .map_err(|error| error.to_string())?;
                self.clear_state_download(end.state_root)
                    .map_err(|error| error.to_string())?;
                if end.identity_sanctions_root != end.state_root {
                    self.clear_state_download(end.identity_sanctions_root)
                        .map_err(|error| error.to_string())?;
                }
                self.with_engine_mut(|engine| {
                    let mut batch = Batch::new();
                    batch.delete(Column::Meta, PENDING_KEY);
                    engine.store_mut().write_observed_batch(batch, true)
                })
                .map_err(|error| error.to_string())?;
                saved_pending = None;
            }
        }
        Ok(saved_pending)
    }

    pub(in crate::chain_backend) async fn begin_bootstrap(
        &self,
        anchor: Option<AnchorOpening>,
        data: BootstrapData,
    ) -> Result<StateProgress, SyncBackendError> {
        self.begin_bootstrap_checked(anchor, data, Check::Admission)
            .await
    }

    /// [`Self::begin_bootstrap`] for a manifest an operator supplied in a
    /// snapshot file, which is not judged stale.
    pub(in crate::chain_backend) async fn begin_offline_bootstrap(
        &self,
        anchor: Option<AnchorOpening>,
        data: BootstrapData,
    ) -> Result<StateProgress, SyncBackendError> {
        self.begin_bootstrap_checked(anchor, data, Check::Offline)
            .await
    }

    async fn begin_bootstrap_checked(
        &self,
        anchor: Option<AnchorOpening>,
        data: BootstrapData,
        check: Check,
    ) -> Result<StateProgress, SyncBackendError> {
        self.bootstrap_fetch(true);
        let future = self
            .bootstrap
            .lock()
            .expect("bootstrap runtime")
            .as_ref()
            .map(|runtime| runtime.max_future_drift_secs)
            .ok_or_else(|| SyncBackendError::NotAvailable("bootstrap is disabled".into()))?;
        let (origin, trusted_at) = self
            .trust_origin()
            .map_err(rejected)?
            .ok_or_else(|| SyncBackendError::NotAvailable("bootstrap is disabled".into()))?;
        let (local, local_head, local_height) = self
            .with_engine(|engine| {
                engine
                    .canonical_boundary(engine.finalized_next_chunk_id())
                    .map(|local| (local, engine.head_hash(), engine.head_height()))
            })
            .map_err(rejected)?;
        let pending = Pending {
            origin,
            trusted_at,
            local,
            local_head,
            local_height,
            anchor,
            data,
        };
        let root = pending.data.history.end().state_root;
        let verifier = std::sync::Arc::clone(&self.proof_system);
        let spec = self.with_engine(|engine| engine.chain_spec().clone());
        let candidate = pending.clone();
        let (_, recent) = tokio::task::spawn_blocking(move || {
            authenticate(verifier.as_ref(), &spec, &candidate, future, check)
        })
        .await
        .map_err(storage_error)??;
        // A certified dependency yields only to a snapshot whose History holds
        // exactly the certified chunk; the install enforces the same rule.
        if let Some(certified) =
            self.with_engine(neutrin0_consensus_engine::Engine::certified_history_context)
            && pending
                .anchor
                .as_ref()
                .is_none_or(|opening| opening.context != certified)
            && !recent
                .iter()
                .any(|opening| opening.record.evidence_context() == certified)
        {
            return Err(rejected(
                "bootstrap endpoint does not finalize the locally certified chunk",
            ));
        }
        self.persist_bootstrap_download(pending)?;
        self.require_bootstrap_programs(root, &self.missing_bootstrap_programs()?)?;
        let items = self.state_download_items(root)?;
        let complete = self.bootstrap_downloads_complete()?;
        if complete {
            self.finish_bootstrap().await?;
        }
        Ok(StateProgress {
            root_complete: complete,
            next_items: items,
        })
    }

    fn persist_bootstrap_download(&self, pending: Pending) -> Result<(), SyncBackendError> {
        let _lifecycle = self
            .program_lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let replaced = self.with_engine_mut(|engine| {
            if engine
                .canonical_boundary(engine.finalized_next_chunk_id())
                .map_err(rejected)?
                != pending.local
                || engine.head_height() != pending.local_height
                || engine.head_hash() != pending.local_head
            {
                return Err(SyncBackendError::ChainBehind(
                    "local chain advanced during bootstrap verification".into(),
                ));
            }
            let mut guard = self.bootstrap.lock().expect("bootstrap runtime");
            let runtime = guard
                .as_mut()
                .ok_or_else(|| SyncBackendError::NotAvailable("bootstrap is disabled".into()))?;
            let new_end = *pending.data.history.end();
            let mut replaced = Vec::new();
            if let Some(old) = &runtime.pending {
                let old_end = *old.data.history.end();
                if old_end != new_end {
                    if new_end.next_chunk_id <= old_end.next_chunk_id {
                        return Err(SyncBackendError::Rejected(
                            "replacement bootstrap endpoint must advance".into(),
                        ));
                    }
                    replaced = [old_end.state_root, old_end.identity_sanctions_root]
                        .into_iter()
                        .filter(|root| {
                            *root != new_end.state_root && *root != new_end.identity_sanctions_root
                        })
                        .collect();
                }
            }
            let mut batch = Batch::new();
            batch.put(
                Column::Meta,
                PENDING_KEY,
                borsh::to_vec(&pending).map_err(storage_error)?,
            );
            engine
                .store_mut()
                .write_observed_batch(batch, true)
                .map_err(storage_error)?;
            runtime.pending = Some(pending);
            drop(guard);
            Ok(replaced)
        })?;
        // Staged objects are content-addressed and mostly shared by the new
        // roots, so only the replaced roots' progress is dropped. A crash
        // before this finishes is completed at startup.
        for root in replaced {
            self.abandon_state_download(root)?;
        }
        Ok(())
    }
}
