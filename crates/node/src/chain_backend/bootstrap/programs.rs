//! The execution programs a snapshot needs: retention pins, the missing set
//! and their authenticated installation.

use neutrin0_consensus_types::bootstrap::{BootstrapData, StateItem, StateItemKind};
use neutrin0_primitives::Hash;
use neutrin0_proof_system::artifacts::ArtifactIdentity;
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;

use super::{
    BootstrapProgramPins, ChainBackend, bootstrap_program_items, not_available, rejected,
    snapshot_program_retention, storage_error,
};

/// The artifact identity a bootstrap program item names.
fn bootstrap_artifact_identity(item: &StateItem) -> Result<ArtifactIdentity, SyncBackendError> {
    match item.kind {
        StateItemKind::Runtime => Ok(ArtifactIdentity::Runtime(item.hash)),
        StateItemKind::Guest => Ok(ArtifactIdentity::Guest(
            item.guest_digest()
                .ok_or_else(|| rejected("invalid bootstrap Guest request"))?,
        )),
        StateItemKind::Node | StateItemKind::Value => {
            Err(rejected("bootstrap requested state as execution code"))
        }
    }
}

/// Authenticate one artifact's bytes against its item: a runtime by content
/// hash, a Guest by SP1 setup, installing it when `keep_warm`.
fn install_bootstrap_artifact<P: ProofSystem>(
    item: StateItem,
    bytes: &[u8],
    keep_warm: bool,
    runtime: &dyn ErasedBlockExecutor,
    verifier: &P,
    budget: &std::sync::Arc<crate::proving_budget::ProvingBudget>,
) -> Result<(), SyncBackendError> {
    match item.kind {
        StateItemKind::Runtime => {
            if neutrin0_primitives::blake3_256(bytes) != item.hash {
                return Err(rejected("bootstrap runtime content hash mismatch"));
            }
            let actual = if keep_warm {
                runtime.install_runtime(bytes).map_err(rejected)?
            } else {
                item.hash
            };
            if actual != item.hash {
                return Err(rejected("bootstrap runtime installed a different identity"));
            }
        }
        StateItemKind::Guest => {
            let digest = item
                .guest_digest()
                .ok_or_else(|| rejected("invalid bootstrap Guest request"))?;
            budget
                .setup(|| {
                    if keep_warm {
                        verifier.install_guest_checked(bytes.to_vec(), digest)
                    } else {
                        verifier.authenticate_guest(bytes.to_vec(), &[digest])
                    }
                })
                .map_err(rejected)?;
        }
        StateItemKind::Node | StateItemKind::Value => {
            return Err(rejected("bootstrap requested state as execution code"));
        }
    }
    Ok(())
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(in crate::chain_backend) fn bootstrap_program_retention(
        &self,
    ) -> neutrin0_proof_system::artifacts::ProgramRetention {
        let mut retention = self
            .bootstrap
            .lock()
            .expect("bootstrap runtime")
            .as_ref()
            .and_then(|runtime| runtime.pending.as_ref())
            .and_then(|pending| snapshot_program_retention(&pending.data).ok())
            .unwrap_or_default();
        let pins = self
            .bootstrap_program_pins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        retention.sources.extend(
            pins.iter()
                .filter(|(_, (sources, _))| *sources != 0)
                .map(|(identity, _)| *identity),
        );
        retention.warm.extend(
            pins.iter()
                .filter(|(_, (_, warm))| *warm != 0)
                .map(|(identity, _)| *identity),
        );
        drop(pins);
        retention.sources.sort_unstable();
        retention.sources.dedup();
        retention.warm.sort_unstable();
        retention.warm.dedup();
        retention
    }

    pub(super) fn pin_bootstrap_programs(
        &self,
        data: &BootstrapData,
    ) -> Result<BootstrapProgramPins, SyncBackendError> {
        let retention = snapshot_program_retention(data)?;
        let _lifecycle = self
            .program_lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut pins = self
            .bootstrap_program_pins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for identity in &retention.sources {
            let (sources, warm) = pins.entry(*identity).or_default();
            *sources += 1;
            if retention.warm.contains(identity) {
                *warm += 1;
            }
        }
        drop(pins);
        Ok(BootstrapProgramPins {
            pins: std::sync::Arc::clone(&self.bootstrap_program_pins),
            retention,
        })
    }

    pub(super) fn missing_bootstrap_programs(&self) -> Result<Vec<StateItem>, SyncBackendError> {
        let data = self
            .bootstrap
            .lock()
            .expect("bootstrap runtime")
            .as_ref()
            .and_then(|runtime| runtime.pending.as_ref())
            .map(|pending| pending.data.clone())
            .ok_or_else(|| not_available("bootstrap has no authenticated context"))?;
        let executor = self
            .block_executor_snapshot()
            .ok_or_else(|| not_available("bootstrap requires a runtime executor"))?;
        let runtimes = executor.installed_runtimes();
        let guests = self.proof_system.installed_guests();
        let store = self.program_store();
        Ok(bootstrap_program_items(&data)?
            .into_iter()
            .filter(|item| match item.kind {
                StateItemKind::Runtime => {
                    !runtimes.contains(&item.hash)
                        && store
                            .read_identity(
                                neutrin0_proof_system::artifacts::ArtifactIdentity::Runtime(
                                    item.hash,
                                ),
                            )
                            .is_none()
                }
                StateItemKind::Guest => item.guest_digest().is_some_and(|digest| {
                    !guests.iter().any(|(installed, _)| *installed == digest)
                        && store
                            .read_identity(
                                neutrin0_proof_system::artifacts::ArtifactIdentity::Guest(digest),
                            )
                            .is_none()
                }),
                StateItemKind::Node | StateItemKind::Value => false,
            })
            .collect())
    }

    /// Resolve every bootstrap artifact from the download, the artifact store
    /// or what is already installed, authenticating and installing each one.
    pub(super) async fn install_bootstrap_programs(
        &self,
        root: Hash,
        data: &BootstrapData,
    ) -> Result<(), SyncBackendError> {
        let executor = self
            .block_executor_snapshot()
            .ok_or_else(|| not_available("bootstrap requires a runtime executor"))?;
        let warm = snapshot_program_retention(data)?.warm;
        for item in bootstrap_program_items(data)? {
            let expected = bootstrap_artifact_identity(&item)?;
            let Some(bytes) = self.bootstrap_artifact_bytes(root, item, expected, &executor)?
            else {
                continue;
            };
            let keep_warm = warm.contains(&expected);
            let verifier = std::sync::Arc::clone(&self.proof_system);
            let budget = std::sync::Arc::clone(&self.proving_budget);
            let runtime = std::sync::Arc::clone(&executor);
            let store = self.program_store();
            let installed = tokio::task::spawn_blocking(move || {
                let hash = crate::programs::content_hash(&bytes)
                    .ok_or_else(|| rejected("bootstrap program size limit"))?;
                // Make the exact bytes durable before exposing their identity to
                // execution/proof jobs or installing a state which requires them.
                let staged = store
                    .stage_authenticated(&hash, &bytes)
                    .map_err(storage_error)?;
                let accepted = install_bootstrap_artifact(
                    item,
                    &bytes,
                    keep_warm,
                    runtime.as_ref(),
                    verifier.as_ref(),
                    &budget,
                );
                if accepted.is_ok() {
                    staged.accept_identity(expected).map_err(storage_error)?;
                }
                accepted
            })
            .await
            .map_err(storage_error)?;
            if let Err(error) = installed {
                self.reset_downloaded_program(root, item)?;
                return Err(error);
            }
        }
        Ok(())
    }

    /// Authenticate every Guest artifact `items` completed for `root` while
    /// its provider is known: a bad artifact is reset and the response
    /// rejected, so the peer that sent it, the only one that sent any of its
    /// bytes, is backed off. A genesis Guest must match the specification's
    /// content pin before any SP1 setup runs.
    pub(in crate::chain_backend) async fn authenticate_received_guests(
        &self,
        root: Hash,
        items: &[StateItem],
    ) -> Result<(), SyncBackendError> {
        for item in items
            .iter()
            .filter(|item| item.kind == StateItemKind::Guest)
        {
            let Some(bytes) = self.downloaded_program(root, *item)? else {
                continue;
            };
            let digest = item
                .guest_digest()
                .ok_or_else(|| rejected("invalid bootstrap Guest request"))?;
            let pinned = self.genesis_program_content(ArtifactIdentity::Guest(digest));
            let verifier = std::sync::Arc::clone(&self.proof_system);
            let budget = std::sync::Arc::clone(&self.proving_budget);
            let authenticated = tokio::task::spawn_blocking(move || {
                if pinned.is_some_and(|pin| crate::programs::content_hash(&bytes) != Some(pin)) {
                    return Err(rejected("bootstrap Guest content hash mismatch"));
                }
                budget
                    .setup(|| verifier.authenticate_guest(bytes, &[digest]))
                    .map(|_| ())
                    .map_err(rejected)
            })
            .await
            .map_err(storage_error)?;
            if let Err(error) = authenticated {
                self.reset_downloaded_program(root, *item)?;
                return Err(error);
            }
        }
        Ok(())
    }

    /// The bytes of `item` from the download or the artifact store, or
    /// `None` when the artifact is installed already and needs nothing.
    fn bootstrap_artifact_bytes(
        &self,
        root: Hash,
        item: StateItem,
        expected: ArtifactIdentity,
        executor: &std::sync::Arc<dyn ErasedBlockExecutor>,
    ) -> Result<Option<Vec<u8>>, SyncBackendError> {
        if let Some(bytes) = self.downloaded_program(root, item)? {
            return Ok(Some(bytes));
        }
        if let Some(bytes) = self.program_store().read_identity(expected) {
            return Ok(Some(bytes));
        }
        let installed = match expected {
            ArtifactIdentity::Runtime(hash) => executor.installed_runtimes().contains(&hash),
            ArtifactIdentity::Guest(digest) => self
                .proof_system
                .installed_guests()
                .iter()
                .any(|(installed, _)| *installed == digest),
        };
        if installed {
            return Ok(None);
        }
        Err(not_available("bootstrap execution artifact is incomplete"))
    }
}
