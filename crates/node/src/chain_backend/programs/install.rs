//! Installing complete, governance-named artifacts into the executor and
//! proof backend.

use std::collections::BTreeMap;
use std::sync::{Arc, atomic::Ordering};

use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use tracing::{info, warn};

use super::{ChainBackend, ExpectedIdentity};
use crate::programs::ArtifactKind;
use crate::programs::hex_hash;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Install complete artifacts that governance names. Cheap when nothing
    /// is complete; called on import completions and before production.
    pub(crate) fn sync_programs(&self) {
        let _lifecycle = self
            .program_lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let wanted = self.wanted_artifacts();
        self.reconcile_programs(&wanted);
        self.install_wanted(&wanted);
        self.reconcile_programs(&wanted);
    }

    pub(in crate::chain_backend) fn configure_program_loader(&self) {
        let store = self.program_store();
        let loader: neutrin0_proof_system::artifacts::ProgramArtifactLoader =
            Arc::new(move |identity| store.read_identity(identity));
        self.proof_system.set_artifact_loader(Arc::clone(&loader));
        for (digest, _) in self.proof_system.installed_guests() {
            if let Some(bytes) = self.proof_system.guest_artifact(&digest)
                && let Some(content) = crate::programs::content_hash(&bytes)
            {
                let _ = self.program_store().remember_identity(
                    &content,
                    &bytes,
                    ExpectedIdentity::Guest(digest),
                );
            }
        }
        if let Some(executor) = self.block_executor_snapshot() {
            // The initial package predates on-chain distribution. Preserve its
            // authenticated source so it can be reopened after a later eviction.
            for hash in executor.installed_runtimes() {
                if let Some(bytes) = executor.runtime_artifact(&hash)
                    && let Some(content) = crate::programs::content_hash(&bytes)
                {
                    let _ = self.program_store().remember_identity(
                        &content,
                        &bytes,
                        ExpectedIdentity::Runtime(hash),
                    );
                }
            }
            executor.set_artifact_loader(loader);
        }
    }

    pub(super) fn install_wanted(&self, wanted: &BTreeMap<Hash, ExpectedIdentity>) {
        for (hash, bytes) in self.program_store().complete() {
            if let Some(expected) = wanted.get(&hash) {
                self.install_artifact(hash, bytes, *expected);
            }
        }
        for (hash, expected) in wanted {
            if !self.warm_identities().contains(expected)
                && self.program_store().has_persisted(hash)
            {
                continue;
            }
            let installed = match expected {
                ExpectedIdentity::Runtime(code_hash) => self
                    .block_executor_snapshot()
                    .is_some_and(|executor| executor.installed_runtimes().contains(code_hash)),
                ExpectedIdentity::Guest(digest) => self
                    .proof_system
                    .installed_guests()
                    .iter()
                    .any(|(installed, _)| installed == digest),
            };
            if !installed
                && let Some(bytes) = self
                    .program_store()
                    .read_identity(*expected)
                    .or_else(|| self.program_store().read_persisted(hash))
                && crate::programs::content_hash(&bytes) == Some(*hash)
            {
                self.install_artifact(*hash, Arc::new(bytes), *expected);
            }
        }
    }

    fn install_artifact(&self, hash: Hash, bytes: Arc<Vec<u8>>, expected: ExpectedIdentity) {
        let store = self.program_store();
        let warm = self.warm_identities().contains(&expected);
        match (ArtifactKind::of(&bytes), expected) {
            (ArtifactKind::Wasm, ExpectedIdentity::Runtime(code_hash)) => {
                self.install_runtime_artifact(&store, hash, &bytes, code_hash, expected, warm);
            }
            (ArtifactKind::Elf, ExpectedIdentity::Guest(digest)) => {
                self.install_guest_artifact(store, hash, bytes, digest, expected, warm);
            }
            (kind, expected) => {
                warn!(hash = %hex_hash(&hash), ?kind, ?expected, "artifact kind does not match its declared identity");
                store.mark_installed(&hash);
            }
        }
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "Each staged artifact is accepted and released on the exact path that authenticated it."
    )]
    fn install_runtime_artifact(
        &self,
        store: &crate::programs::ProgramStore,
        hash: Hash,
        bytes: &[u8],
        code_hash: Hash,
        expected: ExpectedIdentity,
        warm: bool,
    ) {
        // The runtime hash is checked before any bytes are compiled.
        if neutrin0_primitives::blake3_256(bytes) != code_hash {
            warn!(hash = %hex_hash(&hash), "runtime artifact does not match the declared code hash");
            store.mark_installed(&hash);
            return;
        }
        let Some(executor) = self.block_executor_snapshot() else {
            return;
        };
        let staged = match store.stage_authenticated(&hash, bytes) {
            Ok(staged) => staged,
            Err(error) => {
                warn!(hash = %hex_hash(&hash), %error, "runtime persistence failed; retained for retry");
                return;
            }
        };
        if !warm {
            match staged.accept_identity(expected) {
                Ok(()) => store.mark_installed(&hash),
                Err(error) => {
                    warn!(hash = %hex_hash(&hash), %error, "proposed runtime persistence failed; retained for retry");
                }
            }
            return;
        }
        // Persist bounded content and release the disk lock before any
        // compiler/setup work. Reconciliation never waits for a prover
        // while holding the artifact-store mutex.
        staged.accept();
        match executor.install_runtime(bytes) {
            Ok(installed) if installed == code_hash => {
                if let Err(error) = store.remember_identity(&hash, bytes, expected) {
                    warn!(hash = %hex_hash(&hash), %error, "runtime source index failed; retained for retry");
                    return;
                }
                info!(hash = %hex_hash(&hash), code_hash = %hex_hash(&code_hash), "runtime installed");
            }
            Ok(_) => warn!(hash = %hex_hash(&hash), "runtime installed a different identity"),
            Err(error) => {
                warn!(hash = %hex_hash(&hash), %error, "runtime installation deferred; retained for retry");
                return;
            }
        }
        store.mark_installed(&hash);
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "Each staged artifact is accepted and released on the exact path that authenticated it."
    )]
    fn install_guest_artifact(
        &self,
        store: Arc<crate::programs::ProgramStore>,
        hash: Hash,
        bytes: Arc<Vec<u8>>,
        digest: [u32; 8],
        expected: ExpectedIdentity,
        warm: bool,
    ) {
        if self.installing_programs.swap(true, Ordering::AcqRel) {
            return;
        }
        let prover = Arc::clone(&self.proof_system);
        let flag = Arc::clone(&self.installing_programs);
        let budget = Arc::clone(&self.proving_budget);
        let install = move || {
            struct InstallingGuard(Arc<std::sync::atomic::AtomicBool>);
            impl Drop for InstallingGuard {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::Release);
                }
            }
            let _installing = InstallingGuard(flag);
            let staged = match store.stage_authenticated(&hash, &bytes) {
                Ok(staged) => staged,
                Err(error) => {
                    warn!(hash = %hex_hash(&hash), %error, "guest persistence failed; retained for retry");
                    return;
                }
            };
            staged.accept();
            if !warm {
                // Prequorum distribution authenticates bounded content
                // only. Key derivation and GPU setup wait for enactment.
                store.mark_installed(&hash);
                return;
            }
            let result = budget.setup(|| prover.install_guest_checked(bytes.to_vec(), digest));
            match result {
                Ok(derived) if derived == digest => {
                    if let Err(error) = store.remember_identity(&hash, &bytes, expected) {
                        warn!(hash = %hex_hash(&hash), %error, "Guest source index failed; retained for retry");
                        return;
                    }
                    info!(hash = %hex_hash(&hash), ?digest, "guest installed");
                }
                Ok(derived) => {
                    warn!(hash = %hex_hash(&hash), ?digest, ?derived,
                        "guest artifact derives a different verifying key than governance declared");
                }
                Err(error) => {
                    warn!(hash = %hex_hash(&hash), %error, "Guest installation deferred; retained for retry");
                    return;
                }
            }
            store.mark_installed(&hash);
        };
        // SP1 setup is slow; keep it off async workers when possible.
        if tokio::runtime::Handle::try_current().is_ok() {
            self.spawn_supervised("program-install", false, async move {
                tokio::task::spawn_blocking(install)
                    .await
                    .expect("program installation worker panicked");
            });
        } else {
            install();
        }
    }
}
