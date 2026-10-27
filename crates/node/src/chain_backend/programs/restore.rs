//! Reinstalling artifacts an earlier session persisted.

use std::collections::BTreeSet;

use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofSystem;
use neutrin0_proof_system::artifacts::ProgramRetention;
use neutrin0_storage::Database;
use tracing::warn;

use super::{ChainBackend, ExpectedIdentity};
use crate::programs::ArtifactKind;
use crate::programs::hex_hash;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Reinstall artifacts persisted by an earlier session, but only those
    /// whose re-derived identity the chain still names. The directory is
    /// local trusted storage, yet nothing in it is installed on faith: a
    /// file that no longer matches a named identity is deleted.
    pub fn restore_programs(&self) {
        let _lifecycle = self
            .program_lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.configure_program_loader();
        let store = self.program_store();
        let authenticated = self.named_identities();
        let initial = ProgramRetention {
            sources: authenticated.iter().copied().collect(),
            warm: self.warm_identities().into_iter().collect(),
        };
        if let Some(executor) = self.block_executor_snapshot() {
            executor.retain_programs(&initial);
        }
        self.proof_system.retain_programs(&initial);
        // Read one file at a time: thousands of archived source identities do
        // not allocate thousands of ELFs, compiled modules, or CUDA sessions.
        for (hash, kind) in store.persisted_summary() {
            if kind != ArtifactKind::Wasm {
                continue;
            }
            let Some(bytes) = store.read_persisted(&hash) else {
                continue;
            };
            let identity = ExpectedIdentity::Runtime(neutrin0_primitives::blake3_256(&bytes));
            if authenticated.contains(&identity) {
                self.restore_persisted_runtime(hash, &bytes, initial.warm.contains(&identity));
            }
        }
        let named = self.named_identities();
        let warm = self.warm_identities();
        for (hash, kind) in store.persisted_summary() {
            let Some(bytes) = store.read_persisted(&hash) else {
                continue;
            };
            match kind {
                ArtifactKind::Wasm => {
                    let identity =
                        ExpectedIdentity::Runtime(neutrin0_primitives::blake3_256(&bytes));
                    if named.contains(&identity) {
                        self.restore_persisted_runtime(hash, &bytes, warm.contains(&identity));
                    } else {
                        store.forget_persisted(&hash);
                    }
                }
                ArtifactKind::Elf => self.restore_persisted_guest(hash, bytes, &named, &warm),
                ArtifactKind::Unknown => store.forget_persisted(&hash),
            }
        }
        self.reconcile_programs(&self.wanted_artifacts());
    }

    fn restore_persisted_runtime(&self, hash: Hash, bytes: &[u8], warm: bool) {
        let identity = ExpectedIdentity::Runtime(neutrin0_primitives::blake3_256(bytes));
        if let Err(error) = self
            .program_store()
            .remember_identity(&hash, bytes, identity)
        {
            warn!(hash = %hex_hash(&hash), %error, "runtime source index could not be persisted");
            return;
        }
        if !warm {
            return;
        }
        if let Some(executor) = self.block_executor_snapshot()
            && let Err(error) = executor.install_runtime(bytes)
        {
            // A busy/leased cache is operational; authenticated source material
            // remains on disk and can be retried without downloading again.
            warn!(hash = %hex_hash(&hash), %error, "runtime warming deferred; source retained");
        }
    }

    fn restore_persisted_guest(
        &self,
        hash: Hash,
        bytes: Vec<u8>,
        named: &BTreeSet<ExpectedIdentity>,
        warm: &BTreeSet<ExpectedIdentity>,
    ) {
        let expected: Vec<_> = named
            .iter()
            .filter_map(|identity| match identity {
                ExpectedIdentity::Runtime(_) => None,
                ExpectedIdentity::Guest(digest) => Some(*digest),
            })
            .collect();
        let indexed = expected.iter().find(|digest| {
            self.program_store()
                .identity_content_hash(ExpectedIdentity::Guest(**digest))
                == Some(hash)
        });
        if let Some(digest) = indexed {
            if !warm.contains(&ExpectedIdentity::Guest(*digest)) {
                return;
            }
        } else if !self
            .wanted_artifacts()
            .get(&hash)
            .is_some_and(|identity| warm.contains(identity))
        {
            // An unindexed ELF is proposed content, not an installed program.
            // Never perform CPU/GPU setup merely because one validator named it.
            return;
        }
        let result = self.proving_budget.setup(|| {
            self.proof_system
                .authenticate_guest(bytes.clone(), &expected)
        });
        match result {
            Ok(digest) => {
                let identity = ExpectedIdentity::Guest(digest);
                if let Err(error) = self
                    .program_store()
                    .remember_identity(&hash, &bytes, identity)
                {
                    warn!(hash = %hex_hash(&hash), %error, "Guest source index could not be persisted");
                    return;
                }
                if warm.contains(&identity)
                    && let Err(error) = self
                        .proving_budget
                        .setup(|| self.proof_system.install_guest_checked(bytes, digest))
                {
                    warn!(hash = %hex_hash(&hash), %error, "Guest warming deferred; source retained");
                }
            }
            Err(neutrin0_proof_system::ProofError::PublicInputMismatch) => {
                self.program_store().forget_persisted(&hash);
            }
            Err(error) => {
                warn!(hash = %hex_hash(&hash), %error, "Guest authentication unavailable; source retained for retry");
            }
        }
    }
}
