//! Fetching a needed program artifact from peers fragment by fragment.

use std::sync::{Arc, atomic::Ordering};

use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use tracing::{info, warn};

use super::{ChainBackend, ExpectedIdentity, PROGRAM_INSTALL_GRACE, ProgramFetch};
use crate::programs::ArtifactKind;
use crate::programs::hex_hash;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// The next fragment to request from peers: of the artifact being
    /// fetched, or of the first needed program this node lacks.
    pub(in crate::chain_backend) fn next_program_fetch(
        &self,
    ) -> Option<neutrin0_consensus_types::bootstrap::StateItem> {
        let mut fetch = self
            .program_fetch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(active) = fetch.as_ref()
            && !self.holds_program(active.identity)
        {
            match active.assembled {
                None => return Some(active.request()),
                Some(_) if active.rejected.load(Ordering::Acquire) => {}
                Some(at) if at.elapsed() < PROGRAM_INSTALL_GRACE => return None,
                Some(_) => {}
            }
        }
        *fetch = None;
        drop(fetch);
        let identity = self
            .needed_programs()
            .into_iter()
            .find(|identity| !self.holds_program(*identity))?;
        let active = ProgramFetch {
            identity,
            content: self.expected_program_content(identity),
            total_len: None,
            bytes: Vec::new(),
            assembled: None,
            rejected: Arc::default(),
        };
        let request = active.request();
        *self
            .program_fetch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(active);
        Some(request)
    }

    /// Absorb one fetched fragment. A fragment of another artifact or offset,
    /// or one changing the declared length, is refused; the assembled bytes are
    /// trusted only after they reproduce the requested identity.
    pub(in crate::chain_backend) fn absorb_fetched_fragment(
        &self,
        entry: &neutrin0_consensus_types::bootstrap::StateEntry,
    ) -> bool {
        let mut fetch = self
            .program_fetch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(active) = fetch.as_mut() else {
            return false;
        };
        if active.assembled.is_some()
            || !entry.validate_for(&active.request())
            || entry.total_len == 0
            || entry.total_len > u64::from(neutrin0_consensus_types::MAX_PROGRAM_BYTES)
            || active
                .total_len
                .is_some_and(|total| total != entry.total_len)
            || entry.bytes.is_empty()
        {
            return false;
        }
        active.total_len = Some(entry.total_len);
        active.bytes.extend_from_slice(entry.bytes.as_slice());
        if active.bytes.len() as u64 != entry.total_len {
            return true;
        }
        active.assembled = Some(std::time::Instant::now());
        let (identity, expected) = (active.identity, active.content);
        let bytes = core::mem::take(&mut active.bytes);
        let rejected = Arc::clone(&active.rejected);
        drop(fetch);
        match crate::programs::content_hash(&bytes) {
            // A Guest's key costs a full SP1 setup; a pinned content hash
            // refuses junk for the price of hashing it.
            Some(content) if expected.is_none_or(|expected| expected == content) => {
                self.index_fetched(content, Arc::new(bytes), identity, rejected);
            }
            _ => rejected.store(true, Ordering::Release),
        }
        true
    }

    /// Index fetched bytes under `identity` once they reproduce it: the
    /// runtime's BLAKE3 hash, or a Guest key derived locally off the async
    /// workers. The artifact loader then installs them on first use.
    fn index_fetched(
        &self,
        content: Hash,
        bytes: Arc<Vec<u8>>,
        identity: ExpectedIdentity,
        rejected: Arc<std::sync::atomic::AtomicBool>,
    ) {
        let store = self.program_store();
        let index = move || {
            let reproduces = match identity {
                ExpectedIdentity::Runtime(code_hash) => {
                    ArtifactKind::of(&bytes) == ArtifactKind::Wasm
                        && neutrin0_primitives::blake3_256(&bytes) == code_hash
                }
                ExpectedIdentity::Guest(digest) => {
                    ArtifactKind::of(&bytes) == ArtifactKind::Elf
                        && neutrin0_runtime_host::package::guest_key(&bytes).ok() == Some(digest)
                }
            };
            if !reproduces {
                warn!(hash = %hex_hash(&content), ?identity, "fetched artifact does not reproduce its identity");
                rejected.store(true, Ordering::Release);
            } else if let Err(error) = store.remember_identity(&content, &bytes, identity) {
                warn!(hash = %hex_hash(&content), %error, "fetched artifact could not be stored");
            } else {
                info!(hash = %hex_hash(&content), ?identity, "fetched program artifact stored");
            }
            store.mark_installed(&content);
        };
        if tokio::runtime::Handle::try_current().is_ok() {
            self.spawn_supervised("program-fetch-index", false, async move {
                tokio::task::spawn_blocking(index)
                    .await
                    .expect("program indexing worker panicked");
            });
        } else {
            index();
        }
    }
}
