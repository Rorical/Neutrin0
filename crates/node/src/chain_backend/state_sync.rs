//! Durable, bounded content-addressed state reconstruction.
//!
//! Objects are staged by kind and hash, not by root: consecutive state roots
//! share almost every node, so a download for a newer manifest reuses what an
//! older one already fetched instead of starting over. Each root tracks its
//! pending and resolved objects as individual rows, and a large object grows
//! by fragment rows, so a response writes only the rows it changes. A complete
//! download enters the state store a bounded slice at a time, read straight
//! from the staged objects, so no snapshot is ever held in memory whole.

use neutrin0_consensus_types::bootstrap::StateItemKind;
use neutrin0_primitives::Hash;
use neutrin0_storage::{Batch, Column, Database, ReadHandle};
use neutrin0_sync::SyncBackendError;
use neutrin0_trie::NodeSource;

use super::{ChainBackend, storage_error};
use neutrin0_consensus_engine::store::pointers::STATE_DOWNLOAD_ENTRY_PREFIX;
use neutrin0_proof_system::ProofSystem;

mod install;
mod programs;
mod receive;
mod staging;
mod step;

pub(super) use staging::MAX_ENTRY_BYTES;
use staging::{
    OBJECT, PAGE, PENDING, PROGRESS, RESOLVED, TOTALS, discard_fragments, download_key, has, keys,
    live_roots, object_key, object_of, root_key, root_prefix, tagged, totals,
};

/// The staged objects of every download, read by content hash. The store
/// checks each entry against its hash as it installs it.
pub(super) struct StagedObjects(std::sync::Arc<dyn ReadHandle>);

impl core::fmt::Debug for StagedObjects {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StagedObjects")
    }
}

impl StagedObjects {
    fn object(&self, kind: StateItemKind, hash: &Hash) -> Option<Vec<u8>> {
        self.0
            .get(Column::Meta, &object_key(OBJECT, kind, *hash))
            .ok()
            .flatten()
    }
}

impl NodeSource for StagedObjects {
    fn node(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.object(StateItemKind::Node, hash)
    }

    fn value(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.object(StateItemKind::Value, hash)
    }
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Forget `root`'s download, and every staged object once no other
    /// download remains to share them.
    pub(super) fn clear_state_download(&self, root: Hash) -> Result<(), SyncBackendError> {
        self.abandon_state_download(root)?;
        if self
            .with_engine(|engine| live_roots(engine.store().db()))?
            .is_empty()
        {
            self.clear_rows(STATE_DOWNLOAD_ENTRY_PREFIX)?;
        }
        Ok(())
    }

    /// Forget `root`'s progress but keep staged objects for a later root.
    /// The summary goes last, so [`Self::retain_state_downloads`] finds and
    /// finishes an interrupted call.
    pub(super) fn abandon_state_download(&self, root: Hash) -> Result<(), SyncBackendError> {
        self.finish_interrupted_install()?;
        for tag in [PENDING, RESOLVED] {
            self.clear_rows(&root_prefix(tag, root))?;
        }
        self.with_engine_mut(|engine| {
            let mut batch = Batch::new();
            batch.delete(Column::Meta, download_key(root));
            engine
                .store_mut()
                .write_observed_batch(batch, true)
                .map_err(storage_error)
        })
    }

    /// Abandon every download except those of `roots`; with none left, drop
    /// every staged object too.
    pub(super) fn retain_state_downloads(&self, roots: &[Hash]) -> Result<(), SyncBackendError> {
        self.finish_interrupted_install()?;
        for root in self.with_engine(|engine| live_roots(engine.store().db()))? {
            if !roots.contains(&root) {
                self.abandon_state_download(root)?;
            }
        }
        if roots.is_empty() {
            self.clear_rows(STATE_DOWNLOAD_ENTRY_PREFIX)?;
        }
        Ok(())
    }

    /// Delete every row under `prefix`, a bounded page per lock hold.
    pub(super) fn clear_rows(&self, prefix: &[u8]) -> Result<(), SyncBackendError> {
        loop {
            let done = self.with_engine_mut(|engine| {
                let page = keys(engine.store().db(), prefix, prefix, PAGE)?;
                let mut batch = Batch::new();
                for key in &page {
                    batch.delete(Column::Meta, key.clone());
                }
                engine
                    .store_mut()
                    .write_observed_batch(batch, true)
                    .map_err(storage_error)?;
                Ok::<_, SyncBackendError>(page.len() < PAGE)
            })?;
            if done {
                return Ok(());
            }
        }
    }

    /// Free the budget held by objects no live download has resolved or
    /// still awaits, such as those of a replaced manifest. One a live root
    /// has not discovered yet goes too and is fetched again if reached.
    pub(super) fn sweep_unreferenced_objects(&self) -> Result<(), SyncBackendError> {
        self.finish_interrupted_install()?;
        // Partial objects are swept by their progress row, which every
        // fragment of the object accompanies.
        for tag in [OBJECT, PROGRESS] {
            let prefix = tagged(tag);
            let mut from = prefix.clone();
            loop {
                let next = self.with_engine_mut(|engine| {
                    let db = engine.store().db();
                    let roots = live_roots(db)?;
                    let page = keys(db, &prefix, &from, PAGE)?;
                    let mut totals = totals(db)?;
                    let mut batch = Batch::new();
                    for key in &page {
                        let (kind, hash) = object_of(&prefix, key)?;
                        let mut referenced = false;
                        for root in &roots {
                            referenced = has(db, &root_key(PENDING, *root, kind, hash))?
                                || (tag == OBJECT
                                    && has(db, &root_key(RESOLVED, *root, kind, hash))?);
                            if referenced {
                                break;
                            }
                        }
                        if referenced {
                            continue;
                        }
                        let freed = if tag == OBJECT {
                            let bytes = db.get(Column::Meta, key).map_err(storage_error)?;
                            batch.delete(Column::Meta, key.clone());
                            bytes.map_or(0, |bytes| bytes.len() as u64)
                        } else {
                            discard_fragments(db, &mut batch, kind, hash)?
                        };
                        totals.bytes = totals.bytes.saturating_sub(freed);
                    }
                    batch.put(
                        Column::Meta,
                        tagged(TOTALS),
                        borsh::to_vec(&totals).map_err(storage_error)?,
                    );
                    engine
                        .store_mut()
                        .write_observed_batch(batch, false)
                        .map_err(storage_error)?;
                    Ok::<_, SyncBackendError>((page.len() == PAGE).then(|| {
                        let mut next = page.last().expect("full page").clone();
                        next.push(0);
                        next
                    }))
                })?;
                match next {
                    Some(next) => from = next,
                    None => break,
                }
            }
        }
        Ok(())
    }
}
