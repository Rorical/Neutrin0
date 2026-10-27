//! Installing complete downloads into the state store, and staging the
//! objects a snapshot file supplies.

use neutrin0_consensus_types::bootstrap::StateItemKind;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::{Batch, Column, Database};
use neutrin0_sync::SyncBackendError;

use super::super::{rejected, storage_error};
use super::staging::{
    DEFAULT_MAX_BYTES, MAX_ENTRY_BYTES, OBJECT, TOTALS, complete, content_hash, has, object_key,
    tagged, totals,
};
use super::{ChainBackend, StagedObjects};

/// Most trie edges one installation slice counts while holding the engine.
const INSTALL_SLICE: usize = 4096;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Install the complete downloads of `roots` into the state store, in
    /// order, a bounded slice per engine lock hold. The roots stay pinned
    /// for their owner to adopt or release.
    pub(in crate::chain_backend) fn install_downloaded_state(
        &self,
        roots: &[Hash],
    ) -> Result<(), SyncBackendError> {
        self.with_engine(|engine| {
            for root in roots {
                if !complete(engine.store().db(), *root)? {
                    return Err(SyncBackendError::NotAvailable(
                        "state snapshot is incomplete".into(),
                    ));
                }
            }
            Ok(())
        })?;
        self.install_state_slices(roots)
    }

    /// Finish an installation a restart interrupted, before anything may
    /// drop the staged objects it still reads: its partial counts cannot be
    /// undone, only completed.
    pub(in crate::chain_backend) fn finish_interrupted_install(
        &self,
    ) -> Result<(), SyncBackendError> {
        let unfinished = self
            .with_engine(|engine| engine.store().state_install())
            .map_err(storage_error)?
            .filter(|install| !install.finished);
        match unfinished {
            Some(install) => self.install_state_slices(&install.roots),
            None => Ok(()),
        }
    }

    fn install_state_slices(&self, roots: &[Hash]) -> Result<(), SyncBackendError> {
        let source = self.with_engine(|engine| StagedObjects(engine.store().db().read_handle()));
        loop {
            let done = self
                .with_engine_mut(|engine| {
                    engine
                        .store_mut()
                        .install_state_slice(roots, &source, INSTALL_SLICE)
                })
                .map_err(storage_error)?;
            if done {
                return Ok(());
            }
        }
    }

    /// Stage complete objects a snapshot file supplies, as received fragments
    /// are staged: each must fit its kind's size bound and hash to its key
    /// where its kind has a content hash (a Guest's key is checked by SP1
    /// setup before installation), and the shared byte budget holds. Objects
    /// already staged are skipped.
    pub(in crate::chain_backend) fn stage_objects(
        &self,
        objects: &[(StateItemKind, Hash, Vec<u8>)],
    ) -> Result<(), SyncBackendError> {
        self.with_engine_mut(|engine| {
            let db = engine.store().db();
            let mut totals = totals(db)?;
            let mut batch = Batch::new();
            let mut staged = std::collections::BTreeSet::new();
            for (kind, hash, bytes) in objects {
                let limit = match kind {
                    StateItemKind::Runtime | StateItemKind::Guest => {
                        u64::from(neutrin0_consensus_types::MAX_PROGRAM_BYTES)
                    }
                    StateItemKind::Node | StateItemKind::Value => MAX_ENTRY_BYTES,
                };
                if bytes.is_empty()
                    || bytes.len() as u64 > limit
                    || content_hash(*kind, bytes).is_some_and(|content| content != *hash)
                {
                    return Err(rejected("snapshot object does not match its key"));
                }
                let key = object_key(OBJECT, *kind, *hash);
                if !staged.insert(key.clone()) || has(db, &key)? {
                    continue;
                }
                totals.bytes = totals
                    .bytes
                    .checked_add(bytes.len() as u64)
                    .filter(|bytes| *bytes <= DEFAULT_MAX_BYTES)
                    .ok_or_else(|| {
                        SyncBackendError::NotAvailable("state byte budget exceeded".into())
                    })?;
                batch.put(Column::Meta, key, bytes.clone());
            }
            batch.put(
                Column::Meta,
                tagged(TOTALS),
                borsh::to_vec(&totals).map_err(storage_error)?,
            );
            engine
                .store_mut()
                .write_observed_batch(batch, false)
                .map_err(storage_error)
        })
    }
}
