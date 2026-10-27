//! Program artifacts a bootstrap download names, tracked as objects of its
//! state root.

use neutrin0_consensus_types::bootstrap::{StateItem, StateItemKind};
use neutrin0_primitives::{Hash, ZERO_HASH};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::{Batch, Column, Database};
use neutrin0_sync::SyncBackendError;

use super::super::{rejected, storage_error};
use super::ChainBackend;
use super::staging::{
    OBJECT, PENDING, RESOLVED, TOTALS, discard_fragments, has, object_key, root_key, tagged, totals,
};
use super::step::{Step, seed};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Add only program identities authenticated by the verified bootstrap context.
    pub(in crate::chain_backend) fn require_bootstrap_programs(
        &self,
        root: Hash,
        programs: &[StateItem],
    ) -> Result<(), SyncBackendError> {
        self.with_engine_mut(|engine| {
            seed(engine, root)?;
            let mut step = Step::open(engine.store().db(), root)?;
            for item in programs {
                if !matches!(item.kind, StateItemKind::Runtime | StateItemKind::Guest)
                    || item.offset != 0
                    || item.hash == ZERO_HASH
                {
                    return Err(rejected("invalid authenticated bootstrap program"));
                }
                step.discover(item.kind, item.hash)?;
            }
            let Some(batch) = step.finish()? else {
                return Ok(());
            };
            engine
                .store_mut()
                .write_observed_batch(batch, true)
                .map_err(storage_error)
        })
    }

    pub(in crate::chain_backend) fn downloaded_program(
        &self,
        root: Hash,
        item: StateItem,
    ) -> Result<Option<Vec<u8>>, SyncBackendError> {
        self.with_engine(|engine| {
            let db = engine.store().db();
            if !has(db, &root_key(RESOLVED, root, item.kind, item.hash))? {
                return Ok(None);
            }
            db.get(Column::Meta, &object_key(OBJECT, item.kind, item.hash))
                .map_err(storage_error)?
                .ok_or_else(|| storage_error("completed bootstrap program is missing"))
                .map(Some)
        })
    }

    /// Retry a rejected complete artifact without discarding authenticated trie progress.
    pub(in crate::chain_backend) fn reset_downloaded_program(
        &self,
        root: Hash,
        item: StateItem,
    ) -> Result<(), SyncBackendError> {
        self.with_engine_mut(|engine| {
            let db = engine.store().db();
            let mut totals = totals(db)?;
            let mut batch = Batch::new();
            let object = object_key(OBJECT, item.kind, item.hash);
            if let Some(bytes) = db.get(Column::Meta, &object).map_err(storage_error)? {
                totals.bytes = totals.bytes.saturating_sub(bytes.len() as u64);
                batch.delete(Column::Meta, object);
            }
            let staged = discard_fragments(db, &mut batch, item.kind, item.hash)?;
            totals.bytes = totals.bytes.saturating_sub(staged);
            batch.delete(Column::Meta, root_key(RESOLVED, root, item.kind, item.hash));
            batch.put(
                Column::Meta,
                root_key(PENDING, root, item.kind, item.hash),
                Vec::new(),
            );
            batch.put(
                Column::Meta,
                tagged(TOTALS),
                borsh::to_vec(&totals).map_err(storage_error)?,
            );
            engine
                .store_mut()
                .write_observed_batch(batch, true)
                .map_err(storage_error)
        })
    }
}
