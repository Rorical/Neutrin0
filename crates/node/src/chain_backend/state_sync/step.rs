//! One engine-lock hold of work on a root's download.

use neutrin0_consensus_types::bootstrap::{MAX_STATE_ITEMS, StateItem, StateItemKind};
use neutrin0_primitives::{Hash, ZERO_HASH};
use neutrin0_storage::{Batch, Column, Database};
use neutrin0_sync::SyncBackendError;
use neutrin0_trie::Node;
use std::collections::BTreeSet;

use super::super::{rejected, storage_error};
use super::staging::{
    MAX_ENTRIES, OBJECT, PENDING, RESOLVED, SCAN_LIMIT, Summary, decode, download_key, has, keys,
    object_key, object_of, progress, root_key, root_prefix,
};

/// One engine-lock hold of work on `root`'s download. Writes go to one batch;
/// `seen` covers objects the batch queues before it is written.
pub(super) struct Step<'a, DB: Database> {
    db: &'a DB,
    root: Hash,
    pub(super) batch: Batch,
    summary: Summary,
    seen: BTreeSet<(StateItemKind, Hash)>,
    pub(super) changed: bool,
}

impl<'a, DB: Database> Step<'a, DB>
where
    DB::Error: core::fmt::Display,
{
    /// The rows that start `root`'s download, its root node pending, unless
    /// it has started. They are written before any step reads them.
    pub(super) fn seed(db: &'a DB, root: Hash) -> Result<Option<Batch>, SyncBackendError> {
        if has(db, &download_key(root))? {
            return Ok(None);
        }
        let mut step = Self {
            db,
            root,
            batch: Batch::new(),
            summary: Summary::default(),
            seen: BTreeSet::new(),
            changed: true,
        };
        step.discover(StateItemKind::Node, root)?;
        step.finish()
    }

    /// Open `root`'s seeded download.
    pub(super) fn open(db: &'a DB, root: Hash) -> Result<Self, SyncBackendError> {
        let summary: Summary = decode(
            db.get(Column::Meta, &download_key(root))
                .map_err(storage_error)?,
        )?;
        if summary.entries > MAX_ENTRIES {
            return Err(storage_error("state download metadata exceeds budget"));
        }
        Ok(Self {
            db,
            root,
            batch: Batch::new(),
            summary,
            seen: BTreeSet::new(),
            changed: false,
        })
    }

    /// The writes this step made, with the updated summary.
    pub(super) fn finish(mut self) -> Result<Option<Batch>, SyncBackendError> {
        if !self.changed {
            return Ok(None);
        }
        self.batch.put(
            Column::Meta,
            download_key(self.root),
            borsh::to_vec(&self.summary).map_err(storage_error)?,
        );
        Ok(Some(self.batch))
    }

    pub(super) fn pending(
        &self,
        kind: StateItemKind,
        hash: Hash,
    ) -> Result<bool, SyncBackendError> {
        has(self.db, &root_key(PENDING, self.root, kind, hash))
    }

    /// Queue `(kind, hash)` unless this root already holds or awaits it.
    pub(super) fn discover(
        &mut self,
        kind: StateItemKind,
        hash: Hash,
    ) -> Result<(), SyncBackendError> {
        if (kind == StateItemKind::Node && hash == ZERO_HASH) || !self.seen.insert((kind, hash)) {
            return Ok(());
        }
        if has(self.db, &root_key(RESOLVED, self.root, kind, hash))? || self.pending(kind, hash)? {
            return Ok(());
        }
        self.summary.entries += 1;
        if self.summary.entries > MAX_ENTRIES {
            return Err(SyncBackendError::NotAvailable(
                "state entry budget exceeded".into(),
            ));
        }
        self.batch.put(
            Column::Meta,
            root_key(PENDING, self.root, kind, hash),
            Vec::new(),
        );
        self.changed = true;
        Ok(())
    }

    /// The complete object `bytes` is this root's: record it and queue the
    /// children a trie node names.
    pub(super) fn resolve(
        &mut self,
        kind: StateItemKind,
        hash: Hash,
        bytes: &[u8],
    ) -> Result<(), SyncBackendError> {
        self.batch
            .delete(Column::Meta, root_key(PENDING, self.root, kind, hash));
        self.batch.put(
            Column::Meta,
            root_key(RESOLVED, self.root, kind, hash),
            Vec::new(),
        );
        self.changed = true;
        if kind != StateItemKind::Node {
            return Ok(());
        }
        match Node::decode(bytes).map_err(rejected)? {
            Node::Leaf { value_hash, .. } => self.discover(StateItemKind::Value, value_hash),
            Node::Branch { left, right } => {
                self.discover(StateItemKind::Node, left)?;
                self.discover(StateItemKind::Node, right)
            }
            Node::Extension { child, .. } => self.discover(StateItemKind::Node, child),
        }
    }

    /// Resolve pending objects another download already staged and return
    /// up to [`MAX_STATE_ITEMS`] that must come from the network, at their
    /// staged offsets, with the number resolved here.
    pub(super) fn scan(&mut self) -> Result<(Vec<StateItem>, usize), SyncBackendError> {
        let prefix = root_prefix(PENDING, self.root);
        let mut network = Vec::new();
        let mut resolved = 0;
        for key in keys(self.db, &prefix, &prefix, SCAN_LIMIT)? {
            let (kind, hash) = object_of(&prefix, &key)?;
            if let Some(bytes) = self
                .db
                .get(Column::Meta, &object_key(OBJECT, kind, hash))
                .map_err(storage_error)?
            {
                self.resolve(kind, hash, &bytes)?;
                resolved += 1;
            } else if network.len() < MAX_STATE_ITEMS {
                network.push(StateItem {
                    kind,
                    hash,
                    offset: progress(self.db, kind, hash)?,
                });
            } else if resolved == 0 {
                break;
            }
        }
        Ok((network, resolved))
    }
}

/// Start `root`'s download if needed, within the caller's lock hold.
pub(super) fn seed<DB: Database>(
    engine: &mut neutrin0_consensus_engine::Engine<DB>,
    root: Hash,
) -> Result<(), SyncBackendError>
where
    DB::Error: core::fmt::Display,
{
    if let Some(batch) = Step::seed(engine.store().db(), root)? {
        engine
            .store_mut()
            .write_observed_batch(batch, false)
            .map_err(storage_error)?;
    }
    Ok(())
}
