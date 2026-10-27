//! Authenticating received state fragments against a root's download.

use neutrin0_consensus_types::bootstrap::{MAX_STATE_ITEMS, StateEntry, StateItem, StateItemKind};
use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::{Batch, Column, Database};
use neutrin0_sync::{StateProgress, SyncBackendError};

use super::super::{rejected, storage_error};
use super::ChainBackend;
use super::staging::{
    DEFAULT_MAX_BYTES, MAX_ENTRY_BYTES, OBJECT, PROGRESS, TOTALS, Totals, complete, content_hash,
    discard_fragments, fragment_key, fragments, object_key, progress, tagged, totals,
};
use super::step::{Step, seed};

/// Refuse a fragment that does not match what was requested of `root`, is
/// not a program artifact where one was asked for, is unsolicited or too
/// large, or continues an object at the wrong offset.
fn validate_received_fragment<DB: Database>(
    db: &DB,
    step: &Step<'_, DB>,
    expected: &StateItem,
    entry: &StateEntry,
) -> Result<(), SyncBackendError>
where
    DB::Error: core::fmt::Display,
{
    if !entry.validate_for(expected) {
        return Err(SyncBackendError::Rejected(
            "state fragment framing mismatch".into(),
        ));
    }
    let program = matches!(expected.kind, StateItemKind::Runtime | StateItemKind::Guest);
    if program
        && (entry.total_len == 0
            || (expected.offset == 0
                && !entry.bytes.as_slice().starts_with(match expected.kind {
                    StateItemKind::Runtime => b"\0asm",
                    StateItemKind::Guest => b"\x7fELF",
                    StateItemKind::Node | StateItemKind::Value => {
                        unreachable!("program namespace")
                    }
                })))
    {
        return Err(rejected("bootstrap program artifact kind mismatch"));
    }
    let limit = if program {
        u64::from(neutrin0_consensus_types::MAX_PROGRAM_BYTES)
    } else {
        MAX_ENTRY_BYTES
    };
    if !step.pending(expected.kind, expected.hash)? || entry.total_len > limit {
        return Err(SyncBackendError::Rejected(
            "unsolicited or oversized state fragment".into(),
        ));
    }
    if progress(db, expected.kind, expected.hash)? != expected.offset {
        return Err(SyncBackendError::NotAvailable(
            "state fragment offset differs from staged progress".into(),
        ));
    }
    Ok(())
}

/// The complete object `entry` finishes: its staged fragments, which the
/// batch then discards, followed by the final bytes.
fn assemble_received_object<DB: Database>(
    db: &DB,
    batch: &mut Batch,
    expected: &StateItem,
    entry: &StateEntry,
    end: u64,
) -> Result<Vec<u8>, SyncBackendError>
where
    DB::Error: core::fmt::Display,
{
    let mut bytes = Vec::new();
    if expected.offset != 0 {
        for (_, fragment) in fragments(db, expected.kind, expected.hash)? {
            bytes.extend_from_slice(&fragment);
        }
        discard_fragments(db, batch, expected.kind, expected.hash)?;
    }
    bytes.extend_from_slice(entry.bytes.as_slice());
    if bytes.len() as u64 != end {
        return Err(storage_error("staged state fragments are inconsistent"));
    }
    Ok(bytes)
}

/// Stage one authenticated fragment: a partial object keeps growing, a
/// complete one resolves for the root. Returns `true` when the completed
/// object's content hash mismatches, which ends the response.
fn stage_received_entry<DB: Database>(
    db: &DB,
    step: &mut Step<'_, DB>,
    totals: &mut Totals,
    expected: &StateItem,
    entry: &StateEntry,
) -> Result<bool, SyncBackendError>
where
    DB::Error: core::fmt::Display,
{
    validate_received_fragment(db, step, expected, entry)?;
    totals.bytes = totals
        .bytes
        .checked_add(entry.bytes.len() as u64)
        .filter(|bytes| *bytes <= DEFAULT_MAX_BYTES)
        .ok_or_else(|| SyncBackendError::NotAvailable("state byte budget exceeded".into()))?;
    let end = expected.offset + entry.bytes.len() as u64;
    if end != entry.total_len {
        step.batch.put(
            Column::Meta,
            fragment_key(expected.kind, expected.hash, expected.offset),
            entry.bytes.as_slice().to_vec(),
        );
        step.batch.put(
            Column::Meta,
            object_key(PROGRESS, expected.kind, expected.hash),
            borsh::to_vec(&end).map_err(storage_error)?,
        );
        return Ok(false);
    }
    let bytes = assemble_received_object(db, &mut step.batch, expected, entry, end)?;
    if content_hash(expected.kind, &bytes).is_some_and(|hash| hash != expected.hash) {
        // Retry this object from byte zero with another provider;
        // what earlier entries completed is kept.
        totals.bytes -= end;
        return Ok(true);
    }
    step.resolve(expected.kind, expected.hash, &bytes)?;
    step.batch.put(
        Column::Meta,
        object_key(OBJECT, expected.kind, expected.hash),
        bytes,
    );
    Ok(false)
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// The next fragments `root` needs from the network. Objects an earlier
    /// download already staged resolve locally, a bounded slice per lock hold.
    pub(in crate::chain_backend) fn state_download_items(
        &self,
        root: Hash,
    ) -> Result<Vec<StateItem>, SyncBackendError> {
        loop {
            let (items, resolved) = self.with_engine_mut(|engine| {
                seed(engine, root)?;
                let mut step = Step::open(engine.store().db(), root)?;
                let scanned = step.scan()?;
                if let Some(batch) = step.finish()? {
                    engine
                        .store_mut()
                        .write_observed_batch(batch, false)
                        .map_err(storage_error)?;
                }
                Ok::<_, SyncBackendError>(scanned)
            })?;
            if resolved == 0 || items.len() >= MAX_STATE_ITEMS {
                return Ok(items);
            }
        }
    }

    /// Authenticate every received state item against the requested
    /// manifest in one pass.
    pub(in crate::chain_backend) fn receive_state_entries(
        &self,
        root: Hash,
        requested: &[StateItem],
        entries: &[StateEntry],
    ) -> Result<StateProgress, SyncBackendError> {
        if requested.len() > MAX_STATE_ITEMS || requested.len() != entries.len() {
            return Err(SyncBackendError::Rejected(
                "state response does not match requested fragment count".into(),
            ));
        }
        let incoming: u64 = entries.iter().map(|entry| entry.bytes.len() as u64).sum();
        if self
            .with_engine(|engine| totals(engine.store().db()))?
            .bytes
            .saturating_add(incoming)
            > DEFAULT_MAX_BYTES
        {
            self.sweep_unreferenced_objects()?;
        }
        self.with_engine_mut(|engine| {
            self.authorize_state_download(root)?;
            seed(engine, root)?;
            let db = engine.store().db();
            let mut step = Step::open(db, root)?;
            let mut totals = totals(db)?;
            let mut mismatch = false;
            for (expected, entry) in requested.iter().zip(entries) {
                if stage_received_entry(db, &mut step, &mut totals, expected, entry)? {
                    mismatch = true;
                    break;
                }
            }
            step.batch.put(
                Column::Meta,
                tagged(TOTALS),
                borsh::to_vec(&totals).map_err(storage_error)?,
            );
            step.changed = true;
            let batch = step.finish()?.expect("changed step");
            // Each response leaves a consistent download, and a crash loses
            // at most the newest responses, which are fetched again.
            engine
                .store_mut()
                .write_observed_batch(batch, false)
                .map_err(storage_error)?;
            if mismatch {
                return Err(SyncBackendError::Rejected(
                    "state object content hash mismatch".into(),
                ));
            }
            Ok(())
        })?;
        let next_items = self.state_download_items(root)?;
        let root_complete = self.with_engine(|engine| complete(engine.store().db(), root))?;
        Ok(StateProgress {
            root_complete,
            next_items,
        })
    }

    /// Discard the staged fragments of the partly received `items`: each then
    /// restarts from byte zero with a new provider, so a content mismatch
    /// blames only the peer that sent every byte of the object.
    pub(in crate::chain_backend) fn restart_state_fragments(
        &self,
        items: &[StateItem],
    ) -> Result<(), SyncBackendError> {
        self.with_engine_mut(|engine| {
            let db = engine.store().db();
            let mut batch = Batch::new();
            let mut totals = totals(db)?;
            for item in items.iter().filter(|item| item.offset > 0) {
                let staged = discard_fragments(db, &mut batch, item.kind, item.hash)?;
                totals.bytes = totals.bytes.saturating_sub(staged);
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

    /// `root`'s complete download as a trie read from the staged objects,
    /// for tests that inspect what was staged.
    #[cfg(test)]
    pub(in crate::chain_backend) fn reconstructed_state(
        &self,
        root: Hash,
    ) -> Result<neutrin0_trie::Trie, SyncBackendError> {
        self.with_engine(|engine| {
            let db = engine.store().db();
            if !complete(db, root)? {
                return Err(SyncBackendError::NotAvailable(
                    "state snapshot is incomplete".into(),
                ));
            }
            Ok(neutrin0_trie::Trie::with_source(
                root,
                std::sync::Arc::new(super::StagedObjects(db.read_handle())),
            ))
        })
    }
}
