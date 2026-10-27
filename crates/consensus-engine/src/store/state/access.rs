//! The store's access to persisted state: staged reference writers,
//! read-through tries, pin release and bounded collection of released entries.

use std::collections::BTreeMap;
use std::sync::Arc;

use neutrin0_primitives::{Hash, ZERO_HASH};
use neutrin0_storage::{Batch, BatchOp, Column, Database, decode_count};
use neutrin0_trie::{Node, NodeSource, Trie};

use super::{NODE, StateWriter, StoredState, VALUE, decode_node, queue_release, stored_count};
use crate::store::{ChainStore, StoreError};

impl<DB: Database> ChainStore<DB> {
    /// Stage reference changes into `batch`. Changes an earlier writer staged
    /// into the same batch count, so writers compose in sequence.
    pub(crate) fn state_writer<'a>(&'a self, batch: &'a mut Batch) -> StateWriter<'a, DB> {
        let mut counts = BTreeMap::new();
        let mut pins = BTreeMap::new();
        for op in batch.operations() {
            match op {
                BatchOp::AddCount {
                    column: Column::StateRefs,
                    key,
                    delta,
                } => {
                    if let Ok(key) = <[u8; 33]>::try_from(key.as_slice()) {
                        *counts.entry(key).or_default() += delta;
                    }
                }
                BatchOp::Put {
                    column: Column::StatePins,
                    key,
                    value,
                } => {
                    pins.insert(key.clone(), Hash::try_from(value.as_slice()).ok());
                }
                BatchOp::Delete {
                    column: Column::StatePins,
                    key,
                } => {
                    pins.insert(key.clone(), None);
                }
                _ => {}
            }
        }
        StateWriter {
            store: self,
            batch,
            counts,
            pins,
        }
    }

    /// Stage the release of every pin but an installation's: all the state
    /// this node kept readable, which a bootstrap replaces.
    pub(in crate::store) fn release_chain_pins_batch(
        &self,
        batch: &mut Batch,
    ) -> Result<(), StoreError<DB::Error>> {
        let pins = self
            .db
            .entries_from(Column::StatePins, &[], usize::MAX)
            .map_err(StoreError::Database)?;
        for (key, root) in pins {
            if key.first() == Some(&b'i') {
                continue;
            }
            let root = Hash::try_from(root.as_slice())
                .map_err(|_| StoreError::Corrupt("state pin root"))?;
            batch.delete(Column::StatePins, key);
            queue_release(batch, NODE, root);
        }
        Ok(())
    }

    /// Read-through source of this store's persisted state.
    #[must_use]
    pub fn state_source(&self) -> Arc<dyn NodeSource> {
        Arc::new(StoredState(self.db.read_handle()))
    }

    /// The persisted state under `root`, read on demand.
    #[must_use]
    pub fn state_at(&self, root: Hash) -> Trie {
        Trie::with_source(root, self.state_source())
    }

    /// Whether the node `root` is stored; the empty root always is.
    ///
    /// # Errors
    /// Reports database failures.
    pub fn has_state(&self, root: Hash) -> Result<bool, StoreError<DB::Error>> {
        if root == ZERO_HASH {
            return Ok(true);
        }
        Ok(self
            .db
            .get(Column::TrieNodes, &root)
            .map_err(StoreError::Database)?
            .is_some())
    }

    /// Apply up to `limit` queued reference releases in one batch. A count that
    /// reaches zero deletes its entry and queues the references the entry held.
    /// Returns whether no release was queued.
    ///
    /// # Errors
    /// A malformed queue entry, an underflowing count or a counted node that is
    /// missing reports corruption and changes nothing.
    pub fn collect_state_slice(&mut self, limit: usize) -> Result<bool, StoreError<DB::Error>> {
        let queued = self
            .db
            .entries_from(Column::StateReleases, &[], limit)
            .map_err(StoreError::Database)?;
        if queued.is_empty() {
            return Ok(true);
        }
        let mut batch = Batch::new();
        // Take every entry first: a child queued below may share a key with one.
        for (key, _) in &queued {
            batch.delete(Column::StateReleases, key.clone());
        }
        for (key, amount) in queued {
            let released = decode_count(&amount)
                .filter(|amount| *amount > 0)
                .ok_or(StoreError::Corrupt("queued state release"))?;
            let (&kind, hash) = key
                .split_first()
                .ok_or(StoreError::Corrupt("queued state release key"))?;
            let hash = Hash::try_from(hash)
                .map_err(|_| StoreError::Corrupt("queued state release key"))?;
            // Each count has exactly one queue key, so no earlier entry in this
            // slice changed it.
            let remaining = stored_count(self, &key)? - released;
            if remaining < 0 {
                return Err(StoreError::Corrupt("state reference count underflow"));
            }
            if remaining > 0 {
                batch.add_count(Column::StateRefs, key, -released);
                continue;
            }
            batch.delete(Column::StateRefs, key);
            match kind {
                VALUE => batch.delete(Column::StateValues, hash),
                NODE => {
                    let bytes = self
                        .db
                        .get(Column::TrieNodes, &hash)
                        .map_err(StoreError::Database)?
                        .ok_or(StoreError::Corrupt("counted state node is missing"))?;
                    batch.delete(Column::TrieNodes, hash);
                    match decode_node(&bytes)? {
                        Node::Leaf { value_hash, .. } => {
                            queue_release(&mut batch, VALUE, value_hash);
                        }
                        Node::Branch { left, right } => {
                            queue_release(&mut batch, NODE, left);
                            queue_release(&mut batch, NODE, right);
                        }
                        Node::Extension { child, .. } => queue_release(&mut batch, NODE, child),
                    }
                }
                _ => return Err(StoreError::Corrupt("queued state release kind")),
            }
        }
        self.write_observed_batch(batch, false)?;
        Ok(false)
    }
}
