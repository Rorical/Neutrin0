//! Reference-counted execution state in the content-addressed columns.
//!
//! Trie nodes and values keep their `TrieNodes` / `StateValues` rows, keyed
//! by content hash. `StateRefs` counts the references that reach each entry:
//! one per edge from a stored node (a leaf's edge to its value included) and
//! one per pin. `StatePins` names the roots this node keeps readable: every
//! retained block's post-state, each snapshot lease and the live
//! identity-sanctions trie. Pinning a trie writes only the entries the store
//! lacks and counts their edges. Releasing a pin queues one reference in
//! `StateReleases`; bounded slices apply queued releases, delete an entry once
//! its count reaches zero and queue its children. Nothing loads the state
//! columns whole, and collection costs what it frees. A downloaded snapshot
//! enters the same way, a bounded slice at a time (`state_install`).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use neutrin0_primitives::{Hash, ZERO_HASH};
use neutrin0_storage::{Batch, Column, Database, ReadHandle, decode_count};
use neutrin0_trie::{Node, NodeSource, Trie};

use super::{ChainStore, StoreError};

mod access;

pub(super) const NODE: u8 = 0;
const VALUE: u8 = 1;

/// Why a state root stays readable. Each pin holds one reference to its root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "Re-exported crate-wide by the store module."
)]
pub(crate) enum StatePin {
    /// The post-state of a retained block.
    Block(Hash),
    /// A snapshot lease for bootstrapping peers.
    Lease(Hash),
    /// The live permanent identity-sanctions trie.
    Sanctions,
    /// The root at this position of a snapshot being installed, until its
    /// owner adopts or releases it.
    Install(u8),
}

impl StatePin {
    pub(super) fn key(self) -> Vec<u8> {
        match self {
            Self::Block(hash) => [b"b".as_slice(), &hash].concat(),
            Self::Lease(root) => [b"l".as_slice(), &root].concat(),
            Self::Sanctions => b"s".to_vec(),
            Self::Install(index) => vec![b'i', index],
        }
    }
}

fn ref_key(kind: u8, hash: &Hash) -> [u8; 33] {
    let mut key = [0; 33];
    key[0] = kind;
    key[1..].copy_from_slice(hash);
    key
}

/// Persisted state read through the database's live reader. A failed read
/// is a missing entry, which every trie traversal reports as unavailable state.
struct StoredState(Arc<dyn ReadHandle>);

impl fmt::Debug for StoredState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoredState")
    }
}

impl NodeSource for StoredState {
    fn node(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.0.get(Column::TrieNodes, hash).ok().flatten()
    }

    fn value(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.0.get(Column::StateValues, hash).ok().flatten()
    }
}

/// Reference changes staged into one batch. A count is the stored count plus
/// this writer's own changes, so entries staged earlier in the batch count as
/// present for later calls.
#[expect(
    clippy::redundant_pub_crate,
    reason = "Returned crate-wide by `ChainStore::state_writer`."
)]
pub(crate) struct StateWriter<'a, DB: Database> {
    store: &'a ChainStore<DB>,
    batch: &'a mut Batch,
    counts: BTreeMap<[u8; 33], i64>,
    pins: BTreeMap<Vec<u8>, Option<Hash>>,
}

impl<DB: Database> StateWriter<'_, DB> {
    /// Point `pin` at `state`'s root: write the entries the store lacks, count
    /// every new reference and queue the release of the root it held before.
    ///
    /// # Errors
    /// An entry the store lacks must be in `state`'s own maps; otherwise the
    /// state is incomplete and nothing is pinned.
    pub(crate) fn pin(&mut self, pin: StatePin, state: &Trie) -> Result<(), StoreError<DB::Error>> {
        let root = state.root();
        let previous = self.pinned(pin)?;
        if previous == Some(root) {
            return Ok(());
        }
        self.reference_node(root, state)?;
        self.batch.put(Column::StatePins, pin.key(), root);
        self.pins.insert(pin.key(), Some(root));
        if let Some(previous) = previous {
            self.queue_release(NODE, previous);
        }
        Ok(())
    }

    /// Drop `pin`, queueing the release of its root. An absent pin is a no-op.
    pub(crate) fn unpin(&mut self, pin: StatePin) -> Result<(), StoreError<DB::Error>> {
        if let Some(root) = self.pinned(pin)? {
            self.batch.delete(Column::StatePins, pin.key());
            self.pins.insert(pin.key(), None);
            self.queue_release(NODE, root);
        }
        Ok(())
    }

    fn pinned(&self, pin: StatePin) -> Result<Option<Hash>, StoreError<DB::Error>> {
        let key = pin.key();
        if let Some(staged) = self.pins.get(&key) {
            return Ok(*staged);
        }
        self.store
            .db
            .get(Column::StatePins, &key)
            .map_err(StoreError::Database)?
            .map(|bytes| {
                Hash::try_from(bytes.as_slice()).map_err(|_| StoreError::Corrupt("state pin root"))
            })
            .transpose()
    }

    fn count(&self, key: &[u8; 33]) -> Result<i64, StoreError<DB::Error>> {
        Ok(stored_count(self.store, key)? + self.counts.get(key).copied().unwrap_or(0))
    }

    fn add_reference(&mut self, key: [u8; 33]) {
        self.batch.add_count(Column::StateRefs, key.to_vec(), 1);
        *self.counts.entry(key).or_default() += 1;
    }

    /// Count one more reference to the node `root`, writing it and counting its
    /// edges first when the store lacks it. Present nodes already count theirs.
    fn reference_node(&mut self, root: Hash, state: &Trie) -> Result<(), StoreError<DB::Error>> {
        self.reference_pending(&mut vec![root], usize::MAX, &Overlay(state))
    }

    /// Count the node edges in `pending`, depth first, until it is empty or
    /// `limit` edges are counted. A node the store lacks is read from
    /// `source`, written, and its own edges join `pending`, so what remains
    /// is exactly the edges still uncounted.
    pub(super) fn reference_pending(
        &mut self,
        pending: &mut Vec<Hash>,
        limit: usize,
        source: &dyn NodeSource,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut counted = 0;
        while counted < limit {
            let Some(hash) = pending.pop() else {
                break;
            };
            if hash == ZERO_HASH {
                continue;
            }
            counted += 1;
            let key = ref_key(NODE, &hash);
            let present = self.count(&key)? > 0;
            self.add_reference(key);
            if present {
                continue;
            }
            let bytes = source
                .node(&hash)
                .ok_or(StoreError::Corrupt("state node to persist is missing"))?;
            match decode_node(&bytes)? {
                Node::Leaf { value_hash, .. } => self.reference_value(value_hash, source)?,
                Node::Branch { left, right } => pending.extend([left, right]),
                Node::Extension { child, .. } => pending.push(child),
            }
            self.batch.put(Column::TrieNodes, hash, bytes);
        }
        Ok(())
    }

    fn reference_value(
        &mut self,
        hash: Hash,
        source: &dyn NodeSource,
    ) -> Result<(), StoreError<DB::Error>> {
        let key = ref_key(VALUE, &hash);
        let present = self.count(&key)? > 0;
        self.add_reference(key);
        if !present {
            let bytes = source
                .value(&hash)
                .ok_or(StoreError::Corrupt("state value to persist is missing"))?;
            self.batch.put(Column::StateValues, hash, bytes);
        }
        Ok(())
    }

    fn queue_release(&mut self, kind: u8, hash: Hash) {
        queue_release(self.batch, kind, hash);
    }
}

/// The entries a trie produced and has not persisted yet, read from its own
/// maps only: an entry the store lacks must be among them.
#[derive(Debug)]
struct Overlay<'a>(&'a Trie);

impl NodeSource for Overlay<'_> {
    fn node(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.0.overlay_node(hash).map(<[u8]>::to_vec)
    }

    fn value(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.0.overlay_value(hash).map(<[u8]>::to_vec)
    }
}

pub(super) fn queue_release(batch: &mut Batch, kind: u8, hash: Hash) {
    if hash != ZERO_HASH {
        batch.add_count(Column::StateReleases, ref_key(kind, &hash).to_vec(), 1);
    }
}

fn decode_node<E>(bytes: &[u8]) -> Result<Node, StoreError<E>> {
    Node::decode(bytes).map_err(|_| StoreError::Corrupt("state node encoding"))
}

fn stored_count<DB: Database>(
    store: &ChainStore<DB>,
    key: &[u8],
) -> Result<i64, StoreError<DB::Error>> {
    store
        .db
        .get(Column::StateRefs, key)
        .map_err(StoreError::Database)?
        .map_or(Ok(0), |bytes| {
            decode_count(&bytes).ok_or(StoreError::Corrupt("state reference count"))
        })
}
