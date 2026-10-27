//! In-memory binary sparse Merkle trie with prefix compression.
//!
//! See `docs/design/04-state-and-storage.md` for the protocol-level
//! design. This module holds an in-memory node overlay, an optional
//! read-through `NodeSource` and full read/write/proof support.
//! Persistent storage and pruning live in `neutrin0-storage` and the
//! consensus engine; this crate stays no_std + alloc and depends only on
//! `neutrin0-primitives`.
//!
//! # Constraints
//!
//! * Raw runtime keys are length-prefixed before they become trie bit
//!   paths, so arbitrary byte keys are supported, including pairs where
//!   one raw key is a prefix of another.
//! * Empty values are allowed; they hash to a well-defined value via
//!   [`Hasher::hash_value`].
//! * The empty trie has root [`crate::EMPTY_TRIE_ROOT`] (`[0; 32]`).

mod reachability;
mod read;
mod witness;
mod write;

use alloc::collections::BTreeMap;
#[cfg(feature = "store")]
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;

use neutrin0_primitives::{Hash, ZERO_HASH};

use crate::hasher::Hasher;
use crate::poseidon2::Poseidon2Hasher;

pub use read::lookup_persisted;

/// Read-through source of the content-addressed nodes and values a [`Trie`]
/// does not hold itself: the host's persistent state store.
///
/// A source never changes what a hash denotes; an entry it cannot provide,
/// for whatever reason, reads as missing and surfaces as unavailable state.
#[cfg(feature = "store")]
pub trait NodeSource: core::fmt::Debug + Send + Sync {
    /// Encoded node stored under `hash`.
    fn node(&self, hash: &Hash) -> Option<Vec<u8>>;
    /// Value bytes stored under `hash`.
    fn value(&self, hash: &Hash) -> Option<Vec<u8>>;
}

/// A trie serves what it holds or reads through, so a snapshot held in
/// memory can stand in for a store.
#[cfg(feature = "store")]
impl<H: Hasher + core::fmt::Debug + Send + Sync> NodeSource for Trie<H> {
    fn node(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.node_bytes(hash).ok().flatten()
    }

    fn value(&self, hash: &Hash) -> Option<Vec<u8>> {
        self.value_bytes(hash).ok().flatten()
    }
}

/// Binary sparse Merkle trie parameterised by hash function.
///
/// Defaults to [`Poseidon2Hasher`], the SP1-precompile-aligned hash;
/// [`crate::Blake3Hasher`] is an alternative for generic trie consumers
/// and reference hash tests. The runtime always selects Poseidon2.
///
/// The trie buffers every newly produced node and value in
/// `pending_nodes` / `pending_values` so callers wanting persistence
/// (the consensus engine) can drain just the deltas after each block.
/// Drained entries are not removed from the in-memory map; the buffers
/// only describe what is *new since the last drain*, mirroring the
/// content-addressed RocksDB columns the engine writes them to.
#[derive(Clone, Debug)]
pub struct Trie<H: Hasher = Poseidon2Hasher> {
    pub(crate) nodes: BTreeMap<Hash, Vec<u8>>,
    pub(crate) values: BTreeMap<Hash, Vec<u8>>,
    pending_nodes: Vec<(Hash, Vec<u8>)>,
    pending_values: Vec<(Hash, Vec<u8>)>,
    pub(crate) root: Hash,
    /// Entries the maps above lack are read from here. The maps are then an
    /// overlay of what this trie produced since it was opened or cleared.
    #[cfg(feature = "store")]
    source: Option<Arc<dyn NodeSource>>,
    _phantom: PhantomData<H>,
}

impl<H: Hasher> Default for Trie<H> {
    fn default() -> Self {
        Self {
            nodes: BTreeMap::new(),
            values: BTreeMap::new(),
            pending_nodes: Vec::new(),
            pending_values: Vec::new(),
            root: ZERO_HASH,
            #[cfg(feature = "store")]
            source: None,
            _phantom: PhantomData,
        }
    }
}

impl<H: Hasher> Trie<H> {
    /// Build a fresh empty trie. Root is [`crate::EMPTY_TRIE_ROOT`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current trie root.
    #[must_use]
    pub const fn root(&self) -> Hash {
        self.root
    }

    /// Number of distinct nodes currently retained.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of distinct values currently retained.
    #[must_use]
    pub fn value_count(&self) -> usize {
        self.values.len()
    }

    /// Iterate content-addressed nodes without copying the trie.
    pub fn node_entries(&self) -> impl Iterator<Item = (Hash, &[u8])> {
        self.nodes
            .iter()
            .map(|(hash, bytes)| (*hash, bytes.as_slice()))
    }

    /// Iterate content-addressed values without copying the trie.
    pub fn value_entries(&self) -> impl Iterator<Item = (Hash, &[u8])> {
        self.values
            .iter()
            .map(|(hash, bytes)| (*hash, bytes.as_slice()))
    }

    /// Drain every trie-node `(hash, bytes)` pair produced since the
    /// previous call.
    ///
    /// Used by the consensus engine to persist the delta into the
    /// `TrieNodes` storage column without re-writing the entire
    /// content-addressed node store on every block.
    pub fn drain_pending_nodes(&mut self) -> Vec<(Hash, Vec<u8>)> {
        core::mem::take(&mut self.pending_nodes)
    }

    /// Drain every state-value `(hash, bytes)` pair newly inserted
    /// since the previous call. See [`Trie::drain_pending_nodes`] for
    /// rationale.
    pub fn drain_pending_values(&mut self) -> Vec<(Hash, Vec<u8>)> {
        core::mem::take(&mut self.pending_values)
    }

    /// Rebuild a trie from persisted state.
    ///
    /// `root` is the previously committed trie root; `nodes` and
    /// `values` are the full content-addressed contents of the
    /// `TrieNodes` and `StateValues` storage columns. No
    /// `pending_nodes` / `pending_values` are recorded because the
    /// persisted entries are, by definition, already on disk.
    ///
    /// The constructor performs no integrity check beyond storing
    /// every pair as-is: a node whose hash does not match its bytes
    /// surfaces as [`crate::TrieError::MissingRetainedEntry`] from the next
    /// [`Trie::get`] / [`Trie::prove`] call that reaches it. Callers wanting
    /// strong guarantees should hash-check the pairs against their keys
    /// before passing them in.
    #[must_use]
    pub fn from_persisted(
        root: Hash,
        nodes: impl IntoIterator<Item = (Hash, Vec<u8>)>,
        values: impl IntoIterator<Item = (Hash, Vec<u8>)>,
    ) -> Self {
        Self {
            nodes: nodes.into_iter().collect(),
            values: values.into_iter().collect(),
            pending_nodes: Vec::new(),
            pending_values: Vec::new(),
            root,
            #[cfg(feature = "store")]
            source: None,
            _phantom: PhantomData,
        }
    }

    /// Open the state committed under `root` in `source`, reading only the
    /// nodes a traversal reaches. Cloning the result copies just its root and
    /// whatever it has produced since, never the stored state.
    #[cfg(feature = "store")]
    #[must_use]
    pub fn with_source(root: Hash, source: Arc<dyn NodeSource>) -> Self {
        Self {
            source: Some(source),
            ..Self::from_persisted(root, [], [])
        }
    }

    /// Node bytes this trie produced or was built with, without consulting a
    /// source: what a persisting owner still has to write.
    #[must_use]
    pub fn overlay_node(&self, hash: &Hash) -> Option<&[u8]> {
        self.nodes.get(hash).map(Vec::as_slice)
    }

    /// Value bytes this trie produced or was built with, without consulting a
    /// source.
    #[must_use]
    pub fn overlay_value(&self, hash: &Hash) -> Option<&[u8]> {
        self.values.get(hash).map(Vec::as_slice)
    }
}

#[cfg(test)]
mod tests;
