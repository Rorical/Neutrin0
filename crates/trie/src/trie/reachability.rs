//! Walks over what the root reaches: retention and detached copies.

#[cfg(feature = "store")]
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
#[cfg(feature = "store")]
use alloc::vec;

use neutrin0_primitives::{Hash, ZERO_HASH};

use crate::error::TrieError;
use crate::hasher::Hasher;
use crate::node::Node;

use super::Trie;

impl<H: Hasher> Trie<H> {
    /// Remove entries unreachable from the current root and the supplied roots.
    ///
    /// Every retained node and value is checked before any mutation. Missing or
    /// corrupt state leaves the trie unchanged. The caller must commit matching
    /// persistent deletions atomically before installing this pruned snapshot.
    pub fn retain_roots(&mut self, roots: &[Hash]) -> Result<(), TrieError> {
        let mut nodes = BTreeSet::new();
        let mut values = BTreeSet::new();
        let mut pending = roots.to_vec();
        pending.push(self.root);
        while let Some(hash) = pending.pop() {
            if hash == ZERO_HASH || !nodes.insert(hash) {
                continue;
            }
            let bytes = self
                .nodes
                .get(&hash)
                .ok_or(TrieError::MissingRetainedEntry)?;
            if H::hash_node(bytes) != hash {
                return Err(TrieError::RetainedHashMismatch);
            }
            match Node::decode(bytes)? {
                Node::Leaf { value_hash, .. } => {
                    if values.insert(value_hash) {
                        let value = self
                            .values
                            .get(&value_hash)
                            .ok_or(TrieError::MissingRetainedEntry)?;
                        if H::hash_value(value) != value_hash {
                            return Err(TrieError::RetainedHashMismatch);
                        }
                    }
                }
                Node::Branch { left, right } => pending.extend([left, right]),
                Node::Extension { child, .. } => pending.push(child),
            }
        }
        self.nodes.retain(|hash, _| nodes.contains(hash));
        self.values.retain(|hash, _| values.contains(hash));
        self.pending_nodes.retain(|(hash, _)| nodes.contains(hash));
        self.pending_values
            .retain(|(hash, _)| values.contains(hash));
        Ok(())
    }

    /// A self-contained copy holding every entry reachable from the root and
    /// no source. Its memory is the whole state's, so it suits snapshots of
    /// bounded size and test fixtures, never a node's live state.
    ///
    /// # Errors
    /// Returns [`TrieError::MissingRetainedEntry`] when a reachable entry is
    /// unavailable, [`TrieError::RetainedHashMismatch`] when the source holds
    /// other bytes under its hash, or the decode error of a malformed node.
    #[cfg(feature = "store")]
    pub fn detached(&self) -> Result<Self, TrieError> {
        let mut nodes = BTreeMap::new();
        let mut values = BTreeMap::new();
        let mut pending = vec![self.root];
        while let Some(hash) = pending.pop() {
            if hash == ZERO_HASH || nodes.contains_key(&hash) {
                continue;
            }
            let bytes = self
                .node_bytes(&hash)?
                .ok_or(TrieError::MissingRetainedEntry)?;
            match Node::decode(&bytes)? {
                Node::Leaf { value_hash, .. } => {
                    values.insert(value_hash, self.fetch_value(&value_hash)?);
                }
                Node::Branch { left, right } => pending.extend([left, right]),
                Node::Extension { child, .. } => pending.push(child),
            }
            nodes.insert(hash, bytes);
        }
        Ok(Self::from_persisted(self.root, nodes, values))
    }
}
