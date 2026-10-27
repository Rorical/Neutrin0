//! Point reads: key lookup, key enumeration and content-addressed fetches.

use alloc::vec;
use alloc::vec::Vec;

use neutrin0_primitives::{Hash, ZERO_HASH};

use crate::bits::BitPath;
use crate::error::TrieError;
use crate::hasher::Hasher;
use crate::node::Node;

use super::Trie;

impl<H: Hasher> Trie<H> {
    /// Read the value bytes for `key`. Returns `Ok(None)` for keys not in
    /// the trie.
    ///
    /// # Errors
    /// Returns [`TrieError::MissingRetainedEntry`] when a node on the path,
    /// or the value of the leaf holding `key`, is missing from the store, and
    /// a decode error for malformed node bytes. A partial trie that omits the
    /// value of a present key must not read it as absent: the SP1 Guest
    /// aborts on this error instead of proving a forged absence, and a host
    /// treats it as unavailable state.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, TrieError> {
        let path = BitPath::for_key(key);
        let mut current = self.root;
        let mut consumed: u32 = 0;
        loop {
            if current == ZERO_HASH {
                return Ok(None);
            }
            let node = self.fetch_node(&current)?;
            match node {
                Node::Leaf {
                    key_suffix,
                    value_hash,
                } => {
                    let remaining = path.suffix(consumed);
                    if remaining == key_suffix {
                        return self.fetch_value(&value_hash).map(Some);
                    }
                    return Ok(None);
                }
                Node::Branch { left, right } => {
                    if consumed >= path.bit_len() {
                        return Ok(None);
                    }
                    let bit = path.bit(consumed);
                    consumed += 1;
                    current = if bit { right } else { left };
                }
                Node::Extension { prefix, child } => {
                    let len = prefix.bit_len();
                    if consumed + len > path.bit_len() {
                        return Ok(None);
                    }
                    let segment = path.suffix(consumed).prefix(len);
                    if segment != prefix {
                        return Ok(None);
                    }
                    consumed += len;
                    current = child;
                }
            }
        }
    }

    /// Return every raw runtime key currently present in the trie.
    ///
    /// Keys are reconstructed from leaf paths by removing the trie-internal
    /// `u32::LE length || key` prefix used by [`Trie::insert`]. The returned
    /// list is sorted lexicographically so callers can implement cursored
    /// state iteration without depending on the Patricia node shape.
    ///
    /// # Errors
    /// Returns the first missing or malformed node the walk reaches.
    pub fn keys(&self) -> Result<Vec<Vec<u8>>, TrieError> {
        let mut keys = Vec::new();
        let mut prefix = Vec::new();
        self.collect_keys(self.root, &mut prefix, &mut keys)?;
        keys.sort();
        Ok(keys)
    }

    /// Look up the canonical encoded bytes of a node by hash, in this trie
    /// and then its source. Returns `None` for hashes neither holds.
    ///
    /// # Errors
    /// Returns [`TrieError::RetainedHashMismatch`] when the source holds other
    /// bytes under `hash`.
    pub fn node_bytes(&self, hash: &Hash) -> Result<Option<Vec<u8>>, TrieError> {
        if let Some(bytes) = self.nodes.get(hash) {
            return Ok(Some(bytes.clone()));
        }
        #[cfg(feature = "store")]
        if let Some(bytes) = self.source_node(hash)? {
            return Ok(Some(bytes));
        }
        Ok(None)
    }

    /// Look up the canonical bytes of a value by hash, in this trie and then
    /// its source.
    ///
    /// # Errors
    /// Returns [`TrieError::RetainedHashMismatch`] when the source holds other
    /// bytes under `hash`.
    pub fn value_bytes(&self, hash: &Hash) -> Result<Option<Vec<u8>>, TrieError> {
        if let Some(bytes) = self.values.get(hash) {
            return Ok(Some(bytes.clone()));
        }
        #[cfg(feature = "store")]
        if let Some(bytes) = self.source_value(hash)? {
            return Ok(Some(bytes));
        }
        Ok(None)
    }

    /// The node stored under `hash`: a reachable hash that is absent or
    /// malformed is an error, never a panic, so an incomplete store surfaces
    /// as unavailable state to its caller.
    pub(super) fn fetch_node(&self, hash: &Hash) -> Result<Node, TrieError> {
        if let Some(bytes) = self.nodes.get(hash) {
            return Node::decode(bytes);
        }
        #[cfg(feature = "store")]
        if let Some(bytes) = self.source_node(hash)? {
            return Node::decode(&bytes);
        }
        Err(TrieError::MissingRetainedEntry)
    }

    /// The value stored under `hash`; absence is an error like a missing node.
    pub(super) fn fetch_value(&self, hash: &Hash) -> Result<Vec<u8>, TrieError> {
        self.value_bytes(hash)?
            .ok_or(TrieError::MissingRetainedEntry)
    }

    /// The source's node bytes under `hash`. Stored bytes must match their
    /// address: a corrupt store fails the read instead of answering from a
    /// different state.
    #[cfg(feature = "store")]
    fn source_node(&self, hash: &Hash) -> Result<Option<Vec<u8>>, TrieError> {
        let Some(bytes) = self.source.as_ref().and_then(|source| source.node(hash)) else {
            return Ok(None);
        };
        if H::hash_node(&bytes) != *hash {
            return Err(TrieError::RetainedHashMismatch);
        }
        Ok(Some(bytes))
    }

    /// The source's value bytes under `hash`, checked like [`Self::source_node`].
    #[cfg(feature = "store")]
    fn source_value(&self, hash: &Hash) -> Result<Option<Vec<u8>>, TrieError> {
        let Some(bytes) = self.source.as_ref().and_then(|source| source.value(hash)) else {
            return Ok(None);
        };
        if H::hash_value(&bytes) != *hash {
            return Err(TrieError::RetainedHashMismatch);
        }
        Ok(Some(bytes))
    }

    fn collect_keys(
        &self,
        hash: Hash,
        prefix: &mut Vec<bool>,
        keys: &mut Vec<Vec<u8>>,
    ) -> Result<(), TrieError> {
        if hash == ZERO_HASH {
            return Ok(());
        }
        match self.fetch_node(&hash)? {
            Node::Leaf { key_suffix, .. } => {
                let original_len = prefix.len();
                append_bits(prefix, &key_suffix);
                if let Some(key) = decode_raw_key(prefix) {
                    keys.push(key);
                }
                prefix.truncate(original_len);
            }
            Node::Branch { left, right } => {
                prefix.push(false);
                self.collect_keys(left, prefix, keys)?;
                prefix.pop();
                prefix.push(true);
                self.collect_keys(right, prefix, keys)?;
                prefix.pop();
            }
            Node::Extension { prefix: ext, child } => {
                let original_len = prefix.len();
                append_bits(prefix, &ext);
                self.collect_keys(child, prefix, keys)?;
                prefix.truncate(original_len);
            }
        }
        Ok(())
    }
}

fn append_bits(out: &mut Vec<bool>, path: &BitPath) {
    for index in 0..path.bit_len() {
        out.push(path.bit(index));
    }
}

fn decode_raw_key(bits: &[bool]) -> Option<Vec<u8>> {
    if bits.len() < 32 || !bits.len().is_multiple_of(8) {
        return None;
    }
    let mut encoded = vec![0_u8; bits.len() / 8];
    for (index, bit) in bits.iter().copied().enumerate() {
        if bit {
            encoded[index / 8] |= 1 << (7 - (index % 8));
        }
    }
    let key_len = usize::try_from(u32::from_le_bytes(encoded[..4].try_into().ok()?)).ok()?;
    if encoded.len() != 4_usize.checked_add(key_len)? {
        return None;
    }
    Some(encoded[4..].to_vec())
}

/// Read `key` under `root` from content-addressed node and value stores,
/// fetching only the nodes on the key's path instead of materialising the
/// whole trie. The walk is the one [`Trie::get`] performs.
///
/// # Errors
/// Returns [`TrieError::MissingRetainedEntry`] when a node or value the walk
/// reaches is absent, or the decode error of a malformed node.
pub fn lookup_persisted(
    root: Hash,
    key: &[u8],
    mut node: impl FnMut(&Hash) -> Option<Vec<u8>>,
    mut value: impl FnMut(&Hash) -> Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>, TrieError> {
    let path = BitPath::for_key(key);
    let mut current = root;
    let mut consumed: u32 = 0;
    loop {
        if current == ZERO_HASH {
            return Ok(None);
        }
        let bytes = node(&current).ok_or(TrieError::MissingRetainedEntry)?;
        match Node::decode(&bytes)? {
            Node::Leaf {
                key_suffix,
                value_hash,
            } => {
                if path.suffix(consumed) != key_suffix {
                    return Ok(None);
                }
                return value(&value_hash)
                    .map(Some)
                    .ok_or(TrieError::MissingRetainedEntry);
            }
            Node::Branch { left, right } => {
                if consumed >= path.bit_len() {
                    return Ok(None);
                }
                let bit = path.bit(consumed);
                consumed += 1;
                current = if bit { right } else { left };
            }
            Node::Extension { prefix, child } => {
                let len = prefix.bit_len();
                if consumed + len > path.bit_len() || path.suffix(consumed).prefix(len) != prefix {
                    return Ok(None);
                }
                consumed += len;
                current = child;
            }
        }
    }
}
