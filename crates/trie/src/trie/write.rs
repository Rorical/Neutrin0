//! Mutation: insertion, removal and the node collapses removal needs.

use alloc::collections::btree_map::Entry;
use alloc::vec::Vec;

use neutrin0_primitives::{Hash, ZERO_HASH};

use crate::bits::BitPath;
use crate::error::TrieError;
use crate::hasher::Hasher;
use crate::node::Node;

use super::Trie;

impl<H: Hasher> Trie<H> {
    /// Insert (or overwrite) the value at `key`. Returns
    /// [`TrieError::PrefixCollision`] if a malformed internal path
    /// would create a prefix-colliding pair. Normal byte-string keys
    /// are length-prefixed before insertion, so callers should not see
    /// that error in practice.
    pub fn insert(&mut self, key: &[u8], value: Vec<u8>) -> Result<(), TrieError> {
        let path = BitPath::for_key(key);
        let value_hash = H::hash_value(&value);
        match self.values.entry(value_hash) {
            Entry::Vacant(entry) => {
                entry.insert(value.clone());
                self.pending_values.push((value_hash, value));
            }
            Entry::Occupied(mut entry) => {
                entry.insert(value);
            }
        }
        let new_root = self.insert_at(self.root, &path, 0, value_hash)?;
        self.root = new_root;
        Ok(())
    }

    /// Remove the value at `key` and return it if present.
    ///
    /// # Errors
    /// Returns the first missing or malformed node the walk reaches; the trie
    /// is left unchanged.
    pub fn remove(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, TrieError> {
        let path = BitPath::for_key(key);
        let (new_root, removed) = self.remove_at(self.root, &path, 0)?;
        let removed = match removed {
            Some(value_hash) => Some(self.fetch_value(&value_hash)?),
            None => None,
        };
        self.root = new_root;
        Ok(removed)
    }

    fn store_node(&mut self, node: &Node) -> Hash {
        let encoded = node.encode();
        let hash = H::hash_node(&encoded);
        match self.nodes.entry(hash) {
            Entry::Vacant(entry) => {
                entry.insert(encoded.clone());
                self.pending_nodes.push((hash, encoded));
            }
            Entry::Occupied(mut entry) => {
                entry.insert(encoded);
            }
        }
        hash
    }

    /// Insert below `node_hash` the key whose remaining path is `path`'s bits
    /// from `offset` onward (`offset <= path.bit_len()`).
    fn insert_at(
        &mut self,
        node_hash: Hash,
        path: &BitPath,
        offset: u32,
        value_hash: Hash,
    ) -> Result<Hash, TrieError> {
        if node_hash == ZERO_HASH {
            return Ok(self.store_node(&Node::Leaf {
                key_suffix: path.suffix(offset),
                value_hash,
            }));
        }

        let node = self.fetch_node(&node_hash)?;
        match node {
            Node::Leaf {
                key_suffix,
                value_hash: existing_vh,
            } => self.insert_into_leaf(key_suffix, existing_vh, &path.suffix(offset), value_hash),
            Node::Branch { left, right } => {
                if offset >= path.bit_len() {
                    return Err(TrieError::PrefixCollision);
                }
                let bit = path.bit(offset);
                let (new_left, new_right) = if bit {
                    (left, self.insert_at(right, path, offset + 1, value_hash)?)
                } else {
                    (self.insert_at(left, path, offset + 1, value_hash)?, right)
                };
                Ok(self.store_node(&Node::Branch {
                    left: new_left,
                    right: new_right,
                }))
            }
            Node::Extension { prefix, child } => {
                self.insert_into_extension(prefix, child, path, offset, value_hash)
            }
        }
    }

    fn insert_into_leaf(
        &mut self,
        existing_suffix: BitPath,
        existing_vh: Hash,
        path: &BitPath,
        value_hash: Hash,
    ) -> Result<Hash, TrieError> {
        if existing_suffix.bit_len() == path.bit_len() && &existing_suffix == path {
            return Ok(self.store_node(&Node::Leaf {
                key_suffix: existing_suffix,
                value_hash,
            }));
        }
        let common = existing_suffix.common_prefix_len(path);
        if common == existing_suffix.bit_len() || common == path.bit_len() {
            return Err(TrieError::PrefixCollision);
        }

        let existing_bit = existing_suffix.bit(common);
        let existing_tail = existing_suffix.suffix(common + 1);
        let new_tail = path.suffix(common + 1);

        let existing_leaf_hash = self.store_node(&Node::Leaf {
            key_suffix: existing_tail,
            value_hash: existing_vh,
        });
        let new_leaf_hash = self.store_node(&Node::Leaf {
            key_suffix: new_tail,
            value_hash,
        });

        let branch = if existing_bit {
            Node::Branch {
                left: new_leaf_hash,
                right: existing_leaf_hash,
            }
        } else {
            Node::Branch {
                left: existing_leaf_hash,
                right: new_leaf_hash,
            }
        };
        let branch_hash = self.store_node(&branch);
        if common == 0 {
            Ok(branch_hash)
        } else {
            Ok(self.store_node(&Node::Extension {
                prefix: path.prefix(common),
                child: branch_hash,
            }))
        }
    }

    /// [`Trie::insert_at`] for an extension node; `path` and `offset` as there.
    fn insert_into_extension(
        &mut self,
        prefix: BitPath,
        child: Hash,
        path: &BitPath,
        offset: u32,
        value_hash: Hash,
    ) -> Result<Hash, TrieError> {
        if path.matches_at(offset, &prefix) {
            let rest = offset + prefix.bit_len();
            if rest == path.bit_len() {
                return Err(TrieError::PrefixCollision);
            }
            let new_child = self.insert_at(child, path, rest, value_hash)?;
            return Ok(self.store_node(&Node::Extension {
                prefix,
                child: new_child,
            }));
        }
        // The new key diverges inside the prefix; split it on the remaining path.
        let path = &path.suffix(offset);
        let common = prefix.common_prefix_len(path);
        if common == path.bit_len() {
            return Err(TrieError::PrefixCollision);
        }

        let existing_bit = prefix.bit(common);
        let existing_tail = prefix.suffix(common + 1);
        let new_tail = path.suffix(common + 1);

        let existing_side_hash = if existing_tail.is_empty() {
            child
        } else {
            self.store_node(&Node::Extension {
                prefix: existing_tail,
                child,
            })
        };
        let new_leaf_hash = self.store_node(&Node::Leaf {
            key_suffix: new_tail,
            value_hash,
        });

        let branch = if existing_bit {
            Node::Branch {
                left: new_leaf_hash,
                right: existing_side_hash,
            }
        } else {
            Node::Branch {
                left: existing_side_hash,
                right: new_leaf_hash,
            }
        };
        let branch_hash = self.store_node(&branch);

        if common == 0 {
            Ok(branch_hash)
        } else {
            Ok(self.store_node(&Node::Extension {
                prefix: path.prefix(common),
                child: branch_hash,
            }))
        }
    }

    /// Remove below `node_hash` the key whose remaining path is `path`'s bits
    /// from `offset` onward (`offset <= path.bit_len()`).
    fn remove_at(
        &mut self,
        node_hash: Hash,
        path: &BitPath,
        offset: u32,
    ) -> Result<(Hash, Option<Hash>), TrieError> {
        if node_hash == ZERO_HASH {
            return Ok((ZERO_HASH, None));
        }
        let node = self.fetch_node(&node_hash)?;
        match node {
            Node::Leaf {
                key_suffix,
                value_hash,
            } => {
                if key_suffix.bit_len() == path.bit_len() - offset
                    && path.matches_at(offset, &key_suffix)
                {
                    Ok((ZERO_HASH, Some(value_hash)))
                } else {
                    Ok((node_hash, None))
                }
            }
            Node::Branch { left, right } => {
                if offset >= path.bit_len() {
                    return Ok((node_hash, None));
                }
                let bit = path.bit(offset);
                let (new_child, removed) = if bit {
                    self.remove_at(right, path, offset + 1)?
                } else {
                    self.remove_at(left, path, offset + 1)?
                };
                if removed.is_none() {
                    return Ok((node_hash, None));
                }
                let (new_left, new_right) = if bit {
                    (left, new_child)
                } else {
                    (new_child, right)
                };

                let collapsed_hash = self.collapse_branch(new_left, new_right)?;
                Ok((collapsed_hash, removed))
            }
            Node::Extension { prefix, child } => {
                if !path.matches_at(offset, &prefix) {
                    return Ok((node_hash, None));
                }
                let rest = offset + prefix.bit_len();
                let (new_child, removed) = self.remove_at(child, path, rest)?;
                if removed.is_none() {
                    return Ok((node_hash, None));
                }
                let collapsed_hash = self.collapse_extension(prefix, new_child)?;
                Ok((collapsed_hash, removed))
            }
        }
    }

    fn collapse_branch(&mut self, left: Hash, right: Hash) -> Result<Hash, TrieError> {
        Ok(match (left == ZERO_HASH, right == ZERO_HASH) {
            (true, true) => ZERO_HASH,
            (false, true) => self.absorb_into_parent(left, false)?,
            (true, false) => self.absorb_into_parent(right, true)?,
            (false, false) => self.store_node(&Node::Branch { left, right }),
        })
    }

    fn collapse_extension(&mut self, prefix: BitPath, child: Hash) -> Result<Hash, TrieError> {
        if child == ZERO_HASH {
            return Ok(ZERO_HASH);
        }
        let child_node = self.fetch_node(&child)?;
        Ok(match child_node {
            Node::Leaf {
                key_suffix,
                value_hash,
            } => {
                let combined_path = prefix.concat(&key_suffix);
                self.store_node(&Node::Leaf {
                    key_suffix: combined_path,
                    value_hash,
                })
            }
            Node::Extension {
                prefix: child_prefix,
                child: grandchild,
            } => {
                let combined_prefix = prefix.concat(&child_prefix);
                self.store_node(&Node::Extension {
                    prefix: combined_prefix,
                    child: grandchild,
                })
            }
            Node::Branch { .. } => self.store_node(&Node::Extension { prefix, child }),
        })
    }

    fn absorb_into_parent(
        &mut self,
        surviving_child: Hash,
        child_bit: bool,
    ) -> Result<Hash, TrieError> {
        let surviving_node = self.fetch_node(&surviving_child)?;
        let prefix_bits = BitPath::single(child_bit);

        Ok(match surviving_node {
            Node::Leaf {
                key_suffix,
                value_hash,
            } => {
                let combined = prefix_bits.concat(&key_suffix);
                self.store_node(&Node::Leaf {
                    key_suffix: combined,
                    value_hash,
                })
            }
            Node::Extension {
                prefix: child_prefix,
                child: grandchild,
            } => {
                let combined = prefix_bits.concat(&child_prefix);
                self.store_node(&Node::Extension {
                    prefix: combined,
                    child: grandchild,
                })
            }
            Node::Branch { .. } => self.store_node(&Node::Extension {
                prefix: prefix_bits,
                child: surviving_child,
            }),
        })
    }
}
