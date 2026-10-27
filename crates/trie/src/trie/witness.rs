//! Merkle witnesses: inclusion/exclusion proofs and path-node collection.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use neutrin0_primitives::{Hash, ZERO_HASH};

use crate::bits::BitPath;
use crate::error::TrieError;
use crate::hasher::Hasher;
use crate::node::Node;
use crate::proof::{Proof, ProofStep, ProofTerminal};

use super::Trie;

impl<H: Hasher> Trie<H> {
    /// Build an inclusion or exclusion proof for `key` against the
    /// current root.
    ///
    /// # Errors
    /// Returns the first missing or malformed node the walk reaches.
    pub fn prove(&self, key: &[u8]) -> Result<Proof, TrieError> {
        let path = BitPath::for_key(key);
        let mut steps = Vec::new();
        let mut current = self.root;
        let mut consumed: u32 = 0;
        loop {
            if current == ZERO_HASH {
                return Ok(Proof {
                    steps,
                    terminal: ProofTerminal::Empty,
                });
            }
            let node = self.fetch_node(&current)?;
            match node {
                Node::Leaf {
                    key_suffix,
                    value_hash,
                } => {
                    return Ok(Proof {
                        steps,
                        terminal: ProofTerminal::Leaf {
                            key_suffix,
                            value_hash,
                        },
                    });
                }
                Node::Branch { left, right } => {
                    if consumed >= path.bit_len() {
                        // No more key bits left, but the trie demands
                        // we descend. With prefix-free keys this is
                        // unreachable; defensively terminate as empty.
                        return Ok(Proof {
                            steps,
                            terminal: ProofTerminal::Empty,
                        });
                    }
                    let bit = path.bit(consumed);
                    let (sibling, child) = if bit { (left, right) } else { (right, left) };
                    steps.push(ProofStep::Branch {
                        sibling,
                        descended_right: bit,
                    });
                    consumed += 1;
                    current = child;
                }
                Node::Extension { prefix, child } => {
                    let len = prefix.bit_len();
                    let remaining = path.suffix(consumed);
                    let common = prefix.common_prefix_len(&remaining);
                    if common == len {
                        steps.push(ProofStep::Extension { prefix });
                        consumed += len;
                        current = child;
                    } else {
                        return Ok(Proof {
                            steps,
                            terminal: ProofTerminal::DivergentExtension {
                                prefix,
                                child_hash: child,
                            },
                        });
                    }
                }
            }
        }
    }

    /// Walk the trie from root to the terminal for `key`, accumulating
    /// every visited node's `(hash, bytes)` into `out_nodes`, the
    /// terminal leaf's `(value_hash, value_bytes)` (when present) into
    /// `out_values`, and the sibling node at every on-path Branch
    /// into `out_nodes` as well.
    ///
    /// # Why siblings are included
    ///
    /// Reads and inserts only walk the path to `key`; siblings are
    /// referenced by hash and never fetched. Deletes are different:
    /// when a Branch loses one child to `ZERO_HASH`, the trie
    /// inspects the surviving sibling's node bytes via
    /// `absorb_into_parent` to decide whether to fold the parent
    /// away (Leaf/Extension siblings merge into the parent path;
    /// Branch siblings get re-wrapped in an Extension). That top-
    /// level inspection is the only sibling access the trie ever
    /// performs, so harvesting one node per on-path Branch is
    /// sufficient — we do not need the sibling's subtree.
    ///
    /// Sibling *values* are not collected: `absorb_into_parent`
    /// builds the merged node from `value_hash` alone and never
    /// reads the value bytes. Callers that also need to *read* the
    /// sibling's value should call `collect_path_nodes` on the
    /// sibling's key separately.
    ///
    /// Used by witness builders: the resulting subset is the minimum
    /// data needed for a `Trie::from_persisted` reconstruction that
    /// can read `key`, insert at `key`, and remove `key` (with the
    /// guest's `Trie::remove` walking the same path and consulting
    /// the same sibling for collapse decisions).
    ///
    /// Calling this method many times with disjoint keys is the
    /// standard way to assemble a Merkle witness covering the read /
    /// write / delete set of one block.
    ///
    /// # Errors
    /// Returns the first missing, malformed or misaddressed node the walk
    /// reaches, or a misaddressed value; entries collected before it stay in
    /// the output maps. A witness is built only from bytes that match their
    /// hashes, so a corrupt store fails here, not in the Guest.
    pub fn collect_path_nodes(
        &self,
        key: &[u8],
        out_nodes: &mut BTreeMap<Hash, Vec<u8>>,
        out_values: &mut BTreeMap<Hash, Vec<u8>>,
    ) -> Result<(), TrieError> {
        let path = BitPath::for_key(key);
        let mut current = self.root;
        let mut consumed: u32 = 0;
        loop {
            if current == ZERO_HASH {
                return Ok(());
            }
            let bytes = self
                .node_bytes(&current)?
                .ok_or(TrieError::MissingRetainedEntry)?;
            let node = Node::decode(&bytes)?;
            out_nodes.insert(current, bytes);
            match node {
                Node::Leaf { value_hash, .. } => {
                    if let Some(bytes) = self.value_bytes(&value_hash)? {
                        out_values.insert(value_hash, bytes);
                    }
                    return Ok(());
                }
                Node::Branch { left, right } => {
                    if consumed >= path.bit_len() {
                        return Ok(());
                    }
                    let bit = path.bit(consumed);
                    let (sibling, descended) = if bit { (left, right) } else { (right, left) };
                    // Harvest the sibling so a future `Trie::remove`
                    // in the partial trie can call
                    // `absorb_into_parent` without panicking on a
                    // missing node fetch.
                    if sibling != ZERO_HASH
                        && let Some(bytes) = self.node_bytes(&sibling)?
                    {
                        out_nodes.insert(sibling, bytes);
                    }
                    consumed += 1;
                    current = descended;
                }
                Node::Extension { prefix, child } => {
                    let len = prefix.bit_len();
                    if consumed + len > path.bit_len() {
                        return Ok(());
                    }
                    let segment = path.suffix(consumed).prefix(len);
                    if segment != prefix {
                        return Ok(());
                    }
                    consumed += len;
                    current = child;
                }
            }
        }
    }
}
