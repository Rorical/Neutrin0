//! Inclusion and exclusion proofs against a trie root.
//!
//! A proof is the sequence of structural decisions the trie made on the
//! way to the queried key, plus the terminal it reached. Verifying it
//! is two passes:
//!
//! 1. Walk the steps top-down with a cursor over the queried key's bits
//!    and check that the recorded branch sides and extension prefixes
//!    are consistent with the cursor.
//! 2. Recompute the terminal node's hash, then walk the steps in
//!    reverse, rebuilding each ancestor node from `(sibling,
//!    descended_right)` (for branches) or the recorded prefix (for
//!    extensions). The final hash must equal the expected root.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{Hash, ZERO_HASH};

use crate::bits::BitPath;
use crate::hasher::Hasher;
use crate::node::Node;

/// One structural decision recorded on the way from the root to the
/// terminal of a proof.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub enum ProofStep {
    /// A branch was descended. `sibling` is the hash of the subtree
    /// that was *not* taken; `descended_right` records whether the
    /// taken side was the `1`-bit child.
    Branch {
        /// Hash of the sibling subtree.
        sibling: Hash,
        /// `true` iff the proof descended into the right child.
        descended_right: bool,
    },
    /// An extension node was traversed in full. The verifier consumes
    /// `prefix.bit_len()` bits of the queried key and reconstructs
    /// the node from this prefix plus the child hash computed below
    /// it.
    Extension {
        /// Bits the queried key matched against the extension's
        /// stored prefix.
        prefix: BitPath,
    },
}

/// The terminal point a proof reached.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub enum ProofTerminal {
    /// The walk arrived at an empty subtree. Trivial exclusion.
    Empty,
    /// The walk arrived at a leaf. For inclusion, `key_suffix` must
    /// equal the queried key's remaining bits and `value_hash` must
    /// equal `Hasher::hash_value(value)`. For exclusion, `key_suffix`
    /// must differ from the remaining bits.
    Leaf {
        /// Stored key suffix on the leaf.
        key_suffix: BitPath,
        /// Stored value hash on the leaf.
        value_hash: Hash,
    },
    /// The walk arrived at an extension whose prefix diverges from the
    /// queried key. Always proves exclusion. `child_hash` is needed
    /// only to reconstruct the extension node's hash on the way up.
    DivergentExtension {
        /// Stored prefix on the extension.
        prefix: BitPath,
        /// Stored child hash on the extension.
        child_hash: Hash,
    },
}

/// A self-contained inclusion or exclusion proof.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    /// Decisions from root to terminal, in top-down order.
    pub steps: Vec<ProofStep>,
    /// The terminal node the walk reached.
    pub terminal: ProofTerminal,
}

/// Outcome of verifying a proof: either a proven value hash (inclusion)
/// or a proven absence (exclusion).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofOutcome {
    /// The proof showed `key` maps to the value whose hash is `value_hash`.
    Included {
        /// Hash of the included value bytes.
        value_hash: Hash,
    },
    /// The proof showed `key` is not in the trie.
    Excluded,
}

/// Reasons a proof can fail verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofError {
    /// A branch step's `descended_right` did not match the next bit of
    /// the queried key.
    BranchBitMismatch,
    /// An extension step's prefix did not match the queried key's bits
    /// at that position.
    ExtensionPrefixMismatch,
    /// The proof ran out of key bits before reaching its terminal.
    KeyTooShort,
    /// A leaf terminal claimed inclusion but the stored key suffix
    /// did not match the remaining queried key bits.
    LeafKeyMismatch,
    /// A leaf terminal matched the key, but its stored value hash did
    /// not match the caller-supplied value bytes.
    ValueHashMismatch,
    /// A `DivergentExtension` terminal's stored prefix actually does
    /// match the queried key, so it cannot prove exclusion.
    NonDivergentExtensionTerminal,
    /// The recomputed root did not equal the expected root.
    RootMismatch,
}

impl Proof {
    /// Verify against `expected_root` using `hasher`'s node hashing.
    /// Returns the outcome the proof attests to. Inclusion proofs are
    /// not paired with the expected value here; use
    /// [`Proof::verify_inclusion`] when that comparison is needed.
    pub fn verify<H: Hasher>(
        &self,
        expected_root: &Hash,
        key: &[u8],
    ) -> Result<ProofOutcome, ProofError> {
        let key_bits = BitPath::for_key(key);
        let consumed = self.check_step_bits(&key_bits)?;

        match &self.terminal {
            ProofTerminal::Empty => {
                let root = self.recompute_root::<H>(ZERO_HASH);
                if root == *expected_root {
                    Ok(ProofOutcome::Excluded)
                } else {
                    Err(ProofError::RootMismatch)
                }
            }
            ProofTerminal::Leaf {
                key_suffix,
                value_hash,
            } => {
                let remaining = key_bits.suffix(consumed);
                let leaf_hash = H::hash_node(
                    &Node::Leaf {
                        key_suffix: key_suffix.clone(),
                        value_hash: *value_hash,
                    }
                    .encode(),
                );
                let outcome = if leaves_match(key_suffix, &remaining) {
                    ProofOutcome::Included {
                        value_hash: *value_hash,
                    }
                } else {
                    ProofOutcome::Excluded
                };
                let root = self.recompute_root::<H>(leaf_hash);
                if root == *expected_root {
                    Ok(outcome)
                } else {
                    Err(ProofError::RootMismatch)
                }
            }
            ProofTerminal::DivergentExtension { prefix, child_hash } => {
                let remaining = key_bits.suffix(consumed);
                if extension_matches(prefix, &remaining) {
                    return Err(ProofError::NonDivergentExtensionTerminal);
                }
                let ext_hash = H::hash_node(
                    &Node::Extension {
                        prefix: prefix.clone(),
                        child: *child_hash,
                    }
                    .encode(),
                );
                let root = self.recompute_root::<H>(ext_hash);
                if root == *expected_root {
                    Ok(ProofOutcome::Excluded)
                } else {
                    Err(ProofError::RootMismatch)
                }
            }
        }
    }

    /// Convenience: verify the proof and confirm it includes `value` at
    /// `key` under `expected_root`.
    pub fn verify_inclusion<H: Hasher>(
        &self,
        expected_root: &Hash,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), ProofError> {
        match self.verify::<H>(expected_root, key)? {
            ProofOutcome::Included { value_hash } if value_hash == H::hash_value(value) => Ok(()),
            ProofOutcome::Included { .. } => Err(ProofError::ValueHashMismatch),
            ProofOutcome::Excluded => Err(ProofError::LeafKeyMismatch),
        }
    }

    /// Convenience: verify the proof and confirm it excludes `key`
    /// under `expected_root`.
    pub fn verify_exclusion<H: Hasher>(
        &self,
        expected_root: &Hash,
        key: &[u8],
    ) -> Result<(), ProofError> {
        match self.verify::<H>(expected_root, key)? {
            ProofOutcome::Excluded => Ok(()),
            ProofOutcome::Included { .. } => Err(ProofError::LeafKeyMismatch),
        }
    }

    fn check_step_bits(&self, key_bits: &BitPath) -> Result<u32, ProofError> {
        let mut consumed: u32 = 0;
        for step in &self.steps {
            match step {
                ProofStep::Branch {
                    descended_right, ..
                } => {
                    if consumed >= key_bits.bit_len() {
                        return Err(ProofError::KeyTooShort);
                    }
                    if key_bits.bit(consumed) != *descended_right {
                        return Err(ProofError::BranchBitMismatch);
                    }
                    consumed += 1;
                }
                ProofStep::Extension { prefix } => {
                    let len = prefix.bit_len();
                    let end = consumed.checked_add(len).ok_or(ProofError::KeyTooShort)?;
                    if end > key_bits.bit_len() {
                        return Err(ProofError::KeyTooShort);
                    }
                    let segment = key_bits.suffix(consumed).prefix(len);
                    if &segment != prefix {
                        return Err(ProofError::ExtensionPrefixMismatch);
                    }
                    consumed = end;
                }
            }
        }
        Ok(consumed)
    }

    fn recompute_root<H: Hasher>(&self, terminal_hash: Hash) -> Hash {
        let mut current = terminal_hash;
        for step in self.steps.iter().rev() {
            match step {
                ProofStep::Branch {
                    sibling,
                    descended_right,
                } => {
                    let node = if *descended_right {
                        Node::Branch {
                            left: *sibling,
                            right: current,
                        }
                    } else {
                        Node::Branch {
                            left: current,
                            right: *sibling,
                        }
                    };
                    current = H::hash_node(&node.encode());
                }
                ProofStep::Extension { prefix } => {
                    let node = Node::Extension {
                        prefix: prefix.clone(),
                        child: current,
                    };
                    current = H::hash_node(&node.encode());
                }
            }
        }
        current
    }
}

fn leaves_match(stored: &BitPath, remaining: &BitPath) -> bool {
    stored == remaining
}

fn extension_matches(stored_prefix: &BitPath, remaining: &BitPath) -> bool {
    if stored_prefix.bit_len() > remaining.bit_len() {
        return false;
    }
    &remaining.prefix(stored_prefix.bit_len()) == stored_prefix
}

#[cfg(test)]
mod tests;
