//! The witness envelope handed to the SP1 Guest.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{Hash, StateRoot};

/// One trie node carried in a [`StateWitness`].
///
/// `bytes` is the canonical encoded form of a `neutrin0_trie::Node`
/// whose Poseidon2 node hash equals `hash`. The SP1 Guest reconstructs a
/// partial `Trie` from the collected `(hash, bytes)` pairs via
/// `Trie::from_persisted`.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct TrieNodeBytes {
    /// Poseidon2 node hash of `bytes`.
    pub hash: Hash,
    /// Canonical node encoding.
    pub bytes: Vec<u8>,
}

/// One trie value (leaf payload) carried in a [`StateWitness`].
///
/// `bytes` is the raw value stored at the corresponding leaf; `hash`
/// is the Poseidon2 value hash exactly as the trie computes it.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct TrieValueBytes {
    /// Poseidon2 value hash of `bytes`.
    pub hash: Hash,
    /// Raw value bytes referenced by leaves in [`TrieNodeBytes`].
    pub bytes: Vec<u8>,
}

/// Witness handed to the SP1 Guest before it replays the STF.
///
/// The witness is a Merkle subtree of the state trie that covers every
/// key the STF reads or writes. The Guest builds a `Trie` via
/// `Trie::from_persisted(pre_state_root, nodes, values)`, asserts the
/// reconstructed root equals `pre_state_root`, then runs the STF
/// against that partial trie. After the STF finishes the Guest reads
/// the new root from the (now-updated) trie and commits it as the
/// `post_state_root` in `RuntimeBlockOutput`.
///
/// Any STF read whose key is not in `witnessed_keys` panics inside the
/// Guest, which surfaces as a non-zero exit code and rejects the
/// proof. Writes implicitly witness their key.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct StateWitness {
    /// Trie root the supplied nodes / values must reconstruct.
    pub pre_state_root: StateRoot,
    /// Trie nodes (`hash -> bytes`) covering every read / write path.
    pub nodes: Vec<TrieNodeBytes>,
    /// Trie values (`hash -> bytes`) referenced by the witnessed leaves.
    pub values: Vec<TrieValueBytes>,
    /// Raw runtime keys the STF is permitted to read. The host sorts
    /// the set ascending for determinism.
    pub witnessed_keys: Vec<Vec<u8>>,
}
