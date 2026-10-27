//! Binary Merkle root over BLAKE3 used for header and chunk
//! commitments.
//!
//! Commitments use a simple unbalanced binary tree: leaves are 32-byte
//! BLAKE3 digests, internal nodes are `BLAKE3(left || right)`, and an
//! odd leaf at any level is promoted unchanged to the next level. The
//! commitment for an empty list is [`EMPTY_MERKLE_ROOT`].

use neutrin0_primitives::{Hash, blake3_256, merkle_root_from_hashes};

use neutrin0_consensus_types::evidence::commitment;

// The chain's canonical empty root and Merkle root over pre-hashed leaves.
pub use neutrin0_primitives::{EMPTY_MERKLE_ROOT, merkle_root_of_hashes};

/// Compute the Merkle root over `items`. Each item is first
/// borsh-serialised and BLAKE3-hashed to a leaf.
#[must_use]
pub fn merkle_root<T: neutrin0_consensus_types::hashing::Committed>(items: &[T]) -> Hash {
    merkle_root_from_hashes(items.iter().map(commitment).collect())
}

/// Hash a single byte slice as a Merkle leaf, useful for callers that
/// already hold the canonical bytes (e.g. block proof bytes).
#[must_use]
pub fn hash_leaf(bytes: &[u8]) -> Hash {
    blake3_256(bytes)
}

#[cfg(test)]
mod tests;
