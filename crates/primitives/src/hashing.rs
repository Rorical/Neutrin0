//! Canonical BLAKE3 hashing, Merkle roots and tagged commitments.

use alloc::vec::Vec;

use borsh::BorshSerialize;

use crate::{DOMAIN_DA_LANE, DOMAIN_TX_LEAF, DOMAIN_TX_NODE, DOMAIN_TX_ROOT, Hash};

/// Zero hash used for empty roots and genesis placeholders.
pub const ZERO_HASH: Hash = [0; 32];

/// Computes a BLAKE3-256 digest.
pub fn blake3_256(input: &[u8]) -> Hash {
    *blake3::hash(input).as_bytes()
}

/// Incremental canonical chain hasher for streaming commitments.
pub use blake3::Hasher as Blake3Hasher;

/// The validator-set root: `BLAKE3(DOMAIN_VALIDATORS || borsh(validators))`,
/// the commitment every consensus path compares sets by.
#[must_use]
pub fn validators_root(validators: &[crate::Validator]) -> Hash {
    let mut bytes = crate::DOMAIN_VALIDATORS.to_vec();
    validators
        .serialize(&mut bytes)
        .expect("canonical validator set encoding");
    blake3_256(&bytes)
}

/// Sentinel root committed for an empty Merkle leaf list.  Chosen as
/// [`ZERO_HASH`] so an empty body lane and a never-populated lane are
/// indistinguishable by root alone; lane contents differentiate them.
pub const EMPTY_MERKLE_ROOT: Hash = ZERO_HASH;

/// The leaf of one transaction in a block's transaction tree: its Borsh
/// encoding `u32_le(len) || bytes`, under the leaf tag.
#[must_use]
pub fn transaction_leaf(blob: &[u8]) -> Hash {
    let length = u32::try_from(blob.len()).expect("blob length fits u32");
    let mut hasher = Blake3Hasher::new();
    hasher.update(&DOMAIN_TX_LEAF);
    hasher.update(&length.to_le_bytes());
    hasher.update(blob);
    *hasher.finalize().as_bytes()
}

/// A block's transaction root over its transaction leaves, in order.
///
/// Leaves ([`transaction_leaf`]) and internal nodes carry distinct tags, an
/// odd node at any level is promoted unchanged, and the root binds the leaf
/// count: no leaf can be read as a node or the tree as one of another shape,
/// so one root names exactly one transaction list.
///
/// # Panics
/// Panics when the count exceeds the Borsh `u32` bound.
#[must_use]
pub fn transactions_root(mut leaves: Vec<Hash>) -> Hash {
    let count = u32::try_from(leaves.len()).expect("transaction count fits u32");
    while leaves.len() > 1 {
        let length = leaves.len();
        for index in 0..length / 2 {
            let mut hasher = Blake3Hasher::new();
            hasher.update(&DOMAIN_TX_NODE);
            hasher.update(&leaves[index * 2]);
            hasher.update(&leaves[index * 2 + 1]);
            leaves[index] = *hasher.finalize().as_bytes();
        }
        if !length.is_multiple_of(2) {
            leaves[length / 2] = leaves[length - 1];
        }
        leaves.truncate(length.div_ceil(2));
    }
    let mut hasher = Blake3Hasher::new();
    hasher.update(&DOMAIN_TX_ROOT);
    hasher.update(&count.to_le_bytes());
    hasher.update(&leaves.first().copied().unwrap_or(ZERO_HASH));
    *hasher.finalize().as_bytes()
}

/// [`transactions_root`] over raw transaction encodings.
#[must_use]
pub fn transactions_root_of_blobs(blobs: &[Vec<u8>]) -> Hash {
    transactions_root(blobs.iter().map(|blob| transaction_leaf(blob)).collect())
}

/// Binary Merkle root over already-hashed leaves, internal nodes
/// `BLAKE3(left || right)` with an odd leaf promoted unchanged; empty input
/// maps to [`EMPTY_MERKLE_ROOT`].
#[must_use]
pub fn merkle_root_of_hashes(leaves: &[Hash]) -> Hash {
    merkle_root_from_hashes(leaves.to_vec())
}

/// Reduce owned Merkle leaves in place, without allocating at each tree level.
/// Uses exactly the same odd-leaf promotion and empty root as
/// [`merkle_root_of_hashes`].
#[must_use]
pub fn merkle_root_from_hashes(mut leaves: Vec<Hash>) -> Hash {
    if leaves.is_empty() {
        return EMPTY_MERKLE_ROOT;
    }
    while leaves.len() > 1 {
        let length = leaves.len();
        for index in 0..length / 2 {
            let mut concat = [0_u8; 64];
            concat[..32].copy_from_slice(&leaves[index * 2]);
            concat[32..].copy_from_slice(&leaves[index * 2 + 1]);
            leaves[index] = blake3_256(&concat);
        }
        if !length.is_multiple_of(2) {
            leaves[length / 2] = leaves[length - 1];
        }
        leaves.truncate(length.div_ceil(2));
    }
    leaves[0]
}

/// Commit the transaction, vote, program-artifact and participation lanes without hashing
/// their bytes again.
///
/// Each leaf binds its domain, lane index, exact count and Merkle root.
/// Counts are essential: Merkle roots alone do not encode a tree's shape.
/// The program lane carries upgrade artifacts (design 20); the STF never
/// reads it and the chunk Guest only commits the pieces' leaves.
#[must_use]
pub fn da_root_from_lane_roots(lanes: [(u32, Hash); 4]) -> Hash {
    let mut leaves = [[0; 32]; 4];
    for (tag, (count, root)) in (0_u8..4).zip(lanes) {
        let mut bytes = [0; 53];
        bytes[..16].copy_from_slice(&DOMAIN_DA_LANE);
        bytes[16] = tag;
        bytes[17..21].copy_from_slice(&count.to_le_bytes());
        bytes[21..].copy_from_slice(&root);
        leaves[usize::from(tag)] = blake3_256(&bytes);
    }
    merkle_root_of_hashes(&leaves)
}

/// Canonical empty History root, the counted root of no chunk leaves.
pub const EMPTY_HISTORY_ROOT: Hash = [
    0x27, 0x97, 0x96, 0x18, 0xef, 0xa1, 0xcd, 0xf0, 0x11, 0x0b, 0x70, 0x84, 0x2b, 0x2d, 0x7e, 0x3d,
    0x62, 0xa5, 0x75, 0xb2, 0x3a, 0xec, 0x51, 0x5e, 0x4e, 0x17, 0x47, 0xe0, 0x49, 0x92, 0xee, 0xd5,
];

/// `BLAKE3(tag || borsh(value))`.
#[allow(clippy::redundant_pub_crate)] // Crate-internal commitment helper; never part of the public API.
pub(crate) fn tagged_commitment<T: BorshSerialize + ?Sized>(tag: &[u8], value: &T) -> Hash {
    let mut bytes = Vec::from(tag);
    value
        .serialize(&mut bytes)
        .expect("canonical tagged commitment encoding");
    blake3_256(&bytes)
}
