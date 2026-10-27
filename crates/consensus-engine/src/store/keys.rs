//! Key encoders for every consensus column.
//!
//! All integer keys are encoded big-endian so lexicographic iteration
//! over a column matches numeric iteration. Hash-keyed columns store the
//! raw 32-byte hash bytes.

use neutrin0_primitives::{BlockHash, CheckpointIndex, ChunkId, Height, Slot};

/// Big-endian 8-byte key for a [`Height`].
#[must_use]
pub const fn height_key(height: Height) -> [u8; 8] {
    height.to_be_bytes()
}

/// Big-endian 8-byte key for a [`Slot`].
#[must_use]
pub const fn slot_key(slot: Slot) -> [u8; 8] {
    slot.to_be_bytes()
}

/// Slot-index key of one block: its big-endian slot then its hash, so
/// siblings of one slot coexist and a scan can start at any slot.
#[must_use]
pub fn slot_block_key(slot: Slot, hash: &BlockHash) -> [u8; 40] {
    let mut key = [0_u8; 40];
    key[..8].copy_from_slice(&slot.to_be_bytes());
    key[8..].copy_from_slice(hash.as_slice());
    key
}

/// Big-endian 8-byte key for a [`ChunkId`].
#[must_use]
pub const fn chunk_id_key(chunk_id: ChunkId) -> [u8; 8] {
    chunk_id.to_be_bytes()
}

/// Big-endian 8-byte key for a [`CheckpointIndex`].
#[must_use]
pub const fn checkpoint_index_key(index: CheckpointIndex) -> [u8; 8] {
    index.to_be_bytes()
}

/// 32-byte key for any hash-addressed column (headers, bodies, block
/// proofs, witnesses).
#[must_use]
pub const fn hash_key(hash: &BlockHash) -> [u8; 32] {
    *hash
}

/// Big-endian 16-byte key for an ordered pair `(a, b)`.
///
/// Used for history ranges and `(count, index)` openings, so lexicographic
/// iteration matches numeric order on `a`, then `b`.
#[must_use]
pub const fn pair_key(a: u64, b: u64) -> [u8; 16] {
    let a = a.to_be_bytes();
    let b = b.to_be_bytes();
    let mut key = [0; 16];
    let mut i = 0;
    while i < 8 {
        key[i] = a[i];
        key[i + 8] = b[i];
        i += 1;
    }
    key
}

#[cfg(test)]
mod tests;
