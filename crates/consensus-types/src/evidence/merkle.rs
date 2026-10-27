//! Odd-leaf-promoting Merkle openings: counted evidence batches and plain
//! chunk block-hash roots.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{Hash, blake3_256};

/// Opening in the counted, odd-leaf-promoting evidence batch Merkle tree.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize)]
pub struct MerkleOpening {
    /// Statement index within the evidence batch.
    pub index: u64,
    /// Exact leaf count; prevents ambiguous tree shapes.
    pub count: u64,
    /// Bottom-up siblings; promoted odd nodes consume no sibling.
    pub siblings: Vec<Hash>,
}

impl BorshDeserialize for MerkleOpening {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let index = u64::deserialize_reader(reader)?;
        let count = u64::deserialize_reader(reader)?;
        let length = u32::deserialize_reader(reader)?;
        if length > 64 {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "evidence membership path length",
            ));
        }
        let siblings = (0..length)
            .map(|_| Hash::deserialize_reader(reader))
            .collect::<borsh::io::Result<Vec<_>>>()?;
        Ok(Self {
            index,
            count,
            siblings,
        })
    }
}

/// Root bound to both the leaf count and the evidence membership domain.
pub fn counted_merkle_root(count: u64, root: Hash) -> Hash {
    crate::tagged_commitment(b"neutrin0-evidence-membership", &(count, root))
}

impl MerkleOpening {
    /// Produce an opening for an existing leaf.
    pub fn build(leaves: &[Hash], index: usize) -> Option<Self> {
        if index >= leaves.len() {
            return None;
        }
        let mut nodes = leaves.to_vec();
        let mut position = index;
        let mut siblings = Vec::new();
        while nodes.len() > 1 {
            if let Some(sibling) = nodes.get(position ^ 1) {
                siblings.push(*sibling);
            }
            nodes = nodes
                .chunks(2)
                .map(|pair| {
                    if pair.len() == 1 {
                        pair[0]
                    } else {
                        pair_hash(pair[0], pair[1])
                    }
                })
                .collect();
            position /= 2;
        }
        Some(Self {
            index: index as u64,
            count: leaves.len() as u64,
            siblings,
        })
    }

    /// Check shape, exact sibling consumption, count and root.
    pub fn verify(&self, leaf: Hash, expected_root: Hash) -> bool {
        self.fold(leaf)
            .is_some_and(|root| counted_merkle_root(self.count, root) == expected_root)
    }

    /// Check shape and exact sibling consumption against a plain root of
    /// `count` leaves, such as a chunk's `block_hash_root`
    /// ([`neutrin0_primitives::merkle_root_of_hashes`]); the caller fixes the
    /// count, which the plain root does not encode.
    pub fn verify_plain(&self, leaf: Hash, expected_root: Hash) -> bool {
        self.fold(leaf) == Some(expected_root)
    }

    /// The root the siblings reduce `leaf` to, if they fit the shape exactly.
    fn fold(&self, leaf: Hash) -> Option<Hash> {
        if self.index >= self.count || self.count == 0 || self.siblings.len() > 64 {
            return None;
        }
        let mut position = self.index;
        let mut width = self.count;
        let mut hash = leaf;
        let mut siblings = self.siblings.iter();
        while width > 1 {
            if position ^ 1 < width {
                let sibling = siblings.next()?;
                hash = if position.is_multiple_of(2) {
                    pair_hash(hash, *sibling)
                } else {
                    pair_hash(*sibling, hash)
                };
            }
            position /= 2;
            width = width.div_ceil(2);
        }
        siblings.next().is_none().then_some(hash)
    }
}

fn pair_hash(left: Hash, right: Hash) -> Hash {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&left);
    bytes[32..].copy_from_slice(&right);
    blake3_256(&bytes)
}
