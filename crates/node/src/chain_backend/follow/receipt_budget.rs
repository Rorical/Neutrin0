//! Distinct proof byte strings verified per peer and block or chunk.
//!
//! A block or chunk keeps a handful of receipts; beyond that, new bytes for
//! it only cost verification. Each peer may have a bounded number of distinct
//! byte strings verified for one, so a peer sending junk spends only its own
//! allowance, and the record of them is itself bounded.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash as StdHash;

use neutrin0_primitives::Hash;

/// Distinct proof byte strings one peer may have verified for one block or
/// chunk.
pub(in crate::chain_backend) const RECEIPTS_PER_BLOCK: usize = 8;

/// Peer and block or chunk pairs whose attempts are remembered; the oldest go
/// first.
const TRACKED_BLOCKS: usize = 4096;

pub(in crate::chain_backend) struct ReceiptBudget<K> {
    order: VecDeque<K>,
    seen: HashMap<K, Vec<Hash>>,
}

impl<K> Default for ReceiptBudget<K> {
    fn default() -> Self {
        Self {
            order: VecDeque::new(),
            seen: HashMap::new(),
        }
    }
}

impl<K: Copy + Eq + StdHash> ReceiptBudget<K> {
    /// Whether `bytes` (by hash) may be verified for `block`: bytes already
    /// counted always may, new bytes only while the block has room.
    pub(in crate::chain_backend) fn admit(&mut self, block: K, bytes: Hash) -> bool {
        if !self.seen.contains_key(&block) {
            if self.order.len() >= TRACKED_BLOCKS
                && let Some(oldest) = self.order.pop_front()
            {
                self.seen.remove(&oldest);
            }
            self.order.push_back(block);
        }
        let attempts = self.seen.entry(block).or_default();
        if attempts.contains(&bytes) {
            return true;
        }
        if attempts.len() >= RECEIPTS_PER_BLOCK {
            return false;
        }
        attempts.push(bytes);
        true
    }
}

#[cfg(test)]
mod tests;
