//! Per-block execution state diffs for proof-following nodes.
//!
//! A [`BlockStateDiff`] lists the final value of every state key a block's
//! execution wrote. It is a transport artifact, not a consensus commitment:
//! a receiver applies it to the exact pre-state trie and accepts it only when
//! the resulting root equals the post-state root bound by that block's
//! verified Block receipt. Any executing node can reproduce the diff from its
//! own execution, so its availability never depends on the block producer.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{BlockHash, Height, MAX_STATE_DIFF_BYTES, StateRoot};

use crate::Block;

/// Final value one block's execution left under `key`.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct StateWrite {
    /// State key written or deleted by the block.
    pub key: Vec<u8>,
    /// Value after the block, or `None` when the block deleted the key.
    pub value: Option<Vec<u8>>,
}

/// Complete write set of one block over its authenticated pre-state.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct BlockStateDiff {
    /// Height of the block whose execution produced the writes.
    pub height: Height,
    /// Hash of that block's header.
    pub block_hash: BlockHash,
    /// State root the writes extend.
    pub state_root_before: StateRoot,
    /// State root the block header and its receipt commit after the writes.
    pub state_root_after: StateRoot,
    /// Writes in strictly increasing key order, one entry per key.
    pub writes: Vec<StateWrite>,
}

/// Encoded length of the [`BlockStateDiff`] carrying `writes`, computed
/// without encoding it: four fixed fields, then the length-prefixed writes.
fn diff_encoded_len(writes: &[StateWrite]) -> usize {
    writes.iter().fold(8 + 32 + 32 + 32 + 4, |total, write| {
        total
            .saturating_add(4 + write.key.len() + 1)
            .saturating_add(write.value.as_ref().map_or(0, |value| 4 + value.len()))
    })
}

/// `true` when the writes are in strictly increasing key order and their
/// diff fits the [`MAX_STATE_DIFF_BYTES`] ceiling honest production obeys.
fn writes_canonical(writes: &[StateWrite]) -> bool {
    writes.windows(2).all(|pair| pair[0].key < pair[1].key)
        && diff_encoded_len(writes) <= MAX_STATE_DIFF_BYTES
}

/// A producer's complete publication: the block, the bytes of its receipt and
/// the final write set of its execution, accepted or rejected as one unit.
///
/// Nothing in the bundle repeats what the header already states. The receiver
/// derives the canonical receipt envelope (height, hash, public inputs) and the
/// canonical [`BlockStateDiff`] from the header, the parent header and its
/// local consensus boundary, verifies `proof_bytes` against that envelope and
/// requires `writes` to reproduce the header's state root over the parent
/// state. A publication missing any part is not a block to the network.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct ProvenBlock {
    /// Header and body.
    pub block: Block,
    /// Backend receipt bytes of the block's execution.
    pub proof_bytes: Vec<u8>,
    /// Final value of every key the execution wrote, in strictly increasing
    /// key order; `None` marks a delete.
    pub writes: Vec<StateWrite>,
}

impl ProvenBlock {
    /// `true` when the write set is canonically ordered and within the ceiling.
    ///
    /// Receipt validity and root reproduction are checked at import against
    /// the header.
    #[must_use]
    pub fn writes_well_formed(&self) -> bool {
        writes_canonical(&self.writes)
    }

    /// The candidate and the receipt this complete publication combines.
    #[must_use]
    pub fn split(self) -> (CandidateBlock, BlockReceipt) {
        let block_hash = self.block.hash();
        (
            CandidateBlock {
                block: self.block,
                writes: self.writes,
            },
            BlockReceipt {
                block_hash,
                proof_bytes: self.proof_bytes,
            },
        )
    }
}

/// A proposer's candidate publication (design 08).
///
/// The signed block and the write set of its execution, gossiped on `blocks`
/// as soon as the block is executed and before any receipt exists.
///
/// A receiver admits the header and body exactly as it admits a complete
/// publication, then requires `writes` to reproduce the header's state root
/// over the exact parent state. The root check proves only that the writes
/// are the writes the proposer signed for; nothing trusts the candidate's
/// execution until a receipt proves it.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct CandidateBlock {
    /// Header and body.
    pub block: Block,
    /// Final value of every key the execution wrote, in strictly increasing
    /// key order; `None` marks a delete.
    pub writes: Vec<StateWrite>,
}

impl CandidateBlock {
    /// `true` when the write set is canonically ordered and within the diff
    /// ceiling.
    #[must_use]
    pub fn writes_well_formed(&self) -> bool {
        writes_canonical(&self.writes)
    }
}

/// The receipt of one block's execution (design 08).
///
/// Gossiped on `receipts` by whoever proved the block and requested by
/// `ReceiptsByHash`. The envelope and the public inputs are derived locally
/// from the block's header, its parent and the local consensus boundary,
/// never carried.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct BlockReceipt {
    /// Hash of the block the receipt proves.
    pub block_hash: BlockHash,
    /// Backend receipt bytes.
    pub proof_bytes: Vec<u8>,
}

#[cfg(test)]
mod tests;
