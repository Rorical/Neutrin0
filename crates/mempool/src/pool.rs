//! Bounded deterministic priority mempool keyed by transaction hash.

mod admission;
mod revalidation;
mod selection;

use alloc::collections::{BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::fmt;
use neutrin0_runtime_abi::TransactionDependency;

use neutrin0_primitives::Hash;

/// One transaction held in the mempool.
///
/// The mempool computes [`MempoolEntry::hash`] from the raw bytes at
/// insertion time so callers can match removed transactions to those
/// committed in a finalized block without recomputing the hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MempoolEntry {
    /// BLAKE3 hash of the transaction bytes.
    pub hash: Hash,
    /// Opaque transaction bytes. The mempool does not interpret them.
    pub bytes: Vec<u8>,
    /// Higher values are drained before lower values. Equal priority
    /// transactions retain FIFO ordering.
    pub priority: u64,
    /// Runtime-issued sequence and replacement bids, when the runtime uses them.
    pub dependency: Option<TransactionDependency>,
    admitted_at: u64,
}

/// Insertion failure modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertError {
    /// A transaction with the same hash is already in the pool.
    Duplicate,
    /// A same-sequence replacement did not increase both bids by at least 10%.
    ReplacementUnderpriced,
    /// Accepting the transaction would exceed [`Mempool::capacity_bytes`].
    CapacityExceeded,
    /// A single transaction is larger than the entire pool capacity.
    TooLarge,
    /// The runtime's validity verdict rejected the transaction bytes.
    RejectedByValidator,
    /// A sequence-based transaction offers no fee budget.
    ZeroFee,
    /// The runtime-issued account exceeds its local entry or byte quota.
    AccountLimit,
}

impl fmt::Display for InsertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroFee => f.write_str("transaction fee cap must be positive"),
            Self::AccountLimit => f.write_str("mempool account quota exceeded"),
            Self::Duplicate => f.write_str("duplicate transaction hash"),
            Self::ReplacementUnderpriced => {
                f.write_str("replacement requires a 10% increase in both fee and tip caps")
            }
            Self::CapacityExceeded => f.write_str("mempool capacity exceeded"),
            Self::TooLarge => f.write_str("transaction exceeds mempool capacity"),
            Self::RejectedByValidator => f.write_str("transaction rejected by validator"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InsertError {}

/// Bounded deterministic priority mempool keyed by transaction hash.
///
/// # Determinism
///
/// Priority order is fully observable; [`Mempool::iter`] and
/// [`Mempool::candidates`] yield higher priority transactions first and
/// keep FIFO ordering among equal priorities. Two mempools that received
/// the same insert calls in the same order are byte-for-byte identical.
///
/// # Capacity policy
///
/// A strictly better runtime bid can evict lower bids under pressure. Failed
/// inserts never evict existing entries. Sequence accounts have configurable
/// quotas, and callers advance a local clock to expire old entries. These are
/// local admission policies, independent of block validity and consensus.
#[derive(Debug)]
pub struct Mempool {
    capacity_bytes: usize,
    txs: VecDeque<MempoolEntry>,
    by_hash: BTreeSet<Hash>,
    total_bytes: usize,
    account_bytes: usize,
    account_entries: usize,
    queued_bytes: usize,
    clock: u64,
}

impl Mempool {
    /// Construct an empty mempool with the given byte capacity.
    ///
    /// A capacity of zero is legal; every non-empty insertion will be
    /// rejected with [`InsertError::TooLarge`].
    #[must_use]
    pub const fn new(capacity_bytes: usize) -> Self {
        Self {
            capacity_bytes,
            txs: VecDeque::new(),
            by_hash: BTreeSet::new(),
            total_bytes: 0,
            account_bytes: capacity_bytes,
            account_entries: 64,
            queued_bytes: capacity_bytes,
            clock: 0,
        }
    }

    /// Construct a pool with per-account quotas and half its bytes reserved
    /// against future-nonce traffic. These limits do not change block validity.
    #[must_use]
    pub const fn with_account_limits(
        capacity_bytes: usize,
        account_bytes: usize,
        account_entries: usize,
    ) -> Self {
        let mut pool = Self::new(capacity_bytes);
        pool.account_bytes = account_bytes;
        pool.account_entries = account_entries;
        pool.queued_bytes = capacity_bytes / 2;
        pool
    }

    /// Advance the caller's local monotonic clock and expire entries of age `ttl`.
    /// Revalidation and duplicate submissions never renew an entry's lifetime.
    pub fn expire(&mut self, now: u64, ttl: u64) {
        self.clock = self.clock.max(now);
        let clock = self.clock;
        self.txs.retain(|entry| {
            if clock.saturating_sub(entry.admitted_at) < ttl {
                return true;
            }
            self.by_hash.remove(&entry.hash);
            self.total_bytes -= entry.bytes.len();
            false
        });
    }

    /// Maximum total byte budget for buffered transactions.
    #[must_use]
    pub const fn capacity_bytes(&self) -> usize {
        self.capacity_bytes
    }

    /// Sum of `bytes.len()` over every buffered transaction.
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Number of buffered transactions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// `true` when no transactions are buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// `true` when a transaction with `hash` is buffered.
    #[must_use]
    pub fn contains(&self, hash: &Hash) -> bool {
        self.by_hash.contains(hash)
    }

    /// Remove and return the transaction with `hash`, if present.
    ///
    /// Removal is `O(n)` because the pool keeps priority order in a
    /// contiguous queue; removal volume (one block per slot) is
    /// small enough that linear scans are not worth optimising away.
    pub fn remove(&mut self, hash: &Hash) -> Option<MempoolEntry> {
        if !self.by_hash.remove(hash) {
            return None;
        }
        let position = self.txs.iter().position(|e| &e.hash == hash)?;
        let entry = self.txs.remove(position)?;
        self.total_bytes -= entry.bytes.len();
        Some(entry)
    }

    /// Iterate buffered transactions in priority order.
    pub fn iter(&self) -> impl Iterator<Item = &MempoolEntry> {
        self.txs.iter()
    }
}

#[cfg(test)]
mod tests;
