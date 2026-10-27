//! Admission: validation, sequence replacement, quotas and pressure eviction.

use alloc::vec::Vec;
use neutrin0_runtime_abi::{TransactionDependency, TxValidity};

use neutrin0_primitives::{Hash, blake3_256};

use super::{InsertError, Mempool, MempoolEntry};

impl Mempool {
    /// Insert `bytes` as a new zero-priority transaction.
    ///
    /// Returns the BLAKE3 hash on success. Fails when the same hash is
    /// already buffered, the transaction is by itself larger than the
    /// pool, or the pool is too full to accept it.
    pub fn insert(&mut self, bytes: Vec<u8>) -> Result<Hash, InsertError> {
        self.insert_with_priority(bytes, 0)
    }

    /// Insert `bytes` as a new transaction with explicit priority.
    ///
    /// Higher priority entries drain first; entries with the same
    /// priority retain insertion order.
    pub fn insert_with_priority(
        &mut self,
        bytes: Vec<u8>,
        priority: u64,
    ) -> Result<Hash, InsertError> {
        self.insert_admitted(bytes, TxValidity::valid(priority))
    }

    /// Insert runtime-admitted bytes, applying sequence replacement atomically.
    pub fn insert_admitted(
        &mut self,
        bytes: Vec<u8>,
        validity: TxValidity,
    ) -> Result<Hash, InsertError> {
        if !validity.is_valid() {
            return Err(InsertError::RejectedByValidator);
        }
        if validity
            .dependency
            .is_some_and(|dependency| dependency.fee_cap == 0)
        {
            return Err(InsertError::ZeroFee);
        }
        if bytes.len() > self.capacity_bytes {
            return Err(InsertError::TooLarge);
        }
        let hash = blake3_256(&bytes);
        if self.by_hash.contains(&hash) {
            return Err(InsertError::Duplicate);
        }
        let replacement = self.sequence_replacement(validity)?;
        let replaced_bytes = replacement.map_or(0, |entry| entry.bytes.len());
        let replaced_hash = replacement.map(|entry| entry.hash);
        if let Some(dependency) = validity.dependency {
            self.check_account_quota(dependency, bytes.len(), replaced_hash)?;
        }
        if validity
            .dependency
            .is_some_and(|value| value.nonce > value.state_nonce)
        {
            self.check_queued_reserve(bytes.len(), replaced_hash)?;
        }
        let new_total = self.total_bytes - replaced_bytes + bytes.len();
        for hash in self.pressure_evictions(new_total, replaced_hash, validity)? {
            self.remove(&hash);
        }
        if let Some(hash) = replaced_hash {
            self.remove(&hash);
        }
        self.total_bytes += bytes.len();
        self.by_hash.insert(hash);
        let insert_at = self
            .txs
            .partition_point(|tx| tx.priority >= validity.priority);
        self.txs.insert(
            insert_at,
            MempoolEntry {
                hash,
                bytes,
                priority: validity.priority,
                dependency: validity.dependency,
                admitted_at: self.clock,
            },
        );
        Ok(hash)
    }

    /// The queued entry of the same account and sequence, once the incoming
    /// bids outbid it by at least 10%.
    fn sequence_replacement(
        &self,
        validity: TxValidity,
    ) -> Result<Option<&MempoolEntry>, InsertError> {
        let replacement = validity.dependency.and_then(|new| {
            self.txs.iter().find(|entry| {
                entry
                    .dependency
                    .is_some_and(|old| old.account == new.account && old.nonce == new.nonce)
            })
        });
        if let Some(entry) = replacement {
            let old = entry.dependency.expect("sequence replacement");
            let new = validity.dependency.expect("sequence replacement");
            let bump = |value: u128| value.checked_add(value.div_ceil(10).max(1));
            if bump(old.fee_cap).is_none_or(|minimum| new.fee_cap < minimum)
                || bump(old.tip_cap).is_none_or(|minimum| new.tip_cap < minimum)
            {
                return Err(InsertError::ReplacementUnderpriced);
            }
        }
        Ok(replacement)
    }

    fn check_account_quota(
        &self,
        dependency: TransactionDependency,
        incoming_len: usize,
        replaced_hash: Option<Hash>,
    ) -> Result<(), InsertError> {
        let (count, size) = self
            .txs
            .iter()
            .filter(|entry| {
                Some(entry.hash) != replaced_hash
                    && entry
                        .dependency
                        .is_some_and(|old| old.account == dependency.account)
            })
            .fold((0_usize, 0_usize), |(count, size), entry| {
                (count + 1, size + entry.bytes.len())
            });
        if count >= self.account_entries || size.saturating_add(incoming_len) > self.account_bytes {
            return Err(InsertError::AccountLimit);
        }
        Ok(())
    }

    fn check_queued_reserve(
        &self,
        incoming_len: usize,
        replaced_hash: Option<Hash>,
    ) -> Result<(), InsertError> {
        let queued = self
            .txs
            .iter()
            .filter(|entry| {
                Some(entry.hash) != replaced_hash
                    && entry
                        .dependency
                        .is_some_and(|value| value.nonce > value.state_nonce)
            })
            .map(|entry| entry.bytes.len())
            .sum::<usize>();
        if queued.saturating_add(incoming_len) > self.queued_bytes {
            return Err(InsertError::CapacityExceeded);
        }
        Ok(())
    }

    fn pressure_evictions(
        &self,
        mut new_total: usize,
        replaced_hash: Option<Hash>,
        validity: TxValidity,
    ) -> Result<Vec<Hash>, InsertError> {
        let bid = |priority, dependency: Option<TransactionDependency>| {
            (
                priority,
                dependency.map_or(0, |value| value.fee_cap),
                dependency.map_or(0, |value| value.tip_cap),
            )
        };
        let queued = |dependency: Option<TransactionDependency>| {
            dependency.is_some_and(|value| value.nonce > value.state_nonce)
        };
        let incoming_bid = bid(validity.priority, validity.dependency);
        let incoming_queued = queued(validity.dependency);
        // A queued bid is never paid until its gap fills, so it displaces
        // only other queued work, never an executable entry.
        let mut evictable = self
            .txs
            .iter()
            .filter(|entry| {
                Some(entry.hash) != replaced_hash
                    && bid(entry.priority, entry.dependency) < incoming_bid
                    && (!incoming_queued || queued(entry.dependency))
            })
            .collect::<Vec<_>>();
        // Queued work goes first, then the worst bids; on equal bids account
        // tails go first, preserving executable prefixes.
        evictable.sort_by_key(|entry| {
            (
                !queued(entry.dependency),
                bid(entry.priority, entry.dependency),
                core::cmp::Reverse(entry.dependency.map_or(0, |value| value.nonce)),
            )
        });
        let mut evicted = Vec::new();
        for entry in evictable {
            if new_total <= self.capacity_bytes {
                break;
            }
            new_total -= entry.bytes.len();
            evicted.push(entry.hash);
        }
        if new_total > self.capacity_bytes {
            return Err(InsertError::CapacityExceeded);
        }
        Ok(evicted)
    }
}
