//! Revalidation against a new head and the queued-byte reserve.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use neutrin0_runtime_abi::TxValidity;

use neutrin0_primitives::Hash;

use super::Mempool;

impl Mempool {
    /// Every entry's hash and bytes, to validate without holding the pool.
    #[must_use]
    pub fn validation_snapshot(&self) -> Vec<(Hash, Vec<u8>)> {
        self.txs
            .iter()
            .map(|entry| (entry.hash, entry.bytes.clone()))
            .collect()
    }

    /// Apply verdicts reached against one consistent new head or installed
    /// runtime. Rejected entries are removed; validated dependencies are
    /// refreshed. An entry without a verdict, admitted since the snapshot or
    /// whose validation was unavailable, is kept for a later retry.
    pub fn apply_validation(&mut self, verdicts: impl IntoIterator<Item = (Hash, TxValidity)>) {
        let verdicts: BTreeMap<_, _> = verdicts.into_iter().collect();
        self.txs.retain_mut(|entry| {
            let Some(validity) = verdicts.get(&entry.hash) else {
                return true;
            };
            if !validity.is_valid() || validity.dependency.is_some_and(|value| value.fee_cap == 0) {
                self.by_hash.remove(&entry.hash);
                self.total_bytes -= entry.bytes.len();
                return false;
            }
            entry.priority = validity.priority;
            entry.dependency = validity.dependency;
            true
        });
        self.txs
            .make_contiguous()
            .sort_by_key(|entry| core::cmp::Reverse(entry.priority));
        self.trim_queued();
    }

    // A head rollback can return previously executable entries to queued state.
    fn trim_queued(&mut self) {
        let mut queued = self
            .txs
            .iter()
            .filter(|entry| {
                entry
                    .dependency
                    .is_some_and(|value| value.nonce > value.state_nonce)
            })
            .collect::<Vec<_>>();
        let mut bytes = queued.iter().map(|entry| entry.bytes.len()).sum::<usize>();
        if bytes <= self.queued_bytes {
            return;
        }
        queued.sort_by_key(|entry| {
            (
                entry.priority,
                entry.dependency.map_or(0, |value| value.fee_cap),
                core::cmp::Reverse(entry.dependency.map_or(0, |value| value.nonce)),
            )
        });
        let mut removed = BTreeSet::new();
        for entry in queued {
            if bytes <= self.queued_bytes {
                break;
            }
            bytes -= entry.bytes.len();
            removed.insert(entry.hash);
        }
        self.txs.retain(|entry| {
            if !removed.contains(&entry.hash) {
                return true;
            }
            self.by_hash.remove(&entry.hash);
            self.total_bytes -= entry.bytes.len();
            false
        });
    }
}
