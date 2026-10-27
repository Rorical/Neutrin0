//! Block-building reads: candidate selection and sequence queries.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use neutrin0_primitives::Hash;

use super::{Mempool, MempoolEntry};

impl Mempool {
    /// Read candidates in priority order while respecting runtime sequence dependencies.
    /// Entries remain held until successful persistence removes their exact hashes.
    pub fn candidates(&self, byte_limit: usize) -> Vec<MempoolEntry> {
        let mut next: BTreeMap<Hash, u64> = BTreeMap::new();
        for entry in &self.txs {
            if let Some(dependency) = entry.dependency {
                next.entry(dependency.account)
                    .and_modify(|nonce| *nonce = (*nonce).max(dependency.state_nonce))
                    .or_insert(dependency.state_nonce);
            }
        }
        let mut taken = Vec::new();
        let mut picked = BTreeSet::new();
        let mut bytes = 0_usize;
        while let Some(entry) = self.txs.iter().find(|entry| {
            !picked.contains(&entry.hash)
                && bytes.saturating_add(entry.bytes.len()) <= byte_limit
                && entry.dependency.is_none_or(|dependency| {
                    next.get(&dependency.account) == Some(&dependency.nonce)
                })
        }) {
            picked.insert(entry.hash);
            bytes += entry.bytes.len();
            if let Some(dependency) = entry.dependency
                && let Some(nonce) = dependency.nonce.checked_add(1)
            {
                next.insert(dependency.account, nonce);
            }
            taken.push(entry.clone());
        }
        taken
    }

    /// Supply all affordable candidate bytes to runtime selection, including gaps.
    /// Authorization operations can advance another account's nonce, so only the
    /// runtime may conclude that a future sequence is not executable in this block.
    pub fn execution_candidates(&self, byte_limit: usize) -> Vec<MempoolEntry> {
        let mut entries = self.candidates(byte_limit);
        let mut bytes = entries.iter().map(|entry| entry.bytes.len()).sum::<usize>();
        let mut selected = entries
            .iter()
            .map(|entry| entry.hash)
            .collect::<BTreeSet<_>>();
        for entry in &self.txs {
            if !selected.contains(&entry.hash)
                && bytes.saturating_add(entry.bytes.len()) <= byte_limit
            {
                bytes += entry.bytes.len();
                selected.insert(entry.hash);
                entries.push(entry.clone());
            }
        }
        entries
    }

    /// Lookup an opaque queued transaction by its runtime-owned identifier.
    #[must_use]
    pub fn transaction(&self, identifier: &Hash) -> Option<Vec<u8>> {
        self.txs
            .iter()
            .find(|entry| {
                entry
                    .dependency
                    .map_or(entry.hash, |dependency| dependency.identifier)
                    == *identifier
            })
            .map(|entry| entry.bytes.clone())
    }

    /// Next unoccupied local sequence after all contiguous queued transactions.
    #[must_use]
    pub fn pending_nonce(&self, account: Hash, state_nonce: u64) -> u64 {
        let mut nonce = state_nonce;
        while self.txs.iter().any(|entry| {
            entry.dependency.is_some_and(|dependency| {
                dependency.account == account && dependency.nonce == nonce
            })
        }) {
            let Some(next) = nonce.checked_add(1) else {
                break;
            };
            nonce = next;
        }
        nonce
    }
}
