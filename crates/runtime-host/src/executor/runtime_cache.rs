//! Bounded cache of compiled runtimes with leased-eviction accounting.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Weak};

use neutrin0_primitives::Hash;

use crate::wasm::{WasmError, WasmRuntime};

/// Compiled program allocation bounds; query/execution stores have separate limits.
const MAX_RESIDENT_RUNTIMES: usize = 8;
const MAX_RESIDENT_RUNTIME_BYTES: usize = 512 * 1024 * 1024;
pub(super) const MAX_SINGLE_RUNTIME_BYTES: usize = 128 * 1024 * 1024;

pub(super) struct RuntimeEntry {
    pub(super) runtime: Arc<WasmRuntime>,
    pub(super) touched: u64,
    pub(super) bytes: usize,
}

#[derive(Default)]
pub(super) struct RuntimeCache {
    pub(super) entries: HashMap<Hash, RuntimeEntry>,
    pub(super) retired: Vec<(Weak<WasmRuntime>, usize)>,
    pub(super) warm: BTreeSet<Hash>,
    pub(super) sources: BTreeSet<Hash>,
    pub(super) clock: u64,
}

impl RuntimeCache {
    pub(super) fn remove(&mut self, hash: &Hash) {
        if let Some(entry) = self.entries.remove(hash) {
            self.retired
                .push((Arc::downgrade(&entry.runtime), entry.bytes));
        }
    }

    pub(super) fn reserve(&mut self, bytes: usize) -> Result<(), WasmError> {
        self.retired.retain(|(lease, _)| lease.strong_count() != 0);
        loop {
            let count = self.entries.len() + self.retired.len();
            let used: usize = self
                .entries
                .values()
                .map(|entry| entry.bytes)
                .sum::<usize>()
                + self.retired.iter().map(|(_, bytes)| *bytes).sum::<usize>();
            if count < MAX_RESIDENT_RUNTIMES
                && used.saturating_add(bytes) <= MAX_RESIDENT_RUNTIME_BYTES
            {
                return Ok(());
            }
            let victim = self
                .entries
                .iter()
                .filter(|(hash, entry)| {
                    !self.warm.contains(*hash) && Arc::strong_count(&entry.runtime) == 1
                })
                .min_by_key(|(_, entry)| entry.touched)
                .map(|(hash, _)| *hash);
            let Some(victim) = victim else {
                return Err(WasmError::ResourceLimit(
                    "compiled runtime cache is leased or fully protected".into(),
                ));
            };
            self.remove(&victim);
            self.retired.retain(|(lease, _)| lease.strong_count() != 0);
        }
    }
}
