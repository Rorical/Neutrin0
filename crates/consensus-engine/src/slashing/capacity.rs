//! Bounded observation maps that keep observing when full.
//!
//! A first-come cap stops recording once full, so any signer could silence
//! detection for everyone by signing many rounds of its own. Instead a full
//! map makes room by evicting from the owner (the signer, or the chunk for
//! quorums) holding the most entries, its highest-keyed one: its latest
//! round or slot. A flooding signer displaces only itself, and the earliest
//! rounds, where locks form, stay. Each owner's keys and the owners' loads
//! are indexed, so an eviction costs a logarithmic lookup, never a scan.

use std::collections::BTreeSet;
use std::ops::Deref;

use super::BTreeMap;

/// Bounds of one observation map.
#[derive(Clone, Copy, Debug)]
pub(super) struct Limits {
    /// Most entries.
    pub(super) entries: usize,
    /// Most encoded bytes, for maps that size their values.
    pub(super) bytes: usize,
}

/// Bounds of every map outside a reporter: entries for the live window of
/// nine chunks times the largest committee times both vote phases, for seven
/// rounds a chunk on average, and 64 MiB of encoded proposals, quorums or
/// attestations.
pub(super) const MONITOR_LIMITS: Limits = Limits {
    entries: 9 * neutrin0_primitives::MAX_CONSENSUS_VALIDATORS * 2 * 7,
    bytes: 64 * 1024 * 1024,
};

/// An observation map, read through [`Deref`] and changed only through its
/// methods so its indexes stay exact.
#[derive(Debug)]
pub(super) struct Observed<K, V, O> {
    entries: BTreeMap<K, V>,
    /// Each owner's keys, so its latest is found without a scan.
    owners: BTreeMap<O, BTreeSet<K>>,
    /// `(entries held, owner)`: the most loaded owner, the greatest among
    /// equals, is the last.
    loads: BTreeSet<(usize, O)>,
    bytes: usize,
    owner: fn(&K) -> O,
    size: fn(&V) -> usize,
}

impl<K, V, O> Deref for Observed<K, V, O> {
    type Target = BTreeMap<K, V>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl<K: Ord + Clone, V, O: Ord + Clone> Observed<K, V, O> {
    /// An empty map whose keys belong to `owner` and whose values weigh
    /// `size` encoded bytes (zero for maps bounded by entries alone).
    pub(super) const fn new(owner: fn(&K) -> O, size: fn(&V) -> usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            owners: BTreeMap::new(),
            loads: BTreeSet::new(),
            bytes: 0,
            owner,
            size,
        }
    }

    /// Encoded bytes held.
    #[cfg(test)]
    pub(super) const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Insert a new `key → value`, making room as the module describes within
    /// `limits` (none for a reporter's durable replay), and return whether it
    /// was inserted. A new entry that would itself be the one evicted is
    /// refused instead. An existing key is left as it is.
    pub(super) fn insert(&mut self, limits: Option<Limits>, key: K, value: V) -> bool {
        if self.entries.contains_key(&key) {
            return false;
        }
        let added = (self.size)(&value);
        if let Some(limits) = limits {
            if added > limits.bytes {
                return false;
            }
            while self.entries.len() >= limits.entries
                || added > limits.bytes.saturating_sub(self.bytes)
            {
                let Some(evicted) = self.heaviest_latest() else {
                    return false;
                };
                if (self.owner)(&evicted) == (self.owner)(&key) && key > evicted {
                    return false;
                }
                self.remove(&evicted);
            }
        }
        self.bytes = self.bytes.saturating_add(added);
        let owner = (self.owner)(&key);
        let keys = self.owners.entry(owner.clone()).or_default();
        let held = keys.len();
        keys.insert(key.clone());
        self.loads.remove(&(held, owner.clone()));
        self.loads.insert((held + 1, owner));
        self.entries.insert(key, value);
        true
    }

    /// Replace the value under an existing `key` within `limits`, as
    /// [`Self::insert`] makes room for a new one, and return whether it was
    /// replaced. A replacement that does not fit leaves the earlier value.
    pub(super) fn replace(&mut self, limits: Option<Limits>, key: K, value: V) -> bool {
        let Some(previous) = self.remove(&key) else {
            return false;
        };
        if self.insert(limits, key.clone(), value) {
            return true;
        }
        // It fit before it was taken out.
        self.insert(None, key, previous);
        false
    }

    /// Keep only the entries whose keys `keep` accepts.
    pub(super) fn retain(&mut self, mut keep: impl FnMut(&K) -> bool) {
        let dropped: Vec<K> = self
            .entries
            .keys()
            .filter(|key| !keep(key))
            .cloned()
            .collect();
        for key in &dropped {
            self.remove(key);
        }
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        let value = self.entries.remove(key)?;
        self.bytes = self.bytes.saturating_sub((self.size)(&value));
        let owner = (self.owner)(key);
        if let Some(keys) = self.owners.get_mut(&owner) {
            let held = keys.len();
            keys.remove(key);
            self.loads.remove(&(held, owner.clone()));
            if keys.is_empty() {
                self.owners.remove(&owner);
            } else {
                self.loads.insert((held - 1, owner));
            }
        }
        Some(value)
    }

    /// The highest key of the most loaded owner.
    fn heaviest_latest(&self) -> Option<K> {
        let (_, owner) = self.loads.last()?;
        self.owners.get(owner)?.last().cloned()
    }
}

#[cfg(test)]
mod tests;
