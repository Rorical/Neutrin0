//! Insertion-ordered caches of verified receipts, bounded by entry count and
//! by the total encoded size of their entries.

#![allow(clippy::redundant_pub_crate)]

use std::collections::VecDeque;

/// One cached value with the byte size charged against the budget.
struct Entry<K, V> {
    key: K,
    size: usize,
    value: V,
}

/// Cache that keeps entries in insertion order and evicts the oldest while
/// either bound is exceeded. A key is cached at most once.
pub(super) struct BoundedCache<K, V> {
    entries: VecDeque<Entry<K, V>>,
    /// Running total of every entry's charged size.
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
}

impl<K: PartialEq, V> BoundedCache<K, V> {
    /// Empty cache holding at most `max_entries` entries whose sizes sum to
    /// at most `max_bytes`.
    pub(super) const fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
            max_entries,
            max_bytes,
        }
    }

    /// Value cached under `key`.
    pub(super) fn get(&self, key: &K) -> Option<&V> {
        self.entries
            .iter()
            .find(|entry| entry.key == *key)
            .map(|entry| &entry.value)
    }

    /// `true` when `key` is cached.
    pub(super) fn contains(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    /// Cached values, oldest first.
    pub(super) fn values(&self) -> impl DoubleEndedIterator<Item = &V> {
        self.entries.iter().map(|entry| &entry.value)
    }

    /// Cache `value` under `key`, charged `size` bytes, unless `key` is
    /// already cached; then evict the oldest entries while over either
    /// bound. Returns the evicted entries, oldest first.
    pub(super) fn insert(&mut self, key: K, size: usize, value: V) -> Vec<(K, V)> {
        let mut evicted = Vec::new();
        if self.contains(&key) {
            return evicted;
        }
        self.bytes += size;
        self.entries.push_back(Entry { key, size, value });
        while self.entries.len() > self.max_entries || self.bytes > self.max_bytes {
            let Some(old) = self.entries.pop_front() else {
                break;
            };
            self.bytes -= old.size;
            evicted.push((old.key, old.value));
        }
        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::BoundedCache;

    #[test]
    fn evicts_oldest_by_count_and_bytes_and_keeps_first_copy() {
        let mut cache = BoundedCache::new(2, 10);
        assert_eq!(cache.insert(1, 4, 'a'), Vec::new());
        assert_eq!(cache.insert(1, 4, 'z'), Vec::new());
        assert_eq!(cache.get(&1), Some(&'a'));
        assert_eq!(cache.insert(2, 4, 'b'), Vec::new());
        assert_eq!(cache.insert(3, 1, 'c'), vec![(1, 'a')]);
        assert_eq!(cache.insert(4, 9, 'd'), vec![(2, 'b')]);
        assert_eq!(cache.values().copied().collect::<Vec<_>>(), vec!['c', 'd']);
        assert_eq!(cache.insert(5, 11, 'e'), vec![(3, 'c'), (4, 'd'), (5, 'e')]);
        assert!(!cache.contains(&5));
    }
}
