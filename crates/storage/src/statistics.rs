//! Bounded database operation observations; counters reset when a backend opens.

/// Operation labels in the fixed order of the [`DatabaseStatistics`] arrays.
pub const DATABASE_OPERATIONS: [&str; 7] = [
    "get",
    "put",
    "delete",
    "batch",
    "durable_batch",
    "scan",
    "prefix_scan",
];

/// Fixed-order read, put, delete, batch, durable batch, full scan and prefix scan statistics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DatabaseStatistics {
    /// Attempts by operation, including failures.
    pub attempts: [u64; DATABASE_OPERATIONS.len()],
    /// Failed operations.
    pub failures: [u64; DATABASE_OPERATIONS.len()],
    /// Total operation wall time in microseconds.
    pub micros: [u64; DATABASE_OPERATIONS.len()],
    /// Total physical SST bytes, including obsolete files, across column families, if available.
    pub sst_bytes: Option<u64>,
    /// Current memtable bytes across column families, if available.
    pub memtable_bytes: Option<u64>,
    /// Pending compaction bytes across column families, if available.
    pub pending_compaction_bytes: Option<u64>,
}
