//! RocksDB-backed persistent [`Database`](crate::Database) implementation.

use alloc::{boxed::Box, string::String, vec::Vec};
use core::fmt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamilyDescriptor, DB, IteratorMode, MergeOperands, Options,
    WriteBatch,
};

use crate::{
    ALL_COLUMNS, Batch, BatchOp, Column, ColumnSnapshot, DATABASE_OPERATIONS, Database, ReadHandle,
    decode_count,
};

/// Block cache shared by the state columns. Trie nodes are content addressed,
/// so execution and queries read them as random point lookups; a bloom filter
/// per table answers absent hashes and the cache keeps the trie's upper levels.
const STATE_BLOCK_CACHE_BYTES: usize = 256 << 20;

/// Error returned by [`RocksDbDatabase`].
#[derive(Debug)]
pub enum RocksDbError {
    /// RocksDB returned an error.
    RocksDb(rocksdb::Error),
    /// The database was opened without the expected column family.
    MissingColumn(Column),
}

impl fmt::Display for RocksDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RocksDb(err) => write!(f, "rocksdb error: {err}"),
            Self::MissingColumn(column) => {
                write!(f, "rocksdb column family {} is missing", column.name())
            }
        }
    }
}

impl std::error::Error for RocksDbError {}

impl From<rocksdb::Error> for RocksDbError {
    fn from(value: rocksdb::Error) -> Self {
        Self::RocksDb(value)
    }
}

/// Persistent RocksDB storage backend.
pub struct RocksDbDatabase {
    db: Arc<DB>,
    metrics: Box<OperationMetrics>,
}

/// Live reader sharing a [`RocksDbDatabase`]'s handle.
struct SharedDb(Arc<DB>);

impl ReadHandle for SharedDb {
    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let cf = self
            .0
            .cf_handle(column.name())
            .ok_or_else(|| RocksDbError::MissingColumn(column).to_string())?;
        self.0.get_cf(&cf, key).map_err(|error| error.to_string())
    }
}

/// Associative sum behind [`BatchOp::AddCount`]. A malformed counter fails the
/// merge, which RocksDB then reports as corruption when the key is read.
fn add_counts(_key: &[u8], existing: Option<&[u8]>, operands: &MergeOperands) -> Option<Vec<u8>> {
    let mut total = existing.map_or(Some(0), decode_count)?;
    for operand in operands {
        total = total.checked_add(decode_count(operand)?)?;
    }
    Some(total.to_le_bytes().to_vec())
}

fn column_options(column: Column, state_cache: &Cache) -> Options {
    let mut options = Options::default();
    options.set_merge_operator_associative("neutrin0_add_counts", add_counts);
    if matches!(
        column,
        Column::TrieNodes | Column::StateValues | Column::StateRefs
    ) {
        let mut table = BlockBasedOptions::default();
        table.set_block_cache(state_cache);
        table.set_bloom_filter(10.0, false);
        table.set_cache_index_and_filter_blocks(true);
        table.set_pin_l0_filter_and_index_blocks_in_cache(true);
        options.set_block_based_table_factory(&table);
    }
    options
}

#[derive(Default)]
struct OperationMetrics {
    attempts: [AtomicU64; DATABASE_OPERATIONS.len()],
    failures: [AtomicU64; DATABASE_OPERATIONS.len()],
    micros: [AtomicU64; DATABASE_OPERATIONS.len()],
}

/// Index into [`DATABASE_OPERATIONS`].
#[derive(Clone, Copy)]
enum Operation {
    Get,
    Put,
    Delete,
    Batch,
    DurableBatch,
    Scan,
    PrefixScan,
}

impl fmt::Debug for RocksDbDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `rocksdb::DB` does not implement `Debug` and exposing its
        // internals would not be useful anyway; a stable opaque label
        // keeps consumers like the node `Debug` derives happy.
        f.debug_struct("RocksDbDatabase").finish_non_exhaustive()
    }
}

impl RocksDbDatabase {
    /// Opens or creates a database at `path`, creating every Neutrin0
    /// column family if it is missing.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RocksDbError> {
        let mut options = Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        // RocksDB keeps every informational LOG file by default, and a rarely
        // written column family pins old write-ahead logs until it flushes.
        // Cap both so disk use follows the data itself.
        options.set_max_log_file_size(32 << 20);
        options.set_keep_log_file_num(4);
        options.set_max_total_wal_size(1 << 30);

        let state_cache = Cache::new_lru_cache(STATE_BLOCK_CACHE_BYTES);
        let descriptors = ALL_COLUMNS.iter().map(|column| {
            ColumnFamilyDescriptor::new(column.name(), column_options(*column, &state_cache))
        });
        let db = DB::open_cf_descriptors(&options, path, descriptors)?;
        Ok(Self {
            db: Arc::new(db),
            metrics: Box::default(),
        })
    }

    fn observe<T>(
        &self,
        operation: Operation,
        run: impl FnOnce() -> Result<T, RocksDbError>,
    ) -> Result<T, RocksDbError> {
        let index = operation as usize;
        let started = Instant::now();
        let result = run();
        self.metrics.attempts[index].fetch_add(1, Ordering::Relaxed);
        if result.is_err() {
            self.metrics.failures[index].fetch_add(1, Ordering::Relaxed);
        }
        self.metrics.micros[index].fetch_add(
            u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        result
    }

    fn summed_property(&self, name: &str) -> Option<u64> {
        ALL_COLUMNS.iter().try_fold(0_u64, |sum, column| {
            let cf = self.cf(*column).ok()?;
            sum.checked_add(self.db.property_int_value_cf(&cf, name).ok()??)
        })
    }

    fn cf(&self, column: Column) -> Result<impl rocksdb::AsColumnFamilyRef + '_, RocksDbError> {
        self.db
            .cf_handle(column.name())
            .ok_or(RocksDbError::MissingColumn(column))
    }

    /// Translate `batch` into one RocksDB write batch, failing on the first
    /// operation that names a missing column.
    fn to_write_batch(&self, batch: Batch) -> Result<WriteBatch, RocksDbError> {
        let mut write_batch = WriteBatch::default();
        for op in batch.into_operations() {
            match op {
                BatchOp::Put { column, key, value } => {
                    write_batch.put_cf(&self.cf(column)?, key, value);
                }
                BatchOp::Delete { column, key } => {
                    write_batch.delete_cf(&self.cf(column)?, key);
                }
                BatchOp::AddCount { column, key, delta } => {
                    write_batch.merge_cf(&self.cf(column)?, key, delta.to_le_bytes());
                }
            }
        }
        Ok(write_batch)
    }
}

impl Database for RocksDbDatabase {
    type Error = RocksDbError;

    fn statistics(&self) -> Option<crate::DatabaseStatistics> {
        Some(crate::DatabaseStatistics {
            attempts: core::array::from_fn(|index| {
                self.metrics.attempts[index].load(Ordering::Relaxed)
            }),
            failures: core::array::from_fn(|index| {
                self.metrics.failures[index].load(Ordering::Relaxed)
            }),
            micros: core::array::from_fn(|index| {
                self.metrics.micros[index].load(Ordering::Relaxed)
            }),
            sst_bytes: self.summed_property("rocksdb.total-sst-files-size"),
            memtable_bytes: self.summed_property("rocksdb.cur-size-all-mem-tables"),
            pending_compaction_bytes: self
                .summed_property("rocksdb.estimate-pending-compaction-bytes"),
        })
    }

    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        self.observe(Operation::Get, || {
            let cf = self.cf(column)?;
            self.db.get_cf(&cf, key).map_err(Into::into)
        })
    }

    fn read_handle(&self) -> Arc<dyn ReadHandle> {
        Arc::new(SharedDb(Arc::clone(&self.db)))
    }

    fn entries_from(
        &self,
        column: Column,
        from: &[u8],
        limit: usize,
    ) -> Result<ColumnSnapshot, Self::Error> {
        self.observe(Operation::PrefixScan, || {
            let cf = self.cf(column)?;
            let mut out = Vec::new();
            for entry in self
                .db
                .iterator_cf(&cf, IteratorMode::From(from, rocksdb::Direction::Forward))
                .take(limit)
            {
                let (key, value) = entry?;
                out.push((key.into_vec(), value.into_vec()));
            }
            Ok(out)
        })
    }

    fn keys_from(
        &self,
        column: Column,
        from: &[u8],
        limit: usize,
    ) -> Result<Vec<Vec<u8>>, Self::Error> {
        self.observe(Operation::PrefixScan, || {
            let cf = self.cf(column)?;
            let mut iterator = self.db.raw_iterator_cf(&cf);
            iterator.seek(from);
            let mut out = Vec::new();
            while out.len() < limit
                && let Some(key) = iterator.key()
            {
                out.push(key.to_vec());
                iterator.next();
            }
            iterator.status()?;
            Ok(out)
        })
    }

    fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        self.observe(Operation::Put, || {
            let cf = self.cf(column)?;
            self.db.put_cf(&cf, key, value).map_err(Into::into)
        })
    }

    fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), Self::Error> {
        self.observe(Operation::Delete, || {
            let cf = self.cf(column)?;
            self.db.delete_cf(&cf, key).map_err(Into::into)
        })
    }

    fn write_batch(&mut self, batch: Batch) -> Result<(), Self::Error> {
        self.observe(Operation::Batch, || {
            let write_batch = self.to_write_batch(batch)?;
            self.db.write(write_batch).map_err(Into::into)
        })
    }

    fn write_batch_durable(&mut self, batch: Batch) -> Result<(), Self::Error> {
        self.observe(Operation::DurableBatch, || {
            let write_batch = self.to_write_batch(batch)?;
            let mut options = rocksdb::WriteOptions::default();
            options.set_sync(true);
            options.disable_wal(false);
            self.db.write_opt(write_batch, &options).map_err(Into::into)
        })
    }

    fn iter_column(&self, column: Column) -> Result<ColumnSnapshot, Self::Error> {
        self.observe(Operation::Scan, || {
            let cf = self.cf(column)?;
            let mut out = Vec::new();
            for entry in self.db.iterator_cf(&cf, IteratorMode::Start) {
                let (key, value) = entry?;
                out.push((key.into_vec(), value.into_vec()));
            }
            Ok(out)
        })
    }

    fn iter_prefix(&self, column: Column, prefix: &[u8]) -> Result<ColumnSnapshot, Self::Error> {
        self.observe(Operation::PrefixScan, || {
            let cf = self.cf(column)?;
            let mut out = Vec::new();
            for entry in self
                .db
                .iterator_cf(&cf, IteratorMode::From(prefix, rocksdb::Direction::Forward))
            {
                let (key, value) = entry?;
                if !key.starts_with(prefix) {
                    break;
                }
                out.push((key.into_vec(), value.into_vec()));
            }
            Ok(out)
        })
    }

    fn iter_keys(&self, column: Column) -> Result<Vec<Vec<u8>>, Self::Error> {
        self.observe(Operation::Scan, || self.keys_until(column, None))
    }

    fn keys_below(&self, column: Column, upper: &[u8]) -> Result<Vec<Vec<u8>>, Self::Error> {
        self.observe(Operation::PrefixScan, || {
            self.keys_until(column, Some(upper))
        })
    }
}

impl RocksDbDatabase {
    /// Walk keys from the start of `column` with a raw iterator, which never
    /// copies values, stopping before `upper`.
    fn keys_until(
        &self,
        column: Column,
        upper: Option<&[u8]>,
    ) -> Result<Vec<Vec<u8>>, RocksDbError> {
        let cf = self.cf(column)?;
        let mut iterator = self.db.raw_iterator_cf(&cf);
        iterator.seek_to_first();
        let mut out = Vec::new();
        while let Some(key) = iterator.key() {
            if upper.is_some_and(|upper| key >= upper) {
                break;
            }
            out.push(key.to_vec());
            iterator.next();
        }
        iterator.status()?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
