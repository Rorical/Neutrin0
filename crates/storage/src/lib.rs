#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Column-family storage backends for Neutrin0.
//!
//! The crate exposes one small [`Database`] trait, an atomic [`Batch`]
//! write type, a fast in-memory backend for tests and dev harnesses, and
//! a feature-gated RocksDB backend for persistent nodes.

extern crate alloc;

mod batch;
mod column;
#[cfg(feature = "std")]
mod memory;
mod statistics;
pub use statistics::{DATABASE_OPERATIONS, DatabaseStatistics};

#[cfg(feature = "rocksdb")]
mod rocks;

pub use batch::{Batch, BatchOp, decode_count};
pub use column::{ALL_COLUMNS, Column};
#[cfg(feature = "std")]
pub use memory::MemoryDatabase;

#[cfg(feature = "rocksdb")]
pub use rocks::{RocksDbDatabase, RocksDbError};

use alloc::vec::Vec;

/// Snapshot type returned by [`Database::iter_column`].
///
/// A list of owned `(key, value)` byte pairs. Factored into a type
/// alias because clippy flags the nested
/// `Result<Vec<(Vec<u8>, Vec<u8>)>, _>` shape as overly complex when
/// used inline.
pub type ColumnSnapshot = Vec<(Vec<u8>, Vec<u8>)>;

/// Point reads of a database's live contents, shared across threads and
/// outliving any borrow of the database. Writes stay with the database's owner.
#[cfg(feature = "std")]
pub trait ReadHandle: Send + Sync {
    /// Reads a value by column and key; a backend failure is reported as text.
    ///
    /// # Errors
    /// Returns the backend's failure description.
    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, alloc::string::String>;
}

/// Minimal column-family key-value database interface.
pub trait Database {
    /// Backend-specific error type.
    type Error;

    /// Obtain bounded backend statistics without scanning records.
    fn statistics(&self) -> Option<DatabaseStatistics> {
        None
    }

    /// Reads a value by column and key.
    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// A thread-safe reader that sees every later committed write.
    #[cfg(feature = "std")]
    fn read_handle(&self) -> std::sync::Arc<dyn ReadHandle>;

    /// The first `limit` entries of `column` whose keys are at or after
    /// `from`, in key order. Persistent backends seek to `from` and stop after
    /// `limit` instead of reading the column, so callers can page through it.
    fn entries_from(
        &self,
        column: Column,
        from: &[u8],
        limit: usize,
    ) -> Result<ColumnSnapshot, Self::Error> {
        let mut entries: ColumnSnapshot = self
            .iter_column(column)?
            .into_iter()
            .filter(|(key, _)| key.as_slice() >= from)
            .collect();
        entries.sort();
        entries.truncate(limit);
        Ok(entries)
    }

    /// The first `limit` keys of `column` at or after `from`, in key order,
    /// without loading or copying values, so a caller can page through rows
    /// whose payloads may be large.
    fn keys_from(
        &self,
        column: Column,
        from: &[u8],
        limit: usize,
    ) -> Result<Vec<Vec<u8>>, Self::Error> {
        Ok(self
            .entries_from(column, from, limit)?
            .into_iter()
            .map(|(key, _)| key)
            .collect())
    }

    /// Writes a value by column and key.
    fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;

    /// Deletes a value by column and key. Deleting a missing key is a
    /// no-op.
    fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), Self::Error>;

    /// Applies every operation in `batch` atomically. If this returns
    /// an error, callers must assume none of the operations became
    /// visible. Backends that cannot provide that guarantee should not
    /// implement this trait.
    fn write_batch(&mut self, batch: Batch) -> Result<(), Self::Error>;

    /// Atomically commit a batch and make it durable before returning success.
    ///
    /// Persistent backends must synchronize their write-ahead log to stable
    /// storage. An error has uncertain durability, so callers must not sign or
    /// publish an artifact authorized by a failed operation. In-memory backends
    /// provide atomicity for their lifetime; they are not persistent validators.
    fn write_batch_durable(&mut self, batch: Batch) -> Result<(), Self::Error>;

    /// Snapshot every `(key, value)` pair currently stored in `column`.
    ///
    /// Ordering is implementation-defined; callers wanting numeric
    /// iteration over big-endian keys can sort the result. The pairs
    /// are returned by value so backends can read them lazily without
    /// keeping internal iterators alive across other database
    /// operations.
    fn iter_column(&self, column: Column) -> Result<ColumnSnapshot, Self::Error>;

    /// Snapshot only keys beginning with `prefix`.
    ///
    /// Persistent backends should seek directly to the prefix. The default is
    /// suitable for small custom test backends; ordinary backends override it.
    fn iter_prefix(&self, column: Column, prefix: &[u8]) -> Result<ColumnSnapshot, Self::Error> {
        Ok(self
            .iter_column(column)?
            .into_iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .collect())
    }

    /// Snapshot every key in `column` without loading or copying its value.
    ///
    /// Pruning only needs keys; persistent backends override this so a scan
    /// never materializes the column's payloads.
    fn iter_keys(&self, column: Column) -> Result<Vec<Vec<u8>>, Self::Error> {
        Ok(self
            .iter_column(column)?
            .into_iter()
            .map(|(key, _)| key)
            .collect())
    }

    /// Snapshot the keys of `column` strictly below `upper` in byte order.
    ///
    /// Big-endian count keys make this the set of entries below a watermark;
    /// persistent backends stop at `upper` instead of reading the column.
    fn keys_below(&self, column: Column, upper: &[u8]) -> Result<Vec<Vec<u8>>, Self::Error> {
        Ok(self
            .iter_keys(column)?
            .into_iter()
            .filter(|key| key.as_slice() < upper)
            .collect())
    }
}
