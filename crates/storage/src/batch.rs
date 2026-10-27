//! Atomic write batch shared by storage backends.

use alloc::vec::Vec;

use crate::Column;

/// One write operation inside a [`Batch`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchOp {
    /// Store `value` at `(column, key)`, replacing any previous value.
    Put {
        /// Target column.
        column: Column,
        /// Key bytes.
        key: Vec<u8>,
        /// Value bytes.
        value: Vec<u8>,
    },
    /// Delete the entry at `(column, key)` if it exists.
    Delete {
        /// Target column.
        column: Column,
        /// Key bytes.
        key: Vec<u8>,
    },
    /// Add `delta` to the little-endian `i64` counter at `(column, key)`; a
    /// missing counter starts at zero. Backends apply it without reading the
    /// counter first (a RocksDB merge), so callers never pay a read to count.
    AddCount {
        /// Target column.
        column: Column,
        /// Key bytes.
        key: Vec<u8>,
        /// Signed change.
        delta: i64,
    },
}

/// Decode a counter [`BatchOp::AddCount`] maintains.
#[must_use]
pub fn decode_count(bytes: &[u8]) -> Option<i64> {
    Some(i64::from_le_bytes(bytes.try_into().ok()?))
}

/// Ordered batch of write operations applied atomically by a [`Database`](crate::Database).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Batch {
    ops: Vec<BatchOp>,
}

impl Batch {
    /// Creates an empty batch.
    #[must_use]
    pub const fn new() -> Self {
        Self { ops: Vec::new() }
    }

    /// Creates an empty batch with capacity for `capacity` operations.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            ops: Vec::with_capacity(capacity),
        }
    }

    /// Adds a put operation.
    pub fn put(&mut self, column: Column, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) {
        self.ops.push(BatchOp::Put {
            column,
            key: key.into(),
            value: value.into(),
        });
    }

    /// Adds a delete operation.
    pub fn delete(&mut self, column: Column, key: impl Into<Vec<u8>>) {
        self.ops.push(BatchOp::Delete {
            column,
            key: key.into(),
        });
    }

    /// Adds a counter change; see [`BatchOp::AddCount`].
    pub fn add_count(&mut self, column: Column, key: impl Into<Vec<u8>>, delta: i64) {
        self.ops.push(BatchOp::AddCount {
            column,
            key: key.into(),
            delta,
        });
    }

    /// Returns true when no operations are queued.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Number of operations in the batch.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.ops.len()
    }

    /// Borrows the ordered operation list.
    #[must_use]
    pub fn operations(&self) -> &[BatchOp] {
        &self.ops
    }

    /// Consumes the batch and returns the ordered operation list.
    #[must_use]
    pub fn into_operations(self) -> Vec<BatchOp> {
        self.ops
    }
}

#[cfg(test)]
mod tests;
