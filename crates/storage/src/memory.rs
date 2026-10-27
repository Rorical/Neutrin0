//! Fast in-memory [`Database`](crate::Database) backend.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::convert::Infallible;
use core::fmt;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::{Batch, BatchOp, Column, ColumnSnapshot, Database, ReadHandle, decode_count};

type Columns = BTreeMap<Column, BTreeMap<Vec<u8>, Vec<u8>>>;

/// In-memory column store.
///
/// Readers from [`Database::read_handle`] share the live contents, as a
/// persistent backend's readers do; a clone is an independent copy.
#[derive(Default)]
pub struct MemoryDatabase {
    columns: Arc<RwLock<Columns>>,
}

impl Clone for MemoryDatabase {
    fn clone(&self) -> Self {
        Self {
            columns: Arc::new(RwLock::new(self.read().clone())),
        }
    }
}

impl PartialEq for MemoryDatabase {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.columns, &other.columns) || *self.read() == *other.read()
    }
}

impl Eq for MemoryDatabase {}

impl fmt::Debug for MemoryDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryDatabase")
            .field("columns", &*self.read())
            .finish()
    }
}

/// Live reader sharing a [`MemoryDatabase`]'s contents.
struct SharedColumns(Arc<RwLock<Columns>>);

impl ReadHandle for SharedColumns {
    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        Ok(self
            .0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&column)
            .and_then(|values| values.get(key))
            .cloned())
    }
}

impl MemoryDatabase {
    /// Creates an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of entries stored in `column`.
    #[must_use]
    pub fn len(&self, column: Column) -> usize {
        self.read().get(&column).map_or(0, BTreeMap::len)
    }

    /// Whether `column` stores no entries.
    #[must_use]
    pub fn is_empty(&self, column: Column) -> bool {
        self.len(column) == 0
    }

    // A panicking writer leaves whole maps behind, never a torn entry.
    fn read(&self) -> RwLockReadGuard<'_, Columns> {
        self.columns.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, Columns> {
        self.columns.write().unwrap_or_else(PoisonError::into_inner)
    }
}

fn apply_op(columns: &mut Columns, op: BatchOp) {
    match op {
        BatchOp::Put { column, key, value } => {
            columns.entry(column).or_default().insert(key, value);
        }
        BatchOp::Delete { column, key } => remove(columns, column, &key),
        BatchOp::AddCount { column, key, delta } => {
            let values = columns.entry(column).or_default();
            let count = values
                .get(&key)
                .and_then(|bytes| decode_count(bytes))
                .unwrap_or(0)
                .saturating_add(delta);
            values.insert(key, count.to_le_bytes().to_vec());
        }
    }
}

fn remove(columns: &mut Columns, column: Column, key: &[u8]) {
    if let Some(values) = columns.get_mut(&column) {
        values.remove(key);
        if values.is_empty() {
            columns.remove(&column);
        }
    }
}

impl Database for MemoryDatabase {
    type Error = Infallible;

    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self
            .read()
            .get(&column)
            .and_then(|values| values.get(key))
            .cloned())
    }

    fn read_handle(&self) -> Arc<dyn ReadHandle> {
        Arc::new(SharedColumns(Arc::clone(&self.columns)))
    }

    fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        self.write()
            .entry(column)
            .or_default()
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), Self::Error> {
        remove(&mut self.write(), column, key);
        Ok(())
    }

    fn write_batch(&mut self, batch: Batch) -> Result<(), Self::Error> {
        // One write lock covers the whole batch, so readers never observe a
        // partially applied one.
        let mut columns = self.write();
        for op in batch.into_operations() {
            apply_op(&mut columns, op);
        }
        Ok(())
    }

    fn iter_column(&self, column: Column) -> Result<ColumnSnapshot, Self::Error> {
        Ok(self.read().get(&column).map_or_else(Vec::new, |values| {
            values.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        }))
    }

    fn entries_from(
        &self,
        column: Column,
        from: &[u8],
        limit: usize,
    ) -> Result<ColumnSnapshot, Self::Error> {
        Ok(self.read().get(&column).map_or_else(Vec::new, |values| {
            values
                .range(from.to_vec()..)
                .take(limit)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        }))
    }

    fn keys_from(
        &self,
        column: Column,
        from: &[u8],
        limit: usize,
    ) -> Result<Vec<Vec<u8>>, Self::Error> {
        Ok(self.read().get(&column).map_or_else(Vec::new, |values| {
            values
                .range(from.to_vec()..)
                .take(limit)
                .map(|(key, _)| key.clone())
                .collect()
        }))
    }

    fn iter_prefix(&self, column: Column, prefix: &[u8]) -> Result<ColumnSnapshot, Self::Error> {
        Ok(self.read().get(&column).map_or_else(Vec::new, |values| {
            values
                .range(prefix.to_vec()..)
                .take_while(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        }))
    }

    fn iter_keys(&self, column: Column) -> Result<Vec<Vec<u8>>, Self::Error> {
        Ok(self
            .read()
            .get(&column)
            .map_or_else(Vec::new, |values| values.keys().cloned().collect()))
    }

    fn keys_below(&self, column: Column, upper: &[u8]) -> Result<Vec<Vec<u8>>, Self::Error> {
        Ok(self.read().get(&column).map_or_else(Vec::new, |values| {
            values
                .range(..upper.to_vec())
                .map(|(key, _)| key.clone())
                .collect()
        }))
    }

    fn write_batch_durable(&mut self, batch: Batch) -> Result<(), Self::Error> {
        self.write_batch(batch)
    }
}

#[cfg(test)]
mod tests;
