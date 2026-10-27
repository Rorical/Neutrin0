//! Backend-selection wrapper exposed by the node binary.
//!
//! [`NodeDb`] picks between an in-memory backend (used by tests and
//! ephemeral test containers that do not configure `data_dir`) and the
//! persistent RocksDB backend that is the production default. Keeping
//! both behind a single enum avoids leaking generic plumbing into the
//! producer, the engine wrapper, and the runner.

use std::path::Path;

use neutrin0_storage::{
    Batch, Column, ColumnSnapshot, Database, MemoryDatabase, RocksDbDatabase, RocksDbError,
};
use thiserror::Error;

/// Persistent or ephemeral database selected at node startup.
#[derive(Debug)]
pub enum NodeDb {
    /// In-memory backend; data is dropped when the process exits.
    Memory(MemoryDatabase),
    /// RocksDB backend rooted at a `data_dir` directory.
    Rocks(RocksDbDatabase),
}

/// Error returned by [`NodeDb`].
#[derive(Debug, Error)]
pub enum NodeDbError {
    /// Underlying RocksDB error.
    #[error("rocksdb: {0}")]
    Rocks(#[from] RocksDbError),
}

impl NodeDb {
    /// Open the RocksDB backend at `path`, creating it if necessary.
    pub fn open_rocks(path: impl AsRef<Path>) -> Result<Self, NodeDbError> {
        Ok(Self::Rocks(RocksDbDatabase::open(path)?))
    }

    /// Build a fresh in-memory backend.
    #[must_use]
    pub fn memory() -> Self {
        Self::Memory(MemoryDatabase::new())
    }
}

impl From<core::convert::Infallible> for NodeDbError {
    fn from(never: core::convert::Infallible) -> Self {
        match never {}
    }
}

/// Forward one operation to whichever backend is selected.
macro_rules! delegate {
    ($self:expr, $db:ident => $call:expr) => {
        match $self {
            Self::Memory($db) => $call.map_err(NodeDbError::from),
            Self::Rocks($db) => $call.map_err(NodeDbError::from),
        }
    };
}

impl Database for NodeDb {
    type Error = NodeDbError;

    fn statistics(&self) -> Option<neutrin0_storage::DatabaseStatistics> {
        match self {
            Self::Memory(db) => db.statistics(),
            Self::Rocks(db) => db.statistics(),
        }
    }

    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        delegate!(self, db => db.get(column, key))
    }

    fn read_handle(&self) -> std::sync::Arc<dyn neutrin0_storage::ReadHandle> {
        match self {
            Self::Memory(db) => db.read_handle(),
            Self::Rocks(db) => db.read_handle(),
        }
    }

    fn entries_from(
        &self,
        column: Column,
        from: &[u8],
        limit: usize,
    ) -> Result<ColumnSnapshot, Self::Error> {
        delegate!(self, db => db.entries_from(column, from, limit))
    }

    fn keys_from(
        &self,
        column: Column,
        from: &[u8],
        limit: usize,
    ) -> Result<Vec<Vec<u8>>, Self::Error> {
        delegate!(self, db => db.keys_from(column, from, limit))
    }

    fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        delegate!(self, db => db.put(column, key, value))
    }

    fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), Self::Error> {
        delegate!(self, db => db.delete(column, key))
    }

    fn write_batch(&mut self, batch: Batch) -> Result<(), Self::Error> {
        delegate!(self, db => db.write_batch(batch))
    }

    fn write_batch_durable(&mut self, batch: Batch) -> Result<(), Self::Error> {
        delegate!(self, db => db.write_batch_durable(batch))
    }

    fn iter_column(&self, column: Column) -> Result<ColumnSnapshot, Self::Error> {
        delegate!(self, db => db.iter_column(column))
    }

    fn iter_prefix(&self, column: Column, prefix: &[u8]) -> Result<ColumnSnapshot, Self::Error> {
        delegate!(self, db => db.iter_prefix(column, prefix))
    }

    fn iter_keys(&self, column: Column) -> Result<Vec<Vec<u8>>, Self::Error> {
        delegate!(self, db => db.iter_keys(column))
    }

    fn keys_below(&self, column: Column, upper: &[u8]) -> Result<Vec<Vec<u8>>, Self::Error> {
        delegate!(self, db => db.keys_below(column, upper))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_prefix_reads_keep_the_bounded_backend_scan() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "neutrin0-node-prefix-{}-{unique}",
            std::process::id()
        ));
        {
            let mut db = NodeDb::open_rocks(&path).unwrap();
            db.put(Column::Meta, b"wanted:a", b"a").unwrap();
            db.put(Column::Meta, b"other:b", b"b").unwrap();
            assert_eq!(
                db.iter_prefix(Column::Meta, b"wanted:").unwrap(),
                vec![(b"wanted:a".to_vec(), b"a".to_vec())]
            );
            let stats = db.statistics().unwrap();
            assert_eq!(stats.attempts[5], 0, "no full-column scan");
            assert_eq!(stats.attempts[6], 1, "one bounded prefix scan");
        }
        std::fs::remove_dir_all(path).unwrap();
    }
}
