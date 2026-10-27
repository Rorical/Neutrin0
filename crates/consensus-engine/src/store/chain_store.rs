//! `ChainStore`: typed wrapper around a column-family
//! [`Database`](neutrin0_storage::Database).

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{BlockHash, Hash, Seed, Validator};
use neutrin0_storage::{Column, Database};

use super::{StoreError, keys, pointers};

extern crate alloc;

mod abandoned;
mod blocks;
mod evidence_pool;
mod finalization;
mod finalized;
mod receipts;
mod slashing_pool;

#[cfg(test)]
mod tests;

pub use receipts::{StoredChunkReceipt, StoredReceipt};
#[expect(
    clippy::redundant_pub_crate,
    reason = "Re-exported crate-wide by the store module."
)]
pub(crate) use receipts::{chunk_receipt_key, receipt_key};

/// Borsh-encoded validator-set snapshot.
///
/// The list is stored exactly as the engine's view of the active set at
/// a given checkpoint index; consumers can re-derive the validator-set
/// Merkle root over `(pubkey, stake, status)` from this list.
pub type ValidatorSetSnapshot = Vec<Validator>;

/// Typed access layer over a column-family
/// [`Database`](neutrin0_storage::Database) for the consensus engine.
///
/// `ChainStore` owns the [`Database`] and exposes one method per record
/// type. Every value is borsh-encoded and every integer key is
/// big-endian, so backends are interchangeable (memory or RocksDB) and
/// iteration over numeric keys matches numeric order.
#[derive(Debug)]
pub struct ChainStore<DB> {
    pub(super) db: DB,
    pub(super) history_record_window: u64,
    pub(super) reporter_stats_dirty: bool,
}

impl<DB> ChainStore<DB> {
    /// Wrap a database.
    #[must_use]
    pub const fn new(db: DB) -> Self {
        Self {
            db,
            history_record_window: neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS,
            reporter_stats_dirty: true,
        }
    }

    /// Configure the local record service horizon from the authenticated specification.
    pub(crate) fn configure_history_window(&mut self, window: u64) {
        self.history_record_window =
            window.max(neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS);
    }

    /// Borrow the wrapped database.
    #[must_use]
    pub const fn db(&self) -> &DB {
        &self.db
    }

    /// Mutably borrow the wrapped database.
    pub const fn db_mut(&mut self) -> &mut DB {
        // Raw database access can bypass observed writes. Rebuild once before
        // trusting the aggregate again, rather than serving stale inventories.
        self.reporter_stats_dirty = true;
        &mut self.db
    }

    /// Consume the store and return the wrapped database.
    pub fn into_db(self) -> DB {
        self.db
    }
}

impl<DB: Database> ChainStore<DB> {
    // ---------- Generic helpers ----------

    /// Visit every entry of `column` under `prefix` in key order, reading a
    /// page at a time so a scan never holds the column in memory.
    pub(super) fn scan_prefix(
        &self,
        column: Column,
        prefix: &[u8],
        mut visit: impl FnMut(Vec<u8>, Vec<u8>) -> Result<(), StoreError<DB::Error>>,
    ) -> Result<(), StoreError<DB::Error>> {
        const PAGE: usize = 256;
        let mut from = prefix.to_vec();
        loop {
            let page = self
                .db
                .entries_from(column, &from, PAGE)
                .map_err(StoreError::Database)?;
            let full = page.len() == PAGE;
            for (key, value) in page {
                if !key.starts_with(prefix) {
                    return Ok(());
                }
                // The next page starts just after this key.
                from.clone_from(&key);
                from.push(0);
                visit(key, value)?;
            }
            if !full {
                return Ok(());
            }
        }
    }

    /// Encode and write one value; observed columns stay counted via [`Self::put_raw`].
    pub(super) fn put_encoded<T: BorshSerialize>(
        &mut self,
        column: Column,
        key: &[u8],
        value: &T,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(column, key, &borsh::to_vec(value)?)
    }

    pub(super) fn get_decoded<T: BorshDeserialize>(
        &self,
        column: Column,
        key: &[u8],
    ) -> Result<Option<T>, StoreError<DB::Error>> {
        let raw = self.db.get(column, key).map_err(StoreError::Database)?;
        match raw {
            Some(bytes) => {
                let value = T::try_from_slice(&bytes)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    /// Decode a value whose embedded identity must agree with its key. A
    /// disagreement reports `mismatch` as corruption.
    pub(super) fn get_checked<T: BorshDeserialize>(
        &self,
        column: Column,
        key: &[u8],
        matches_key: impl FnOnce(&T) -> bool,
        mismatch: &'static str,
    ) -> Result<Option<T>, StoreError<DB::Error>> {
        let value: Option<T> = self.get_decoded(column, key)?;
        if value.as_ref().is_some_and(|value| !matches_key(value)) {
            return Err(StoreError::Corrupt(mismatch));
        }
        Ok(value)
    }

    /// Read a fixed-width raw value. A stored value of another length reports
    /// `invalid` as corruption.
    fn get_fixed<const N: usize>(
        &self,
        column: Column,
        key: &[u8],
        invalid: &'static str,
    ) -> Result<Option<[u8; N]>, StoreError<DB::Error>> {
        self.get_raw(column, key)?
            .map(|bytes| {
                <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| StoreError::Corrupt(invalid))
            })
            .transpose()
    }

    /// Read a big-endian integer pointer from the `Finalized` column.
    fn get_integer_pointer(&self, key: &[u8]) -> Result<Option<u64>, StoreError<DB::Error>> {
        Ok(self
            .get_fixed::<8>(Column::Finalized, key, "invalid integer pointer")?
            .map(u64::from_be_bytes))
    }

    /// Number of finalized chunks, which is also the next chunk to finalize.
    pub(super) fn finalized_count(&self) -> Result<u64, StoreError<DB::Error>> {
        Ok(self
            .get_latest_finalized_chunk_id()?
            .map_or(0, |id| id.saturating_add(1)))
    }

    pub(super) fn put_raw(
        &mut self,
        column: Column,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StoreError<DB::Error>> {
        if super::reporter_metrics::observed_column(column) || column == Column::Finalized {
            let mut batch = neutrin0_storage::Batch::new();
            batch.put(column, key, value);
            self.write_observed_batch(batch, false)
        } else {
            self.db
                .put(column, key, value)
                .map_err(StoreError::Database)
        }
    }

    pub(super) fn get_raw(
        &self,
        column: Column,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, StoreError<DB::Error>> {
        self.db.get(column, key).map_err(StoreError::Database)
    }

    // ---------- Meta ----------

    /// Every genesis metadata row and pointer except the tip, which
    /// [`Self::commit_tip`] adds when it writes this batch. The chain-spec
    /// hash marks the database initialised, so nothing of genesis is
    /// durable without the rest.
    pub(crate) fn genesis_batch(
        chain_spec_hash: Hash,
        validators: &ValidatorSetSnapshot,
        genesis_hash: BlockHash,
        seed: Seed,
    ) -> Result<neutrin0_storage::Batch, StoreError<DB::Error>> {
        let mut batch = neutrin0_storage::Batch::new();
        batch.put(Column::Meta, pointers::CHAIN_SPEC_HASH, chain_spec_hash);
        batch.delete(Column::Meta, pointers::SIGNING_TRANSFER_SPEC);
        batch.put(
            Column::ValidatorSetSnapshots,
            keys::checkpoint_index_key(0),
            borsh::to_vec(validators)?,
        );
        batch.put(Column::Finalized, pointers::FINALIZED_HEAD, genesis_hash);
        batch.put(Column::Finalized, pointers::FINALIZED_SEED, seed);
        Ok(batch)
    }

    /// Write the chain-spec hash to metadata.
    pub fn put_chain_spec_hash(&mut self, hash: Hash) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(Column::Meta, pointers::CHAIN_SPEC_HASH, &hash)
    }

    /// Read the chain-spec hash. Absent metadata is `None`; malformed bytes
    /// are corruption, never an uninitialised database that genesis may
    /// overwrite.
    pub fn get_chain_spec_hash(&self) -> Result<Option<Hash>, StoreError<DB::Error>> {
        self.get_fixed(
            Column::Meta,
            pointers::CHAIN_SPEC_HASH,
            "invalid chain spec hash",
        )
    }
}
