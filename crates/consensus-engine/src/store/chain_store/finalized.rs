//! Finalized chunk records, validator-set snapshots and the pointers of the
//! `Finalized` column.

use neutrin0_consensus_types::{Chunk, ChunkProof, FinalityCert};
use neutrin0_primitives::{BlockHash, CheckpointIndex, ChunkId, Seed};
use neutrin0_storage::{Batch, Column, Database};

use super::{ChainStore, ValidatorSetSnapshot};
use crate::store::{StoreError, keys, pointers};

impl<DB: Database> ChainStore<DB> {
    // ---------- Chunks ----------

    /// Persist `chunk` keyed by `chunk.chunk_id`.
    pub fn put_chunk(&mut self, chunk: &Chunk) -> Result<(), StoreError<DB::Error>> {
        self.put_encoded(Column::Chunks, &keys::chunk_id_key(chunk.chunk_id), chunk)
    }

    /// Read the chunk with id `chunk_id`.
    pub fn get_chunk(&self, chunk_id: ChunkId) -> Result<Option<Chunk>, StoreError<DB::Error>> {
        self.get_decoded(Column::Chunks, &keys::chunk_id_key(chunk_id))
    }

    /// Persist a chunk proof keyed by chunk id.
    pub fn put_chunk_proof(
        &mut self,
        chunk_id: ChunkId,
        proof: &ChunkProof,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_encoded(Column::ChunkProofs, &keys::chunk_id_key(chunk_id), proof)
    }

    /// Read a chunk proof by chunk id.
    pub fn get_chunk_proof(
        &self,
        chunk_id: ChunkId,
    ) -> Result<Option<ChunkProof>, StoreError<DB::Error>> {
        self.get_decoded(Column::ChunkProofs, &keys::chunk_id_key(chunk_id))
    }

    /// Read the finality certificate this node finalized `chunk_id` with,
    /// kept once, in the chunk's historical record.
    pub fn get_finality_cert(
        &self,
        chunk_id: ChunkId,
    ) -> Result<Option<FinalityCert>, StoreError<DB::Error>> {
        Ok(self
            .historical_chunk(chunk_id)?
            .map(|record| record.finality))
    }

    // ---------- Validator-set snapshots ----------

    /// Persist a validator-set snapshot keyed by checkpoint index.
    pub fn put_validator_set_snapshot(
        &mut self,
        index: CheckpointIndex,
        snapshot: &ValidatorSetSnapshot,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_encoded(
            Column::ValidatorSetSnapshots,
            &keys::checkpoint_index_key(index),
            snapshot,
        )
    }

    /// Read a validator-set snapshot by checkpoint index.
    pub fn get_validator_set_snapshot(
        &self,
        index: CheckpointIndex,
    ) -> Result<Option<ValidatorSetSnapshot>, StoreError<DB::Error>> {
        self.get_decoded(
            Column::ValidatorSetSnapshots,
            &keys::checkpoint_index_key(index),
        )
    }

    // ---------- Pointers (Finalized column) ----------

    /// Read the tip pointer.
    pub fn get_tip(&self) -> Result<Option<BlockHash>, StoreError<DB::Error>> {
        self.get_fixed(Column::Finalized, pointers::TIP, "invalid tip hash")
    }

    /// Write the finalized-head pointer to `hash`.
    pub fn put_finalized_head(&mut self, hash: BlockHash) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(Column::Finalized, pointers::FINALIZED_HEAD, &hash)
    }

    /// Read the finalized-head pointer.
    pub fn get_finalized_head(&self) -> Result<Option<BlockHash>, StoreError<DB::Error>> {
        self.get_fixed(
            Column::Finalized,
            pointers::FINALIZED_HEAD,
            "invalid block hash pointer",
        )
    }

    /// Write the latest finalized chunk id.
    pub fn put_latest_finalized_chunk_id(
        &mut self,
        id: ChunkId,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(
            Column::Finalized,
            pointers::LATEST_FINALIZED_CHUNK_ID,
            &keys::chunk_id_key(id),
        )
    }

    /// Read the latest finalized chunk id.
    pub fn get_latest_finalized_chunk_id(&self) -> Result<Option<ChunkId>, StoreError<DB::Error>> {
        self.get_integer_pointer(pointers::LATEST_FINALIZED_CHUNK_ID)
    }

    /// Persist a validator-set snapshot and make it the latest in one
    /// durable batch, so a crash never leaves the index naming a missing set.
    pub fn put_latest_validator_set(
        &mut self,
        index: CheckpointIndex,
        snapshot: &ValidatorSetSnapshot,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut batch = Batch::new();
        batch.put(
            Column::ValidatorSetSnapshots,
            keys::checkpoint_index_key(index),
            borsh::to_vec(snapshot)?,
        );
        batch.put(
            Column::Finalized,
            pointers::LATEST_VALIDATOR_SET_INDEX,
            keys::checkpoint_index_key(index),
        );
        self.write_observed_batch(batch, true)
    }

    /// Read the latest validator-set snapshot index.
    pub fn get_latest_validator_set_index(
        &self,
    ) -> Result<Option<CheckpointIndex>, StoreError<DB::Error>> {
        self.get_integer_pointer(pointers::LATEST_VALIDATOR_SET_INDEX)
    }

    /// Read the currently active VRF seed.
    pub fn get_finalized_seed(&self) -> Result<Option<Seed>, StoreError<DB::Error>> {
        self.get_fixed(
            Column::Finalized,
            pointers::FINALIZED_SEED,
            "invalid seed pointer",
        )
    }
}
