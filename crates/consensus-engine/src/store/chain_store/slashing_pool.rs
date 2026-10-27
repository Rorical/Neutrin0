//! The durable pool of raw slashing evidence awaiting proof.

use alloc::vec::Vec;

use borsh::BorshDeserialize;
use neutrin0_consensus_types::SlashingEvidence;
use neutrin0_primitives::Hash;
use neutrin0_storage::{Column, Database};

use super::ChainStore;
use crate::store::StoreError;

extern crate alloc;

impl<DB: Database> ChainStore<DB> {
    // ---------- Slashing pool ----------

    /// Persist one slashing-evidence item under
    /// [`Column::SlashingPool`]. Key is BLAKE3 of the borsh-encoded
    /// evidence so two detectors that observe the same equivocation
    /// produce the same key (de-dup is free).
    ///
    /// A node that detects equivocation and crashes before its next
    /// produced block must not lose the evidence. Every `pool_and_gossip_slashing` / restore site in
    /// `ChainBackend` mirrors its in-memory write here so a fresh
    /// `ChainBackend::new` rehydrates the prior observations via
    /// [`Self::iter_slashing_evidence`].
    ///
    /// Returns `Ok(())` for new and duplicate inserts alike; the
    /// caller is responsible for de-duplicating in memory.
    pub fn put_slashing_evidence(
        &mut self,
        evidence: &SlashingEvidence,
    ) -> Result<Hash, StoreError<DB::Error>> {
        let bytes = borsh::to_vec(evidence)?;
        let key = neutrin0_primitives::blake3_256(&bytes);
        self.put_raw(Column::SlashingPool, &key, &bytes)?;
        Ok(key)
    }

    /// Delete one persisted slashing-evidence item. `key` is the
    /// BLAKE3 of the borsh-encoded evidence returned by
    /// [`Self::put_slashing_evidence`]. Deleting a missing key is a
    /// no-op so restart loops never trip over already-drained items.
    pub fn delete_slashing_evidence(&mut self, key: &Hash) -> Result<(), StoreError<DB::Error>> {
        let mut batch = neutrin0_storage::Batch::new();
        batch.delete(Column::SlashingPool, key);
        self.write_observed_batch(batch, false)
    }

    /// Iterate every persisted slashing-evidence item. Returns
    /// `(content_hash, evidence)` pairs; a row that does not decode is
    /// corruption.
    ///
    /// Iteration order is implementation-defined. Callers that need
    /// FIFO order must track it separately; the in-memory pool's
    /// `Vec` already preserves it within a single session and the
    /// load-from-disk path uses arbitrary order (post-restart all
    /// loaded items become an unordered batch — semantically fine
    /// because evidence ordering does not affect slashing outcomes).
    pub fn iter_slashing_evidence(
        &self,
    ) -> Result<Vec<(Hash, SlashingEvidence)>, StoreError<DB::Error>> {
        let mut out = Vec::new();
        for (key, value) in self
            .db
            .iter_column(Column::SlashingPool)
            .map_err(StoreError::Database)?
        {
            let hash = Hash::try_from(key.as_slice())
                .map_err(|_| StoreError::Corrupt("slashing pool key"))?;
            let evidence = SlashingEvidence::try_from_slice(&value).map_err(StoreError::Codec)?;
            out.push((hash, evidence));
        }
        Ok(out)
    }
}
