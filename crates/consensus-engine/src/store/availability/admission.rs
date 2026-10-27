//! Admission of signed sources under the peer and local budgets, and the
//! exact-pointer compaction of accepted receipts.

use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
use neutrin0_primitives::{ChunkId, Hash};
use neutrin0_storage::{Batch, Column, Database};

use super::{
    MAX_LOCAL_SIGNED_ARTIFACT_BYTES, MAX_LOCAL_SIGNED_ARTIFACTS, MAX_PEER_SIGNED_ARTIFACT_BYTES,
    MAX_PEER_SIGNED_ARTIFACTS, SignedArtifactMetadata, StoredArtifact, StoredPayload,
    delete_metadata, put_metadata,
};
use crate::{ChainStore, RetentionPolicy, StoreError};

impl<DB: Database> ChainStore<DB> {
    /// Persist a checked source before publication; peer capacity excludes local reserve.
    pub fn put_signed_artifact(
        &mut self,
        chunk_id: ChunkId,
        artifact: &SignedArtifact,
    ) -> Result<Hash, StoreError<DB::Error>> {
        self.put_signed_artifact_with_priority(chunk_id, artifact, false, &[])
    }
    /// Reserved capacity for completed local signatures and actual lock dependencies.
    pub fn put_local_signed_artifact(
        &mut self,
        chunk_id: ChunkId,
        artifact: &SignedArtifact,
    ) -> Result<Hash, StoreError<DB::Error>> {
        self.put_signed_artifact_with_priority(chunk_id, artifact, true, &[])
    }
    /// Atomically replace superseded local publication slots, preserving actual locks.
    pub fn put_local_signed_artifact_protected(
        &mut self,
        chunk_id: ChunkId,
        artifact: &SignedArtifact,
        protected: &[Hash],
    ) -> Result<Hash, StoreError<DB::Error>> {
        self.put_signed_artifact_with_priority(chunk_id, artifact, true, protected)
    }

    fn put_signed_artifact_with_priority(
        &mut self,
        chunk_id: ChunkId,
        artifact: &SignedArtifact,
        local: bool,
        protected: &[Hash],
    ) -> Result<Hash, StoreError<DB::Error>> {
        let id = artifact.id();
        if self.readmit_retained_artifact(chunk_id, id, artifact, local)? {
            return Ok(id);
        }
        let bytes = self.stored_artifact_bytes(chunk_id, artifact)?;
        let policy = self.retention_info()?.policy;
        let archive = policy == RetentionPolicy::Archive;
        let incoming = SignedArtifactMetadata::for_artifact(chunk_id, id, artifact)?;
        let (removed, count, size) = self.budget_after_supersession(
            chunk_id,
            &incoming,
            local,
            archive,
            protected,
            bytes.len(),
        )?;
        let (count_limit, size_limit) = if local {
            (MAX_LOCAL_SIGNED_ARTIFACTS, MAX_LOCAL_SIGNED_ARTIFACT_BYTES)
        } else {
            (MAX_PEER_SIGNED_ARTIFACTS, MAX_PEER_SIGNED_ARTIFACT_BYTES)
        };
        if count >= count_limit || size > size_limit {
            if policy == RetentionPolicy::Reporter {
                self.retain_reporter_source_with(chunk_id, id, artifact, policy)?;
                if self.reporter_source(&id)?.is_some() {
                    return Ok(id);
                }
            }
            return Err(StoreError::Corrupt(
                "signed artifact capacity; defer publication",
            ));
        }
        let mut metadata = incoming;
        metadata.local = local;
        metadata.storage_bytes =
            u64::try_from(bytes.len()).map_err(|_| StoreError::Corrupt("source size overflow"))?;
        let mut batch = Batch::new();
        self.retain_reporter_source_batch(&mut batch, chunk_id, id, artifact, policy)?;
        for removed_id in removed {
            batch.delete(Column::SignedArtifacts, removed_id);
            delete_metadata(&mut batch, chunk_id, removed_id);
        }
        batch.put(Column::SignedArtifacts, id, bytes);
        put_metadata(&mut batch, &metadata)?;
        self.write_observed_batch(batch, true)?;
        Ok(id)
    }

    /// Whether `artifact` is already retained under `id`. A differing source
    /// at that identity is corruption; a retained one is handed to reporter
    /// retention again and may move to the local budget.
    fn readmit_retained_artifact(
        &mut self,
        chunk_id: ChunkId,
        id: Hash,
        artifact: &SignedArtifact,
        local: bool,
    ) -> Result<bool, StoreError<DB::Error>> {
        let Some((source, prior)) = self.signed_artifact(&id)? else {
            return Ok(false);
        };
        if source != chunk_id || prior != *artifact {
            return Err(StoreError::Corrupt("signed artifact identity conflict"));
        }
        let policy = self.retention_info()?.policy;
        self.retain_reporter_source_with(chunk_id, id, artifact, policy)?;
        // A peer record this node now publishes moves to the local budget
        // only while that budget has room; otherwise it stays retained
        // under the peer budget it already occupies.
        if local
            && let Some(mut metadata) = self.signed_artifact_metadata_by_id(&id)?
            && !metadata.local
            && self.local_capacity_admits(chunk_id, metadata.storage_bytes)?
        {
            metadata.local = true;
            let mut batch = Batch::new();
            put_metadata(&mut batch, &metadata)?;
            self.write_observed_batch(batch, true)?;
        }
        Ok(true)
    }

    /// The encoded row of `artifact`: a pointer while `BlockProofs` holds the
    /// exact accepted receipt, otherwise the source bytes.
    fn stored_artifact_bytes(
        &self,
        chunk_id: ChunkId,
        artifact: &SignedArtifact,
    ) -> Result<Vec<u8>, StoreError<DB::Error>> {
        let payload = if let SignedArtifact::BlockProof(proof) = artifact {
            if self.get_block_proof(&proof.block_hash)?.as_ref() == Some(proof) {
                StoredPayload::AcceptedBlockProof(proof.block_hash)
            } else {
                StoredPayload::Source(Box::new(artifact.clone()))
            }
        } else {
            StoredPayload::Source(Box::new(artifact.clone()))
        };
        Ok(borsh::to_vec(&StoredArtifact { chunk_id, payload })?)
    }

    /// The superseded local slots `incoming` replaces, and the record count
    /// and byte size its budget would hold once they are gone, counting the
    /// incoming row's `incoming_bytes`.
    fn budget_after_supersession(
        &self,
        chunk_id: ChunkId,
        incoming: &SignedArtifactMetadata,
        local: bool,
        archive: bool,
        protected: &[Hash],
        incoming_bytes: usize,
    ) -> Result<(Vec<Hash>, usize, usize), StoreError<DB::Error>> {
        let mut removed = Vec::new();
        let mut count = 0_usize;
        let mut size = incoming_bytes;
        let retained = if archive {
            self.signed_artifact_metadata_for_chunk(chunk_id)?
        } else {
            self.active_signed_artifact_metadata()?
        };
        for existing in retained {
            let superseded = local
                && !archive
                && existing.local
                && existing.chunk_id == chunk_id
                && existing.kind == incoming.kind
                && existing.phase == incoming.phase
                && existing
                    .round
                    .zip(incoming.round)
                    .is_some_and(|(old, new)| old < new)
                && !protected.contains(&existing.id);
            if superseded {
                removed.push(existing.id);
                continue;
            }
            if (!archive || existing.chunk_id == chunk_id) && existing.local == local {
                count += 1;
                size = size
                    .saturating_add(usize::try_from(existing.storage_bytes).unwrap_or(usize::MAX));
            }
        }
        Ok((removed, count, size))
    }

    /// Whether one more local record of `storage_bytes` fits the local budget.
    fn local_capacity_admits(
        &self,
        chunk_id: ChunkId,
        storage_bytes: u64,
    ) -> Result<bool, StoreError<DB::Error>> {
        let archive = self.retention_info()?.policy == RetentionPolicy::Archive;
        let retained = if archive {
            self.signed_artifact_metadata_for_chunk(chunk_id)?
        } else {
            self.active_signed_artifact_metadata()?
        };
        let (mut count, mut size) = (
            0_usize,
            usize::try_from(storage_bytes).unwrap_or(usize::MAX),
        );
        for existing in retained.iter().filter(|existing| existing.local) {
            count += 1;
            size =
                size.saturating_add(usize::try_from(existing.storage_bytes).unwrap_or(usize::MAX));
        }
        Ok(count < MAX_LOCAL_SIGNED_ARTIFACTS && size <= MAX_LOCAL_SIGNED_ARTIFACT_BYTES)
    }

    /// Replace duplicate bytes with an exact pointer after normal proof admission.
    pub fn compact_accepted_artifact(
        &mut self,
        proof: &neutrin0_consensus_types::BlockProof,
    ) -> Result<(), StoreError<DB::Error>> {
        let artifact = SignedArtifact::BlockProof(proof.clone());
        let id = artifact.id();
        if self.get_block_proof(&proof.block_hash)?.as_ref() != Some(proof) {
            return Ok(());
        }
        let Some((source, prior)) = self.signed_artifact(&id)? else {
            return Ok(());
        };
        if prior != artifact {
            return Err(StoreError::Corrupt("accepted artifact pointer mismatch"));
        }
        let bytes = borsh::to_vec(&StoredArtifact {
            chunk_id: source,
            payload: StoredPayload::AcceptedBlockProof(proof.block_hash),
        })?;
        let Some(mut metadata) = self.signed_artifact_metadata_by_id(&id)? else {
            return Ok(());
        };
        metadata.storage_bytes =
            u64::try_from(bytes.len()).map_err(|_| StoreError::Corrupt("source size overflow"))?;
        let mut batch = Batch::new();
        batch.put(Column::SignedArtifacts, id, bytes);
        put_metadata(&mut batch, &metadata)?;
        self.write_observed_batch(batch, true)
    }

    /// Keep an accepted receipt addressable once `BlockProofs` stops holding it.
    ///
    /// A compacted pointer row becomes the exact source bytes again, in the
    /// same batch that replaces the receipt.
    pub(crate) fn expand_accepted_artifact_batch(
        &self,
        batch: &mut Batch,
        proof: &neutrin0_consensus_types::BlockProof,
    ) -> Result<(), StoreError<DB::Error>> {
        let artifact = SignedArtifact::BlockProof(proof.clone());
        let id = artifact.id();
        let Some(bytes) = self
            .db
            .get(Column::SignedArtifacts, &id)
            .map_err(StoreError::Database)?
        else {
            return Ok(());
        };
        let stored: StoredArtifact = borsh::from_slice(&bytes)?;
        if !matches!(stored.payload, StoredPayload::AcceptedBlockProof(_)) {
            return Ok(());
        }
        let bytes = borsh::to_vec(&StoredArtifact {
            chunk_id: stored.chunk_id,
            payload: StoredPayload::Source(Box::new(artifact)),
        })?;
        if let Some(mut metadata) = self.signed_artifact_metadata_by_id(&id)? {
            metadata.storage_bytes = u64::try_from(bytes.len())
                .map_err(|_| StoreError::Corrupt("source size overflow"))?;
            put_metadata(batch, &metadata)?;
        }
        batch.put(Column::SignedArtifacts, id, bytes);
        Ok(())
    }
}
