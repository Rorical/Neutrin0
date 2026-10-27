//! Reading retained sources and their bounded metadata, inventory
//! pagination and pruning below the finalized retention window.

use neutrin0_consensus_types::signed_artifacts::{
    MAX_ARTIFACT_INVENTORY, SignedArtifact, SignedArtifactInventory,
};
use neutrin0_primitives::{ChunkId, Hash};
use neutrin0_storage::{Batch, Column, Database};

use super::{
    METADATA_BY_ID, PRUNED_FLOOR_KEY, SignedArtifactMetadata, StoredArtifact, StoredPayload,
    delete_metadata, metadata_chunk_key, metadata_chunk_prefix, metadata_id_key,
};
use crate::{ChainStore, RetentionPolicy, StoreError};

impl<DB: Database> ChainStore<DB> {
    /// Exact original source; no alternate encoding can satisfy this immutable ID.
    pub fn signed_artifact(
        &self,
        id: &Hash,
    ) -> Result<Option<(ChunkId, SignedArtifact)>, StoreError<DB::Error>> {
        let Some(bytes) = self
            .db
            .get(Column::SignedArtifacts, id)
            .map_err(StoreError::Database)?
        else {
            return self.reporter_source(id);
        };
        let stored: StoredArtifact = borsh::from_slice(&bytes)?;
        let artifact = match stored.payload {
            StoredPayload::Source(artifact) => *artifact,
            StoredPayload::AcceptedBlockProof(block_hash) => {
                if let Some(proof) = self.get_block_proof(&block_hash)? {
                    SignedArtifact::BlockProof(proof)
                } else {
                    return self.reporter_source(id)?.map_or(
                        Err(StoreError::Corrupt("accepted source receipt unavailable")),
                        |source| Ok(Some(source)),
                    );
                }
            }
        };
        if artifact.id() != *id {
            return Err(StoreError::Corrupt("signed artifact key mismatch"));
        }
        Ok(Some((stored.chunk_id, artifact)))
    }

    /// Inspect one dependency row without decoding a receipt.
    pub fn signed_artifact_metadata_by_id(
        &self,
        id: &Hash,
    ) -> Result<Option<SignedArtifactMetadata>, StoreError<DB::Error>> {
        let Some(bytes) = self
            .db
            .get(Column::SignedArtifactIndex, &metadata_id_key(*id))
            .map_err(StoreError::Database)?
        else {
            return Ok(None);
        };
        let metadata: SignedArtifactMetadata = borsh::from_slice(&bytes)?;
        if metadata.id != *id {
            return Err(StoreError::Corrupt("signed source index mismatch"));
        }
        Ok(Some(metadata))
    }

    /// Iterate bounded metadata without decoding every raw source or receipt.
    pub fn signed_artifact_metadata(
        &self,
    ) -> Result<Vec<SignedArtifactMetadata>, StoreError<DB::Error>> {
        self.db
            .iter_prefix(Column::SignedArtifactIndex, &[METADATA_BY_ID])
            .map_err(StoreError::Database)?
            .into_iter()
            .map(|(key, bytes)| {
                let metadata: SignedArtifactMetadata = borsh::from_slice(&bytes)?;
                if key.as_slice() != metadata_id_key(metadata.id) {
                    return Err(StoreError::Corrupt("signed source index mismatch"));
                }
                Ok(metadata)
            })
            .collect()
    }

    /// Whether a retained signed declaration of `chunk_id` names the proof
    /// envelope `id` in its proof manifest.
    ///
    /// # Errors
    /// Returns storage or decoding failures.
    pub fn proof_named_by_declaration(
        &self,
        chunk_id: ChunkId,
        id: &Hash,
    ) -> Result<bool, StoreError<DB::Error>> {
        Ok(self
            .signed_artifact_metadata_for_chunk(chunk_id)?
            .iter()
            .any(|metadata| metadata.proof_hashes.contains(id)))
    }

    /// Read one source chunk without scanning retained proof-lag backlog.
    pub fn signed_artifact_metadata_for_chunk(
        &self,
        chunk_id: ChunkId,
    ) -> Result<Vec<SignedArtifactMetadata>, StoreError<DB::Error>> {
        self.db
            .iter_prefix(
                Column::SignedArtifactIndex,
                &metadata_chunk_prefix(chunk_id),
            )
            .map_err(StoreError::Database)?
            .into_iter()
            .map(|(key, bytes)| {
                let metadata: SignedArtifactMetadata = borsh::from_slice(&bytes)?;
                if metadata.chunk_id != chunk_id
                    || key.as_slice() != metadata_chunk_key(chunk_id, metadata.id)
                {
                    return Err(StoreError::Corrupt("signed source chunk index mismatch"));
                }
                Ok(metadata)
            })
            .collect()
    }

    /// Bound live admission independently of old rows awaiting pruning.
    pub fn active_signed_artifact_metadata(
        &self,
    ) -> Result<Vec<SignedArtifactMetadata>, StoreError<DB::Error>> {
        let next = self
            .get_latest_finalized_chunk_id()?
            .map_or(Some(0), |id| id.checked_add(1))
            .ok_or(StoreError::Corrupt("signed source active window overflow"))?;
        let mut metadata = Vec::new();
        for chunk in
            next.saturating_sub(neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS)..=next
        {
            metadata.extend(self.signed_artifact_metadata_for_chunk(chunk)?);
        }
        Ok(metadata)
    }

    /// Stable bounded pagination over immutable source identities.
    pub fn signed_artifact_inventory(
        &self,
        chunk_id: ChunkId,
        after: Option<Hash>,
    ) -> Result<SignedArtifactInventory, StoreError<DB::Error>> {
        let mut entries: Vec<_> = self
            .signed_artifact_metadata_for_chunk(chunk_id)?
            .into_iter()
            .filter(|metadata| {
                metadata.chunk_id == chunk_id && after.is_none_or(|cursor| metadata.id > cursor)
            })
            .map(
                |metadata| neutrin0_consensus_types::signed_artifacts::SignedArtifactRef {
                    id: metadata.id,
                    kind: metadata.kind,
                },
            )
            .collect();
        entries.extend(
            self.reporter_source_refs(chunk_id)?
                .into_iter()
                .filter(|entry| after.is_none_or(|cursor| entry.id > cursor)),
        );
        entries.sort_by_key(|entry| entry.id);
        entries.dedup_by_key(|entry| entry.id);
        let more = entries.len() > MAX_ARTIFACT_INVENTORY;
        entries.truncate(MAX_ARTIFACT_INVENTORY);
        let next = if more {
            entries.last().map(|entry| entry.id)
        } else {
            None
        };
        Ok(SignedArtifactInventory {
            chunk_id,
            entries,
            next,
        })
    }
    /// Remove obsolete sources only below the finalized retention window.
    pub fn prune_signed_artifacts(
        &mut self,
        first_chunk: ChunkId,
    ) -> Result<(), StoreError<DB::Error>> {
        if self.retention_info()?.policy == RetentionPolicy::Archive
            || first_chunk
                <= self
                    .get_decoded::<u64>(Column::Meta, PRUNED_FLOOR_KEY)?
                    .unwrap_or(0)
        {
            return Ok(());
        }
        let mut batch = Batch::new();
        for metadata in self.signed_artifact_metadata()? {
            if metadata.chunk_id < first_chunk {
                batch.delete(Column::SignedArtifacts, metadata.id);
                delete_metadata(&mut batch, metadata.chunk_id, metadata.id);
            }
        }
        batch.put(Column::Meta, PRUNED_FLOOR_KEY, borsh::to_vec(&first_chunk)?);
        self.write_observed_batch(batch, true)
    }
}
