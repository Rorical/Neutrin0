//! Retained signed headers and historical boundaries: each canonical or
//! observed header kept as its proposer's side of a possible double proposal.

use neutrin0_consensus_types::Header;
use neutrin0_consensus_types::history_proof::ConsensusBoundary;
use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
use neutrin0_primitives::{BlsPublicKey, Hash, Validator};
use neutrin0_prover_chunk::history::HistoricalChunk;
use neutrin0_storage::{Batch, Column, Database};
use std::collections::BTreeSet;

use super::{
    HEADER_LOOKUP, HEADER_STEP, Owned, SOURCE_LOOKUP, inventory_key, lookup_key, put_owned,
    put_reporter_boundary_batch, source_key, statement_key,
};
use crate::RetentionPolicy;
use crate::store::{ChainStore, StoreError};

impl<DB: Database> ChainStore<DB> {
    pub(super) fn put_reporter_header_batch(
        &self,
        batch: &mut Batch,
        chunk: u64,
        header: &Header,
        owners: &[BlsPublicKey],
    ) -> Result<(), StoreError<DB::Error>> {
        let hash = header.hash();
        let key = source_key(chunk, hash);
        let mut all = owners.to_vec();
        if let Some(prior) =
            self.staged_decoded::<Owned<Header>>(batch, Column::ReporterHeaders, &key)?
        {
            all.extend(prior.owners);
        }
        all.sort_unstable();
        all.dedup();
        if !all.is_empty() {
            put_owned(batch, Column::ReporterHeaders, key, &all, header)?;
            let lookup = lookup_key(HEADER_LOOKUP, &hash);
            let mut chunks: Vec<u64> = self
                .staged_decoded(batch, Column::ReporterIndex, &lookup)?
                .unwrap_or_default();
            chunks.push(chunk);
            chunks.sort_unstable();
            chunks.dedup();
            batch.put(Column::ReporterIndex, lookup, borsh::to_vec(&chunks)?);
        }
        Ok(())
    }

    /// Compact saved boundary used for forensic source verification, never live BFT admission.
    pub fn reporter_boundary(
        &self,
        count: u64,
    ) -> Result<Option<ConsensusBoundary>, StoreError<DB::Error>> {
        self.get_decoded::<Owned<ConsensusBoundary>>(
            Column::ReporterBoundaries,
            &count.to_be_bytes(),
        )
        .map(|entry| entry.map(|e| e.value))
    }

    /// Retain a signed header and its parent dependency without retaining its block body.
    pub fn retain_reporter_header(
        &mut self,
        chunk: u64,
        header: &Header,
        validators: &[Validator],
    ) -> Result<(), StoreError<DB::Error>> {
        if self.retention_info()?.policy != RetentionPolicy::Reporter {
            return Ok(());
        }
        let count = self.finalized_count()?;
        if chunk > count {
            return Ok(());
        }
        let mut batch = Batch::new();
        let context = self.reporter_context_batch(&mut batch, chunk)?;
        if context.validators != validators {
            return Err(StoreError::Corrupt("reporter header validator context"));
        }
        let Some(owner) = context
            .validators
            .get(header.proposer_index as usize)
            .map(|v| v.pubkey)
            .filter(|key| context.owners.contains(key))
        else {
            return Ok(());
        };
        let hash = header.hash();
        // A header already kept for its proposer, a canonical one included,
        // needs no statement entry that could later evict it.
        if self
            .get_decoded::<Owned<Header>>(Column::ReporterHeaders, &source_key(chunk, hash))?
            .is_some_and(|entry| entry.owners.contains(&owner))
            || !self.admit_statement_batch(
                &mut batch,
                chunk,
                &owner,
                (header.slot, HEADER_STEP, hash),
                hash,
            )?
        {
            return Ok(());
        }
        self.put_reporter_header_batch(&mut batch, chunk, header, &[owner])?;
        self.write_observed_batch(batch, true)
    }

    pub(in crate::store) fn retain_reporter_finalization_batch(
        &self,
        batch: &mut Batch,
        record: &HistoricalChunk,
        boundary: &ConsensusBoundary,
        headers: impl Iterator<Item = Header>,
    ) -> Result<(), StoreError<DB::Error>> {
        if self.retention_info()?.policy != RetentionPolicy::Reporter {
            return Ok(());
        }
        put_reporter_boundary_batch(batch, record, boundary)?;
        // Each canonical header stays as its proposer's side of a double
        // proposal. Canonical receipts are not copied: the Chunk Guest verified
        // every one, so accepting one can never be an offence.
        let chunk = record.chunk.chunk_id;
        let mut canonical = BTreeSet::new();
        for header in headers {
            let hash = header.hash();
            canonical.insert(hash);
            if let Some(owner) = record
                .validators
                .get(header.proposer_index as usize)
                .map(|v| v.pubkey)
            {
                self.put_reporter_header_batch(batch, chunk, &header, &[owner])?;
                // A canonical header is kept outright, outside its proposer's cap.
                batch.delete(
                    Column::ReporterIndex,
                    statement_key(chunk, &owner, header.slot, HEADER_STEP, &hash),
                );
            }
        }
        // A vote's receipt dependency copied before finality is released once
        // it is exactly a retained, verified receipt of a canonical block: a
        // valid receipt never supports `InvalidProofSigning`.
        for source in self.reporter_sources_for_chunk(chunk)? {
            let SignedArtifact::BlockProof(proof) = &source else {
                continue;
            };
            let block = proof.public_inputs.block_hash;
            if !canonical.contains(&block)
                || self
                    .block_receipt_by_key(&block, &proof.statement_key)?
                    .is_none_or(|stored| stored.proof != *proof)
            {
                continue;
            }
            let id = source.id();
            batch.delete(Column::ReporterIndex, lookup_key(SOURCE_LOOKUP, &id));
            batch.delete(Column::ReporterIndex, inventory_key(chunk, id));
            batch.delete(Column::ReporterSources, source_key(chunk, id));
        }
        Ok(())
    }

    /// Saved compact header dependency for exact historical block proof authentication.
    pub fn reporter_header(&self, hash: &Hash) -> Result<Option<Header>, StoreError<DB::Error>> {
        let Some(chunks): Option<Vec<u64>> =
            self.get_decoded(Column::ReporterIndex, &lookup_key(HEADER_LOOKUP, hash))?
        else {
            return Ok(None);
        };
        let chunk = chunks
            .first()
            .ok_or(StoreError::Corrupt("reporter header lookup empty"))?;
        let entry: Owned<Header> = self
            .get_decoded(Column::ReporterHeaders, &source_key(*chunk, *hash))?
            .ok_or(StoreError::Corrupt("reporter header lookup dangling"))?;
        if entry.value.hash() != *hash {
            return Err(StoreError::Corrupt("reporter header key"));
        }
        Ok(Some(entry.value))
    }

    /// Saved signed headers for restoring objective proposer and VRF detection.
    pub fn reporter_headers_for_chunk(
        &self,
        chunk: u64,
    ) -> Result<Vec<Header>, StoreError<DB::Error>> {
        self.db
            .iter_prefix(Column::ReporterHeaders, &chunk.to_be_bytes())
            .map_err(StoreError::Database)?
            .into_iter()
            .map(|(_, bytes)| {
                let entry: Owned<Header> = borsh::from_slice(&bytes)?;
                Ok(entry.value)
            })
            .collect()
    }
}
