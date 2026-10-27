//! Transactional deletion plans for proof-backed historical retention.

use neutrin0_consensus_types::Header;
use neutrin0_primitives::{ChainSpec, Hash};
use neutrin0_storage::{Batch, Column, Database};
use std::collections::{BTreeMap, BTreeSet};

use super::{ChainStore, StoreError};
use crate::{RetentionInfo, RetentionPolicy};

pub(super) const RETENTION_KEY: &[u8] = b"history_retention";

/// Per-block source columns keyed by block hash that pruning drops together.
const PER_BLOCK_SOURCE_COLUMNS: [Column; 5] = [
    Column::Blocks,
    Column::BlockProofs,
    Column::BlockStates,
    Column::Witnesses,
    Column::StateDiffs,
];

/// Retained header hashes and every stored header.
type RetainedBlocks = (BTreeSet<Hash>, BTreeMap<Hash, Header>);

mod blocks;

#[cfg(test)]
mod tests;

impl<DB: Database> ChainStore<DB> {
    /// Read local retention metadata; a fresh database has no deleted history.
    pub fn retention_info(&self) -> Result<RetentionInfo, StoreError<DB::Error>> {
        let info: RetentionInfo = self
            .get_decoded(Column::Meta, RETENTION_KEY)?
            .unwrap_or_default();
        // An archive keeps every source from genesis, or from a hard fork's
        // start, the only bootstrap an archive takes.
        if info.first_retained_height == 0
            || (info.policy == RetentionPolicy::Archive
                && info.pruned_before_chunk != 0
                && info.pruned_before_chunk != self.bootstrap_source_floor()?)
        {
            return Err(StoreError::Corrupt("invalid retention metadata"));
        }
        Ok(info)
    }

    pub(crate) fn retention_info_for_spec(
        &self,
        spec: &ChainSpec,
    ) -> Result<RetentionInfo, StoreError<DB::Error>> {
        let info = self.retention_info()?;
        if info
            .pruned_before_chunk
            .checked_mul(spec.consensus.chunk_size)
            .and_then(|height| height.checked_add(1))
            != Some(info.first_retained_height)
        {
            return Err(StoreError::Corrupt(
                "retention height disagrees with chain specification",
            ));
        }
        Ok(info)
    }

    pub(crate) fn set_retention_policy(
        &mut self,
        policy: RetentionPolicy,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut info = self.retention_info()?;
        let stored = info.policy;
        let archive = stored == RetentionPolicy::Archive;
        if policy == RetentionPolicy::Archive
            && !archive
            && (info.pruned_before_chunk != 0
                || !self
                    .db
                    .iter_keys(Column::HistoryFrontiers)
                    .map_err(StoreError::Database)?
                    .is_empty())
        {
            return Err(StoreError::Corrupt(
                "archive mode requires restoring complete history",
            ));
        }
        info.policy = policy;
        let mut batch = Batch::new();
        if policy != RetentionPolicy::Reporter {
            for column in [
                Column::ReporterHistory,
                Column::ReporterSources,
                Column::ReporterHeaders,
                Column::ReporterBoundaries,
                Column::ReporterValidators,
                Column::ReporterIndex,
            ] {
                for key in self.db.iter_keys(column).map_err(StoreError::Database)? {
                    batch.delete(column, key);
                }
            }
        }
        if archive && policy != RetentionPolicy::Archive {
            for key in self
                .db
                .iter_keys(Column::HistoryNodes)
                .map_err(StoreError::Database)?
            {
                batch.delete(Column::HistoryNodes, key);
            }
            let current = self.finalized_count()?;
            // Until this batch commits, the stored policy is still the old one.
            self.prune_history_cache_batch(&mut batch, current, stored)?;
            self.prune_history_frontiers_batch(&mut batch, current)?;
        }
        batch.put(Column::Meta, RETENTION_KEY, borsh::to_vec(&info)?);
        self.write_observed_batch(batch, true)
    }

    /// Prepare one deletion batch before changing any live state.
    pub(crate) fn retention_batch(
        &self,
        spec: &ChainSpec,
        info: RetentionInfo,
    ) -> Result<Batch, StoreError<DB::Error>> {
        // Every finalized chunk receipt proves the chain from genesis, so the
        // latest one already covers everything below the watermark.
        let finalized_count = self.finalized_count()?;
        if info.pruned_before_chunk > finalized_count {
            return Err(StoreError::Corrupt("retention watermark exceeds finality"));
        }
        let mut batch = Batch::new();
        // Complete historical records outlive raw blocks for one unbonding
        // delay so recent safety evidence can still be built here. Older
        // reports bring their authenticated opening; pooled paths advance
        // atomically with finalization independently of the bounded cache.
        let record_window = neutrin0_consensus_types::history::history_record_window_chunks(
            spec.runtime.unbonding_delay_blocks,
            spec.consensus.chunk_size,
        );
        let record_floor = finalized_count.saturating_sub(record_window);
        // The latest finalized chunk's proof, statement and start boundary
        // stay even when a bootstrap anchor puts the source floor above it:
        // its receipt is this node's History proof and the proof the next
        // certificate ratifies.
        let consensus_floor = info
            .pruned_before_chunk
            .min(finalized_count.saturating_sub(1));
        self.prune_count_columns(&mut batch, consensus_floor, record_floor)?;
        self.prune_blocks(&mut batch, info, spec.genesis_block_hash)?;
        let policy = self.retention_info()?.policy;
        self.prune_history_cache_batch(&mut batch, finalized_count, policy)?;
        self.prune_evidence(
            &mut batch,
            spec,
            info.pruned_before_chunk.min(
                finalized_count
                    .saturating_sub(neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS),
            ),
            info.pruned_before_chunk.min(record_floor),
        )?;
        batch.put(Column::Meta, RETENTION_KEY, borsh::to_vec(&info)?);
        Ok(batch)
    }

    fn prune_count_columns(
        &self,
        batch: &mut Batch,
        floor: u64,
        record_floor: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        // Every count-keyed column is big-endian, so the entries below a
        // watermark are one bounded key range; nothing above it is read.
        // Retained chunk proofs are keyed by chunk id then statement key and
        // follow the chunk proof window.
        for key in self
            .db
            .keys_below(Column::ChunkReceipts, &floor.to_be_bytes())
            .map_err(StoreError::Database)?
        {
            batch.delete(Column::ChunkReceipts, key);
        }
        for column in [
            Column::Chunks,
            Column::ChunkProofs,
            Column::ChunkStatements,
            Column::HistoricalChunks,
            Column::ValidatorSetSnapshots,
            Column::ConsensusBoundaries,
        ] {
            // Complete historical records outlive the block window.
            let upper = if column == Column::HistoricalChunks {
                floor.min(record_floor)
            } else {
                floor
            };
            for key in self
                .db
                .keys_below(column, &upper.to_be_bytes())
                .map_err(StoreError::Database)?
            {
                // The genesis boundary stays an authenticated anchor.
                if column == Column::ConsensusBoundaries && decode_count(&key)? == 0 {
                    continue;
                }
                batch.delete(column, key);
            }
        }
        Ok(())
    }

    /// Release evidence no retaining node can still use: liveness receipts,
    /// kept abandoned headers and finalized-offence records below
    /// `liveness_floor`, and
    /// every receipt or report against an identity a finalized block has
    /// already sanctioned. Safety receipts have no age floor and leave only
    /// through those finalized facts, never on unfinalized head state.
    fn prune_evidence(
        &self,
        batch: &mut Batch,
        spec: &ChainSpec,
        liveness_floor: u64,
        record_floor: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        self.drop_stale_evidence_batch(batch, |artifact| {
            !artifact.statement.kind.is_safety()
                && artifact.statement.context.chunk_id < liveness_floor
        })?;
        // Chunk `c` starts at height `c * chunk_size + 1`.
        self.prune_abandoned_headers_batch(
            batch,
            liveness_floor
                .saturating_mul(spec.consensus.chunk_size)
                .saturating_add(1),
        )?;
        for (key, evidence) in self.iter_slashing_evidence()? {
            let Ok(chunk_id) = neutrin0_prover_chunk::history::evidence_chunk_id(spec, &evidence)
            else {
                continue;
            };
            let accused = self.historical_chunk(chunk_id)?.and_then(|source| {
                source
                    .validators
                    .get(evidence.offender_index() as usize)
                    .map(|validator| validator.pubkey)
            });
            let accused_slashed = if let Some(pubkey) = accused {
                self.is_identity_slashed(&pubkey)?
            } else {
                false
            };
            if accused_slashed {
                batch.delete(Column::SlashingPool, key);
            }
        }
        // Finalized offence identities only guard the bounded pool; past the
        // record window nothing can cite them. Finalized safety identities are
        // permanent, like the runtime tombstone they mirror.
        for (key, bytes) in self
            .db
            .iter_column(Column::FinalizedOffences)
            .map_err(StoreError::Database)?
        {
            let height = decode_count(&bytes)?;
            if height
                .checked_sub(1)
                .and_then(|h| h.checked_div(spec.consensus.chunk_size))
                .is_some_and(|id| id < record_floor)
            {
                batch.delete(Column::FinalizedOffences, key);
            }
        }
        Ok(())
    }
}

pub(super) fn decode_count<E>(key: &[u8]) -> Result<u64, StoreError<E>> {
    key.try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| StoreError::Corrupt("invalid retained count key"))
}
