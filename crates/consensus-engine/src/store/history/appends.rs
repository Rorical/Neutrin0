//! Appending one finalized record to the bounded frontier and pruning the
//! cached openings and frontiers below the retention window.

use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::history::{HistoryFrontier, HistoryPath, counted_history_root};
use neutrin0_primitives::Hash;
use neutrin0_prover_chunk::history::HistoricalChunk;
use neutrin0_storage::{Batch, Column, Database};

use super::{decode_history_path_key, put_history_frontier, put_history_path, put_path_nodes};
use crate::RetentionPolicy;
use crate::store::{ChainStore, StoreError, keys};

impl<DB: Database> ChainStore<DB> {
    /// Append one finalized record and refresh bounded openings in the same batch.
    /// Pruned nodes store no binary history nodes; archives retain the complete tree.
    pub(crate) fn append_history_batch(
        &self,
        batch: &mut Batch,
        record: &HistoricalChunk,
    ) -> Result<HistoryFrontier, StoreError<DB::Error>> {
        let index = record.chunk.chunk_id;
        let (old_frontier, _) = self.history_snapshot(index)?;
        let leaf = commitment(&record.evidence_context());
        let path = old_frontier
            .append_path(leaf)
            .ok_or(StoreError::Corrupt("invalid history append path"))?;
        let mut frontier = old_frontier.clone();
        let expected = frontier
            .append(leaf)
            .ok_or(StoreError::Corrupt("invalid history append"))?;
        let policy = self.retention_info()?.policy;
        if policy == RetentionPolicy::Archive {
            let root = put_path_nodes(batch, leaf, &path)?;
            if counted_history_root(frontier.count, root) != expected {
                return Err(StoreError::Corrupt("history append/frontier disagreement"));
            }
        }
        for (_, bytes) in self
            .db
            .iter_prefix(Column::HistoryPaths, &index.to_be_bytes())
            .map_err(StoreError::Database)?
        {
            let (prior_leaf, mut prior): (Hash, HistoryPath) = borsh::from_slice(&bytes)?;
            if prior.index < frontier.count.saturating_sub(self.history_record_window) {
                continue;
            }
            if prior.advance(prior_leaf, &old_frontier, leaf) != Some(expected) {
                return Err(StoreError::Corrupt("history opening advance"));
            }
            put_history_path(batch, &prior, prior_leaf, expected)?;
        }
        put_history_path(batch, &path, leaf, expected)?;
        put_history_frontier(batch, &frontier)?;
        batch.put(
            Column::HistoricalChunks,
            keys::chunk_id_key(index),
            borsh::to_vec(record)?,
        );
        self.advance_evidence_reports_batch(batch, &old_frontier, leaf)?;
        self.advance_reporter_history_batch(batch, record, &old_frontier, &path, policy)?;
        self.prune_history_cache_batch(batch, frontier.count, policy)?;
        Ok(frontier)
    }

    /// `policy` is the stored retention policy, read once by the caller.
    pub(in crate::store) fn prune_history_cache_batch(
        &self,
        batch: &mut Batch,
        current: u64,
        policy: RetentionPolicy,
    ) -> Result<(), StoreError<DB::Error>> {
        let recent =
            current.saturating_sub(neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS);
        for key in self
            .db
            .iter_keys(Column::HistoryPaths)
            .map_err(StoreError::Database)?
        {
            let (count, index) = decode_history_path_key(&key)?;
            let window = if count == current {
                self.history_record_window
            } else {
                neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS
            };
            if !(recent..=current).contains(&count)
                || index < count.saturating_sub(window)
                || index >= count
            {
                batch.delete(Column::HistoryPaths, key);
            }
        }
        if policy != RetentionPolicy::Archive {
            self.prune_history_frontiers_batch(batch, current)?;
        }
        Ok(())
    }

    pub(in crate::store) fn prune_history_frontiers_batch(
        &self,
        batch: &mut Batch,
        current: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        let recent =
            current.saturating_sub(neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS);
        for key in self
            .db
            .iter_keys(Column::HistoryFrontiers)
            .map_err(StoreError::Database)?
        {
            let count = crate::store::retention::decode_count(&key)?;
            if !(recent..=current).contains(&count) {
                batch.delete(Column::HistoryFrontiers, key);
            }
        }
        Ok(())
    }
}
