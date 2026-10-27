//! Openings of historical records under a retained frontier, history
//! witnesses and the startup recheck of the whole cache.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::history::{
    HISTORY_DEPTH, HistoryFrontier, HistoryPath, empty_history_hashes, history_leaf_hash,
};
use neutrin0_primitives::Hash;
use neutrin0_prover_chunk::history::{
    HistoricalContextOpening, HistoricalOpening, HistoryWitness, MAX_HISTORY_CONTEXT_BYTES,
    MAX_HISTORY_READS,
};
use neutrin0_storage::{Column, Database};

use super::{decode_history_path_key, frontier_tree_root};
use crate::RetentionPolicy;
use crate::store::{ChainStore, StoreError, keys};

extern crate alloc;

impl<DB: Database> ChainStore<DB> {
    /// Open a locally cached path or, on an archive, resolve the complete tree.
    /// Older pruned-node claims must carry an authenticated opening from their holder.
    pub fn history_path(
        &self,
        index: u64,
        count: u64,
        leaf: Hash,
    ) -> Result<HistoryPath, StoreError<DB::Error>> {
        if index >= count {
            return Err(StoreError::Corrupt("history index outside boundary"));
        }
        let (frontier, mut cursor) = self.history_snapshot(count)?;
        let expected = frontier
            .root()
            .ok_or(StoreError::Corrupt("invalid frontier"))?;
        if let Some((cached_leaf, path)) = self.get_decoded::<(Hash, HistoryPath)>(
            Column::HistoryPaths,
            &keys::pair_key(count, index),
        )? {
            if cached_leaf != leaf
                || path.index != index
                || path.count != count
                || !path.verify(leaf, expected)
            {
                return Err(StoreError::Corrupt("history opening mismatch"));
            }
            return Ok(path);
        }
        if self.retention_info()?.policy != RetentionPolicy::Archive {
            if let Some(opening) = self.reporter_opening(index)?
                && opening.path.count == count
                && commitment(&opening.record.evidence_context()) == leaf
            {
                return Ok(opening.path);
            }
            return Err(StoreError::Corrupt("history opening is unavailable"));
        }
        let empty = empty_history_hashes();
        let mut siblings = Vec::with_capacity(HISTORY_DEPTH);
        for level in (0..HISTORY_DEPTH).rev() {
            let (left, right) = self.history_children(cursor, level, &empty)?;
            if (index >> level) & 1 == 0 {
                siblings.push(right);
                cursor = left;
            } else {
                siblings.push(left);
                cursor = right;
            }
        }
        siblings.reverse();
        let path = HistoryPath {
            index,
            count,
            siblings,
        };
        if cursor != history_leaf_hash(Some(leaf)) || !path.verify(leaf, expected) {
            return Err(StoreError::Corrupt("history opening mismatch"));
        }
        Ok(path)
    }

    /// Recheck every retained opening and frontier before resuming from disk.
    pub(crate) fn validate_history_cache(&self) -> Result<(), StoreError<DB::Error>> {
        self.validate_reporter_history()?;
        let mut roots = BTreeMap::new();
        for (key, bytes) in self
            .db
            .iter_column(Column::HistoryFrontiers)
            .map_err(StoreError::Database)?
        {
            let count = crate::store::retention::decode_count(&key)?;
            let (frontier, root): (HistoryFrontier, Hash) = borsh::from_slice(&bytes)?;
            if frontier.count != count || frontier_tree_root(&frontier)? != root {
                return Err(StoreError::Corrupt("history frontier root mismatch"));
            }
            if self
                .consensus_boundary(count)?
                .is_some_and(|boundary| frontier.root() != Some(boundary.history_root))
            {
                return Err(StoreError::Corrupt(
                    "history frontier differs from canonical boundary",
                ));
            }
        }
        for (key, bytes) in self
            .db
            .iter_column(Column::HistoryPaths)
            .map_err(StoreError::Database)?
        {
            let (count, index) = decode_history_path_key(&key)?;
            let (leaf, path): (Hash, HistoryPath) = borsh::from_slice(&bytes)?;
            let expected = self
                .cached_history_root(count, &mut roots)?
                .ok_or(StoreError::Corrupt("invalid frontier"))?;
            if path.count != count || path.index != index || !path.verify(leaf, expected) {
                return Err(StoreError::Corrupt("history opening mismatch"));
            }
            if self
                .historical_chunk(index)?
                .is_some_and(|record| commitment(&record.evidence_context()) != leaf)
            {
                return Err(StoreError::Corrupt(
                    "history opening differs from canonical record",
                ));
            }
        }
        if let Some(state) = self.get_consensus_state()? {
            let current = state.boundary.next_chunk_id;
            if self.history_frontier(current)? != state.frontier {
                return Err(StoreError::Corrupt(
                    "history frontier differs from consensus state",
                ));
            }
            for index in current
                .saturating_sub(neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS)
                ..current
            {
                self.historical_opening(index, current)?;
            }
        }
        Ok(())
    }

    /// Open a retained historical record together with its tree path under
    /// the frontier at `count`.
    pub fn historical_opening(
        &self,
        index: u64,
        count: u64,
    ) -> Result<HistoricalOpening, StoreError<DB::Error>> {
        let record = self
            .historical_chunk(index)?
            .ok_or(StoreError::Corrupt("historical record is unavailable"))?;
        let path = self.history_path(index, count, commitment(&record.evidence_context()))?;
        Ok(HistoricalOpening { record, path })
    }

    /// Build a witness containing only the requested historical records.
    pub fn history_witness(
        &self,
        count: u64,
        ids: impl IntoIterator<Item = u64>,
    ) -> Result<HistoryWitness, StoreError<DB::Error>> {
        let mut requested = BTreeSet::new();
        for id in ids {
            if !neutrin0_consensus_types::history::is_recent_history_index(id, count) {
                return Err(StoreError::Corrupt("history index outside boundary"));
            }
            if requested.insert(id) && requested.len() > MAX_HISTORY_READS {
                return Err(StoreError::Corrupt("historical read count"));
            }
        }
        let frontier = self.history_frontier(count)?;
        let mut records = Vec::with_capacity(requested.len());
        let mut remaining = MAX_HISTORY_CONTEXT_BYTES;
        for id in requested {
            let opening = HistoricalContextOpening::from(self.historical_opening(id, count)?);
            remaining = remaining
                .checked_sub(borsh::object_length(&opening.record)?)
                .ok_or(StoreError::Corrupt("historical context byte budget"))?;
            records.push(opening);
        }
        Ok(HistoryWitness { frontier, records })
    }
}
