//! Watched historical chunks: their records, the complete History subtrees
//! that open them under the current frontier, and dormant chunks.

use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::history::{
    HISTORY_DEPTH, HistoryFrontier, HistoryPath, HistorySubtree,
};
use neutrin0_consensus_types::history_proof::ConsensusBoundary;
use neutrin0_primitives::Hash;
use neutrin0_prover_chunk::history::{HistoricalChunk, HistoricalOpening};
use neutrin0_storage::{Batch, Column, Database};
use std::collections::{BTreeMap, BTreeSet};

use super::{
    CHUNK_LOOKUP, DORMANT, Owned, ReporterContext, chunk_lookup_key, dormant_key, put_owned,
    put_reporter_opening_batch, put_subtrees, subtree_key,
};
use crate::RetentionPolicy;
use crate::store::{ChainStore, StoreError};

impl<DB: Database> ChainStore<DB> {
    pub(super) fn reporter_context_batch(
        &self,
        batch: &mut Batch,
        chunk: u64,
    ) -> Result<ReporterContext, StoreError<DB::Error>> {
        if let Some(record) = self.reporter_record(chunk)? {
            let owners = self.reporter_owners(&record.validators)?;
            return Ok(ReporterContext {
                validators: record.validators,
                owners,
            });
        }
        let state = self.get_consensus_state()?;
        let count = state.as_ref().map_or_else(
            || self.finalized_count(),
            |state| Ok(state.boundary.next_chunk_id),
        )?;
        if chunk < count {
            let opening = self.historical_opening(chunk, count)?;
            let boundary = self.consensus_boundary(chunk)?;
            return self.promote_reporter_opening_batch(batch, &opening, boundary.as_ref());
        }
        if chunk != count {
            return Err(StoreError::Corrupt("reporter source is not authenticated"));
        }
        let validators = if let Some(state) = state {
            state.next_context.active_validators
        } else {
            self.get_validator_set_snapshot(self.get_latest_validator_set_index()?.unwrap_or(0))?
                .unwrap_or_default()
        };
        Ok(ReporterContext {
            owners: self.reporter_owners(&validators)?,
            validators,
        })
    }

    fn promote_reporter_opening_batch(
        &self,
        batch: &mut Batch,
        opening: &HistoricalOpening,
        boundary: Option<&ConsensusBoundary>,
    ) -> Result<ReporterContext, StoreError<DB::Error>> {
        let mut owners = self.reporter_owners(&opening.record.validators)?;
        let identities = self.accountable_identities(&opening.record.validators)?;
        owners.extend(identities.iter().map(|(key, _)| *key));
        owners.sort_unstable();
        owners.dedup();
        self.merge_reporter_identities_batch(batch, &identities)?;
        if !owners.is_empty() {
            put_reporter_opening_batch(batch, opening, &owners)?;
            if let Some(boundary) = boundary {
                put_owned(
                    batch,
                    Column::ReporterBoundaries,
                    opening.record.chunk.chunk_id.to_be_bytes(),
                    &owners,
                    boundary,
                )?;
            }
        }
        Ok(ReporterContext {
            validators: opening.record.validators.clone(),
            owners,
        })
    }

    pub(in crate::store) fn retain_reporter_bootstrap_batch(
        &self,
        batch: &mut Batch,
        recent: &[HistoricalOpening],
        policy: RetentionPolicy,
    ) -> Result<(), StoreError<DB::Error>> {
        if policy != RetentionPolicy::Reporter {
            return Ok(());
        }
        let mut identities = Vec::new();
        for opening in recent {
            self.promote_reporter_opening_batch(batch, opening, None)?;
            identities.extend(self.accountable_identities(&opening.record.validators)?);
        }
        // Each opening can contain a different account for the same BLS key.
        // Publish their complete union after the individual context writes.
        self.merge_reporter_identities_batch(batch, &identities)
    }

    /// Follow one finalized append. Nothing watched is rewritten: each right
    /// child the append completes is kept when its left neighbour holds a
    /// watched chunk, whose sibling it now is, so the stored subtrees keep
    /// opening every watched chunk at the new count.
    pub(in crate::store) fn advance_reporter_history_batch(
        &self,
        batch: &mut Batch,
        record: &HistoricalChunk,
        old: &HistoryFrontier,
        path: &HistoryPath,
        policy: RetentionPolicy,
    ) -> Result<(), StoreError<DB::Error>> {
        if policy != RetentionPolicy::Reporter {
            return Ok(());
        }
        let leaf = commitment(&record.evidence_context());
        let formed = old
            .completed_subtrees(leaf)
            .ok_or(StoreError::Corrupt("reporter history append"))?;
        for subtree in formed {
            let width = 1_u64 << subtree.level;
            if subtree.start & width != 0
                && self.watches_between(subtree.start - width, subtree.level)?
            {
                put_subtrees(batch, [subtree]);
            }
        }
        // New memberships are retained immediately. The finalized runtime query
        // following this append decides whether they remain economically accountable.
        let identities = self.accountable_identities(&record.validators)?;
        let owners: Vec<_> = identities.iter().map(|(key, _)| *key).collect();
        self.merge_reporter_identities_batch(batch, &identities)?;
        if !owners.is_empty() {
            let opening = HistoricalOpening {
                record: record.clone(),
                path: path.clone(),
            };
            put_reporter_opening_batch(batch, &opening, &owners)?;
        }
        Ok(())
    }

    /// The current opening of a watched chunk, built from its stored subtrees
    /// and verified before its selectively saved context is used. A dormant
    /// chunk opens nothing until it is refreshed.
    pub fn reporter_opening(
        &self,
        chunk: u64,
    ) -> Result<Option<HistoricalOpening>, StoreError<DB::Error>> {
        let frontier = self.history_frontier(self.finalized_count()?)?;
        self.verified_reporter_opening(chunk, &frontier)
    }

    /// A watched chunk's record, whose leaf was authenticated when it was
    /// first saved, whether or not its path is current.
    pub fn reporter_record(
        &self,
        chunk: u64,
    ) -> Result<Option<HistoricalChunk>, StoreError<DB::Error>> {
        Ok(self.reporter_entry(chunk)?.map(|(record, _)| record))
    }

    /// A watched chunk's record and its leaf, authenticated when first saved.
    fn reporter_entry(
        &self,
        chunk: u64,
    ) -> Result<Option<(HistoricalChunk, Hash)>, StoreError<DB::Error>> {
        let Some(entry) = self
            .get_decoded::<Owned<HistoricalChunk>>(Column::ReporterHistory, &chunk.to_be_bytes())?
        else {
            return Ok(None);
        };
        let leaf: Hash = self
            .get_decoded(Column::ReporterIndex, &chunk_lookup_key(chunk))?
            .ok_or(StoreError::Corrupt("reporter watched leaf"))?;
        if entry.owners.is_empty()
            || entry.value.chunk.chunk_id != chunk
            || leaf != commitment(&entry.value.evidence_context())
        {
            return Err(StoreError::Corrupt("reporter historical opening"));
        }
        Ok(Some((entry.value, leaf)))
    }

    /// Open a watched chunk under `frontier` from the stored subtrees. A
    /// dormant chunk lacks some of them and opens nothing.
    pub(super) fn verified_reporter_opening(
        &self,
        chunk: u64,
        frontier: &HistoryFrontier,
    ) -> Result<Option<HistoricalOpening>, StoreError<DB::Error>> {
        let Some((record, leaf)) = self.reporter_entry(chunk)? else {
            return Ok(None);
        };
        if self
            .db
            .get(Column::ReporterIndex, &dormant_key(chunk))
            .map_err(StoreError::Database)?
            .is_some()
        {
            return Ok(None);
        }
        let path = frontier
            .open(chunk, |level, start| self.reporter_subtree(level, start))?
            .ok_or(StoreError::Corrupt("reporter history subtree missing"))?;
        if !frontier.root().is_some_and(|root| path.verify(leaf, root)) {
            return Err(StoreError::Corrupt("reporter historical opening"));
        }
        Ok(Some(HistoricalOpening { record, path }))
    }

    fn reporter_subtree(
        &self,
        level: u8,
        start: u64,
    ) -> Result<Option<Hash>, StoreError<DB::Error>> {
        self.get_decoded(Column::ReporterIndex, &subtree_key(level, start))
    }

    /// Watched chunks a snapshot jump left dormant.
    pub fn reporter_dormant_chunks(&self) -> Result<Vec<u64>, StoreError<DB::Error>> {
        self.db
            .iter_prefix(Column::ReporterIndex, &[DORMANT])
            .map_err(StoreError::Database)?
            .into_iter()
            .map(|(key, _)| {
                key.get(1..)
                    .ok_or(StoreError::Corrupt("reporter dormant key"))
                    .and_then(crate::store::retention::decode_count)
            })
            .collect()
    }

    /// Revive a watched chunk from an opening of its leaf under the current
    /// finalized root: its complete siblings are exactly the subtrees later
    /// appends do not supply. Returns `false` when it opens nothing watched.
    pub(crate) fn refresh_reporter_path(
        &mut self,
        path: &HistoryPath,
        root: Hash,
    ) -> Result<bool, StoreError<DB::Error>> {
        let Some((_, leaf)) = self.reporter_entry(path.index)? else {
            return Ok(false);
        };
        if path.count != self.finalized_count()? || !path.verify(leaf, root) {
            return Ok(false);
        }
        let mut batch = Batch::new();
        put_subtrees(&mut batch, path.complete_siblings());
        batch.delete(Column::ReporterIndex, dormant_key(path.index));
        self.write_observed_batch(batch, true)?;
        Ok(true)
    }

    /// Re-anchor the watched chunks a snapshot's recent openings cover at its
    /// count `frontier`, and mark dormant every other watched chunk whose
    /// subtrees the jump left incomplete. Runs once per bootstrap over every
    /// watched chunk.
    pub(in crate::store) fn refresh_reporter_paths_batch(
        &self,
        batch: &mut Batch,
        recent: &[HistoricalOpening],
        frontier: &HistoryFrontier,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut revealed = BTreeMap::new();
        for opening in recent {
            let chunk = opening.record.chunk.chunk_id;
            let leaf = commitment(&opening.record.evidence_context());
            if self.get_decoded::<Hash>(Column::ReporterIndex, &chunk_lookup_key(chunk))?
                == Some(leaf)
            {
                for sibling in opening.path.complete_siblings() {
                    revealed.insert((sibling.level, sibling.start), sibling.root);
                }
            }
        }
        for chunk in self.reporter_history_chunks()? {
            let opened = frontier.open(chunk, |level, start| {
                revealed.get(&(level, start)).map_or_else(
                    || self.reporter_subtree(level, start),
                    |root| Ok(Some(*root)),
                )
            })?;
            if opened.is_some() {
                batch.delete(Column::ReporterIndex, dormant_key(chunk));
            } else {
                batch.put(Column::ReporterIndex, dormant_key(chunk), Vec::new());
            }
        }
        put_subtrees(
            batch,
            revealed
                .into_iter()
                .map(|((level, start), root)| HistorySubtree { level, start, root }),
        );
        Ok(())
    }

    /// The first watched chunk at or after `from`.
    fn next_watched(&self, from: u64) -> Result<Option<u64>, StoreError<DB::Error>> {
        let first = self
            .db
            .entries_from(Column::ReporterIndex, &chunk_lookup_key(from), 1)
            .map_err(StoreError::Database)?;
        let Some((key, _)) = first
            .first()
            .filter(|(key, _)| key.first() == Some(&CHUNK_LOOKUP))
        else {
            return Ok(None);
        };
        key.get(1..)
            .ok_or(StoreError::Corrupt("reporter chunk lookup key"))
            .and_then(crate::store::retention::decode_count)
            .map(Some)
    }

    /// Whether a watched chunk lies in the aligned `2^level` positions from `start`.
    fn watches_between(&self, start: u64, level: u8) -> Result<bool, StoreError<DB::Error>> {
        let end = u128::from(start) + (1_u128 << level);
        Ok(self
            .next_watched(start)?
            .is_some_and(|chunk| u128::from(chunk) < end))
    }

    /// Delete the subtrees only `removed` watched chunks needed. A chunk's
    /// level sibling pairs with the level block holding the chunk, so it stays
    /// while another watched chunk shares that block. A block known to hold
    /// one makes its parent hold one too, so each level reads at most the
    /// halves no removed chunk lies in.
    pub(super) fn release_reporter_subtrees_batch(
        &self,
        batch: &mut Batch,
        removed: &BTreeSet<u64>,
    ) -> Result<(), StoreError<DB::Error>> {
        // Level blocks holding a removed chunk, and those of them holding
        // nothing watched besides removed chunks; a single leaf holds only itself.
        let mut blocks = removed.clone();
        let mut empty = removed.clone();
        for level in 0..HISTORY_DEPTH {
            let height = u8::try_from(level).expect("history levels fit one byte");
            for block in &empty {
                batch.delete(
                    Column::ReporterIndex,
                    subtree_key(height, (block ^ 1) << level),
                );
            }
            if empty.is_empty() || level + 1 == HISTORY_DEPTH {
                break;
            }
            let parents: BTreeSet<u64> = blocks.iter().map(|block| block >> 1).collect();
            let mut parents_empty = BTreeSet::new();
            for parent in &parents {
                let mut held = false;
                for half in [parent << 1, (parent << 1) | 1] {
                    held = held
                        || (!empty.contains(&half)
                            && (blocks.contains(&half)
                                || self.watches_between(half << level, height)?));
                }
                if !held {
                    parents_empty.insert(*parent);
                }
            }
            blocks = parents;
            empty = parents_empty;
        }
        Ok(())
    }

    /// Watched finalized chunk IDs for restart and delayed dependency discovery.
    pub fn reporter_history_chunks(&self) -> Result<Vec<u64>, StoreError<DB::Error>> {
        self.db
            .iter_prefix(Column::ReporterIndex, &[CHUNK_LOOKUP])
            .map_err(StoreError::Database)?
            .into_iter()
            .map(|(key, _)| {
                key.get(1..)
                    .ok_or(StoreError::Corrupt("reporter chunk lookup key"))
                    .and_then(crate::store::retention::decode_count)
            })
            .collect()
    }
}
