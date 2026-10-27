//! Proof-backed retention of the live state and a bounded recent chain window.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS;
use neutrin0_storage::Database;

use crate::{Engine, StoreError};

/// Local historical-data retention policy. This does not change consensus validity.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum RetentionPolicy {
    /// Retain complete canonical history.
    Archive,
    /// Delete finalized data outside the most recent eight finalized chunks;
    /// the latest chunk receipt proves everything before them.
    #[default]
    Pruned,
    /// Keep selective accountability sources while their identities remain slashable.
    Reporter,
}

/// Durable lower bound for complete historical data served by this node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct RetentionInfo {
    /// Configured local policy.
    pub policy: RetentionPolicy,
    /// Every chunk below this count may have had its complete source data removed.
    pub pruned_before_chunk: u64,
    /// First fully retained block height; the preceding anchor header is also retained.
    pub first_retained_height: u64,
}

impl Default for RetentionInfo {
    fn default() -> Self {
        Self {
            policy: RetentionPolicy::Pruned,
            pruned_before_chunk: 0,
            first_retained_height: 1,
        }
    }
}

impl<DB: Database> Engine<DB> {
    /// Read the durable retention policy and deletion watermark.
    pub fn retention_info(&self) -> Result<RetentionInfo, StoreError<DB::Error>> {
        self.store().retention_info_for_spec(self.chain_spec())
    }

    /// Select local retention. Deleted history cannot be restored by selecting archive mode.
    pub fn set_retention_policy(
        &mut self,
        policy: RetentionPolicy,
    ) -> Result<(), StoreError<DB::Error>> {
        self.store_mut().set_retention_policy(policy)?;
        if policy == RetentionPolicy::Reporter {
            self.seed_reporter_tracking()?;
        }
        Ok(())
    }

    /// Prune finalized history and complete the state collection at once;
    /// see [`Self::prune_finalized_sources`] and [`Self::collect_state_slice`].
    pub fn prune_finalized_history(&mut self) -> Result<RetentionInfo, StoreError<DB::Error>> {
        let info = self.prune_finalized_sources()?;
        while !self.collect_state_slice(usize::MAX)? {}
        Ok(info)
    }

    /// Atomically prune finalized historical data below the most recent eight
    /// finalized chunks and release the state roots it no longer retains.
    /// Every finalized chunk receipt recursively proves the chain from
    /// genesis, so finality itself is the covered prefix. A failed deletion
    /// leaves the watermark and every in-memory structure unchanged.
    pub fn prune_finalized_sources(&mut self) -> Result<RetentionInfo, StoreError<DB::Error>> {
        let mut info = self.retention_info()?;
        let count = self.finalized_next_chunk_id();
        if count == 0 {
            return Ok(info);
        }
        if info.policy == RetentionPolicy::Archive {
            // Archives keep every durable source, but no live structure
            // below finality: fork choice and sessions stay bounded.
            self.fork_choice.retain_finalized_subtree();
            self.bft_sessions.retain(|id, _| *id >= count);
            return Ok(info);
        }
        let floor = count
            .saturating_sub(HISTORY_RETENTION_CHUNKS)
            .max(self.store().bootstrap_source_floor()?);
        if floor < info.pruned_before_chunk {
            return Err(StoreError::Corrupt("finality regressed after pruning"));
        }
        info.pruned_before_chunk = floor;
        info.first_retained_height = floor
            .checked_mul(self.chunk_size())
            .and_then(|height| height.checked_add(1))
            .ok_or(StoreError::Corrupt("retention height overflow"))?;
        let mut batch = self.store().retention_batch(self.chain_spec(), info)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| StoreError::Corrupt("snapshot retention clock is invalid"))?
            .as_secs();
        self.store().snapshot_retention(&mut batch, now)?;
        self.store_mut().write_observed_batch(batch, false)?;
        self.fork_choice.retain_finalized_subtree();
        self.bft_sessions.retain(|id, _| *id >= count);
        self.rejected_proofs
            .retain_from_height(info.first_retained_height);
        self.slashing_monitor
            .retain_history_window(count.saturating_sub(HISTORY_RETENTION_CHUNKS));
        Ok(info)
    }

    /// Apply at most `budget` queued state releases and return whether none
    /// remains. Each slice is one atomic batch, so the caller may release the
    /// engine lock between slices; collection reads only what it frees.
    pub fn collect_state_slice(&mut self, budget: usize) -> Result<bool, StoreError<DB::Error>> {
        self.store_mut().collect_state_slice(budget)
    }
}

#[cfg(test)]
mod tests;
