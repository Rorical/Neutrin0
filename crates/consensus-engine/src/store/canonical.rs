//! Atomic publication of a materialized head and its canonical height index.

extern crate alloc;

use neutrin0_consensus_types::Header;
use neutrin0_primitives::BlockHash;
use neutrin0_storage::{Batch, BatchOp, Column, Database};

use super::{ChainStore, StoreError, keys, pointers};

impl<DB: Database> ChainStore<DB> {
    fn chain_header(&self, hash: BlockHash) -> Result<Header, StoreError<DB::Error>> {
        let header = self
            .get_header(&hash)?
            .ok_or(StoreError::Corrupt("chain header is missing"))?;
        if header.hash() != hash || header.height == 0 {
            return Err(StoreError::Corrupt(
                "chain header hash or height is invalid",
            ));
        }
        Ok(header)
    }

    /// Publish `hash` as the materialized head. Reindex the changed ancestry,
    /// remove the old tail and persist caller-supplied state writes in one batch.
    /// Header archival alone never changes the selected branch.
    pub fn commit_tip(
        &mut self,
        hash: BlockHash,
        genesis: BlockHash,
        mut batch: Batch,
    ) -> Result<(), StoreError<DB::Error>> {
        let anchor_height = self.retention_info()?.first_retained_height - 1;
        let old_height = match self.get_tip()? {
            Some(old) if old != genesis => {
                let height = self.chain_header(old)?.height;
                if self.get_block_hash_by_height(height)? != Some(old) {
                    return Err(StoreError::Corrupt(
                        "tip disagrees with canonical height index",
                    ));
                }
                height
            }
            _ => 0,
        };
        let mut staged = alloc::collections::BTreeMap::new();
        for op in batch.operations() {
            if let BatchOp::Put {
                column: Column::Headers,
                key,
                value,
            } = op
            {
                let header: Header = borsh::from_slice(value)?;
                if header.hash().as_slice() != key || header.height == 0 {
                    return Err(StoreError::Corrupt("staged header is inconsistent"));
                }
                staged.insert(header.hash(), header);
            }
        }
        let staged_header = |hash| {
            staged
                .get(&hash)
                .map_or_else(|| self.chain_header(hash), |header| Ok(header.clone()))
        };
        let height = if hash == genesis {
            0
        } else {
            staged_header(hash)?.height
        };
        if height < anchor_height {
            return Err(StoreError::Corrupt("head predates retained anchor"));
        }
        let mut cursor = hash;
        let mut expected = height;
        let mut updates = Vec::new();
        while expected > 0 {
            if self.get_block_hash_by_height(expected)? == Some(cursor) {
                break;
            }
            if expected <= anchor_height {
                return Err(StoreError::Corrupt("reorg crosses retained anchor"));
            }
            let header = staged_header(cursor)?;
            if header.height != expected {
                return Err(StoreError::Corrupt(
                    "chain ancestry heights are not contiguous",
                ));
            }
            updates.push((expected, cursor));
            cursor = header.parent_hash;
            expected -= 1;
        }
        for (height, hash) in updates {
            batch.put(Column::HeaderByHeight, keys::height_key(height), hash);
        }
        if expected == 0 && cursor != genesis {
            return Err(StoreError::Corrupt(
                "chain ancestry does not reach trusted genesis",
            ));
        }
        batch.put(Column::HeaderByHeight, keys::height_key(0), genesis);
        if height < old_height {
            for stale in height + 1..=old_height {
                batch.delete(Column::HeaderByHeight, keys::height_key(stale));
            }
        }
        batch.put(Column::Finalized, pointers::TIP, hash);
        // A replayed finalization carries its consensus-owned auxiliary trie
        // in this same batch. Publish the materialized head only after WAL sync.
        self.write_observed_batch(batch, true)
    }

    /// Check the entire persisted canonical index against the selected ancestry.
    /// Startup rejects missing, stale or inconsistent entries without repairing data.
    pub fn validate_canonical_index(
        &self,
        genesis: BlockHash,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut cursor = self
            .get_tip()?
            .ok_or(StoreError::Corrupt("tip is missing"))?;
        let height = if cursor == genesis {
            0
        } else {
            self.chain_header(cursor)?.height
        };
        let info = self.retention_info()?;
        let anchor_height = info.first_retained_height - 1;
        if height < anchor_height {
            return Err(StoreError::Corrupt("tip precedes retained anchor"));
        }
        let mut expected = height;
        while expected > anchor_height {
            let header = self.chain_header(cursor)?;
            if header.height != expected || self.get_block_hash_by_height(expected)? != Some(cursor)
            {
                return Err(StoreError::Corrupt(
                    "canonical index disagrees with selected ancestry",
                ));
            }
            cursor = header.parent_hash;
            expected -= 1;
        }
        let anchor = if info.pruned_before_chunk == 0 {
            genesis
        } else {
            let boundary = self
                .consensus_boundary(info.pruned_before_chunk)?
                .ok_or(StoreError::Corrupt("retained consensus anchor is missing"))?;
            if boundary.height != anchor_height
                || self.chain_header(boundary.block_hash)?.state_root != boundary.state_root
            {
                return Err(StoreError::Corrupt(
                    "retained consensus anchor is inconsistent",
                ));
            }
            boundary.block_hash
        };
        if cursor != anchor
            || self.get_block_hash_by_height(anchor_height)? != Some(anchor)
            || self.get_block_hash_by_height(0)? != Some(genesis)
        {
            return Err(StoreError::Corrupt(
                "canonical retained anchor is inconsistent",
            ));
        }
        let count = self.height_index_len()?;
        let expected_count = height
            .checked_sub(anchor_height)
            .and_then(|n| n.checked_add(if anchor_height == 0 { 1 } else { 2 }));
        if Some(count) != expected_count {
            return Err(StoreError::Corrupt(
                "canonical index contains missing or stale heights",
            ));
        }
        Ok(())
    }

    /// Entries in the canonical height index, counted a page of keys at a
    /// time so an archive's index is never held whole.
    fn height_index_len(&self) -> Result<u64, StoreError<DB::Error>> {
        const PAGE: usize = 4096;
        let mut count = 0_u64;
        let mut from = Vec::new();
        loop {
            let page = self
                .db()
                .keys_from(Column::HeaderByHeight, &from, PAGE)
                .map_err(StoreError::Database)?;
            let full = page.len() == PAGE;
            count = u64::try_from(page.len())
                .ok()
                .and_then(|len| count.checked_add(len))
                .ok_or(StoreError::Corrupt("height index size overflow"))?;
            match page.into_iter().last().filter(|_| full) {
                Some(mut key) => {
                    key.push(0);
                    from = key;
                }
                None => return Ok(count),
            }
        }
    }
}

#[cfg(test)]
mod tests;
