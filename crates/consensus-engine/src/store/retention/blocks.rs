//! Block-level pruning: which headers the retention window keeps, and the
//! per-block sources, indexes, receipts and post-state pins that follow them.

use neutrin0_consensus_types::Header;
use neutrin0_primitives::Hash;
use neutrin0_storage::{Batch, Column, Database};
use std::collections::{BTreeMap, BTreeSet};

use super::{PER_BLOCK_SOURCE_COLUMNS, RetainedBlocks, decode_count};
use crate::RetentionInfo;
use crate::store::{ChainStore, StatePin, StoreError, keys};

impl<DB: Database> ChainStore<DB> {
    /// Drop retained receipts, keyed by block hash then statement key, of
    /// blocks no longer retained above `first_retained_height`.
    fn prune_block_receipts(
        &self,
        batch: &mut Batch,
        retained: &BTreeSet<Hash>,
        headers: &BTreeMap<Hash, neutrin0_consensus_types::Header>,
        first_retained_height: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        for key in self
            .db
            .iter_keys(Column::BlockReceipts)
            .map_err(StoreError::Database)?
        {
            let hash = Hash::try_from(key.get(..32).unwrap_or_default())
                .map_err(|_| StoreError::Corrupt("invalid block receipt key"))?;
            let complete = retained.contains(&hash)
                && headers
                    .get(&hash)
                    .is_some_and(|header| header.height >= first_retained_height);
            if !complete {
                batch.delete(Column::BlockReceipts, key);
            }
        }
        Ok(())
    }

    /// Retained header hashes and every stored header: the canonical
    /// finalized window and every branch above finality descending from it.
    fn retained_blocks(
        &self,
        info: RetentionInfo,
    ) -> Result<RetainedBlocks, StoreError<DB::Error>> {
        let anchor_height = info.first_retained_height.saturating_sub(1);
        let finalized = self
            .get_finalized_head()?
            .ok_or(StoreError::Corrupt("missing finalized head"))?;
        let finalized_height = self
            .get_header(&finalized)?
            .ok_or(StoreError::Corrupt(
                "finalized header is unavailable during pruning",
            ))?
            .height;
        let mut headers = BTreeMap::new();
        for (key, bytes) in self
            .db
            .iter_column(Column::Headers)
            .map_err(StoreError::Database)?
        {
            let header: Header = borsh::from_slice(&bytes)?;
            if key.as_slice() != header.hash() {
                return Err(StoreError::Corrupt("header key mismatch"));
            }
            headers.insert(header.hash(), header);
        }
        let mut retained = BTreeSet::from([finalized]);
        let mut ordered: Vec<_> = headers.iter().collect();
        ordered.sort_by_key(|(hash, header)| (header.height, **hash));
        for (hash, header) in ordered {
            let canonical = header.height >= anchor_height
                && header.height <= finalized_height
                && self.get_block_hash_by_height(header.height)? == Some(*hash);
            if canonical
                || (header.height > finalized_height && retained.contains(&header.parent_hash))
            {
                retained.insert(*hash);
            }
        }
        if anchor_height > 0 {
            let anchor = self
                .get_block_hash_by_height(anchor_height)?
                .ok_or(StoreError::Corrupt("retained anchor height is missing"))?;
            if !retained.contains(&anchor) {
                return Err(StoreError::Corrupt("retained anchor header is missing"));
            }
        }
        let head = self.get_tip()?.ok_or(StoreError::Corrupt("missing head"))?;
        if head != finalized && !retained.contains(&head) {
            return Err(StoreError::Corrupt(
                "head is outside retained finalized subtree",
            ));
        }
        Ok((retained, headers))
    }

    /// Delete the blocks `info` no longer retains, releasing their post-states.
    /// The genesis block has no stored header; its state goes once the window
    /// has moved past it.
    pub(super) fn prune_blocks(
        &self,
        batch: &mut Batch,
        info: RetentionInfo,
        genesis: Hash,
    ) -> Result<(), StoreError<DB::Error>> {
        let anchor_height = info.first_retained_height - 1;
        let (retained, headers) = self.retained_blocks(info)?;
        let mut released = Vec::new();
        for hash in headers.keys() {
            if !retained.contains(hash) {
                batch.delete(Column::Headers, hash);
                released.push(*hash);
            }
        }
        if anchor_height > 0 {
            released.push(genesis);
        }
        let mut writer = self.state_writer(batch);
        for hash in released {
            writer.unpin(StatePin::Block(hash))?;
        }
        // Per-block columns follow the retained headers, so only keys are read.
        let complete = |hash: &Hash| {
            retained.contains(hash)
                && headers
                    .get(hash)
                    .is_some_and(|header| header.height >= info.first_retained_height)
        };
        for key in self
            .db
            .iter_keys(Column::ExecutionTransactions)
            .map_err(StoreError::Database)?
        {
            let hash = key
                .get(32..)
                .and_then(|bytes| Hash::try_from(bytes).ok())
                .ok_or(StoreError::Corrupt("execution transaction index key"))?;
            if !complete(&hash) {
                batch.delete(Column::ExecutionTransactions, key);
            }
        }
        for column in PER_BLOCK_SOURCE_COLUMNS {
            for key in self.db.iter_keys(column).map_err(StoreError::Database)? {
                let hash = Hash::try_from(key.as_slice())
                    .map_err(|_| StoreError::Corrupt("invalid block data key"))?;
                if !complete(&hash) {
                    batch.delete(column, key);
                }
            }
        }
        self.prune_block_receipts(batch, &retained, &headers, info.first_retained_height)?;
        for key in self
            .db
            .keys_below(Column::HeaderByHeight, &anchor_height.to_be_bytes())
            .map_err(StoreError::Database)?
        {
            if decode_count(&key)? > 0 {
                batch.delete(Column::HeaderByHeight, key);
            }
        }
        self.prune_slot_index(batch, &retained)?;
        Ok(())
    }

    /// Stage the deletion of a candidate this node stopped following: its
    /// header and slot index entry, body, execution index, receipts, per-block
    /// sources and post-state pin. Accountability keeps its own copies: the
    /// slashing monitor the signed header, the engine any contradicting receipt.
    pub(crate) fn discard_block_batch(
        &self,
        batch: &mut Batch,
        hash: &Hash,
    ) -> Result<(), StoreError<DB::Error>> {
        let Some(header) = self.get_header(hash)? else {
            return Ok(());
        };
        if let Some(body) = self.get_body(hash)? {
            for (_, identifier) in &body.artifacts.transaction_ids {
                batch.delete(
                    Column::ExecutionTransactions,
                    [identifier.as_slice(), hash.as_slice()].concat(),
                );
            }
        }
        batch.delete(Column::Headers, hash);
        for column in PER_BLOCK_SOURCE_COLUMNS {
            batch.delete(column, hash);
        }
        // At most `max_receipts_per_block` receipts share the block's prefix.
        for (key, _) in self
            .db
            .iter_prefix(Column::BlockReceipts, hash)
            .map_err(StoreError::Database)?
        {
            batch.delete(Column::BlockReceipts, key);
        }
        batch.delete(
            Column::HeaderBySlot,
            keys::slot_block_key(header.slot, hash),
        );
        self.state_writer(batch).unpin(StatePin::Block(*hash))
    }

    fn prune_slot_index(
        &self,
        batch: &mut Batch,
        retained: &BTreeSet<Hash>,
    ) -> Result<(), StoreError<DB::Error>> {
        for key in self
            .db
            .iter_keys(Column::HeaderBySlot)
            .map_err(StoreError::Database)?
        {
            let hash = key
                .get(8..)
                .filter(|_| key.len() == 40)
                .and_then(|bytes| Hash::try_from(bytes).ok())
                .ok_or(StoreError::Corrupt("invalid slot index key"))?;
            if !retained.contains(&hash) {
                batch.delete(Column::HeaderBySlot, key);
            }
        }
        Ok(())
    }
}
