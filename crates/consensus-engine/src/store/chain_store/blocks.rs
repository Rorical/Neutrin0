//! Headers with their height and slot indexes, bodies, the execution
//! transaction index, block FSM state, witnesses and state diffs.

use alloc::vec::Vec;

use neutrin0_consensus_types::{Body, Header};
use neutrin0_primitives::{BlockHash, Hash, Height, Slot};
use neutrin0_storage::{Column, Database};

use super::ChainStore;
use crate::block_state::BlockState;
use crate::store::{StoreError, keys};

extern crate alloc;

impl<DB: Database> ChainStore<DB> {
    // ---------- Headers + height/slot indexes ----------

    /// Archive `header` by hash and slot without selecting its branch.
    ///
    /// Returns the header hash so callers do not have to recompute it.
    /// The canonical height index changes only through [`Self::commit_tip`].
    pub fn put_header(&mut self, header: &Header) -> Result<BlockHash, StoreError<DB::Error>> {
        let hash = header.hash();
        self.put_encoded(Column::Headers, &keys::hash_key(&hash), header)?;
        self.put_raw(
            Column::HeaderBySlot,
            &keys::slot_block_key(header.slot, &hash),
            &[],
        )?;
        Ok(hash)
    }

    /// Stage a verified block archive; publication chooses whether this batch
    /// also advances the canonical head.
    pub(crate) fn block_archive_batch(
        block: &neutrin0_consensus_types::Block,
        witness: Option<&[u8]>,
        state_diff: Option<&neutrin0_consensus_types::BlockStateDiff>,
    ) -> Result<neutrin0_storage::Batch, StoreError<DB::Error>> {
        let hash = block.hash();
        let mut batch = neutrin0_storage::Batch::new();
        batch.put(Column::Headers, hash, borsh::to_vec(&block.header)?);
        batch.put(
            Column::HeaderBySlot,
            keys::slot_block_key(block.header.slot, &hash),
            Vec::new(),
        );
        batch.put(Column::Blocks, hash, borsh::to_vec(&block.body)?);
        Self::stage_execution_transactions(&mut batch, hash, block.header.height, &block.body)?;
        batch.put(
            Column::BlockStates,
            hash,
            borsh::to_vec(&BlockState::BlockProduced)?,
        );
        if let Some(bytes) = witness {
            batch.put(Column::Witnesses, hash, bytes.to_vec());
        }
        if let Some(diff) = state_diff {
            batch.put(Column::StateDiffs, hash, borsh::to_vec(diff)?);
        }
        Ok(batch)
    }

    fn stage_execution_transactions(
        batch: &mut neutrin0_storage::Batch,
        hash: Hash,
        height: u64,
        body: &Body,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut indexes = alloc::collections::BTreeSet::new();
        let mut identifiers = alloc::collections::BTreeSet::new();
        for (index, identifier) in &body.artifacts.transaction_ids {
            if usize::try_from(*index).map_or(true, |index| index >= body.transactions.len())
                || !indexes.insert(*index)
                || !identifiers.insert(*identifier)
            {
                return Err(StoreError::Corrupt("invalid execution transaction index"));
            }
            let mut key = identifier.to_vec();
            key.extend_from_slice(&hash);
            batch.put(
                Column::ExecutionTransactions,
                key,
                borsh::to_vec(&(height, index))?,
            );
        }
        Ok(())
    }

    /// Find an authenticated transaction on the current canonical branch.
    /// Fork entries remain keyed by native block hash; canonical height mappings
    /// change atomically during reorganization, so no stale lookup can win.
    pub fn execution_transaction(
        &self,
        identifier: &Hash,
    ) -> Result<Option<(Hash, u32)>, StoreError<DB::Error>> {
        for (key, bytes) in self
            .db
            .iter_prefix(Column::ExecutionTransactions, identifier)
            .map_err(StoreError::Database)?
        {
            let hash = key
                .get(32..)
                .and_then(|bytes| <Hash>::try_from(bytes).ok())
                .ok_or(StoreError::Corrupt("execution transaction index key"))?;
            let (height, index): (u64, u32) = borsh::from_slice(&bytes)?;
            if self.get_block_hash_by_height(height)? == Some(hash) {
                return Ok(Some((hash, index)));
            }
        }
        Ok(None)
    }

    /// Read a header by its hash.
    pub fn get_header(&self, hash: &BlockHash) -> Result<Option<Header>, StoreError<DB::Error>> {
        self.get_decoded(Column::Headers, &keys::hash_key(hash))
    }

    /// Read the canonical header hash at a height.
    pub fn get_block_hash_by_height(
        &self,
        height: Height,
    ) -> Result<Option<BlockHash>, StoreError<DB::Error>> {
        self.get_fixed(
            Column::HeaderByHeight,
            &keys::height_key(height),
            "invalid canonical height hash",
        )
    }

    /// Read the canonical header at a height, following the height
    /// index.
    pub fn get_header_by_height(
        &self,
        height: Height,
    ) -> Result<Option<Header>, StoreError<DB::Error>> {
        let Some(hash) = self.get_block_hash_by_height(height)? else {
            return Ok(None);
        };
        let header = self.get_header(&hash)?;
        match header {
            Some(header) if header.hash() == hash && header.height == height => Ok(Some(header)),
            None if height == 0 => Ok(None),
            _ => Err(StoreError::Corrupt(
                "canonical height header is missing or inconsistent",
            )),
        }
    }

    /// Every archived block whose slot is at or after `slot`, in slot order.
    /// Reads only that part of the slot index, a page at a time.
    pub fn block_hashes_from_slot(
        &self,
        slot: Slot,
    ) -> Result<Vec<BlockHash>, StoreError<DB::Error>> {
        const PAGE: usize = 4096;
        let mut hashes = Vec::new();
        let mut from = keys::slot_key(slot).to_vec();
        loop {
            let page = self
                .db()
                .keys_from(Column::HeaderBySlot, &from, PAGE)
                .map_err(StoreError::Database)?;
            let full = page.len() == PAGE;
            for key in &page {
                hashes.push(slot_index_hash(key)?);
            }
            match page.into_iter().last().filter(|_| full) {
                Some(mut key) => {
                    key.push(0);
                    from = key;
                }
                None => return Ok(hashes),
            }
        }
    }

    // ---------- Bodies ----------

    /// Persist the body associated with `hash`.
    pub fn put_body(&mut self, hash: &BlockHash, body: &Body) -> Result<(), StoreError<DB::Error>> {
        self.put_encoded(Column::Blocks, &keys::hash_key(hash), body)
    }

    /// Read the body associated with `hash`.
    pub fn get_body(&self, hash: &BlockHash) -> Result<Option<Body>, StoreError<DB::Error>> {
        self.get_decoded(Column::Blocks, &keys::hash_key(hash))
    }

    /// Read the complete block at `hash` when both its header and body are retained.
    pub fn get_block(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<neutrin0_consensus_types::Block>, StoreError<DB::Error>> {
        let Some(header) = self.get_header(hash)? else {
            return Ok(None);
        };
        let Some(body) = self.get_body(hash)? else {
            return Ok(None);
        };
        Ok(Some(neutrin0_consensus_types::Block { header, body }))
    }

    // ---------- Block FSM state ----------

    /// Persist the block FSM state for `hash`.
    ///
    /// Per-block state is tracked in [`Column::BlockStates`] so the
    /// engine can enforce each block's progression:
    /// `BlockProduced → PendingProof → Proven → Finalized`.
    pub fn put_block_state(
        &mut self,
        hash: &BlockHash,
        state: BlockState,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_encoded(Column::BlockStates, &keys::hash_key(hash), &state)
    }

    /// Read the block FSM state for `hash`.
    pub fn get_block_state(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<BlockState>, StoreError<DB::Error>> {
        self.get_decoded(Column::BlockStates, &keys::hash_key(hash))
    }

    // ---------- Witnesses ----------

    /// Persist a block's execution witness keyed by block hash.
    ///
    /// `bytes` is the backend-specific execution witness produced during
    /// runtime execution. The store does not decode the bytes; it only
    /// round-trips them.
    pub fn put_witness(
        &mut self,
        hash: &BlockHash,
        bytes: &[u8],
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_raw(Column::Witnesses, &keys::hash_key(hash), bytes)
    }

    /// Read the borsh-encoded execution witness for `hash`, if any.
    pub fn get_witness(&self, hash: &BlockHash) -> Result<Option<Vec<u8>>, StoreError<DB::Error>> {
        self.get_raw(Column::Witnesses, &keys::hash_key(hash))
    }

    // ---------- State diffs ----------

    /// Persist the state diff a block's execution produced, keyed by block
    /// hash. Executing nodes serve it to proof-following nodes; followers
    /// retain the diff they verified for branch replay.
    pub fn put_state_diff(
        &mut self,
        hash: &BlockHash,
        diff: &neutrin0_consensus_types::BlockStateDiff,
    ) -> Result<(), StoreError<DB::Error>> {
        self.put_encoded(Column::StateDiffs, &keys::hash_key(hash), diff)
    }

    /// Read the retained state diff for `hash`, if any.
    pub fn get_state_diff(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<neutrin0_consensus_types::BlockStateDiff>, StoreError<DB::Error>> {
        self.get_decoded(Column::StateDiffs, &keys::hash_key(hash))
    }
}

/// The block hash a slot-index key ends with.
fn slot_index_hash<E>(key: &[u8]) -> Result<BlockHash, StoreError<E>> {
    key.get(8..)
        .filter(|_| key.len() == 40)
        .and_then(|bytes| BlockHash::try_from(bytes).ok())
        .ok_or(StoreError::Corrupt("invalid slot index key"))
}
