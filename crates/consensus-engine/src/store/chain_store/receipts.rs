//! Retained block receipts and chunk proofs (design 08): bounded per block
//! and per chunk, with the block's preferred receipt.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::{BlockProof, ChunkProof};
use neutrin0_primitives::{BlockHash, ChunkId, Hash};
use neutrin0_storage::{Column, Database};

use super::ChainStore;
use crate::block_state::BlockState;
use crate::store::{StoreError, keys};

extern crate alloc;

impl<DB: Database> ChainStore<DB> {
    // ---------- Block proofs ----------

    /// Retain `proof` as a receipt of `hash` without marking the block proven:
    /// a fixture convenience over [`Self::put_block_receipt`].
    ///
    /// # Errors
    /// Returns storage failures or a proof that does not name `hash`.
    pub fn put_block_proof(
        &mut self,
        hash: &BlockHash,
        proof: &BlockProof,
    ) -> Result<(), StoreError<DB::Error>> {
        if proof.block_hash != *hash {
            return Err(StoreError::Corrupt("block proof names another block"));
        }
        self.put_block_receipt(
            proof,
            0,
            usize::MAX,
            false,
            &alloc::collections::BTreeSet::new(),
        )
    }

    /// Retain `proof` and mark `hash` proven: a fixture convenience over
    /// [`Self::put_block_receipt`].
    ///
    /// # Errors
    /// Returns storage failures or a proof that does not name `hash`.
    pub fn put_proven_block(
        &mut self,
        hash: &BlockHash,
        proof: &BlockProof,
    ) -> Result<(), StoreError<DB::Error>> {
        if proof.block_hash != *hash {
            return Err(StoreError::Corrupt("block proof names another block"));
        }
        self.put_block_receipt(
            proof,
            0,
            usize::MAX,
            true,
            &alloc::collections::BTreeSet::new(),
        )
    }

    /// Retain a verified receipt of its block (design 08) and refresh the
    /// block's preferred receipt.
    ///
    /// At most `max_per_block` distinct statements are kept: the receipt
    /// attributed to the block's proposer whenever one is held and every
    /// `protected` one, then the earliest verified others. A statement already
    /// retained keeps its first verification slot. The preferred receipt under
    /// [`Column::BlockProofs`] is the proposer's, else the earliest verified.
    /// With `mark_proven` the block
    /// advances to [`BlockState::Proven`] unless it is finalized.
    ///
    /// # Errors
    /// Returns a corruption error when the receipt's envelope does not bind
    /// the block or differs from the retained receipts' public inputs.
    pub fn put_block_receipt(
        &mut self,
        proof: &BlockProof,
        first_verified_slot: neutrin0_primitives::Slot,
        max_per_block: usize,
        mark_proven: bool,
        protected: &alloc::collections::BTreeSet<Hash>,
    ) -> Result<(), StoreError<DB::Error>> {
        let hash = proof.block_hash;
        let retained = self.retained_receipts_with(proof, first_verified_slot)?;
        let proposer = proof.public_inputs.proposer_address;
        let keep = select_kept_receipts(&retained, proposer, protected, max_per_block);
        let mut batch = neutrin0_storage::Batch::new();
        stage_kept_receipts(&mut batch, &hash, &retained, &keep)?;
        let preferred = keep
            .iter()
            .find(|receipt| receipt.proof.prover_address == proposer)
            .or_else(|| {
                keep.iter().min_by_key(|receipt| {
                    (receipt.first_verified_slot, receipt.proof.statement_key)
                })
            })
            .ok_or(StoreError::Corrupt("no receipt retained"))?;
        if let Some(current) = self.get_block_proof(&hash)?
            && current != preferred.proof
        {
            self.expand_accepted_artifact_batch(&mut batch, &current)?;
        }
        batch.put(Column::BlockProofs, hash, borsh::to_vec(&preferred.proof)?);
        if mark_proven && self.get_block_state(&hash)? != Some(BlockState::Finalized) {
            batch.put(
                Column::BlockStates,
                hash,
                borsh::to_vec(&BlockState::Proven)?,
            );
        }
        self.write_observed_batch(batch, false)
    }

    /// The retained receipts of `proof`'s block with `proof` merged in, once
    /// its envelope binds the block and agrees with the retained public inputs.
    fn retained_receipts_with(
        &self,
        proof: &BlockProof,
        first_verified_slot: neutrin0_primitives::Slot,
    ) -> Result<Vec<StoredReceipt>, StoreError<DB::Error>> {
        let hash = proof.block_hash;
        if proof.public_inputs.block_hash != hash || proof.height != proof.public_inputs.height {
            return Err(StoreError::Corrupt("block receipt binding mismatch"));
        }
        let mut retained = self.block_receipts(&hash)?;
        if retained
            .iter()
            .any(|existing| existing.proof.public_inputs != proof.public_inputs)
        {
            return Err(StoreError::Corrupt("stored block receipt binding changed"));
        }
        if !retained
            .iter()
            .any(|existing| existing.proof.statement_key == proof.statement_key)
        {
            retained.push(StoredReceipt {
                proof: proof.clone(),
                first_verified_slot,
            });
        }
        Ok(retained)
    }

    /// Retain a verified chunk proof for ratification (design 08). At most
    /// `max_per_chunk` distinct statements are kept: the ones `preferred`
    /// (this node's prover account) proved, then the earliest verified. A
    /// statement already retained keeps its first verification slot.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn put_chunk_receipt(
        &mut self,
        receipt: StoredChunkReceipt,
        preferred: Option<Hash>,
        max_per_chunk: usize,
    ) -> Result<(), StoreError<DB::Error>> {
        let chunk_id = receipt.proof.chunk_id;
        let mut retained = self.chunk_receipts(chunk_id)?;
        if retained
            .iter()
            .any(|existing| existing.statement_key == receipt.statement_key)
        {
            return Ok(());
        }
        retained.push(receipt);
        let (mut keep, mut others): (Vec<_>, Vec<_>) = retained
            .iter()
            .cloned()
            .partition(|kept| Some(kept.proof.prover_address) == preferred);
        others.sort_by_key(|kept| (kept.first_verified_slot, kept.statement_key));
        for other in others {
            if keep.len() >= max_per_chunk.max(1) {
                break;
            }
            keep.push(other);
        }
        let mut batch = neutrin0_storage::Batch::new();
        for existing in &retained {
            let key = chunk_receipt_key(chunk_id, &existing.statement_key);
            if keep
                .iter()
                .any(|kept| kept.statement_key == existing.statement_key)
            {
                batch.put(Column::ChunkReceipts, key, borsh::to_vec(existing)?);
            } else {
                batch.delete(Column::ChunkReceipts, key);
            }
        }
        self.write_observed_batch(batch, false)
    }

    /// Every retained chunk proof of `chunk_id`, in ascending statement key
    /// order.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn chunk_receipts(
        &self,
        chunk_id: ChunkId,
    ) -> Result<Vec<StoredChunkReceipt>, StoreError<DB::Error>> {
        let mut receipts = Vec::new();
        for (key, bytes) in self
            .db
            .iter_prefix(Column::ChunkReceipts, &chunk_id.to_be_bytes())
            .map_err(StoreError::Database)?
        {
            if key.len() != 40 {
                return Err(StoreError::Corrupt("invalid chunk receipt key"));
            }
            receipts.push(borsh::from_slice::<StoredChunkReceipt>(&bytes)?);
        }
        receipts.sort_by_key(|receipt| receipt.statement_key);
        Ok(receipts)
    }

    /// Every retained receipt of `hash`, in ascending statement key order.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn block_receipts(
        &self,
        hash: &BlockHash,
    ) -> Result<Vec<StoredReceipt>, StoreError<DB::Error>> {
        let mut receipts = Vec::new();
        for (key, bytes) in self
            .db
            .iter_prefix(Column::BlockReceipts, hash)
            .map_err(StoreError::Database)?
        {
            if key.len() != 64 {
                return Err(StoreError::Corrupt("invalid block receipt key"));
            }
            receipts.push(borsh::from_slice::<StoredReceipt>(&bytes)?);
        }
        receipts.sort_by_key(|receipt| receipt.proof.statement_key);
        Ok(receipts)
    }

    /// The retained receipt of `hash` with statement key `key`.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn block_receipt_by_key(
        &self,
        hash: &BlockHash,
        key: &Hash,
    ) -> Result<Option<StoredReceipt>, StoreError<DB::Error>> {
        self.get_decoded(Column::BlockReceipts, &receipt_key(hash, key))
    }

    /// Read a block's preferred receipt by block hash.
    pub fn get_block_proof(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<BlockProof>, StoreError<DB::Error>> {
        self.get_decoded(Column::BlockProofs, &keys::hash_key(hash))
    }
}

/// A retained receipt and the local slot at which this node first verified
/// it; receipt selection (design 08) compares that slot with the proposer's
/// lease and with proposal arrival.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct StoredReceipt {
    /// The receipt record with its attribution.
    pub proof: BlockProof,
    /// Local slot of first verification.
    pub first_verified_slot: neutrin0_primitives::Slot,
}

/// A verified chunk proof retained for ratification and the local slot at
/// which this node first verified it (design 08).
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct StoredChunkReceipt {
    /// The chunk proof artifact, naming its prover.
    pub proof: ChunkProof,
    /// Commitment of the proof's complete public values.
    pub statement_key: Hash,
    /// Local slot of first verification.
    pub first_verified_slot: neutrin0_primitives::Slot,
}

impl StoredChunkReceipt {
    /// Retain `proof` of `statement`, first verified at `first_verified_slot`.
    #[must_use]
    pub fn new(
        proof: ChunkProof,
        statement: &neutrin0_consensus_types::history_proof::ConsensusStatement,
        first_verified_slot: neutrin0_primitives::Slot,
    ) -> Self {
        let statement_key = neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
            statement: statement.clone(),
            chunk_prover_address: proof.prover_address,
        }
        .statement_key();
        Self {
            proof,
            statement_key,
            first_verified_slot,
        }
    }
}

/// Key of a retained chunk proof: chunk id then statement key.
#[expect(
    clippy::redundant_pub_crate,
    reason = "Re-exported crate-wide by the store module."
)]
pub(crate) fn chunk_receipt_key(chunk_id: ChunkId, statement_key: &Hash) -> [u8; 40] {
    let mut key = [0; 40];
    key[..8].copy_from_slice(&chunk_id.to_be_bytes());
    key[8..].copy_from_slice(statement_key);
    key
}

/// Key of a retained block receipt: block hash then statement key.
#[expect(
    clippy::redundant_pub_crate,
    reason = "Re-exported crate-wide by the store module."
)]
pub(crate) fn receipt_key(hash: &BlockHash, statement_key: &Hash) -> [u8; 64] {
    let mut key = [0; 64];
    key[..32].copy_from_slice(hash);
    key[32..].copy_from_slice(statement_key);
    key
}

/// The receipts of `retained` to keep: the proposer's and every `protected`
/// one, then the earliest verified others up to `max_per_block`.
fn select_kept_receipts(
    retained: &[StoredReceipt],
    proposer: Hash,
    protected: &alloc::collections::BTreeSet<Hash>,
    max_per_block: usize,
) -> Vec<StoredReceipt> {
    // The proposer's receipt and every receipt a vote, proposal or
    // certificate names are always kept, then the earliest verified
    // others: selection has no key order (design 08).
    let pinned = |receipt: &StoredReceipt| {
        receipt.proof.prover_address == proposer || protected.contains(&receipt.proof.statement_key)
    };
    let mut keep: Vec<StoredReceipt> = retained.iter().filter(|r| pinned(r)).cloned().collect();
    let mut others: Vec<StoredReceipt> = retained.iter().filter(|r| !pinned(r)).cloned().collect();
    others.sort_by_key(|receipt| (receipt.first_verified_slot, receipt.proof.statement_key));
    for receipt in others {
        if keep.len() >= max_per_block.max(1) {
            break;
        }
        keep.push(receipt);
    }
    keep
}

/// Stage the deletion of every retained receipt that is not kept and the
/// write of every kept one.
fn stage_kept_receipts<E>(
    batch: &mut neutrin0_storage::Batch,
    hash: &BlockHash,
    retained: &[StoredReceipt],
    keep: &[StoredReceipt],
) -> Result<(), StoreError<E>> {
    for receipt in retained {
        if !keep
            .iter()
            .any(|kept| kept.proof.statement_key == receipt.proof.statement_key)
        {
            batch.delete(
                Column::BlockReceipts,
                receipt_key(hash, &receipt.proof.statement_key),
            );
        }
    }
    for receipt in keep {
        batch.put(
            Column::BlockReceipts,
            receipt_key(hash, &receipt.proof.statement_key),
            borsh::to_vec(receipt)?,
        );
    }
    Ok(())
}
