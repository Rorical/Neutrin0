//! Receipts for retained blocks (design 08): a receipt proves a candidate,
//! a stale one included while it is retained, and a further receipt of a
//! proven block is another ticket for selection.

use super::ImportError;
use crate::block_state::BlockState;
use crate::engine::Engine;
use neutrin0_consensus_types::{BlockReceipt, Header};
use neutrin0_primitives::{BlockHash, Height, StateRoot};
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_storage::Database;

impl<DB: Database> Engine<DB> {
    /// The retained receipt of `hash` as the network carries it, or `None`
    /// while the block is unknown or unproven.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn block_receipt(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<BlockReceipt>, crate::store::StoreError<DB::Error>> {
        Ok(self
            .store()
            .get_block_proof(hash)?
            .map(|proof| BlockReceipt {
                block_hash: *hash,
                proof_bytes: proof.proof_bytes,
            }))
    }

    /// Import a receipt for a retained block (design 08). The envelope and
    /// public inputs are derived from the retained header, its pre-state root
    /// and the program set of its chunk; verification and archival follow
    /// [`Engine::import_block_proof`], and a newly proven block may move the
    /// head. For a block already proven or finalized, identical bytes are a
    /// duplicate and different bytes are verified: a valid one is retained
    /// for selection while the block is proven, and only verified once it is
    /// finalized.
    ///
    /// # Errors
    /// Returns [`ImportError::UnknownBlock`] when the block is not retained,
    /// the receipt failures of [`Engine::import_block_proof`], replay errors
    /// or storage failures.
    pub fn import_block_receipt<PS: ProofSystem>(
        &mut self,
        receipt: &BlockReceipt,
        proof_system: &PS,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<ReceiptOutcome, ImportError<DB::Error>> {
        let hash = receipt.block_hash;
        let header = self
            .store()
            .get_header(&hash)?
            .ok_or(ImportError::UnknownBlock(hash))?;
        let state_root_before =
            self.state_root_before(&header)?
                .ok_or(ImportError::MissingParentHeader {
                    parent_hash: header.parent_hash,
                })?;
        let height = header.height;
        let state = self.store().get_block_state(&hash)?;
        if matches!(state, Some(BlockState::Proven | BlockState::Finalized)) {
            return self.admit_receipt_for_proven_block(
                hash,
                &header,
                state_root_before,
                receipt,
                proof_system,
                state == Some(BlockState::Proven),
            );
        }
        let proof =
            self.canonical_block_proof(&header, state_root_before, receipt.proof_bytes.clone())?;
        // A stale candidate still retained is restored by a valid receipt
        // (design 08): dropping it would split nodes that judged staleness on
        // either side of a receipt arriving near the deadline, and those that
        // dropped could never validate the other side's proven branch.
        self.import_block_proof_inner(&proof, proof_system, executor)?;
        Ok(ReceiptOutcome::Proven { height })
    }

    /// Whether importing `receipt` would verify its bytes: exact duplicates of
    /// a retained receipt and statements already held are settled unverified,
    /// so a caller verifying ahead of the import skips them.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn receipt_needs_verification<PS: ProofSystem>(
        &self,
        receipt: &BlockReceipt,
        proof_system: &PS,
    ) -> Result<bool, ImportError<DB::Error>> {
        let hash = receipt.block_hash;
        if !matches!(
            self.store().get_block_state(&hash)?,
            Some(BlockState::Proven | BlockState::Finalized)
        ) {
            return Ok(true);
        }
        if self
            .store()
            .get_block_proof(&hash)?
            .is_none_or(|retained| retained.proof_bytes == receipt.proof_bytes)
        {
            return Ok(false);
        }
        Ok(!self.holds_receipt_statement(&hash, &receipt.proof_bytes, proof_system)?)
    }

    /// A receipt for a block already proven or finalized: identical bytes are
    /// a duplicate, a statement already held is skipped unverified, and other
    /// bytes are verified; a proven block retains the further receipt for
    /// selection while a finalized block's selection is settled.
    fn admit_receipt_for_proven_block<PS: ProofSystem>(
        &mut self,
        hash: BlockHash,
        header: &Header,
        state_root_before: StateRoot,
        receipt: &BlockReceipt,
        proof_system: &PS,
        proven: bool,
    ) -> Result<ReceiptOutcome, ImportError<DB::Error>> {
        let height = header.height;
        let retained = self.store().get_block_proof(&hash)?;
        if retained.is_none_or(|retained| retained.proof_bytes == receipt.proof_bytes) {
            return Ok(ReceiptOutcome::AlreadyProven { height });
        }
        // A receipt of a statement already held adds nothing, so it is
        // not verified again: its claimed statement suffices to skip it.
        if self.holds_receipt_statement(&hash, &receipt.proof_bytes, proof_system)? {
            return Ok(ReceiptOutcome::StatementHeld { height });
        }
        let mut proof =
            self.canonical_block_proof(header, state_root_before, receipt.proof_bytes.clone())?;
        let body = self.store().get_body(&hash)?;
        let statement = self.verify_block_receipt(
            header,
            body.as_ref(),
            state_root_before,
            &proof,
            proof_system,
        )?;
        // A further valid receipt of a proven block is another ticket for
        // selection (design 08): retained within `max_receipts_per_block`,
        // the proposer's first and then the earliest verified. A finalized
        // block's selection is settled; its receipt is only verified.
        if proven {
            crate::prove::attribute(&mut proof, &statement);
            // The proposer's own receipt decides selection whenever held,
            // so a newly retained one is relayed even though another
            // receipt proved the block first.
            let proposers = proof.prover_address == proof.public_inputs.proposer_address
                && !self
                    .store()
                    .block_receipts(&hash)?
                    .iter()
                    .any(|held| held.proof.statement_key == proof.statement_key);
            let (slot, max) = (self.local_slot(), self.max_receipts_per_block());
            let protected = self.protected_receipt_keys();
            self.store_mut()
                .put_block_receipt(&proof, slot, max, false, &protected)?;
            if proposers {
                return Ok(ReceiptOutcome::ProposerReceipt { height });
            }
        }
        Ok(ReceiptOutcome::AlreadyProven { height })
    }
}

/// Outcome of [`Engine::import_block_receipt`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptOutcome {
    /// Other bytes claiming a statement already held for a proven block. They
    /// were not verified, so they earn no verdict and must not be retained.
    StatementHeld {
        /// Height of the already proven block.
        height: Height,
    },
    /// The receipt proved a candidate; its height may now complete a chunk.
    Proven {
        /// Height of the newly proven block.
        height: Height,
    },
    /// The block was already proven or finalized; the retained receipt stands.
    AlreadyProven {
        /// Height of the block.
        height: Height,
    },
    /// The proposer's own receipt of a block another receipt proved first:
    /// newly retained, and to be relayed because selection prefers it.
    ProposerReceipt {
        /// Height of the block.
        height: Height,
    },
}
