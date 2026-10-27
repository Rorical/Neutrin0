//! Publication import: a block, the bytes of its receipt and the write set of
//! its execution are judged as one unit (design 07).
//!
//! The network carries only what the header does not already state: the body,
//! the receipt bytes and the write set. This module derives the canonical
//! receipt envelope and diff record from the header, the parent header and the
//! local consensus boundary, so every node stores identical records and the
//! same rejected-envelope identity feeds proof-signing accountability. A
//! proof-following node applies the writes; an executing node re-executes the
//! body and archives its own diff.

extern crate alloc;

use super::{AdmittedBlock, ImportBlockOutcome, ImportError, JudgedWrites};
use crate::block_state::BlockState;
use crate::engine::{Engine, StateSource};
use alloc::vec::Vec;
use neutrin0_consensus_fork_choice::ProofStatus;
use neutrin0_consensus_types::{Block, BlockProof, BlockStateDiff, Header, ProvenBlock};
use neutrin0_primitives::{BlockHash, StateRoot, ZERO_HASH};
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_storage::{Column, Database};

impl<DB: Database> Engine<DB> {
    /// The canonical receipt envelope of `header` for `proof_bytes`: height,
    /// hash and the public inputs this node derives from the header, its
    /// pre-state root and the program set of its chunk.
    ///
    /// # Errors
    /// Returns [`ImportError::DryRunFailed`] when the chunk's program set is
    /// not available locally yet.
    pub fn canonical_block_proof(
        &self,
        header: &Header,
        state_root_before: StateRoot,
        proof_bytes: Vec<u8>,
    ) -> Result<BlockProof, ImportError<DB::Error>> {
        let block_hash = header.hash();
        let public_inputs = self
            .block_public_inputs(header, state_root_before, block_hash)
            .map_err(|_| ImportError::DryRunFailed(super::PROGRAMS_UNAVAILABLE.to_owned()))?;
        Ok(BlockProof {
            height: header.height,
            block_hash,
            public_inputs,
            proof_bytes,
            // Attribution is read from the verified public values.
            prover_address: ZERO_HASH,
            statement_key: ZERO_HASH,
        })
    }

    /// Whether a receipt of `hash` already held commits the statement that
    /// `proof_bytes` claim, read from their public values before any proof
    /// verification.
    pub(super) fn holds_receipt_statement<PS: ProofSystem>(
        &self,
        hash: &BlockHash,
        proof_bytes: &[u8],
        proof_system: &PS,
    ) -> Result<bool, ImportError<DB::Error>> {
        let Some(key) = borsh::from_slice::<PS::BlockProof>(proof_bytes)
            .ok()
            .and_then(|decoded| proof_system.block_statement(&decoded).ok())
            .map(|statement| crate::statement_key(&statement))
        else {
            return Ok(false);
        };
        Ok(self
            .store()
            .get_block_proof(hash)?
            .is_some_and(|retained| retained.statement_key == key)
            || self
                .store()
                .block_receipts(hash)?
                .iter()
                .any(|held| held.proof.statement_key == key))
    }

    /// The slot of this node's wall clock, recorded as a receipt's first
    /// verification time.
    #[must_use]
    pub fn local_slot(&self) -> neutrin0_primitives::Slot {
        self.clock().slot_for(self.wall_clock_secs())
    }

    /// Distinct receipts retained per block under the chain specification.
    pub(crate) fn max_receipts_per_block(&self) -> usize {
        usize::try_from(self.chain_spec().consensus.max_receipts_per_block).unwrap_or(usize::MAX)
    }

    /// The publication unit of a locally retained block: its body, receipt
    /// bytes and write set, or `None` while any part is missing.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn proven_block(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<ProvenBlock>, crate::store::StoreError<DB::Error>> {
        let Some(header) = self.store().get_header(hash)? else {
            return Ok(None);
        };
        let Some(body) = self.store().get_body(hash)? else {
            return Ok(None);
        };
        let Some(proof) = self.store().get_block_proof(hash)? else {
            return Ok(None);
        };
        let Some(diff) = self.store().get_state_diff(hash)? else {
            return Ok(None);
        };
        Ok(Some(ProvenBlock {
            block: Block { header, body },
            proof_bytes: proof.proof_bytes,
            writes: diff.writes,
        }))
    }

    /// Import a producer's publication: the block, the bytes of its receipt
    /// and the write set of its execution, advancing the materialized head
    /// when the block extends it.
    ///
    /// Admission runs the same header and body checks as every import. The
    /// receipt envelope is derived from the header and the parent's state
    /// root and verified under the program set of the block's chunk before
    /// any state is touched. Then, by mode:
    ///
    /// - with an `executor`, the body is re-executed over the exact pre-state
    ///   and its commitments checked against the header; the published writes
    ///   must equal the local ones or, failing that, reproduce the header's
    ///   state root, exactly as a proof-following node judges them. The
    ///   locally executed diff and witness are archived;
    /// - without an executor under [`StateSource::ReceiptDiffs`], the
    ///   published writes must reproduce the header's state root over a
    ///   scratch copy of the parent state, which then becomes the new state;
    /// - without an executor under [`StateSource::Execution`] the block
    ///   cannot be judged and the import is refused with
    ///   [`ImportError::ExecutorRequired`]; no mode trusts a header.
    ///
    /// Block, receipt and diff are archived in one batch with the block
    /// already `Proven`; a failure anywhere imports nothing. A block already
    /// archived as proven or finalized with the same receipt bytes returns the
    /// current head unchanged; different receipt bytes are judged for
    /// accountability without replacing the retained receipt, and a retained
    /// block that is still awaiting its own receipt admits this one.
    /// Fork-choice selection of another branch replays it from retained
    /// receipts and diffs or by execution.
    ///
    /// # Errors
    /// Returns admission failures of [`Engine::import_block`], receipt
    /// failures of [`Engine::import_block_proof`], checked-execution
    /// mismatches of [`Engine::import_block`],
    /// [`ImportError::StateDiffMismatch`], [`ImportError::StateDiffRootMismatch`],
    /// [`ImportError::StateDiffMalformed`], replay errors or storage failures.
    pub fn import_proven_block<PS: ProofSystem>(
        &mut self,
        bundle: &ProvenBlock,
        proof_system: &PS,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<ImportBlockOutcome, ImportError<DB::Error>> {
        let block = &bundle.block;
        let hash = block.hash();
        let header = &block.header;
        if !bundle.writes_well_formed() {
            return Err(ImportError::StateDiffMismatch { hash });
        }
        if self.is_archived_duplicate(block, &hash)? {
            return self.admit_receipt_for_archived_block(bundle, &hash, proof_system, executor);
        }

        let AdmittedBlock {
            parent_hash,
            parent_state_root,
            extends_materialised_head,
        } = self.admit_block_header_and_body(block)?;
        // First-block participation is authenticated from this exact branch
        // even when the program set is unknown and bindings are skipped.
        if executor.is_none() {
            self.participation_for_block(header, &block.body)
                .map_err(ImportError::DryRunFailed)?;
        }
        let mut proof =
            self.canonical_block_proof(header, parent_state_root, bundle.proof_bytes.clone())?;
        let statement = self.verify_block_receipt(
            header,
            Some(&block.body),
            parent_state_root,
            &proof,
            proof_system,
        )?;
        crate::prove::attribute(&mut proof, &statement);

        // The receipt binds `parent_state_root -> header.state_root`; the
        // writes must reproduce that transition over the exact pre-state.
        let published = BlockStateDiff {
            height: header.height,
            block_hash: hash,
            state_root_before: parent_state_root,
            state_root_after: header.state_root,
            writes: bundle.writes.clone(),
        };
        let (post_state, witness, diff) = self.judged_publication_state(
            executor,
            block,
            extends_materialised_head,
            parent_state_root,
            published,
        )?;

        self.require_fork_choice_parent(parent_hash)?;
        let batch =
            self.proven_publication_batch(block, hash, &proof, witness.as_deref(), &diff)?;
        if extends_materialised_head {
            self.commit_materialized_head_with_batch(
                header.height,
                hash,
                header.state_root,
                post_state,
                batch,
            )?;
        } else {
            self.write_sibling_state(hash, batch, post_state.as_ref())?;
        }
        // Cannot fail: the parent was checked above and commits leave fork choice untouched.
        let _ = self.fork_choice.add_block(header);
        let _ = self.fork_choice.on_block_proof(hash, ProofStatus::Proven);

        // A newly selected branch replays from retained receipts and diffs or
        // by execution; earlier archival and DAG registration remain.
        self.materialise_to_fork_choice_head(executor)?;
        Ok(self.import_outcome(hash)?)
    }

    /// The post-state, witness and diff a publication yields by mode: an
    /// executor re-executes the body and the published writes must equal the
    /// local ones or reproduce the header's root; a receipt-following node
    /// applies the writes to a scratch pre-state; otherwise the block cannot
    /// be judged.
    fn judged_publication_state(
        &self,
        executor: Option<&dyn ErasedBlockExecutor>,
        block: &Block,
        extends_materialised_head: bool,
        parent_state_root: StateRoot,
        published: BlockStateDiff,
    ) -> Result<JudgedWrites, ImportError<DB::Error>> {
        match (executor, self.state_source) {
            (Some(executor), _) => {
                let (state, checked) = if extends_materialised_head {
                    self.dry_run_block_against_head(executor, block)?
                } else {
                    self.dry_run_block_against_parent(executor, block, parent_state_root)?
                };
                if checked.diff.writes != published.writes {
                    let mut scratch =
                        self.scratch_pre_state(extends_materialised_head, parent_state_root)?;
                    Self::require_diff_reproduces_root(&mut scratch, &published)?;
                }
                Ok((Some(state), Some(checked.witness), checked.diff))
            }
            (None, StateSource::ReceiptDiffs) => {
                let mut scratch =
                    self.scratch_pre_state(extends_materialised_head, parent_state_root)?;
                Self::require_diff_reproduces_root(&mut scratch, &published)?;
                Ok((Some(scratch), None, published))
            }
            (None, StateSource::Execution) => Err(ImportError::ExecutorRequired),
        }
    }

    /// The archive batch of a publication: the block with its witness and
    /// diff, its receipt and the `Proven` state.
    fn proven_publication_batch(
        &self,
        block: &Block,
        hash: BlockHash,
        proof: &BlockProof,
        witness: Option<&[u8]>,
        diff: &BlockStateDiff,
    ) -> Result<neutrin0_storage::Batch, ImportError<DB::Error>> {
        let mut batch =
            crate::store::ChainStore::<DB>::block_archive_batch(block, witness, Some(diff))?;
        // The archive batch registers a freshly produced block; this block is
        // proven on arrival. A later put in the same batch wins.
        batch.put(Column::BlockProofs, hash, borsh::to_vec(proof)?);
        batch.put(
            Column::BlockReceipts,
            crate::store::receipt_key(&hash, &proof.statement_key),
            borsh::to_vec(&crate::store::StoredReceipt {
                proof: proof.clone(),
                first_verified_slot: self.local_slot(),
            })?,
        );
        batch.put(
            Column::BlockStates,
            hash,
            borsh::to_vec(&BlockState::Proven)?,
        );
        Ok(batch)
    }

    /// A publication for a block this node already retains. Proven or
    /// finalized content with the retained receipt bytes returns the head
    /// unchanged; different receipt bytes are verified, so a rejected
    /// alternative is cached as exact evidence while a valid one for a proven
    /// block is retained beside the first for selection. A block still awaiting
    /// its own receipt (local production in progress) admits the published
    /// one and keeps a diff for serving.
    fn admit_receipt_for_archived_block<PS: ProofSystem>(
        &mut self,
        bundle: &ProvenBlock,
        hash: &BlockHash,
        proof_system: &PS,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<ImportBlockOutcome, ImportError<DB::Error>> {
        let header = &bundle.block.header;
        let state_root_before =
            self.state_root_before(header)?
                .ok_or(ImportError::MissingParentHeader {
                    parent_hash: header.parent_hash,
                })?;
        let state = self.store().get_block_state(hash)?;
        if matches!(state, Some(BlockState::Proven | BlockState::Finalized)) {
            if let Some(executor) = executor {
                self.retain_missing_import_witness(executor, &bundle.block)?;
            }
            let retained = self.store().get_block_proof(hash)?;
            if retained.is_none_or(|retained| retained.proof_bytes == bundle.proof_bytes) {
                return Ok(self.import_outcome(*hash)?);
            }
            let mut proof =
                self.canonical_block_proof(header, state_root_before, bundle.proof_bytes.clone())?;
            let statement = self.verify_block_receipt(
                header,
                Some(&bundle.block.body),
                state_root_before,
                &proof,
                proof_system,
            )?;
            // Another ticket for a proven block is retained for selection
            // (design 08); a finalized block's selection is settled.
            if state == Some(BlockState::Proven) {
                crate::prove::attribute(&mut proof, &statement);
                let (slot, max) = (self.local_slot(), self.max_receipts_per_block());
                let protected = self.protected_receipt_keys();
                self.store_mut()
                    .put_block_receipt(&proof, slot, max, false, &protected)?;
            }
            return Ok(self.import_outcome(*hash)?);
        }
        // A retained block without a diff (never the case for own production,
        // which archives its execution) keeps the published writes only once
        // they reproduce the header's state root over the exact pre-state.
        let published = (self.store().get_state_diff(hash)?.is_none()).then(|| BlockStateDiff {
            height: header.height,
            block_hash: *hash,
            state_root_before,
            state_root_after: header.state_root,
            writes: bundle.writes.clone(),
        });
        if let Some(published) = &published {
            let mut scratch = self.persisted_trie(state_root_before)?;
            Self::require_diff_reproduces_root(&mut scratch, published)?;
        }
        let proof =
            self.canonical_block_proof(header, state_root_before, bundle.proof_bytes.clone())?;
        self.import_block_proof_inner(&proof, proof_system, executor)?;
        if let Some(published) = &published {
            self.store_mut().put_state_diff(hash, published)?;
        }
        Ok(self.import_outcome(*hash)?)
    }
}
