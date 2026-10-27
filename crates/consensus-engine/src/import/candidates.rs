//! Candidate blocks and receipts (design 08): a signed block with its write
//! set is accepted at slot speed, a receipt proves it later, and a candidate
//! nobody proves goes stale.

extern crate alloc;

use super::{AdmittedBlock, ImportBlockOutcome, ImportError, JudgedWrites};
use crate::engine::{Engine, StateSource};
use alloc::vec::Vec;
use neutrin0_consensus_fork_choice::ProofStatus;
use neutrin0_consensus_types::{Block, BlockStateDiff, CandidateBlock};
use neutrin0_primitives::{BlockHash, Height, StateRoot};
use neutrin0_proof_system::ErasedBlockExecutor;
use neutrin0_storage::Database;

impl<DB: Database> Engine<DB> {
    /// The candidate publication of a locally retained block: its body and
    /// write set, whether or not a receipt exists yet, or `None` while either
    /// is missing.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn candidate_block(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<CandidateBlock>, crate::store::StoreError<DB::Error>> {
        let Some(header) = self.store().get_header(hash)? else {
            return Ok(None);
        };
        let Some(body) = self.store().get_body(hash)? else {
            return Ok(None);
        };
        let Some(diff) = self.store().get_state_diff(hash)? else {
            return Ok(None);
        };
        Ok(Some(CandidateBlock {
            block: Block { header, body },
            writes: diff.writes,
        }))
    }

    /// Highest height a candidate may reach right now: two chunks above the
    /// finalized head, the chunk awaiting its certificate and proof plus the
    /// chunk being produced (design 11's bounded pipeline).
    #[must_use]
    pub fn pending_chain_limit(&self) -> Height {
        let chunk_size = self.chain_spec().consensus.chunk_size.max(1);
        let finalized_end = self
            .latest_finalized_chunk_id()
            .and_then(|id| self.chunk_heights(id))
            .map_or(0, |(_, end)| end);
        finalized_end.saturating_add(chunk_size.saturating_mul(2))
    }

    /// The highest block on the materialized branch whose every ancestor
    /// since the finalized anchor is proven: the state RPC `safe` serves.
    /// The finalized anchor itself when the first unfinalized block is still
    /// a candidate.
    #[must_use]
    pub fn proven_head(&self) -> BlockHash {
        let finalized = self.fork_choice.finalized();
        let mut path = Vec::new();
        let mut hash = self.head_hash();
        while hash != finalized {
            let Some(node) = self.fork_choice.block(&hash) else {
                break;
            };
            path.push((hash, node.proof_status));
            hash = node.parent_hash;
        }
        let mut proven = finalized;
        for (hash, status) in path.into_iter().rev() {
            if matches!(status, ProofStatus::Proven | ProofStatus::Finalized) {
                proven = hash;
            } else {
                break;
            }
        }
        proven
    }

    /// Mark candidates whose exclusive window has passed at `now_slot` as
    /// stale and move the materialized head off any stale branch (design
    /// 08). A stale candidate is not extended by production and does not
    /// select the head; a valid receipt that arrives while it is still
    /// retained restores it. One window later the stale candidate and its
    /// descendants are deleted, so a proving outage cannot accumulate
    /// candidates. Returns whether the head moved.
    ///
    /// # Errors
    /// Returns the replay errors of a head move and storage failures.
    pub fn refresh_stale_candidates(
        &mut self,
        now_slot: neutrin0_primitives::Slot,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<bool, ImportError<DB::Error>> {
        let window = self.chain_spec().consensus.proof_exclusive_slots;
        let Some(cutoff) = now_slot.checked_sub(window) else {
            return Ok(false);
        };
        // A head left on a stale branch by a failed replay is retried on
        // every refresh, not only when new candidates turn stale.
        let marked = self.fork_choice.mark_stale(cutoff) > 0;
        if marked {
            self.keep_abandoned_headers(cutoff)?;
        }
        let moved = if marked || self.fork_choice.on_stale_branch(self.head_hash()) {
            self.materialise_to_fork_choice_head(executor)?
        } else {
            false
        };
        if let Some(expired) = cutoff.checked_sub(window) {
            self.discard_stale_candidates(expired)?;
        }
        Ok(moved)
    }

    /// Keep the header of each candidate stale at `cutoff_slot` whose parent
    /// is not stale: the only blocks an abandonment can charge, kept
    /// durably until their height leaves the liveness window, whichever way
    /// the candidate itself is deleted.
    fn keep_abandoned_headers(
        &mut self,
        cutoff_slot: neutrin0_primitives::Slot,
    ) -> Result<(), ImportError<DB::Error>> {
        let stale = self.fork_choice.stale_subtrees(cutoff_slot);
        let mut batch = neutrin0_storage::Batch::new();
        for hash in &stale {
            if let Some(header) = self.store().get_header(hash)?
                && !stale.contains(&header.parent_hash)
            {
                crate::ChainStore::<DB>::keep_abandoned_header_batch(&mut batch, &header)?;
            }
        }
        self.store_mut().write_observed_batch(batch, false)?;
        Ok(())
    }

    /// Delete the candidates stale at or before `cutoff_slot` with every
    /// descendant: records, post-states and fork-choice nodes. The late
    /// receipt window has passed; a block a certified chunk still needs comes
    /// back through complete-chunk sync with its proof. The materialized head
    /// never lies on a stale branch, so a set reaching it deletes nothing.
    fn discard_stale_candidates(
        &mut self,
        cutoff_slot: neutrin0_primitives::Slot,
    ) -> Result<(), ImportError<DB::Error>> {
        let discarded = self.fork_choice.stale_subtrees(cutoff_slot);
        if discarded.is_empty() || discarded.contains(&self.head_hash()) {
            return Ok(());
        }
        let mut batch = neutrin0_storage::Batch::new();
        for hash in &discarded {
            self.store().discard_block_batch(&mut batch, hash)?;
        }
        self.store_mut().write_observed_batch(batch, false)?;
        self.fork_choice.remove_blocks(&discarded);
        Ok(())
    }

    /// Refuse a second unproven candidate its proposer signed for one slot
    /// (design 08 case 13) and any candidate past the unproven bound.
    fn require_candidate_room(
        &self,
        header: &neutrin0_consensus_types::Header,
        hash: BlockHash,
    ) -> Result<(), ImportError<DB::Error>> {
        if let Some(existing) = self
            .fork_choice
            .block_at_slot(header.slot, header.proposer_index)
            .filter(|existing| *existing != hash)
        {
            return Err(ImportError::SlotAlreadyProposed {
                slot: header.slot,
                existing,
            });
        }
        let limit = self.unproven_candidate_limit();
        if self.fork_choice.unproven_count() >= limit {
            return Err(ImportError::CandidateBound { limit });
        }
        Ok(())
    }

    /// Unproven candidates this node keeps above finality: one per height of
    /// the pending chain.
    #[must_use]
    pub fn unproven_candidate_limit(&self) -> usize {
        usize::try_from(self.chain_spec().consensus.chunk_size.saturating_mul(2))
            .unwrap_or(usize::MAX)
    }

    /// Import a proposer's candidate publication: the signed block and the
    /// write set of its execution, without a receipt (design 08).
    ///
    /// Admission runs the same header and body checks as every import and
    /// refuses a candidate beyond [`Self::pending_chain_limit`]. Then, by
    /// mode: with an `executor` the body is re-executed over the exact
    /// pre-state and the published writes must equal the local ones or
    /// reproduce the header's state root; without an executor under
    /// [`StateSource::ReceiptDiffs`] the writes must reproduce the header's
    /// state root over a scratch copy of the parent state, which then becomes
    /// the candidate state; without an executor under
    /// [`StateSource::Execution`] the candidate cannot be judged. Nothing
    /// trusts the candidate's execution: the root check only binds the writes
    /// to the signed header, and the block stays a candidate until a receipt
    /// proves it.
    ///
    /// A candidate for a block already retained adds its writes when the
    /// retained block has none and returns the head unchanged otherwise.
    ///
    /// # Errors
    /// Returns admission failures of [`Engine::import_block`],
    /// [`ImportError::PendingChainBound`], [`ImportError::StateDiffMismatch`],
    /// [`ImportError::StateDiffRootMismatch`], [`ImportError::StateDiffMalformed`],
    /// [`ImportError::ExecutorRequired`], replay errors or storage failures.
    pub fn import_candidate_block(
        &mut self,
        candidate: &CandidateBlock,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<ImportBlockOutcome, ImportError<DB::Error>> {
        let block = &candidate.block;
        let hash = block.hash();
        let header = &block.header;
        if !candidate.writes_well_formed() {
            return Err(ImportError::StateDiffMismatch { hash });
        }
        if self.is_archived_duplicate(block, &hash)? {
            return self.admit_writes_for_archived_block(candidate, &hash, executor);
        }
        let limit = self.pending_chain_limit();
        if header.height > limit {
            return Err(ImportError::PendingChainBound {
                height: header.height,
                limit,
            });
        }
        self.require_candidate_room(header, hash)?;

        let AdmittedBlock {
            parent_hash,
            parent_state_root,
            extends_materialised_head,
        } = self.admit_block_header_and_body(block)?;
        if executor.is_none() {
            self.participation_for_block(header, &block.body)
                .map_err(ImportError::DryRunFailed)?;
        }

        let published = BlockStateDiff {
            height: header.height,
            block_hash: hash,
            state_root_before: parent_state_root,
            state_root_after: header.state_root,
            writes: candidate.writes.clone(),
        };
        let (post_state, witness, diff) = self.judged_candidate_state(
            executor,
            block,
            extends_materialised_head,
            parent_state_root,
            published,
        )?;

        self.require_fork_choice_parent(parent_hash)?;
        let batch = crate::store::ChainStore::<DB>::block_archive_batch(
            block,
            witness.as_deref(),
            Some(&diff),
        )?;
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
        self.materialise_to_fork_choice_head(executor)?;
        Ok(self.import_outcome(hash)?)
    }

    /// The candidate state, witness and diff a candidate yields by mode: an
    /// executor re-executes the body, and an execution that contradicts the
    /// header while the writes reproduce its root is a divergence, not a
    /// gossip verdict; a receipt-following node applies the writes to a
    /// scratch pre-state; otherwise the candidate cannot be judged.
    fn judged_candidate_state(
        &self,
        executor: Option<&dyn ErasedBlockExecutor>,
        block: &Block,
        extends_materialised_head: bool,
        parent_state_root: StateRoot,
        published: BlockStateDiff,
    ) -> Result<JudgedWrites, ImportError<DB::Error>> {
        match (executor, self.state_source) {
            (Some(executor), _) => {
                let checked = if extends_materialised_head {
                    self.dry_run_block_against_head(executor, block)
                } else {
                    self.dry_run_block_against_parent(executor, block, parent_state_root)
                };
                let (state, checked) = match checked {
                    Ok(checked) => checked,
                    // Writes that reproduce the root are what a following
                    // node accepts; only a receipt can settle the claim. A
                    // failed local execution is no verdict on the relay either.
                    Err(error)
                        if error.is_execution_divergence()
                            || matches!(error, ImportError::DryRunFailed(_)) =>
                    {
                        let mut scratch =
                            self.scratch_pre_state(extends_materialised_head, parent_state_root)?;
                        return Err(
                            if Self::require_diff_reproduces_root(&mut scratch, &published).is_ok()
                            {
                                ImportError::ExecutionDiverges(Box::new(error))
                            } else {
                                error
                            },
                        );
                    }
                    Err(error) => return Err(error),
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

    /// A candidate for a block this node already retains: keep its writes
    /// when none are retained and they reproduce the header's state root over
    /// the exact pre-state; otherwise the head is returned unchanged.
    fn admit_writes_for_archived_block(
        &mut self,
        candidate: &CandidateBlock,
        hash: &BlockHash,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<ImportBlockOutcome, ImportError<DB::Error>> {
        let header = &candidate.block.header;
        if let Some(executor) = executor {
            self.retain_missing_import_witness(executor, &candidate.block)?;
        }
        if self.store().get_state_diff(hash)?.is_none() {
            let state_root_before =
                self.state_root_before(header)?
                    .ok_or(ImportError::MissingParentHeader {
                        parent_hash: header.parent_hash,
                    })?;
            let published = BlockStateDiff {
                height: header.height,
                block_hash: *hash,
                state_root_before,
                state_root_after: header.state_root,
                writes: candidate.writes.clone(),
            };
            let mut scratch = self.persisted_trie(state_root_before)?;
            Self::require_diff_reproduces_root(&mut scratch, &published)?;
            self.store_mut().put_state_diff(hash, &published)?;
        }
        Ok(self.import_outcome(*hash)?)
    }
}
