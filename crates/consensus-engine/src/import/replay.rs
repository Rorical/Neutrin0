//! Branch replay through the executor or retained receipt diffs.

extern crate alloc;

use super::{ImportError, ReplayedHead};
use crate::engine::{Engine, StateSource};
use alloc::vec::Vec;
use neutrin0_primitives::{BlockHash, Height, StateRoot};
use neutrin0_proof_system::ErasedBlockExecutor;
use neutrin0_storage::{Batch, Database};

impl<DB: Database> Engine<DB> {
    /// Replay and publish the fork-choice head when it differs from the
    /// currently materialized head and an executor is available.
    ///
    /// Replay reconstructs the lowest common ancestor's state, executes the
    /// new branch through the shared commitment checks, then commits its state
    /// and selected ancestry before publishing the corresponding head.
    ///
    /// Without an executor, a [`StateSource::ReceiptDiffs`] engine replays the
    /// branch from its retained verified receipts and state diffs instead.
    ///
    /// Returns `Ok(false)` when the heads already agree or no replay source is
    /// available, and `Ok(true)` after successful publication. A rejected
    /// replay or failed commit leaves this operation's materialized head/state
    /// unchanged. Earlier effects of a surrounding import remain in place.
    ///
    /// # Errors
    /// Returns [`ImportError::MissingParentHeader`] for missing stored ancestry
    /// or bodies, [`ImportError::ReorgPastFinalized`] when the LCA is below the
    /// finalized chunk's end height, [`ImportError::DryRunFailed`] for context
    /// or executor failures, the corresponding commitment-mismatch variant
    /// when replay disagrees with a header, or [`ImportError::Store`] on a
    /// storage/publication failure.
    pub fn materialise_to_fork_choice_head(
        &mut self,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<bool, ImportError<DB::Error>> {
        let new_head = self.fork_choice_head();
        if new_head == self.head_hash() {
            return Ok(false);
        }
        let mut replayed = self.replay_branch(new_head, executor)?;
        let mut batch = Batch::new();
        replayed
            .stage_witnesses(&mut batch)
            .map_err(ImportError::Codec)?;
        self.commit_materialized_head_with_batch(
            replayed.height,
            replayed.hash,
            replayed.state_root,
            Some(replayed.state),
            batch,
        )?;
        Ok(true)
    }

    /// Replay the branch ending at `new_head` through `executor`, or from
    /// retained receipts and diffs when this engine follows receipts.
    ///
    /// # Errors
    /// Returns [`ImportError::DryRunFailed`] when neither replay source is
    /// available, otherwise the replay's own errors.
    pub(crate) fn replay_branch(
        &self,
        new_head: BlockHash,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<ReplayedHead, ImportError<DB::Error>> {
        match (executor, self.state_source) {
            (Some(executor), _) => self.replay_to_head(new_head, executor),
            (None, StateSource::ReceiptDiffs) => self.replay_to_head_with_diffs(new_head),
            (None, StateSource::Execution) => Err(ImportError::DryRunFailed(
                "branch replay requires an executor".into(),
            )),
        }
    }

    pub(crate) fn replay_to_head(
        &self,
        new_head: BlockHash,
        executor: &dyn ErasedBlockExecutor,
    ) -> Result<ReplayedHead, ImportError<DB::Error>> {
        let (lca_hash, new_branch) = self.find_lca_and_path_to(new_head)?;
        let (lca_state_root, lca_height) = self.lookup_block_state(lca_hash)?;
        self.check_reorg_floor(lca_height)?;

        // Open the LCA's state trie; it reads only the nodes on the paths
        // replay touches below `lca_state_root`.
        let mut state = self.persisted_trie(lca_state_root)?;

        // Replay forward through `new_branch`. On any cross-check
        // mismatch we abandon the reorg — the materialised head
        // stays where it was, the stored header is left as
        // evidence, and the caller sees the variant-specific error.
        let mut current_height = lca_height;
        let mut current_hash = lca_hash;
        let mut current_state_root = lca_state_root;
        let mut artifacts = Vec::new();
        for block_hash in new_branch {
            let header =
                self.store()
                    .get_header(&block_hash)?
                    .ok_or(ImportError::MissingParentHeader {
                        parent_hash: block_hash,
                    })?;
            let body =
                self.store()
                    .get_body(&block_hash)?
                    .ok_or(ImportError::MissingParentHeader {
                        parent_hash: block_hash,
                    })?;

            let ctx = self.import_execution_context(&header, &body)?;
            let checked = Self::execute_checked(executor, &ctx, &header, &body, &mut state)?;
            if self.store().get_witness(&block_hash)?.is_none()
                || self.store().get_state_diff(&block_hash)?.is_none()
            {
                artifacts.push((block_hash, checked));
            }

            current_height = header.height;
            current_hash = block_hash;
            current_state_root = header.state_root;
        }

        Ok(ReplayedHead {
            height: current_height,
            hash: current_hash,
            state_root: current_state_root,
            state,
            artifacts,
        })
    }

    /// Refuse a branch whose common ancestor is below the certified execution
    /// dependency or the finalized chunk's end height. No state, head or
    /// height index changes until replay fully succeeds.
    pub(super) fn check_reorg_floor(
        &self,
        lca_height: Height,
    ) -> Result<(), ImportError<DB::Error>> {
        if let Some(boundary) = self.certified_execution_boundary()
            && lca_height < boundary.height
        {
            return Err(ImportError::ReorgPastCertified {
                lca_height,
                certified_height: boundary.height,
            });
        }
        if let Some(finalized_chunk_id) = self.latest_finalized_chunk_id() {
            let finalized_height = self
                .chunk_heights(finalized_chunk_id)
                .map_or(Height::MAX, |(_, end)| end);
            if lca_height < finalized_height {
                return Err(ImportError::ReorgPastFinalized {
                    lca_height,
                    finalized_height,
                });
            }
        }
        Ok(())
    }

    /// Walk both branches by height until their lowest common ancestor (LCA).
    /// Return the new branch in ancestor-first order, excluding the LCA.
    ///
    /// Valid branches meet at or above the finalized anchor. Do not collect the
    /// current head's entire ancestry first: older finalized headers may already
    /// have been pruned even when the LCA and both branches remain available.
    pub(super) fn find_lca_and_path_to(
        &self,
        new_head: BlockHash,
    ) -> Result<(BlockHash, Vec<BlockHash>), ImportError<DB::Error>> {
        let mut current = self.head_hash();
        let mut target = new_head;
        let (_, mut current_height) = self.lookup_block_state(current)?;
        let (_, mut target_height) = self.lookup_block_state(target)?;
        let mut new_branch = Vec::new();
        while current != target {
            let walk_current = current_height > target_height;
            let cursor = if walk_current { current } else { target };
            let header =
                self.store()
                    .get_header(&cursor)?
                    .ok_or(ImportError::MissingParentHeader {
                        parent_hash: cursor,
                    })?;
            let parent_height =
                header
                    .height
                    .checked_sub(1)
                    .ok_or(ImportError::MissingParentHeader {
                        parent_hash: header.parent_hash,
                    })?;
            if walk_current {
                current = header.parent_hash;
                current_height = parent_height;
            } else {
                new_branch.push(target);
                target = header.parent_hash;
                target_height = parent_height;
            }
        }
        new_branch.reverse();
        Ok((current, new_branch))
    }

    /// Look up `(state_root, height)` for a block hash, returning
    /// the genesis values when `hash` is the genesis-block hash
    /// (which has no stored header).
    pub(super) fn lookup_block_state(
        &self,
        hash: BlockHash,
    ) -> Result<(StateRoot, Height), ImportError<DB::Error>> {
        if hash == self.chain_spec().genesis_block_hash {
            return Ok((self.chain_spec().genesis_state_root, 0));
        }
        let header = self
            .store()
            .get_header(&hash)?
            .ok_or(ImportError::MissingParentHeader { parent_hash: hash })?;
        Ok((header.state_root, header.height))
    }
}
