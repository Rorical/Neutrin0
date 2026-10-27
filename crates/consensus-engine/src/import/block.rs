//! Admission and checked import of a peer block.

use neutrin0_consensus_types::Block;
use neutrin0_primitives::BlockHash;
use neutrin0_proof_system::ErasedBlockExecutor;
use neutrin0_storage::Database;

use super::{AdmittedBlock, ImportBlockOutcome, ImportError};
use crate::engine::Engine;
use crate::store::StoreError;

impl<DB: Database> Engine<DB> {
    /// Import a peer-supplied [`Block`] with checked execution of its body.
    ///
    /// The parent requires a stored header unless it is synthetic genesis.
    /// Independently, it must be present in the fork-choice DAG or equal its
    /// finalized anchor. Height, gas limit, timestamp and slot ordering are
    /// checked before header signature and VRF eligibility. Program pieces,
    /// body roots and the embedded historical-vote window must also match
    /// the chain's rules.
    ///
    /// The body executes against a clone of the live head trie when the
    /// block extends it and against a reconstruction of its parent's
    /// persisted state otherwise. The executor's state root, runtime-extra,
    /// receipts root and gas used must match the supplied header, in that
    /// order. A verified extending post-state is committed with the
    /// materialized head; a sibling's verified post-state is archived with
    /// its block so descendants can reconstruct that parent, then
    /// fork-choice state replay may select the branch. Replay and selected-
    /// state publication use the same checks.
    ///
    /// A new block is archived as [`BlockState::BlockProduced`](crate::BlockState::BlockProduced) with its
    /// witness and diff and added to fork choice. An already stored block
    /// with the same authenticated header and consensus body content returns
    /// the current head without demoting its proof state, retaining a
    /// witness it still lacks.
    ///
    /// Checked-execution failures precede block archival and DAG insertion.
    /// Later replay failures retain the earlier import effects; the complete
    /// import call is not a single transaction. There is no header-only
    /// import: a block whose execution this engine cannot check is refused.
    ///
    /// # Errors
    /// Returns [`ImportError`] for unknown ancestry, header timing/gas/
    /// signature/VRF failures, malformed program pieces, mismatched body
    /// roots, historical votes outside the allowed window, execution context
    /// or executor failures as [`ImportError::DryRunFailed`], commitment
    /// mismatches as [`ImportError::StateRootMismatch`],
    /// [`ImportError::HeaderRuntimeExtraMismatch`],
    /// [`ImportError::ReceiptsRootMismatch`] or [`ImportError::GasUsedMismatch`],
    /// branch replay errors such as [`ImportError::ReorgPastFinalized`], or
    /// storage failure.
    pub fn import_block(
        &mut self,
        block: &Block,
        executor: &dyn ErasedBlockExecutor,
    ) -> Result<ImportBlockOutcome, ImportError<DB::Error>> {
        // Replayed gossip must not demote Proven/Finalized back to Produced.
        // Compare the full previously authenticated artifact, including signature
        // and body, before returning the current materialized head unchanged.
        let hash = block.hash();
        if self.is_archived_duplicate(block, &hash)? {
            self.retain_missing_import_witness(executor, block)?;
            return Ok(self.import_outcome(hash)?);
        }

        let AdmittedBlock {
            parent_hash,
            parent_state_root,
            extends_materialised_head,
        } = self.admit_block_header_and_body(block)?;

        // Check a scratch live-head trie or reconstructed parent state before
        // archiving the block. The verified post-state is committed with an
        // extending head or archived for sibling descendants. A failure here
        // does not register the block in fork choice or publish its scratch
        // trie; earlier authenticated reporter observations remain.
        let (post_state, checked) = if extends_materialised_head {
            debug_assert_eq!(
                self.state().root(),
                self.head_state_root(),
                "engine state trie must match head_state_root on every executor-equipped import",
            );
            self.dry_run_block_against_head(executor, block)?
        } else {
            // Sibling import. Reconstruct the parent's state trie from
            // persisted nodes/values and re-execute against it; this catches
            // a malicious proposer who publishes a forged commitment for a
            // block that does not extend our materialised head. The verified
            // post-state is persisted for subsequent sibling descendants; the
            // materialized head stays put until fork choice picks this branch
            // and `materialise_to_fork_choice_head` replays forward with the
            // same checks.
            self.dry_run_block_against_parent(executor, block, parent_state_root)?
        };

        self.require_fork_choice_parent(parent_hash)?;
        let batch = crate::store::ChainStore::<DB>::block_archive_batch(
            block,
            Some(checked.witness.as_slice()),
            Some(&checked.diff),
        )?;
        if extends_materialised_head {
            self.commit_materialized_head_with_batch(
                block.header.height,
                hash,
                block.header.state_root,
                Some(post_state),
                batch,
            )?;
        } else {
            self.write_sibling_state(hash, batch, Some(&post_state))?;
        }
        // Cannot fail: the parent was checked above and commits leave fork choice untouched.
        let _ = self.fork_choice.add_block(&block.header);

        // Replay a newly selected fork-choice branch. Archive/head publication
        // and DAG registration above have already happened: replay failure
        // retains those earlier import effects without publishing the failed
        // replay's selected state.
        self.materialise_to_fork_choice_head(Some(executor))?;

        Ok(self.import_outcome(hash)?)
    }

    /// `true` when `block` is already archived with the same authenticated
    /// header and consensus body content.
    pub(crate) fn is_archived_duplicate(
        &self,
        block: &Block,
        hash: &BlockHash,
    ) -> Result<bool, StoreError<DB::Error>> {
        Ok(
            self.store().get_header(hash)?.as_ref() == Some(&block.header)
                && self
                    .store()
                    .get_body(hash)?
                    .as_ref()
                    .is_some_and(|body| body.same_consensus_content(&block.body)),
        )
    }

    /// Fork choice records a block only under a known parent (its only
    /// insertion failure). Check before writing so a rejection leaves no
    /// store residue.
    pub(crate) fn require_fork_choice_parent(
        &self,
        parent_hash: BlockHash,
    ) -> Result<(), ImportError<DB::Error>> {
        if parent_hash != self.fork_choice.finalized()
            && self.fork_choice.block(&parent_hash).is_none()
        {
            return Err(ImportError::ParentMismatch {
                expected: self.head_hash(),
                actual: parent_hash,
            });
        }
        Ok(())
    }

    /// Outcome of importing `block_hash`: that block and the local head the
    /// import left, which a sibling or duplicate import does not move.
    pub(super) fn import_outcome(
        &self,
        block_hash: BlockHash,
    ) -> Result<ImportBlockOutcome, StoreError<DB::Error>> {
        let new_head_hash = self.head_hash();
        let new_head_slot = self
            .store()
            .get_header(&new_head_hash)?
            .map_or(0, |header| header.slot);
        Ok(ImportBlockOutcome {
            block_hash,
            new_head_hash,
            new_head_height: self.head_height(),
            new_head_slot,
        })
    }
}
