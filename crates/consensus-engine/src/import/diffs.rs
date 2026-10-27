//! State diffs: applying a published write set to a scratch pre-state and
//! replaying a branch from retained receipt-authenticated diffs.

extern crate alloc;

use super::{ImportError, ReplayedHead};
use crate::engine::Engine;
use alloc::vec::Vec;
use neutrin0_consensus_types::BlockStateDiff;
use neutrin0_primitives::{BlockHash, StateRoot};
use neutrin0_storage::Database;
use neutrin0_trie::Trie;

/// Apply every write of `diff` to `state` and return the resulting root.
///
/// # Errors
/// Returns [`ImportError::StateDiffMalformed`] when a key cannot be addressed
/// by the state trie or `state` does not hold every node on a written path;
/// `state` may then hold a partial application and must be discarded by the
/// caller.
pub fn apply_state_diff<E>(
    state: &mut Trie,
    diff: &BlockStateDiff,
) -> Result<StateRoot, ImportError<E>> {
    for write in &diff.writes {
        match &write.value {
            Some(value) => state
                .insert(&write.key, value.clone())
                .map_err(|_| ImportError::StateDiffMalformed)?,
            None => {
                state
                    .remove(&write.key)
                    .map_err(|_| ImportError::StateDiffMalformed)?;
            }
        }
    }
    Ok(state.root())
}

impl<DB: Database> Engine<DB> {
    /// A scratch copy of the state a block executes over: the live head trie
    /// for an extending block, the parent's persisted trie for a sibling.
    pub(super) fn scratch_pre_state(
        &self,
        extends_materialised_head: bool,
        parent_state_root: StateRoot,
    ) -> Result<Trie, ImportError<DB::Error>> {
        if extends_materialised_head {
            let mut scratch = self.state().clone();
            scratch.drain_pending_nodes();
            scratch.drain_pending_values();
            Ok(scratch)
        } else {
            Ok(self.persisted_trie(parent_state_root)?)
        }
    }

    /// Apply `diff` to `scratch` and require the diff's post-state root.
    pub(super) fn require_diff_reproduces_root(
        scratch: &mut Trie,
        diff: &BlockStateDiff,
    ) -> Result<(), ImportError<DB::Error>> {
        let computed = apply_state_diff(scratch, diff)?;
        if computed != diff.state_root_after {
            return Err(ImportError::StateDiffRootMismatch {
                expected: diff.state_root_after,
                computed,
            });
        }
        Ok(())
    }

    /// Replay the branch ending at `new_head` from retained verified receipts
    /// and state diffs, without an executor.
    ///
    /// Every block on the new branch must have a retained diff that extends
    /// the running state root and reproduces its header's state root. A
    /// retained diff was either verified against the block's receipt at
    /// import or produced by this node's own execution.
    pub(super) fn replay_to_head_with_diffs(
        &self,
        new_head: BlockHash,
    ) -> Result<ReplayedHead, ImportError<DB::Error>> {
        let (lca_hash, new_branch) = self.find_lca_and_path_to(new_head)?;
        let (lca_state_root, lca_height) = self.lookup_block_state(lca_hash)?;
        self.check_reorg_floor(lca_height)?;

        let mut state = self.persisted_trie(lca_state_root)?;
        let mut current_height = lca_height;
        let mut current_hash = lca_hash;
        let mut current_state_root = lca_state_root;
        for block_hash in new_branch {
            let header =
                self.store()
                    .get_header(&block_hash)?
                    .ok_or(ImportError::MissingParentHeader {
                        parent_hash: block_hash,
                    })?;
            let diff = self
                .store()
                .get_state_diff(&block_hash)?
                .ok_or(ImportError::MissingStateDiff(block_hash))?;
            if diff.block_hash != block_hash
                || diff.state_root_before != current_state_root
                || diff.state_root_after != header.state_root
            {
                return Err(ImportError::StateDiffMismatch { hash: block_hash });
            }
            let computed = apply_state_diff(&mut state, &diff)?;
            if computed != header.state_root {
                return Err(ImportError::StateDiffRootMismatch {
                    expected: header.state_root,
                    computed,
                });
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
            artifacts: Vec::new(),
        })
    }
}
