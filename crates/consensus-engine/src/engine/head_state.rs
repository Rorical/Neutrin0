//! Publication of the materialized head state, validator set and consensus
//! context: every in-memory view changes only after its durable batch.

extern crate alloc;

use alloc::vec::Vec;
use core::cell::RefCell;

use neutrin0_consensus_fork_choice::ForkChoice;
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_primitives::{BlockHash, CheckpointIndex, Height, StateRoot, Validator};
use neutrin0_storage::{Batch, Database};
use neutrin0_trie::Trie;

use super::{Engine, RejectedProofCache};
use crate::error::EngineError;
use crate::slashing::SlashingMonitor;
use crate::store::{StatePin, StoreError};

impl<DB: Database> Engine<DB> {
    /// Persist what the head state produced since it was last persisted,
    /// pinned as the head block's post-state.
    ///
    /// Idempotent: every commit already persists the head state, so this is a
    /// no-op unless the head state was changed in place since.
    pub fn flush_trie_to_store(&mut self) -> Result<(), StoreError<DB::Error>> {
        if self.state.node_count() == 0 && self.state.value_count() == 0 {
            return Ok(());
        }
        let mut batch = Batch::new();
        self.store
            .state_writer(&mut batch)
            .pin(StatePin::Block(self.head_hash), &self.state)?;
        self.store.write_observed_batch(batch, false)?;
        self.state = self.store.state_at(self.state.root());
        Ok(())
    }

    /// Persist a sibling branch's post-state as block `hash`'s together with
    /// `batch`. A block without a materialized state pins nothing.
    pub(crate) fn write_sibling_state(
        &mut self,
        hash: BlockHash,
        mut batch: Batch,
        state: Option<&Trie>,
    ) -> Result<(), StoreError<DB::Error>> {
        if let Some(state) = state {
            self.store
                .state_writer(&mut batch)
                .pin(StatePin::Block(hash), state)?;
        }
        self.store.write_observed_batch(batch, false)
    }

    /// Install the head state rebuilt from a peer's `StateByRoot` response,
    /// pinned as the head block's post-state.
    ///
    /// Callers must have already verified that
    /// `reconstructed.root() == self.head_state_root()`; the engine
    /// re-asserts the invariant defensively and panics on mismatch. The
    /// trie must hold what the store lacks, so this suits states small
    /// enough to hold whole; a downloaded state is streamed in and adopted
    /// by [`Self::adopt_installed_head_state`] instead.
    ///
    /// # Errors
    /// Returns the store error of an incomplete state or a failed write; the
    /// head state is then unchanged.
    pub fn replace_state_with_reconstructed(
        &mut self,
        reconstructed: &Trie,
    ) -> Result<(), StoreError<DB::Error>> {
        assert_eq!(
            reconstructed.root(),
            self.head_state_root,
            "snap-sync trie root must match the committed head_state_root"
        );
        let mut batch = Batch::new();
        self.store
            .state_writer(&mut batch)
            .pin(StatePin::Block(self.head_hash), reconstructed)?;
        self.store.write_observed_batch(batch, false)?;
        self.state = self.store.state_at(self.head_state_root);
        Ok(())
    }

    /// Adopt the finished installation of exactly the head state root as the
    /// head block's post-state, or release it once the head has moved past
    /// it. Returns whether it was adopted.
    ///
    /// # Errors
    /// Refuses an unfinished installation and reports a failed write; the
    /// head state is then unchanged.
    pub fn adopt_installed_head_state(&mut self) -> Result<bool, StoreError<DB::Error>> {
        let root = self.head_state_root;
        if self
            .store
            .state_install()?
            .is_none_or(|install| install.roots != [root])
        {
            self.store.release_state_install()?;
            return Ok(false);
        }
        let mut batch = Batch::new();
        self.store
            .state_writer(&mut batch)
            .unpin(StatePin::Block(self.head_hash))?;
        self.store.adopt_state_install_batch(
            &mut batch,
            &[root],
            &[StatePin::Block(self.head_hash)],
        )?;
        self.store.write_observed_batch(batch, false)?;
        self.state = self.store.state_at(root);
        Ok(true)
    }

    /// Install and persist the runtime state a fresh genesis engine starts
    /// from.
    ///
    /// The engine is created with an empty trie and the chain spec's
    /// `genesis_state_root`; callers derive the genesis allocation from the
    /// same spec and hand it over here so every node materialises identical
    /// state. Nodes reopening an existing database reload the persisted
    /// nodes instead.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] when the engine is past genesis or
    /// `state` does not hash to the committed genesis state root.
    pub fn install_genesis_state(&mut self, state: Trie) -> Result<(), StoreError<DB::Error>> {
        if self.head_height != 0 || self.head_hash != self.chain_spec.genesis_block_hash {
            return Err(StoreError::Corrupt(
                "genesis state can only be installed at genesis",
            ));
        }
        if state.root() != self.head_state_root {
            return Err(StoreError::Corrupt(
                "genesis state does not match the chain spec genesis_state_root",
            ));
        }
        let genesis_hash = self.chain_spec.genesis_block_hash;
        let root = self.head_state_root;
        self.commit_materialized_head_with_batch(0, genesis_hash, root, Some(state), Batch::new())
    }

    /// Replace the in-memory active validator set with `new_set` and
    /// persist a snapshot indexed at `effective_at`.
    ///
    /// Called by the chain backend at chunk-close to bridge runtime
    /// stake mutations into consensus proposer eligibility / BFT
    /// quorum weighting. `effective_at` is the chunk index at which
    /// the new set begins driving consensus (typically
    /// `latest_finalized_chunk_id + 1`).
    ///
    /// The transition is monotonic per `effective_at`: re-calling
    /// with a stale (smaller) index is a no-op so a duplicate finalize
    /// signal cannot rewind the active set.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Store`] when the snapshot fails to persist.
    pub fn set_active_validator_set(
        &mut self,
        effective_at: CheckpointIndex,
        new_set: Vec<Validator>,
    ) -> Result<(), EngineError<DB::Error>> {
        // Reject backwards transitions so a late-arriving finalize
        // signal cannot un-rotate the set.
        if let Some(latest) = self.store.get_latest_validator_set_index()?
            && effective_at <= latest
        {
            return Ok(());
        }
        self.store
            .put_latest_validator_set(effective_at, &new_set)?;
        self.active_validator_set = new_set;
        self.rebind_local_voter();
        Ok(())
    }

    /// Persist state deltas, selected ancestry and tip together before publishing
    /// the corresponding in-memory view. Failed writes leave that view unchanged.
    #[cfg(test)]
    pub(crate) fn commit_materialized_head(
        &mut self,
        height: Height,
        hash: BlockHash,
        state_root: StateRoot,
        next_state: Option<Trie>,
    ) -> Result<(), StoreError<DB::Error>> {
        self.commit_materialized_head_with_batch(height, hash, state_root, next_state, Batch::new())
    }

    pub(crate) fn commit_materialized_head_with_batch(
        &mut self,
        height: Height,
        hash: BlockHash,
        state_root: StateRoot,
        next_state: Option<Trie>,
        mut batch: Batch,
    ) -> Result<(), StoreError<DB::Error>> {
        if next_state
            .as_ref()
            .is_some_and(|state| state.root() != state_root)
        {
            return Err(StoreError::Corrupt("staged state root disagrees with head"));
        }
        let state = next_state.unwrap_or_else(|| self.state.clone());
        self.store
            .state_writer(&mut batch)
            .pin(StatePin::Block(hash), &state)?;
        self.store
            .commit_tip(hash, self.chain_spec.genesis_block_hash, batch)?;
        // Whatever the staged trie held is persisted now; read it from the store.
        self.state = self.store.state_at(state_root);
        self.head_height = height;
        self.head_hash = hash;
        self.head_state_root = state_root;
        Ok(())
    }

    /// Open the trie rooted at `root` over the persisted state columns for
    /// execution, replay or witness collection.
    ///
    /// A non-empty root whose node is not retained is unavailable state and
    /// an error here; a reachable node missing deeper down surfaces as a trie
    /// error from the first traversal that reaches it.
    pub(crate) fn persisted_trie(&self, root: StateRoot) -> Result<Trie, StoreError<DB::Error>> {
        if !self.store.has_state(root)? {
            return Err(StoreError::Corrupt("state root is not retained"));
        }
        Ok(self.store.state_at(root))
    }

    /// Install only after the complete finalization batch has committed.
    pub(crate) fn install_consensus_state(&mut self, state: &crate::full_chunk::ConsensusState) {
        self.projected_execution = None;
        self.signing_verdicts.next_generation();
        self.latest_finalized_chunk_id = state.boundary.next_chunk_id.checked_sub(1);
        self.finalized_seed = state.next_seed;
        self.active_validator_set
            .clone_from(&state.next_context.active_validators);
        self.previous_validator_set_root = commitment(&state.next_context.active_validators);
        self.rebind_local_voter();
        self.retain_accountability_observations();
    }

    /// Publish a bootstrap only after its state and every canonical pointer
    /// are durable; both tries are then read from the store.
    pub(crate) fn publish_bootstrap_state(
        &mut self,
        consensus: &crate::full_chunk::ConsensusState,
    ) {
        self.install_consensus_state(consensus);
        self.head_height = consensus.boundary.height;
        self.head_hash = consensus.boundary.block_hash;
        self.head_state_root = consensus.boundary.state_root;
        self.state = self.store.state_at(consensus.boundary.state_root);
        self.identity_sanctions = self
            .store
            .state_at(consensus.boundary.identity_sanctions_root);
        self.fork_choice = ForkChoice::new(consensus.boundary.block_hash);
        self.bft_sessions.clear();
        self.awaited_receipts.clear();
        self.certified_execution = None;
        self.certified_validation = None;
        self.slashing_monitor = SlashingMonitor::default();
        self.bls_verifier = RefCell::default();
        self.rejected_proofs = RejectedProofCache::default();
    }
}
