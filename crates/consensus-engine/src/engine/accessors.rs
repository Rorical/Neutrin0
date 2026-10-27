//! Read accessors and small configuration setters of the engine.

use neutrin0_consensus_fork_choice::ForkChoice;
use neutrin0_consensus_types::{BlockProof, ProofRejectionReason};
use neutrin0_primitives::{
    BlockHash, ChainSpec, ChunkId, ConsensusDomain, Hash, Height, Seed, StateRoot, Validator,
};
use neutrin0_storage::Database;
use neutrin0_trie::Trie;

use super::{Engine, StateSource};
use crate::clock::SlotClock;
use crate::store::ChainStore;

impl<DB: Database> Engine<DB> {
    /// Select how imported blocks advance the materialized head state.
    ///
    /// [`StateSource::ReceiptDiffs`] makes branch replay apply retained,
    /// receipt-authenticated state diffs instead of requiring an executor;
    /// blocks then enter through [`Engine::import_proven_block`].
    pub const fn set_state_source(&mut self, source: StateSource) {
        self.state_source = source;
    }

    /// Current head-state advancement mode.
    #[must_use]
    pub const fn state_source(&self) -> StateSource {
        self.state_source
    }

    /// Insert a rejected `BlockProof` into the bounded cache.
    ///
    /// The latest rejected envelope per block is retained independently of
    /// successful alternate envelopes. The cache is FIFO and bounded at
    /// [`MAX_REJECTED_PROOFS_CACHED`] entries so a
    /// long-running node never grows the cache unboundedly.
    pub(crate) fn record_rejected_proof(
        &mut self,
        block_hash: BlockHash,
        proof: BlockProof,
        reason: ProofRejectionReason,
    ) {
        self.rejected_proofs.record(block_hash, proof, reason);
    }

    /// Number of rejected `BlockProof` envelopes currently cached.
    /// Exposed for tests; never panics, never depends on the cache's
    /// FIFO order.
    #[must_use]
    pub fn rejected_proof_cache_len(&self) -> usize {
        self.rejected_proofs.len()
    }

    /// Borrow the active chain spec.
    #[must_use]
    pub const fn chain_spec(&self) -> &ChainSpec {
        &self.chain_spec
    }

    /// Consensus signing domain of the active chain spec.
    #[must_use]
    pub const fn consensus_domain(&self) -> ConsensusDomain {
        self.consensus_domain
    }

    /// Blocks per chunk under the active chain spec.
    pub(crate) const fn chunk_size(&self) -> u64 {
        self.chain_spec.consensus.chunk_size
    }

    /// Chunk containing block `height`; `None` for the genesis height.
    pub(crate) fn chunk_of_height(&self, height: Height) -> Option<ChunkId> {
        height.checked_sub(1)?.checked_div(self.chunk_size())
    }

    /// First and last block heights of `chunk_id`; `None` when either overflows.
    pub fn chunk_heights(&self, chunk_id: ChunkId) -> Option<(Height, Height)> {
        let chunk_size = self.chunk_size();
        let start = chunk_id.checked_mul(chunk_size)?.checked_add(1)?;
        let end = chunk_id.checked_add(1)?.checked_mul(chunk_size)?;
        Some((start, end))
    }

    /// Validator-set root committed by the previous complete chunk, or the
    /// chain spec's genesis root before any chunk is finalized. Every BFT
    /// session binds this root so equivocations across a validator-set
    /// rotation cannot finalize.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "BFT callers keep the fallible signature of the former store read."
    )]
    pub(crate) const fn previous_validator_set_root(
        &self,
    ) -> Result<Hash, crate::BftLoopError<DB::Error>> {
        Ok(self.previous_validator_set_root)
    }

    /// Borrow the chain store.
    #[must_use]
    pub const fn store(&self) -> &ChainStore<DB> {
        &self.store
    }

    /// Mutably borrow the chain store.
    pub const fn store_mut(&mut self) -> &mut ChainStore<DB> {
        &mut self.store
    }

    /// Borrow the slot clock.
    #[must_use]
    pub const fn clock(&self) -> &SlotClock {
        &self.clock
    }

    /// Current local wall-clock time in Unix seconds.
    #[must_use]
    pub fn wall_clock_secs(&self) -> u64 {
        (self.wall_clock)()
    }

    /// Replace the local wall clock, for simulations that run ahead of or
    /// behind real time.
    pub const fn set_wall_clock(&mut self, wall_clock: fn() -> u64) {
        self.wall_clock = wall_clock;
    }

    /// Height of the current local head.
    #[must_use]
    pub const fn head_height(&self) -> Height {
        self.head_height
    }

    /// Hash of the current local head.
    #[must_use]
    pub const fn head_hash(&self) -> BlockHash {
        self.head_hash
    }

    /// Post-execution state root of the current local head.
    #[must_use]
    pub const fn head_state_root(&self) -> StateRoot {
        self.head_state_root
    }

    /// The active validator set currently driving proposer eligibility
    /// and BFT quorum weighting.
    #[must_use]
    pub fn active_validator_set(&self) -> &[Validator] {
        &self.active_validator_set
    }

    /// Borrow the fork-choice DAG.
    ///
    /// The DAG records every imported block including non-extending
    /// siblings; the local materialized head ([`Self::head_hash`])
    /// follows the linearly-applied chain. Callers that want the
    /// vote-weighted heaviest-proven-chain head should call
    /// [`Self::fork_choice_head`] instead of consulting the DAG
    /// directly.
    #[must_use]
    pub const fn fork_choice(&self) -> &ForkChoice {
        &self.fork_choice
    }

    /// Vote-weighted heaviest-proven-chain head per the fork-choice
    /// DAG. May differ from [`Self::head_hash`] when a competing
    /// branch has accumulated more vote weight than the locally
    /// materialized chain. Reorg materialisation replays the selected branch
    /// through the configured executor.
    #[must_use]
    pub fn fork_choice_head(&self) -> BlockHash {
        self.certified_execution_boundary().map_or_else(
            || self.fork_choice.head(),
            |boundary| self.fork_choice.head_descending_from(boundary.block_hash),
        )
    }

    /// Current fork-choice finalised anchor. Returns the
    /// chain-spec genesis block hash before any chunk has been
    /// finalised, and the most-recently-finalised chunk's
    /// `end_block_hash` afterwards. [`Engine::finalize_chunk`] advances it.
    ///
    /// `head()` candidates that do not descend from this hash are
    /// excluded from fork-choice scoring, so an operator that
    /// observes a stale anchor here knows reorgs across already-
    /// finalised history are still possible — useful for catching
    /// the symptom if `add_finalized_chunk` regresses.
    #[must_use]
    pub const fn fork_choice_finalized(&self) -> BlockHash {
        self.fork_choice.finalized()
    }

    /// Number of distinct validators whose latest vote is
    /// recorded in fork-choice's scoring map. Diagnostic helper
    /// for integration tests asserting the vote ingest path is wired.
    #[must_use]
    pub fn fork_choice_vote_count(&self) -> usize {
        self.fork_choice.vote_count()
    }

    /// Mutable test-only hook into the fork-choice DAG.
    ///
    /// In production, fork-choice mutations are driven by
    /// [`Self::import_block`], [`Self::import_block_proof`], and the
    /// finalize-chunk path. Tests that want to inject votes or
    /// promote proof status without round-tripping through a real
    /// `ProofSystem` use this hook directly. The accessor is `pub`
    /// because it is consumed by integration tests in `neutrin0-node`
    /// that live in a separate crate; production callers should
    /// never reach for it.
    #[doc(hidden)]
    pub const fn fork_choice_mut_for_test(&mut self) -> &mut ForkChoice {
        &mut self.fork_choice
    }

    /// Finalized seed currently used to evaluate VRF eligibility.
    #[must_use]
    pub const fn finalized_seed(&self) -> Seed {
        self.finalized_seed
    }

    /// Latest finalized chunk id, `None` until chunk 0 finalizes.
    #[must_use]
    pub const fn latest_finalized_chunk_id(&self) -> Option<ChunkId> {
        self.latest_finalized_chunk_id
    }

    /// Chain-spec hash recorded at boot.
    #[must_use]
    pub const fn chain_spec_hash(&self) -> Hash {
        self.chain_spec_hash
    }

    /// The head state: the post-execution root recorded in
    /// `head_state_root`, read from the persisted columns on demand. Cloning
    /// it copies only its root.
    #[must_use]
    pub const fn state(&self) -> &Trie {
        &self.state
    }
}
