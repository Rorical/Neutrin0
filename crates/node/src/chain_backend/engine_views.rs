//! Read-only views of the engine for the producer and tests.

use neutrin0_consensus_engine::Engine;
use neutrin0_primitives::{BlockHash, ChunkId, Height};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;

use super::{ChainBackend, storage_error};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Current head height, snapshotted under the engine mutex.
    pub fn head_height(&self) -> neutrin0_primitives::Height {
        if let Some(checkpoint) = self.light_checkpoint() {
            return checkpoint.boundary.height;
        }
        self.with_engine(neutrin0_consensus_engine::Engine::head_height)
    }

    /// Vote-weighted heaviest-proven-chain head per
    /// [`Engine::fork_choice_head`](neutrin0_consensus_engine::Engine::fork_choice_head).
    /// May differ from the materialised `head_block_hash` returned
    /// by [`SyncBackend::local_status`](neutrin0_sync::SyncBackend::local_status) when a competing branch has
    /// accumulated more vote weight that has not yet been observed
    /// by an import path. Imports materialise the fork-choice head
    /// to converge the two.
    pub fn fork_choice_head(&self) -> BlockHash {
        if let Some(checkpoint) = self.light_checkpoint() {
            return checkpoint.boundary.block_hash;
        }
        self.with_engine(neutrin0_consensus_engine::Engine::fork_choice_head)
    }

    /// Current fork-choice finalised anchor (the hash below which
    /// no DAG reorg is possible). Returns the chain-spec genesis
    /// block hash until the first chunk finalises, then advances to
    /// the latest finalised chunk's end block.
    ///
    /// Used by integration tests to confirm the finalisation pipeline
    /// is feeding fork choice.
    pub fn fork_choice_finalized(&self) -> BlockHash {
        if let Some(checkpoint) = self.light_checkpoint() {
            return checkpoint.boundary.block_hash;
        }
        self.with_engine(neutrin0_consensus_engine::Engine::fork_choice_finalized)
    }

    /// Distinct-validator vote count currently recorded in
    /// fork-choice's scoring map. Diagnostic.
    pub fn fork_choice_vote_count(&self) -> usize {
        self.with_engine(neutrin0_consensus_engine::Engine::fork_choice_vote_count)
    }

    /// Test-only: whether a background evidence proving job is in flight.
    /// Lets integration tests wait for the worker to settle before asserting
    /// that a redundant report produced nothing.
    #[doc(hidden)]
    pub fn evidence_worker_running_for_test(&self) -> bool {
        self.evidence_job_running
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// FSM state of the block at `hash`, if it has been observed.
    ///
    /// Used by integration tests that check whether a block has
    /// progressed past [`BlockState::BlockProduced`](neutrin0_consensus_engine::BlockState::BlockProduced).
    pub fn block_state(&self, hash: &BlockHash) -> Option<neutrin0_consensus_engine::BlockState> {
        self.with_engine(|e| e.store().get_block_state(hash).ok().flatten())
    }

    /// Raw execution witness bytes persisted for `hash`.
    ///
    /// Checked local production, import and replay persist authenticated
    /// execution inputs here so [`Self::prove_block`] can independently prove
    /// retained pending blocks. Peers never supply these witness bytes.
    pub fn witness_bytes(&self, hash: &BlockHash) -> Option<Vec<u8>> {
        self.with_engine(|e| e.store().get_witness(hash).ok().flatten())
    }

    /// Chunk size declared by the active chain spec. Used by the
    /// producer to detect chunk boundaries from the head height.
    pub fn chunk_size(&self) -> u64 {
        self.with_engine(|e| e.chain_spec().consensus.chunk_size)
    }

    /// Subnet routing for `chunk_id`'s aggregate finality votes.
    /// Exposed for the aggregator test harness; production callers stay
    /// inside [`Engine::subnet_for_chunk`].
    pub fn subnet_for_chunk(&self, chunk_id: ChunkId) -> u8 {
        self.with_engine(|e| e.subnet_for_chunk(chunk_id))
    }

    /// Scan the retained canonical suffix until an artifact predicate reports a gap.
    fn contiguous_canonical_height(
        e: &Engine<DB>,
        mut artifact_present: impl FnMut(Height, BlockHash) -> Result<bool, SyncBackendError>,
    ) -> Result<Height, SyncBackendError> {
        let first = e
            .retention_info()
            .map_err(storage_error)?
            .first_retained_height;
        let mut height = first.saturating_sub(1);
        for candidate in first..=e.head_height() {
            let hash = e
                .store()
                .get_block_hash_by_height(candidate)
                .map_err(storage_error)?
                .ok_or_else(|| {
                    SyncBackendError::Storage("canonical height is missing".to_owned())
                })?;
            if !artifact_present(candidate, hash)? {
                break;
            }
            height = candidate;
        }
        Ok(height)
    }

    pub(super) fn contiguous_proven_height(e: &Engine<DB>) -> Result<Height, SyncBackendError> {
        Self::contiguous_canonical_height(e, |candidate, hash| {
            let Some(proof) = e.store().get_block_proof(&hash).map_err(storage_error)? else {
                return Ok(false);
            };
            if proof.height != candidate || proof.block_hash != hash {
                return Err(storage_error("canonical proof cursor is inconsistent"));
            }
            Ok(true)
        })
    }
}
