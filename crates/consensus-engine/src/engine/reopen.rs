//! Reopening an initialised database: every durable pointer is checked
//! against the others before the engine resumes.

extern crate alloc;

use alloc::vec::Vec;

use neutrin0_consensus_fork_choice::ForkChoice;
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_primitives::{BlockHash, ChainSpec, ChunkId, Hash, Seed, Validator};
use neutrin0_storage::Database;
use neutrin0_trie::Trie;

use super::{Engine, EngineParts};
use crate::block_state::BlockState;
use crate::error::EngineError;
use crate::store::{ChainStore, StoreError};

impl<DB: Database> Engine<DB> {
    /// Re-open an already-initialised database.
    ///
    /// Verifies that the stored chain-spec hash matches `chain_spec`
    /// and decodes the current stored format. Rehydrates
    /// the in-memory head and finalization pointers from the store.
    pub fn open(chain_spec: ChainSpec, db: DB) -> Result<Self, EngineError<DB::Error>> {
        chain_spec.validate()?;
        let store = Self::spec_store(&chain_spec, db);
        let stored_spec_hash = store
            .get_chain_spec_hash()?
            .ok_or(EngineError::NotInitialised)?;
        let chain_spec_hash = chain_spec.hash();
        if stored_spec_hash != chain_spec_hash {
            return Err(EngineError::ChainSpecMismatch {
                stored: stored_spec_hash,
                provided: chain_spec_hash,
            });
        }

        store.retention_info_for_spec(&chain_spec)?;
        store.validate_history_cache()?;
        store.validate_evidence_reports()?;
        store.validate_canonical_index(chain_spec.genesis_block_hash)?;

        let head_hash = store.get_tip()?.ok_or(EngineError::NotInitialised)?;
        let finalized_head = store
            .get_finalized_head()?
            .ok_or(EngineError::NotInitialised)?;
        let latest_finalized_chunk_id = store.get_latest_finalized_chunk_id()?;

        // The head height + state root are reconstructed from the
        // latest stored header; at genesis there is no header so we
        // fall back to the chain spec.
        let (head_height, head_state_root) = if head_hash == chain_spec.genesis_block_hash {
            (0, chain_spec.genesis_state_root)
        } else {
            let header = store
                .get_header(&head_hash)?
                .ok_or(EngineError::NotInitialised)?;
            (header.height, header.state_root)
        };

        // Restart resume must observe whatever VRF seed the last
        // finalized chunk derived; falling back to the genesis seed would
        // silently fork the chain after the first chunk-close.
        let finalized_seed = store
            .get_finalized_seed()?
            .unwrap_or(chain_spec.genesis_seed);

        // The head state is read from the persisted columns on demand. A
        // light client or a node that has not installed its execution state
        // opens it all the same: every traversal reaching a missing node
        // reports unavailable state, never a panic.
        let state = store.state_at(head_state_root);

        // Rehydrate the latest validator-set snapshot so producers
        // resume with the correct active set for eligibility and BFT
        // quorum weighting. Falls back to `initial_validators` when
        // no snapshot beyond genesis has been persisted.
        let active_index = store.get_latest_validator_set_index()?.unwrap_or(0);
        let active_validator_set = store
            .get_validator_set_snapshot(active_index)?
            .unwrap_or_else(|| chain_spec.initial_validators.clone());

        let previous_validator_set_root = Self::restore_validator_set_root(
            &store,
            &chain_spec,
            chain_spec_hash,
            latest_finalized_chunk_id,
            finalized_head,
            finalized_seed,
            &active_validator_set,
        )?;
        Self::validate_retention_floor(&store, latest_finalized_chunk_id)?;

        let identity_sanctions = Self::restore_identity_sanctions(&store)?;
        let fork_choice = Self::restore_fork_choice(&store, finalized_head, head_hash)?;
        // The pinned trust profile is process configuration this node persisted
        // itself; restoring it keeps genesis boundaries derivable before the
        // proof backend re-pins the same set (a different set is rejected then).
        let domain = store.history_domain()?;
        let programs = domain.map(|domain| domain.programs);

        let parts = EngineParts {
            state,
            identity_sanctions,
            head_height,
            head_hash,
            head_state_root,
            finalized_seed,
            latest_finalized_chunk_id,
            active_validator_set,
            previous_validator_set_root,
            programs,
            fork_choice,
        };
        let mut engine = Self::assemble(chain_spec, chain_spec_hash, store, parts)?;
        engine.restore_certified_execution()?;
        engine.restore_bft_sessions()?;
        Ok(engine)
    }

    /// The validator-set root the stored consensus context commits, after
    /// checking that context against every finalized pointer; the genesis
    /// root before any chunk finalized.
    fn restore_validator_set_root(
        store: &ChainStore<DB>,
        chain_spec: &ChainSpec,
        chain_spec_hash: Hash,
        latest_finalized_chunk_id: Option<ChunkId>,
        finalized_head: BlockHash,
        finalized_seed: Seed,
        active_validator_set: &[Validator],
    ) -> Result<Hash, EngineError<DB::Error>> {
        if let Some(consensus) = store.get_consensus_state()? {
            let boundary = neutrin0_prover_chunk::consensus::context_boundary(
                &consensus.next_context,
                consensus.next_seed,
            )
            .map_err(|_| StoreError::Corrupt("stored consensus context is invalid"))?;
            if boundary != consensus.boundary
                || consensus.next_context.chain_id != chain_spec.chain_id
                || consensus.next_context.chain_spec_hash != chain_spec_hash
                || consensus.next_context.chunk_size != chain_spec.consensus.chunk_size
                || consensus.next_context.vm_code_hash
                    != consensus.next_context.programs.runtime_code_hash
                || consensus.next_context.programs != boundary.programs
                || latest_finalized_chunk_id != boundary.next_chunk_id.checked_sub(1)
                || finalized_head != boundary.block_hash
                || finalized_seed != boundary.seed
                || active_validator_set != consensus.next_context.active_validators
                || store.history_frontier(boundary.next_chunk_id)? != consensus.frontier
                || consensus.frontier.root() != Some(boundary.history_root)
                || store.consensus_boundary(boundary.next_chunk_id)? != Some(boundary)
            {
                return Err(
                    StoreError::Corrupt("stored consensus boundary pointers disagree").into(),
                );
            }
            Ok(commitment(&consensus.next_context.active_validators))
        } else if latest_finalized_chunk_id.is_some() {
            Err(StoreError::Corrupt("finalized chunk has no consensus context").into())
        } else {
            Ok(chain_spec.genesis_validator_set_root)
        }
    }

    /// The permanent identity sanctions trie at the stored boundary's root,
    /// which must be completely retained.
    fn restore_identity_sanctions(store: &ChainStore<DB>) -> Result<Trie, EngineError<DB::Error>> {
        let sanctions_root = store
            .get_consensus_state()?
            .map_or(neutrin0_runtime_core::EMPTY_STATE_ROOT, |consensus| {
                consensus.boundary.identity_sanctions_root
            });
        if !store.has_state(sanctions_root)? {
            return Err(
                StoreError::Corrupt("permanent identity sanctions state is incomplete").into(),
            );
        }
        Ok(store.state_at(sanctions_root))
    }

    /// Pruning never passes the finalized window, and a bootstrap never
    /// claims sources beyond finality.
    fn validate_retention_floor(
        store: &ChainStore<DB>,
        latest_finalized_chunk_id: Option<u64>,
    ) -> Result<(), StoreError<DB::Error>> {
        let finalized_count = latest_finalized_chunk_id
            .map(|id| {
                id.checked_add(1)
                    .ok_or(StoreError::Corrupt("finalized chunk count overflow"))
            })
            .transpose()?
            .unwrap_or(0);
        let floor = store.retention_info()?.pruned_before_chunk;
        let bootstrap_floor = store.bootstrap_source_floor()?;
        if floor
            > finalized_count
                .saturating_sub(neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS)
                .max(bootstrap_floor)
            || bootstrap_floor > floor
            || bootstrap_floor > finalized_count
        {
            return Err(StoreError::Corrupt(
                "retention exceeds proven finalized history",
            ));
        }
        Ok(())
    }

    fn restore_fork_choice(
        store: &ChainStore<DB>,
        finalized: BlockHash,
        head: BlockHash,
    ) -> Result<ForkChoice, StoreError<DB::Error>> {
        // Every descendant of finality has a later slot, so an archive's
        // older headers are never read.
        let finalized_slot = store
            .get_header(&finalized)?
            .map_or(0, |header| header.slot);
        let mut headers = Vec::new();
        for hash in store.block_hashes_from_slot(finalized_slot)? {
            let header = store
                .get_header(&hash)?
                .ok_or(StoreError::Corrupt("slot index names a missing header"))?;
            if header.hash() != hash || header.height == 0 {
                return Err(StoreError::Corrupt(
                    "archived header key or height is inconsistent",
                ));
            }
            headers.push(header);
        }
        headers.sort_by_key(|header| (header.height, header.hash()));
        let mut fork = ForkChoice::new(finalized);
        for header in headers {
            if header.parent_hash != finalized && fork.block(&header.parent_hash).is_none() {
                continue;
            }
            let hash = fork
                .add_block(&header)
                .map_err(|_| StoreError::Corrupt("archived DAG ancestry is inconsistent"))?;
            if matches!(
                store.get_block_state(&hash)?,
                Some(BlockState::Proven | BlockState::Finalized)
            ) {
                fork.on_block_proof(hash, neutrin0_consensus_fork_choice::ProofStatus::Proven)
                    .map_err(|_| StoreError::Corrupt("archived DAG proof state is inconsistent"))?;
            }
        }
        if head != finalized && fork.block(&head).is_none() {
            return Err(StoreError::Corrupt(
                "materialized head does not descend from finality",
            ));
        }
        Ok(fork)
    }
}
