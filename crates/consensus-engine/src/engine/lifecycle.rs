//! Engine construction: genesis initialisation and reopening a database.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;

use neutrin0_consensus_fork_choice::ForkChoice;
use neutrin0_primitives::{ChainSpec, Hash};
use neutrin0_storage::{Column, Database};
use neutrin0_trie::Trie;

use super::{Engine, EngineParts, RejectedProofCache, StateSource};
use crate::clock::SlotClock;
use crate::error::EngineError;
use crate::slashing::SlashingMonitor;
use crate::store::{ChainStore, StatePin, StoreError};

impl<DB: Database> Engine<DB> {
    /// Initialise a brand new engine on an empty `db` without its genesis
    /// state, which [`Self::install_genesis_state`] adds later.
    ///
    /// Validates `chain_spec` and writes, in one durable batch, metadata
    /// (`chain_spec_hash`), the initial validator-set snapshot, and the genesis
    /// pointers (`tip`, `finalized_head`, `finalized_seed`).
    /// Returns an [`EngineError`] if the spec is invalid or the
    /// database is already initialised.
    pub fn genesis(chain_spec: ChainSpec, db: DB) -> Result<Self, EngineError<DB::Error>> {
        Self::initialize(chain_spec, db, None)
    }

    /// Initialise a brand new engine on an empty `db` with its genesis
    /// `state` in the same durable batch as every pointer, so a failed first
    /// start leaves nothing a later start would mistake for a chain.
    ///
    /// # Errors
    /// As [`Self::genesis`], and when `state` does not hash to the committed
    /// genesis state root.
    pub fn genesis_with_state(
        chain_spec: ChainSpec,
        db: DB,
        state: &Trie,
    ) -> Result<Self, EngineError<DB::Error>> {
        Self::initialize(chain_spec, db, Some(state))
    }

    fn initialize(
        chain_spec: ChainSpec,
        db: DB,
        state: Option<&Trie>,
    ) -> Result<Self, EngineError<DB::Error>> {
        chain_spec.validate()?;

        let mut store = Self::spec_store(&chain_spec, db);
        if store.get_chain_spec_hash()?.is_some() {
            return Err(EngineError::AlreadyInitialised);
        }

        let chain_spec_hash = chain_spec.hash();
        // Signing protection imported into this directory must be this chain's.
        if store
            .db()
            .get(Column::Meta, crate::store::pointers::SIGNING_TRANSFER_SPEC)
            .map_err(StoreError::Database)?
            .is_some_and(|imported| imported != chain_spec_hash)
        {
            return Err(StoreError::Corrupt(
                "imported signing protection belongs to another chain specification",
            )
            .into());
        }
        let genesis_hash = chain_spec.genesis_block_hash;
        let mut batch = ChainStore::<DB>::genesis_batch(
            chain_spec_hash,
            &chain_spec.initial_validators,
            genesis_hash,
            chain_spec.genesis_seed,
        )?;
        let state_root = match state {
            Some(state) => {
                if state.root() != chain_spec.genesis_state_root {
                    return Err(StoreError::Corrupt(
                        "genesis state does not match the chain spec genesis_state_root",
                    )
                    .into());
                }
                store
                    .state_writer(&mut batch)
                    .pin(StatePin::Block(genesis_hash), state)?;
                chain_spec.genesis_state_root
            }
            None => neutrin0_trie::EMPTY_TRIE_ROOT,
        };
        store.commit_tip(genesis_hash, genesis_hash, batch)?;

        // Without a genesis state, empty until one is installed; reads go to
        // the store.
        let parts = EngineParts {
            state: store.state_at(state_root),
            identity_sanctions: store.state_at(neutrin0_trie::EMPTY_TRIE_ROOT),
            head_height: 0,
            head_hash: chain_spec.genesis_block_hash,
            head_state_root: chain_spec.genesis_state_root,
            finalized_seed: chain_spec.genesis_seed,
            latest_finalized_chunk_id: None,
            active_validator_set: chain_spec.initial_validators.clone(),
            previous_validator_set_root: chain_spec.genesis_validator_set_root,
            programs: None,
            fork_choice: ForkChoice::new(chain_spec.genesis_block_hash),
        };
        Self::assemble(chain_spec, chain_spec_hash, store, parts)
    }

    /// Wrap `db` in a store bounded by the spec's historical record window.
    pub(super) fn spec_store(chain_spec: &ChainSpec, db: DB) -> ChainStore<DB> {
        let mut store = ChainStore::new(db);
        store.configure_history_window(
            neutrin0_consensus_types::history::history_record_window_chunks(
                chain_spec.runtime.unbonding_delay_blocks,
                chain_spec.consensus.chunk_size,
            ),
        );
        store
    }

    /// Build an engine with empty live caches over durable `parts`.
    pub(super) fn assemble(
        chain_spec: ChainSpec,
        chain_spec_hash: Hash,
        store: ChainStore<DB>,
        parts: EngineParts,
    ) -> Result<Self, EngineError<DB::Error>> {
        let local_signing_policy = crate::LocalSigningPolicy::load(store.db())?;
        let clock = SlotClock::new(
            chain_spec.genesis_time,
            chain_spec.consensus.slot_duration_secs,
        );
        let consensus_domain = chain_spec.consensus_domain_with(chain_spec_hash);
        Ok(Self {
            chain_spec,
            chain_spec_hash,
            consensus_domain,
            store,
            clock,
            wall_clock: crate::clock::system_unix_secs,
            state: parts.state,
            identity_sanctions: parts.identity_sanctions,
            head_height: parts.head_height,
            head_hash: parts.head_hash,
            head_state_root: parts.head_state_root,
            finalized_seed: parts.finalized_seed,
            latest_finalized_chunk_id: parts.latest_finalized_chunk_id,
            certified_execution: None,
            certified_validation: None,
            projected_execution: None,
            active_validator_set: parts.active_validator_set,
            previous_validator_set_root: parts.previous_validator_set_root,
            bft_sessions: BTreeMap::new(),
            local_voter: None,
            standby_voter: None,
            local_signing_policy,
            local_control_faulted: false,
            local_signer_stopping: false,
            signing_quiet_until: 0,
            doppelganger: None,
            prover_address: None,
            programs: parts.programs,
            program_switches: Self::new_program_switch_cache(),
            slashing_monitor: SlashingMonitor::new(),
            bls_verifier: RefCell::default(),
            signing_verdicts: crate::signing_validation::SigningVerdicts::default(),
            rejected_proofs: RejectedProofCache::default(),
            awaited_receipts: BTreeMap::new(),
            proposal_arrivals: BTreeMap::new(),
            contradicting_receipts: Vec::new(),
            state_source: StateSource::Execution,
            fork_choice: parts.fork_choice,
        })
    }
}
