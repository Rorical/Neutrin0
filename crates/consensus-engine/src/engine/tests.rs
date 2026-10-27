use super::*;
use crate::error::EngineError;
use crate::slashing::SlashingError;
use crate::store::{StatePin, StoreError};
use crate::validator_set::validator_set_root;
use neutrin0_consensus_types::FinalityVote;
use neutrin0_storage::{Batch, Column, MemoryDatabase};

fn validators() -> Vec<Validator> {
    vec![Validator {
        pubkey: [9; 48],
        withdrawal_credentials: neutrin0_primitives::runtime_account([10; 20]),
        effective_stake: 32_000_000_000_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }]
}

fn chain_spec() -> ChainSpec {
    crate::test_db::spec(b"m5-local", 1, validators())
}

#[test]
fn cached_vote_equations_do_not_outlive_active_membership_or_source_window() {
    use neutrin0_consensus_types::FinalityVoteData;
    use neutrin0_crypto::bls::{Signature, aggregate_signatures};
    let keys: Vec<_> = (0..2)
        .map(|index| ProposerKey::from_ikm(&[42 + index; 32], u32::from(index)).unwrap())
        .collect();
    let mut spec = chain_spec();
    spec.initial_validators = keys
        .iter()
        .map(|key| Validator {
            pubkey: *key.public_key_bytes(),
            ..validators()[0].clone()
        })
        .collect();
    spec.genesis_validator_set_root = validator_set_root(&spec.initial_validators);
    let data = FinalityVoteData {
        chunk_id: 0,
        chunk_hash: [7; 32],
        selection: crate::bft_loop::fixture_selection(),
        round: 1,
        phase: FinalityVotePhase::Prevote,
    };
    let signatures: Vec<_> = keys
        .iter()
        .map(|key| {
            Signature::from_bytes(&key.sign_finality_vote(spec.consensus_domain(), &data)).unwrap()
        })
        .collect();
    let vote = FinalityVote {
        proof_manifests: Vec::new(),
        attestations: keys
            .iter()
            .map(|key| key.attest_vote(spec.consensus_domain(), data.clone(), Vec::new(), None))
            .collect(),
        data,
        aggregation_bits: neutrin0_primitives::BitVec::from_bytes(2, vec![3]).unwrap(),
        signature: aggregate_signatures(&signatures.iter().collect::<Vec<_>>())
            .unwrap()
            .to_bytes(),
    };
    {
        let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
        assert_eq!(
            engine.observe_votes_for_slashing(&vote).unwrap(),
            Vec::new()
        );
        assert_eq!(
            engine.observe_votes_for_slashing(&vote).unwrap(),
            Vec::new()
        );
        let mut inactive = spec.initial_validators.clone();
        inactive[0].effective_stake = 0;
        engine.set_active_validator_set(1, inactive).unwrap();
        assert!(engine.observe_votes_for_slashing(&vote).is_err());
    }
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).unwrap();
    assert_eq!(
        engine.observe_votes_for_slashing(&vote).unwrap(),
        Vec::new()
    );
    // Exercise the window predicate after authenticated local finality advances.
    engine.latest_finalized_chunk_id = Some(9);
    assert_eq!(
        engine.observe_votes_for_slashing(&vote),
        Err(SlashingError::SourceOutsideAccountabilityWindow),
    );
}

#[test]
fn genesis_writes_metadata_validator_snapshot_and_pointers() {
    let spec = chain_spec();
    let engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");

    assert_eq!(engine.head_height(), 0);
    assert_eq!(engine.head_hash(), spec.genesis_block_hash);
    assert_eq!(engine.head_state_root(), spec.genesis_state_root);
    assert_eq!(engine.finalized_seed(), spec.genesis_seed);
    assert_eq!(engine.latest_finalized_chunk_id(), None);
    assert_eq!(engine.chain_spec_hash(), spec.hash());
    assert_eq!(engine.consensus_domain(), spec.consensus_domain());
    assert_eq!(
        engine.clock().slot_duration_secs(),
        spec.consensus.slot_duration_secs,
    );

    let store = engine.store();
    assert_eq!(store.get_chain_spec_hash().unwrap(), Some(spec.hash()));
    assert_eq!(
        store.get_validator_set_snapshot(0).unwrap(),
        Some(spec.initial_validators.clone()),
    );
    assert_eq!(store.get_tip().unwrap(), Some(spec.genesis_block_hash));
    assert_eq!(
        store.get_finalized_head().unwrap(),
        Some(spec.genesis_block_hash)
    );
    assert_eq!(store.get_latest_finalized_chunk_id().unwrap(), None);
}

#[test]
fn genesis_on_already_initialised_db_is_rejected() {
    let spec = chain_spec();
    let db = MemoryDatabase::new();
    let engine = Engine::genesis(spec.clone(), db).expect("first genesis");
    let db2 = engine.store().db().clone();
    let err = Engine::genesis(spec, db2).expect_err("second genesis fails");
    assert!(matches!(err, EngineError::AlreadyInitialised));
}

#[test]
fn a_failed_first_start_leaves_no_partial_chain() {
    let mut spec = chain_spec();
    let mut state = Trie::new();
    state.insert(b"genesis", b"allocation".to_vec()).unwrap();
    spec.genesis_state_root = state.root();
    let mut db = crate::test_db::FaultDb::default();
    db.fail_durable_after = Some(0);
    let reader = db.read_handle();
    assert!(Engine::genesis_with_state(spec.clone(), db, &state).is_err());
    // Nothing marks the directory initialised, so the next start retries.
    assert_eq!(
        reader
            .get(Column::Meta, crate::store::pointers::CHAIN_SPEC_HASH)
            .unwrap(),
        None
    );
    let engine = Engine::genesis_with_state(spec.clone(), MemoryDatabase::new(), &state).unwrap();
    let reopened = Engine::open(spec, engine.store().db().clone()).unwrap();
    assert_eq!(
        reopened.state().get(b"genesis").unwrap(),
        Some(b"allocation".to_vec())
    );
}

#[test]
fn genesis_rejects_invalid_chain_spec() {
    let mut spec = chain_spec();
    spec.chain_id = 0;
    let err = Engine::genesis(spec, MemoryDatabase::new()).expect_err("invalid spec");
    assert!(matches!(err, EngineError::InvalidChainSpec(_)));
}

#[test]
fn open_round_trips_with_genesis_state() {
    let spec = chain_spec();
    let db = MemoryDatabase::new();
    let engine = Engine::genesis(spec.clone(), db).expect("genesis");
    let saved_db = engine.store().db().clone();
    let reopened = Engine::open(spec, saved_db).expect("reopen");
    assert_eq!(reopened.head_hash(), engine.head_hash());
    assert_eq!(reopened.head_height(), engine.head_height());
    assert_eq!(reopened.head_state_root(), engine.head_state_root());
    assert_eq!(reopened.finalized_seed(), engine.finalized_seed());
    assert_eq!(reopened.latest_finalized_chunk_id(), None);
}

#[test]
fn pinned_state_reads_on_demand_and_released_state_is_fully_collected() {
    let spec = chain_spec();
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    let columns = [
        Column::TrieNodes,
        Column::StateValues,
        Column::StateRefs,
        Column::StateReleases,
    ];
    let sizes =
        |engine: &Engine<MemoryDatabase>| columns.map(|column| engine.store().db().len(column));
    let genesis = sizes(&engine);
    let mut first = engine.state().clone();
    first.insert(b"alice", b"100".to_vec()).unwrap();
    first.insert(b"bob", b"50".to_vec()).unwrap();
    let mut second = first.clone();
    second.insert(b"alice", b"99".to_vec()).unwrap();
    // Both pins share the bob leaf; one batch stages them in sequence.
    let mut batch = Batch::new();
    let mut writer = engine.store().state_writer(&mut batch);
    writer.pin(StatePin::Block([1; 32]), &first).unwrap();
    writer.pin(StatePin::Block([2; 32]), &second).unwrap();
    engine
        .store_mut()
        .write_observed_batch(batch, false)
        .unwrap();
    let reopened = Engine::open(engine.chain_spec().clone(), engine.store().db().clone()).unwrap();
    assert_eq!(
        reopened
            .store()
            .state_at(first.root())
            .get(b"alice")
            .unwrap(),
        Some(b"100".to_vec())
    );
    let release = |engine: &mut Engine<MemoryDatabase>, block| {
        let mut batch = Batch::new();
        engine
            .store()
            .state_writer(&mut batch)
            .unpin(StatePin::Block(block))
            .unwrap();
        engine
            .store_mut()
            .write_observed_batch(batch, false)
            .unwrap();
        while !engine.collect_state_slice(1).unwrap() {}
    };
    release(&mut engine, [1; 32]);
    assert!(!engine.store().has_state(first.root()).unwrap());
    let survivor = engine.store().state_at(second.root());
    assert_eq!(survivor.get(b"alice").unwrap(), Some(b"99".to_vec()));
    assert_eq!(survivor.get(b"bob").unwrap(), Some(b"50".to_vec()));
    release(&mut engine, [2; 32]);
    assert_eq!(sizes(&engine), genesis);
}

#[test]
fn open_rejects_unknown_chain_spec_hash() {
    let spec = chain_spec();
    let db = MemoryDatabase::new();
    let engine = Engine::genesis(spec.clone(), db).expect("genesis");
    let saved_db = engine.store().db().clone();

    let mut other = spec;
    other.genesis_time += 1;
    let err = Engine::open(other, saved_db).expect_err("hash mismatch");
    assert!(matches!(err, EngineError::ChainSpecMismatch { .. }));
}

#[test]
fn failed_publication_keeps_memory_and_persisted_state_in_agreement() {
    use crate::test_db::{FaultDb, header};
    let spec = chain_spec();
    let mut engine = Engine::genesis(spec.clone(), FaultDb::default()).unwrap();
    let mut next_state = engine.state().clone();
    next_state.insert(b"alice", b"100".to_vec()).unwrap();
    let root = next_state.root();
    let block = neutrin0_consensus_types::Block {
        header: header(1, 1, engine.head_hash(), root),
        body: neutrin0_consensus_types::Body::default(),
    };
    let batch =
        crate::store::ChainStore::<FaultDb>::block_archive_batch(&block, None, None).unwrap();
    engine.store_mut().db_mut().fail_batch = true;
    assert!(
        engine
            .commit_materialized_head_with_batch(
                1,
                block.hash(),
                root,
                Some(next_state.clone()),
                batch
            )
            .is_err()
    );
    assert_eq!(engine.head_hash(), spec.genesis_block_hash);
    assert_eq!(engine.state().root(), spec.genesis_state_root);
    assert_eq!(engine.store().get_header(&block.hash()).unwrap(), None);
    assert_eq!(engine.store().get_block_hash_by_height(1).unwrap(), None);
    let restarted = Engine::open(spec.clone(), engine.store().db().clone()).unwrap();
    assert_eq!(restarted.head_hash(), spec.genesis_block_hash);
    engine.store_mut().db_mut().fail_batch = false;
    let batch =
        crate::store::ChainStore::<FaultDb>::block_archive_batch(&block, None, None).unwrap();
    engine
        .commit_materialized_head_with_batch(1, block.hash(), root, Some(next_state), batch)
        .unwrap();
    let restarted = Engine::open(spec, engine.store().db().clone()).unwrap();
    assert_eq!(restarted.head_hash(), block.hash());
    assert_eq!(
        restarted.state().get(b"alice").unwrap(),
        Some(b"100".to_vec())
    );
    engine
        .store_mut()
        .db_mut()
        .delete(Column::HeaderByHeight, &crate::store::keys::height_key(1))
        .unwrap();
    assert!(Engine::open(engine.chain_spec().clone(), engine.store().db().clone()).is_err());
}

#[test]
fn open_rejects_empty_database() {
    let spec = chain_spec();
    let err = Engine::open(spec, MemoryDatabase::new()).expect_err("not initialised");
    assert!(matches!(err, EngineError::NotInitialised));
}

#[test]
fn malformed_chain_spec_hash_is_corruption_not_an_empty_database() {
    use crate::store::pointers::CHAIN_SPEC_HASH;

    let spec = chain_spec();
    let engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).expect("genesis");
    let mut db = engine.store().db().clone();
    let tip = engine.store().get_tip().unwrap();
    db.put(Column::Meta, CHAIN_SPEC_HASH, &[7; 31]).unwrap();

    // Genesis must not mistake the damaged database for an empty one and
    // overwrite it; reopening reports the corruption.
    let err = Engine::genesis(spec.clone(), db.clone()).expect_err("corrupt metadata");
    assert!(matches!(err, EngineError::Store(StoreError::Corrupt(_))));
    let err = Engine::open(spec, db.clone()).expect_err("corrupt metadata");
    assert!(matches!(err, EngineError::Store(StoreError::Corrupt(_))));
    let store = ChainStore::new(db);
    assert!(matches!(
        store.get_chain_spec_hash(),
        Err(StoreError::Corrupt(_))
    ));
    assert_eq!(store.get_tip().unwrap(), tip);
}
