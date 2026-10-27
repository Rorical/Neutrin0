//! Storage fixtures model already verified finalizations; no cryptographic receipts are generated.

mod bootstrap_storage_tests;
mod evidence_path_retention_tests;
mod reporter_retention_tests;
mod snapshot_tests;

use super::*;
use crate::full_chunk::ConsensusState;
use crate::test_db::{FaultDb, header};
use crate::{BlockState, ChainStore};
use neutrin0_consensus_types::history_proof::{
    ChainBinding, ConsensusBoundary, ConsensusStatement, ExecutionPrograms, ProofDomain,
};
use neutrin0_consensus_types::{AggregatedVote, ChunkProof, ChunkProofPublicInputs, FinalityCert};
use neutrin0_primitives::{
    BitVec, ChainSpec, ConsensusParams, Hash, LightClientParams, ProofParams, RuntimeParams,
    Validator, ZERO_HASH,
};
use neutrin0_prover_chunk::consensus::{as_chunk, genesis_context};

use neutrin0_consensus_types::evidence::commitment;
use neutrin0_prover_chunk::history::HistoricalChunk;
use neutrin0_storage::{Batch, Column, MemoryDatabase};
use neutrin0_trie::Trie;

/// Stream `state` and then `sanctions` into `target`'s store, as a
/// downloaded snapshot is installed before its bootstrap commits.
fn install_snapshot<DB: Database>(target: &mut Engine<DB>, state: &Trie, sanctions: &Trie)
where
    DB::Error: std::fmt::Debug,
{
    #[derive(Debug)]
    struct Both<'a>(&'a Trie, &'a Trie);
    impl neutrin0_trie::NodeSource for Both<'_> {
        fn node(&self, hash: &Hash) -> Option<Vec<u8>> {
            self.0.node(hash).or_else(|| self.1.node(hash))
        }
        fn value(&self, hash: &Hash) -> Option<Vec<u8>> {
            self.0.value(hash).or_else(|| self.1.value(hash))
        }
    }
    target
        .store_mut()
        .install_state_slice(
            &[state.root(), sanctions.root()],
            &Both(state, sanctions),
            usize::MAX,
        )
        .unwrap();
}

fn spec() -> ChainSpec {
    let validators = vec![Validator {
        pubkey: [9; 48],
        withdrawal_credentials: neutrin0_primitives::runtime_account([10; 20]),
        effective_stake: 100,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }];
    ChainSpec {
        genesis_execution: neutrin0_primitives::ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
        genesis_time: 0,
        genesis_gas_limit: 1_000_000,
        runtime_code_hash: [3; 32],
        genesis_chunk: [4; 8],
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: [4; 32],
        genesis_block_hash: [5; 32],
        consensus: ConsensusParams {
            chunk_size: 1,
            ..ConsensusParams::default()
        },
        proof: ProofParams::default(),
        light_client: LightClientParams {
            weak_subjectivity_period_secs: 7 * neutrin0_primitives::DEFAULT_SLOT_DURATION_SECS,
            ..LightClientParams::default()
        },
        // An eight-block unbonding delay over one-block chunks keeps the
        // historical record window at the eight-chunk minimum these fixtures
        // count on; the liveness window stays strictly inside it.
        runtime: RuntimeParams {
            evidence_max_age_blocks: 7,
            unbonding_delay_blocks: 8,
            ..RuntimeParams::default()
        },
        ..crate::test_db::spec(b"retention-test", 7, validators)
    }
}

fn domain(spec: &ChainSpec) -> ProofDomain {
    ProofDomain {
        chain: ChainBinding::new(spec),
        chunk: spec.genesis_chunk,
        programs: neutrin0_consensus_types::history_proof::ProgramSet {
            runtime_code_hash: spec.runtime_code_hash,
            execution: ExecutionPrograms {
                fact: [1; 8],
                evidence: [2; 8],
                block: [3; 8],
            },
        },
    }
}

fn fixture<DB: Database>(db: DB, count: u64) -> Engine<DB>
where
    DB::Error: std::fmt::Debug,
{
    fixture_with_spec(db, count, &spec())
}

fn fixture_with_spec<DB: Database>(db: DB, count: u64, spec: &ChainSpec) -> Engine<DB>
where
    DB::Error: std::fmt::Debug,
{
    let mut engine = Engine::genesis(spec.clone(), db).unwrap();
    engine.set_history_domain(domain(spec)).unwrap();
    for _ in 0..count {
        append(&mut engine);
    }
    engine
}

#[allow(
    clippy::too_many_lines,
    reason = "The fixture explicitly writes the complete persisted finalization transaction."
)]
fn append<DB: Database>(engine: &mut Engine<DB>)
where
    DB::Error: std::fmt::Debug,
{
    let spec = engine.chain_spec().clone();
    let id = engine.finalized_next_chunk_id();
    let start = engine.canonical_boundary(id).unwrap();
    let mut trie = engine.state().clone();
    trie.insert(b"counter", (id + 1).to_be_bytes().to_vec())
        .unwrap();
    let header = header(id + 1, id + 1, start.block_hash, trie.root());
    let hash = engine.store_mut().put_header(&header).unwrap();
    engine.fork_choice.add_block(&header).unwrap();
    let inputs = ChunkProofPublicInputs {
        next_identity_sanctions_root: [0; 32],

        chunk_id: id,
        start_height: id + 1,
        end_height: id + 1,
        start_state_root: start.state_root,
        end_state_root: header.state_root,
        start_block_hash: hash,
        end_block_hash: hash,
        block_hash_root: hash,
        block_proof_root: [7; 32],
        vrf_proof_root: [8; 32],
        active_validator_set_root: spec.genesis_validator_set_root,
        next_validator_set_root: spec.genesis_validator_set_root,
        da_root: [9; 32],
    };
    let chunk = as_chunk(&inputs);
    let vote = AggregatedVote {
        aggregation_bits: BitVec::default(),
        signature: [0; 96],
    };
    let cert = FinalityCert {
        proposal: neutrin0_consensus_types::BftProposal {
            chunk: chunk.clone(),
            round: 0,
            proposer_index: 0,
            valid_quorum: None,
            round_change_certificate: None,
            proposal_slot: 0,
            receipts: Vec::new(),
            ratified_chunk_proofs: Vec::new(),
            signature: [0; 96],
        },
        chunk_id: id,
        round: 0,
        chunk_hash: chunk.hash(),
        prevote: vote.clone(),
        precommit: vote,
        active_validator_set_root: spec.genesis_validator_set_root,
        prevote_attestations: Vec::new(),
        precommit_attestations: Vec::new(),
        proof_manifests: Vec::new(),
    };
    let record = HistoricalChunk {
        runtime_code_hash: start.programs.runtime_code_hash,
        block_guest_vk_digest: start.programs.execution.block,
        start_boundary: start.commitment(),
        chunk: chunk.clone(),
        validators: spec.initial_validators.clone(),
        seed: start.seed,
        finality: cert.clone(),
    };
    let mut batch = Batch::new();
    let frontier = engine
        .store()
        .append_history_batch(&mut batch, &record)
        .unwrap();
    let end = ConsensusBoundary {
        identity_sanctions_root: [0; 32],

        next_chunk_id: id + 1,
        height: id + 1,
        block_hash: hash,
        state_root: header.state_root,
        slot: id + 1,
        validators_root: spec.genesis_validator_set_root,
        seed: spec.genesis_seed,
        history_root: frontier.root().unwrap(),
        programs: domain(&spec).programs,
        participation: [u8::try_from(id).expect("fixture chunk ids fit u8"); 32],
        proving: neutrin0_consensus_types::proving::NO_PROVING,
        fork: None,
    };
    let statement = ConsensusStatement {
        chain: domain(&spec).chain,
        start,
        end,
        chunk: inputs.clone(),
        finality_cert_hash: commitment(&cert),
    };
    let mut next_context = genesis_context(&spec, domain(&spec).programs);
    next_context.chunk_id = id + 1;
    next_context.parent_block_hash = hash;
    next_context.pre_state_root = end.state_root;
    next_context.parent_slot = end.slot;
    next_context.history_root = end.history_root;
    next_context.participation = end.participation;
    let state = ConsensusState {
        boundary: statement.end,
        next_context,
        next_seed: end.seed,
        frontier,
    };
    let proof = ChunkProof {
        chunk_id: id,
        chunk_hash: chunk.hash(),
        public_inputs: inputs,
        prover_address: [0; 32],
        finality_cert: cert.clone(),
        proof_bytes: vec![1],
    };
    batch.put(
        Column::ChunkStatements,
        id.to_be_bytes(),
        borsh::to_vec(&statement).unwrap(),
    );
    batch.put(
        Column::Chunks,
        id.to_be_bytes(),
        borsh::to_vec(&chunk).unwrap(),
    );
    batch.put(
        Column::ChunkProofs,
        id.to_be_bytes(),
        borsh::to_vec(&proof).unwrap(),
    );
    for boundary in [start, end] {
        batch.put(
            Column::ConsensusBoundaries,
            boundary.next_chunk_id.to_be_bytes(),
            borsh::to_vec(&boundary).unwrap(),
        );
    }
    batch.put(
        Column::Finalized,
        crate::pointers::CONSENSUS_STATE,
        borsh::to_vec(&state).unwrap(),
    );
    batch.put(
        Column::Finalized,
        crate::pointers::LATEST_FINALIZED_CHUNK_ID,
        id.to_be_bytes(),
    );
    batch.put(Column::Finalized, crate::pointers::FINALIZED_HEAD, hash);
    batch.put(Column::Finalized, crate::pointers::FINALIZED_SEED, end.seed);
    batch.put(
        Column::Finalized,
        crate::pointers::LATEST_VALIDATOR_SET_INDEX,
        (id + 1).to_be_bytes(),
    );
    batch.put(
        Column::ValidatorSetSnapshots,
        (id + 1).to_be_bytes(),
        borsh::to_vec(&spec.initial_validators).unwrap(),
    );
    batch.put(
        Column::BlockStates,
        hash,
        borsh::to_vec(&BlockState::Finalized).unwrap(),
    );
    for column in [
        Column::Blocks,
        Column::BlockProofs,
        Column::Witnesses,
        Column::StateDiffs,
    ] {
        batch.put(column, hash, [1]);
    }
    batch.put(Column::FinalizedOffences, hash, (id + 1).to_be_bytes());
    engine
        .commit_materialized_head_with_batch(id + 1, hash, trie.root(), Some(trie), batch)
        .unwrap();
    engine
        .fork_choice
        .add_finalized_chunk(&chunk, &cert)
        .unwrap();
    engine.install_consensus_state(&state);
}

/// Stored trie nodes and state values together.
fn stored_state_entries<DB: Database>(engine: &Engine<DB>) -> usize
where
    DB::Error: core::fmt::Debug,
{
    [Column::TrieNodes, Column::StateValues]
        .into_iter()
        .map(|column| engine.store().db().iter_keys(column).unwrap().len())
        .sum()
}

/// Every stored state entry carries exactly the references that reach it, one
/// per edge from a stored node and one per pin; every counted entry is stored
/// and no release is left queued.
fn assert_state_counted<DB: Database>(engine: &Engine<DB>)
where
    DB::Error: core::fmt::Debug,
{
    let db = engine.store().db();
    assert_eq!(
        db.iter_keys(Column::StateReleases).unwrap(),
        Vec::<Vec<u8>>::new()
    );
    let mut expected = std::collections::BTreeMap::<Vec<u8>, i64>::new();
    let mut reference = |kind: u8, hash: &[u8]| {
        if hash != ZERO_HASH {
            *expected.entry([&[kind], hash].concat()).or_default() += 1;
        }
    };
    for (_, root) in db.iter_column(Column::StatePins).unwrap() {
        reference(0, &root);
    }
    for (_, bytes) in db.iter_column(Column::TrieNodes).unwrap() {
        match neutrin0_trie::Node::decode(&bytes).unwrap() {
            neutrin0_trie::Node::Leaf { value_hash, .. } => reference(1, &value_hash),
            neutrin0_trie::Node::Branch { left, right } => {
                reference(0, &left);
                reference(0, &right);
            }
            neutrin0_trie::Node::Extension { child, .. } => reference(0, &child),
        }
    }
    let counted: std::collections::BTreeMap<Vec<u8>, i64> = db
        .iter_column(Column::StateRefs)
        .unwrap()
        .into_iter()
        .map(|(key, count)| (key, neutrin0_storage::decode_count(&count).unwrap()))
        .collect();
    assert_eq!(
        counted, expected,
        "reference counts disagree with stored edges"
    );
    for key in counted.keys() {
        let column = if key[0] == 0 {
            Column::TrieNodes
        } else {
            Column::StateValues
        };
        assert!(
            db.get(column, &key[1..]).unwrap().is_some(),
            "counted entry is missing"
        );
    }
    assert_eq!(
        stored_state_entries(engine),
        counted.len(),
        "a stored entry is not counted"
    );
}

#[test]
fn state_collection_runs_in_bounded_slices_interleaved_with_imports() {
    let mut engine = fixture(MemoryDatabase::new(), 70);
    let stored_before = stored_state_entries(&engine);
    engine.prune_finalized_sources().unwrap();
    // Pruning sources alone deletes no state: the collection runs in slices.
    assert_eq!(stored_state_entries(&engine), stored_before);
    let mut slices = 1;
    while !engine.collect_state_slice(1).unwrap() {
        slices += 1;
        // The node releases the engine lock between slices; a chunk
        // finalized meanwhile writes state the collection must keep.
        if slices == 2 {
            append(&mut engine);
        }
    }
    assert!(slices > 2, "a one-entry budget needs many slices");
    assert_state_counted(&engine);
    assert!(stored_state_entries(&engine) < stored_before);
    let retained = engine.canonical_boundary(63).unwrap().state_root;
    assert_eq!(
        engine
            .persisted_trie(retained)
            .unwrap()
            .get(b"counter")
            .unwrap(),
        Some(63u64.to_be_bytes().to_vec())
    );
    let reopened = Engine::open(engine.chain_spec().clone(), engine.store().db().clone()).unwrap();
    assert_eq!(
        reopened.state().get(b"counter").unwrap(),
        Some(71u64.to_be_bytes().to_vec())
    );
}

#[test]
#[allow(clippy::too_many_lines)] // One pruning cycle checked through restart and the next append.
fn pruning_retains_eight_finalized_chunks_and_supports_restart_and_append() {
    let mut engine = fixture(MemoryDatabase::new(), 70);
    let old_head = engine.head_hash();
    let nodes_before = engine
        .store()
        .db()
        .iter_column(Column::HistoryNodes)
        .unwrap()
        .len();
    let stored_before = stored_state_entries(&engine);
    let info = engine.prune_finalized_history().unwrap();
    assert_state_counted(&engine);
    assert_eq!(info.pruned_before_chunk, 62);
    assert_eq!(info.first_retained_height, 63);
    // The latest receipt alone is the History proof of everything pruned.
    assert_eq!(
        engine
            .latest_history_proof()
            .unwrap()
            .unwrap()
            .end()
            .next_chunk_id,
        70
    );
    assert!(engine.history_proof(62).unwrap().is_none());
    assert!(engine.history_proof(63).unwrap().is_some());
    assert!(engine.store().get_header_by_height(61).unwrap().is_none());
    assert!(engine.store().get_header_by_height(62).unwrap().is_some());
    assert!(engine.store().get_chunk_proof(61).unwrap().is_none());
    assert!(engine.store().get_chunk_proof(62).unwrap().is_some());
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::Chunks)
            .unwrap()
            .len(),
        8
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::Blocks)
            .unwrap()
            .len(),
        8
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::FinalizedOffences)
            .unwrap()
            .len(),
        8
    );
    // Ordinary nodes retain bounded paths and never write binary history nodes.
    assert_eq!(nodes_before, 0);
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::HistoryNodes)
            .unwrap()
            .len(),
        nodes_before
    );
    assert!(stored_state_entries(&engine) < stored_before);
    assert!(engine.fork_choice.block(&old_head).is_none());
    for id in [62, 69] {
        engine.store().historical_opening(id, 70).unwrap();
    }
    let db = engine.store().db().clone();
    let mut reopened = Engine::open(engine.chain_spec().clone(), db).unwrap();
    assert_eq!(
        reopened.state().get(b"counter").unwrap(),
        Some(70u64.to_be_bytes().to_vec())
    );
    append(&mut reopened);
    reopened.store().historical_opening(62, 70).unwrap();
    for id in [63, 69, 70] {
        reopened.store().historical_opening(id, 71).unwrap();
    }
    assert_eq!(
        reopened
            .prune_finalized_history()
            .unwrap()
            .pruned_before_chunk,
        63
    );
    let after = reopened
        .store()
        .db()
        .iter_column(Column::HistoryNodes)
        .unwrap();
    reopened.prune_finalized_history().unwrap();
    assert_eq!(
        after,
        reopened
            .store()
            .db()
            .iter_column(Column::HistoryNodes)
            .unwrap()
    );
    Engine::open(reopened.chain_spec().clone(), reopened.store().db().clone()).unwrap();
}

#[test]
fn record_window_keeps_records_and_bounded_paths_without_a_permanent_tree() {
    let mut spec = spec();
    // A 21-block unbonding delay over one-block chunks: complete records stay
    // for 21 chunks while raw blocks keep the eight-chunk window.
    spec.runtime.unbonding_delay_blocks = 21;
    spec.light_client.weak_subjectivity_period_secs =
        20 * neutrin0_primitives::DEFAULT_SLOT_DURATION_SECS;
    spec.validate().unwrap();
    let mut engine = fixture_with_spec(MemoryDatabase::new(), 70, &spec);
    let oldest_leaf = neutrin0_consensus_types::evidence::commitment(
        &engine
            .store()
            .historical_chunk(10)
            .unwrap()
            .unwrap()
            .evidence_context(),
    );
    let info = engine.prune_finalized_history().unwrap();
    assert_eq!(info.pruned_before_chunk, 62);
    assert_eq!(engine.history_record_window_chunks(), 21);
    assert!(engine.store().get_header_by_height(61).unwrap().is_none());
    assert!(engine.store().get_chunk_proof(61).unwrap().is_none());
    assert!(engine.store().historical_chunk(48).unwrap().is_none());
    for id in [49, 61, 69] {
        assert!(engine.store().historical_chunk(id).unwrap().is_some());
        engine.store().historical_opening(id, 70).unwrap();
        assert!(engine.in_history_record_window(id));
    }
    assert!(!engine.in_history_record_window(48));
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::HistoricalChunks)
            .unwrap()
            .len(),
        21
    );
    // Older claims require a path supplied by their holder; the local cache expires.
    assert!(engine.store().history_path(10, 70, oldest_leaf).is_err());
    assert!(engine.store().historical_opening(10, 70).is_err());
    // The retained paths survive restart and a further append.
    let mut reopened =
        Engine::open(engine.chain_spec().clone(), engine.store().db().clone()).unwrap();
    append(&mut reopened);
    assert!(reopened.store().historical_opening(49, 71).is_err());
    assert!(reopened.store().history_path(10, 71, oldest_leaf).is_err());
    reopened.prune_finalized_history().unwrap();
    assert!(reopened.store().historical_chunk(49).unwrap().is_none());
    reopened.store().historical_opening(50, 71).unwrap();
    reopened
        .store()
        .history_path(49, 71, oldest_leaf)
        .unwrap_err();
}

#[test]
fn pruned_node_opens_anchors_across_the_record_window() {
    use neutrin0_consensus_types::history_proof::anchors;
    let mut spec = spec();
    // Records stay for 21 chunks while boundaries keep the eight-chunk window.
    spec.runtime.unbonding_delay_blocks = 21;
    spec.light_client.weak_subjectivity_period_secs =
        20 * neutrin0_primitives::DEFAULT_SLOT_DURATION_SECS;
    spec.validate().unwrap();
    let mut engine = fixture_with_spec(MemoryDatabase::new(), 70, &spec);
    let genesis = engine.canonical_boundary(0).unwrap();
    // Boundaries a bootstrapping node trusted before this provider pruned.
    let trusted: Vec<_> = [49_u64, 55, 61]
        .into_iter()
        .map(|count| engine.canonical_boundary(count).unwrap())
        .collect();
    assert_eq!(
        engine
            .prune_finalized_history()
            .unwrap()
            .pruned_before_chunk,
        62
    );
    let end = engine.canonical_boundary(70).unwrap();
    for anchor in trusted {
        // The provider no longer holds the boundary itself, only the record
        // of the chunk it starts, which commits it.
        assert!(engine.canonical_boundary(anchor.next_chunk_id).is_err());
        let opening = engine.anchor_opening(anchor.next_chunk_id, 70).unwrap();
        assert!(opening.is_some());
        assert!(anchors(&genesis, &anchor, &end, opening.as_ref()));
        // The opening authenticates only its own boundary.
        let other = engine.canonical_boundary(62).unwrap();
        assert!(!anchors(&genesis, &other, &end, opening.as_ref()));
    }
    // Beyond the record window only an archive can open.
    assert!(engine.anchor_opening(48, 70).is_err());
    // Genesis and the endpoint itself need no opening.
    assert_eq!(engine.anchor_opening(0, 70).unwrap(), None);
    assert_eq!(engine.anchor_opening(70, 70).unwrap(), None);
}

#[test]
fn archive_history_is_preserved_and_switching_cannot_restore_data() {
    let mut genesis = fixture(MemoryDatabase::new(), 0);
    assert_eq!(
        genesis
            .prune_finalized_history()
            .unwrap()
            .pruned_before_chunk,
        0
    );
    let mut engine = fixture(MemoryDatabase::new(), 12);
    // Even before pruning, ordinary appends did not retain archive nodes.
    assert!(
        engine
            .set_retention_policy(RetentionPolicy::Archive)
            .is_err()
    );
    assert_eq!(
        engine
            .prune_finalized_history()
            .unwrap()
            .pruned_before_chunk,
        4
    );
    assert!(
        engine
            .set_retention_policy(RetentionPolicy::Archive)
            .is_err()
    );
    let mut archive = fixture(MemoryDatabase::new(), 0);
    archive
        .set_retention_policy(RetentionPolicy::Archive)
        .unwrap();
    for _ in 0..12 {
        append(&mut archive);
    }
    archive.store().historical_opening(0, 12).unwrap();
    assert_eq!(
        archive
            .prune_finalized_history()
            .unwrap()
            .pruned_before_chunk,
        0
    );
    assert_eq!(
        archive
            .store()
            .db()
            .iter_column(Column::Chunks)
            .unwrap()
            .len(),
        12
    );
    archive
        .set_retention_policy(RetentionPolicy::Pruned)
        .unwrap();
    assert_eq!(
        archive
            .store()
            .db()
            .iter_column(Column::HistoryNodes)
            .unwrap(),
        [] as [(Vec<u8>, Vec<u8>); 0]
    );
    assert!(
        archive
            .store()
            .db()
            .iter_column(Column::HistoryFrontiers)
            .unwrap()
            .len()
            <= 9
    );
    assert!(
        archive
            .set_retention_policy(RetentionPolicy::Archive)
            .is_err()
    );
    assert_eq!(
        archive
            .prune_finalized_history()
            .unwrap()
            .pruned_before_chunk,
        4
    );
}

#[test]
fn archive_prunes_its_in_memory_fork_choice_but_keeps_every_source() {
    let mut archive = fixture(MemoryDatabase::new(), 0);
    archive
        .set_retention_policy(RetentionPolicy::Archive)
        .unwrap();
    for _ in 0..12 {
        append(&mut archive);
    }
    let early = archive
        .store()
        .get_block_hash_by_height(1)
        .unwrap()
        .unwrap();
    let mut stale = header(
        10,
        10,
        archive
            .store()
            .get_block_hash_by_height(9)
            .unwrap()
            .unwrap(),
        ZERO_HASH,
    );
    stale.proposer_index = 1;
    let detached = archive.store_mut().put_header(&stale).unwrap();
    archive.fork_choice.add_block(&stale).unwrap();
    assert!(archive.fork_choice.block(&early).is_some());

    archive.prune_finalized_history().unwrap();
    // Fork choice keeps nothing below finality, so it stays bounded...
    assert!(archive.fork_choice.block(&early).is_none());
    assert!(archive.fork_choice.block(&detached).is_none());
    // ...while the archive keeps every durable source.
    assert!(archive.store().get_header(&early).unwrap().is_some());
    assert!(archive.store().get_header(&detached).unwrap().is_some());
    assert_eq!(archive.retention_info().unwrap().pruned_before_chunk, 0);
}

#[test]
fn failed_prune_batch_preserves_watermark_disk_and_live_state() {
    let mut engine = fixture(FaultDb::default(), 12);
    let stored = stored_state_entries(&engine);
    let disk = engine
        .store()
        .db()
        .iter_column(Column::HistoryNodes)
        .unwrap();
    let head = engine.head_hash();
    engine.store_mut().db_mut().fail_batch = true;
    assert!(matches!(
        engine.prune_finalized_history(),
        Err(StoreError::Database(_))
    ));
    assert_eq!(engine.retention_info().unwrap().pruned_before_chunk, 0);
    assert_eq!(stored_state_entries(&engine), stored);
    assert!(engine.fork_choice.block(&head).is_some());
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::HistoryNodes)
            .unwrap(),
        disk
    );
    engine.store_mut().db_mut().fail_batch = false;
    assert_eq!(
        engine
            .prune_finalized_history()
            .unwrap()
            .pruned_before_chunk,
        4
    );
}

#[test]
fn durable_retention_metadata_rejects_inconsistent_archive_claim() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let invalid = RetentionInfo {
        policy: RetentionPolicy::Archive,
        pruned_before_chunk: 1,
        first_retained_height: 2,
    };
    store
        .db_mut()
        .put(
            Column::Meta,
            b"history_retention",
            &borsh::to_vec(&invalid).unwrap(),
        )
        .unwrap();
    assert!(store.retention_info().is_err());
}

#[test]
fn detached_forks_are_removed_without_losing_a_retained_slot_index() {
    let mut engine = fixture(MemoryDatabase::new(), 12);
    let canonical = engine
        .store()
        .get_block_hash_by_height(10)
        .unwrap()
        .unwrap();
    let mut stale = header(
        10,
        10,
        engine.store().get_block_hash_by_height(9).unwrap().unwrap(),
        ZERO_HASH,
    );
    stale.proposer_index = 1;
    let hash = engine.store_mut().put_header(&stale).unwrap();
    engine.fork_choice.add_block(&stale).unwrap();
    engine
        .store_mut()
        .put_body(&hash, &neutrin0_consensus_types::Body::default())
        .unwrap();
    assert!(
        engine
            .store()
            .block_hashes_from_slot(10)
            .unwrap()
            .contains(&hash)
    );
    engine.prune_finalized_history().unwrap();
    assert!(engine.store().get_header(&hash).unwrap().is_none());
    assert!(engine.store().get_body(&hash).unwrap().is_none());
    assert!(engine.fork_choice.block(&hash).is_none());
    let indexed = engine.store().block_hashes_from_slot(10).unwrap();
    assert!(indexed.contains(&canonical) && !indexed.contains(&hash));
}

#[test]
fn missing_finalized_header_cannot_delete_the_remaining_canonical_chain() {
    let mut engine = fixture(MemoryDatabase::new(), 4);
    let head = engine.head_hash();
    engine
        .store_mut()
        .db_mut()
        .delete(Column::Headers, &head)
        .unwrap();
    let headers = engine.store().db().iter_column(Column::Headers).unwrap();
    assert!(engine.prune_finalized_history().is_err());
    assert_eq!(
        engine.store().db().iter_column(Column::Headers).unwrap(),
        headers
    );
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::Blocks)
            .unwrap()
            .len(),
        4
    );
}

/// A no-op executor isolates branch reconstruction and atomic publication from STF work.
struct RetainedBranchExecutor;

impl neutrin0_proof_system::ErasedBlockExecutor for RetainedBranchExecutor {
    fn execute_block(
        &self,
        context: &neutrin0_proof_system::BlockExecutionContext,
        body: &neutrin0_consensus_types::Body,
        state: &mut neutrin0_trie::Trie,
    ) -> Result<neutrin0_proof_system::ExecutionOutcome, String> {
        Ok(neutrin0_proof_system::ExecutionOutcome {
            artifacts: body.artifacts.clone(),
            state_root_after: state.root(),
            runtime_extra: [0; 32],
            receipts_root: body.artifacts.commitment(),
            gas_used: 0,
            witness_bytes: context.block_height.to_be_bytes().to_vec(),
            state_writes: Vec::new(),
        })
    }

    fn query(
        &self,
        _request: &neutrin0_runtime_abi::QueryRequest,
        _runtime: Hash,
        _state: &neutrin0_trie::Trie,
    ) -> Result<neutrin0_runtime_abi::QueryResponse, String> {
        Err("unused replay fixture query".into())
    }

    fn validate_tx(
        &self,
        _transaction: &[u8],
        _chain: u64,
        _gas_limit: u64,
        _runtime: Hash,
        _state: &neutrin0_trie::Trie,
    ) -> Result<neutrin0_runtime_abi::TxValidity, String> {
        Err("unused replay fixture admission".into())
    }

    fn install_runtime(&self, _wasm: &[u8]) -> Result<Hash, String> {
        Err("unused replay fixture installation".into())
    }

    fn installed_runtimes(&self) -> Vec<Hash> {
        Vec::new()
    }
}

fn retained_replay_header(
    engine: &mut Engine<FaultDb>,
    height: u64,
    slot: u64,
    parent: Hash,
) -> neutrin0_consensus_types::Header {
    let body = neutrin0_consensus_types::Body::default();
    let mut candidate = header(height, slot, parent, engine.state().root());
    crate::body::apply_body_roots(&mut candidate, &crate::body::compute_body_roots(&body));
    candidate.receipts_root = body.artifacts.commitment();
    let hash = engine.store_mut().put_header(&candidate).unwrap();
    engine.store_mut().put_body(&hash, &body).unwrap();
    candidate
}

#[test]
fn pruned_reorg_replays_and_publishes_only_retained_branch() {
    for current_depth in [1, 2] {
        let mut engine = fixture(FaultDb::default(), 70);
        engine.prune_finalized_history().unwrap();
        assert!(engine.store().get_header_by_height(61).unwrap().is_none());
        // These storage fixtures have opaque certificates, so execution omits
        // live participation authentication; consensus/proof checks are separate.
        let programs = engine.programs.take();
        let finalized = engine.head_hash();
        let mut current = finalized;
        for depth in 1..=current_depth {
            let candidate = retained_replay_header(&mut engine, 70 + depth, 70 + depth, current);
            current = candidate.hash();
            engine.fork_choice.add_block(&candidate).unwrap();
        }
        engine
            .commit_materialized_head_with_batch(
                70 + current_depth,
                current,
                engine.state().root(),
                None,
                Batch::new(),
            )
            .unwrap();
        let target = retained_replay_header(&mut engine, 71, 80, finalized);
        let target_hash = target.hash();
        engine.fork_choice.add_block(&target).unwrap();
        engine
            .fork_choice
            .on_block_proof(
                target_hash,
                neutrin0_consensus_fork_choice::ProofStatus::Proven,
            )
            .unwrap();
        crate::test_db::support_block(&mut engine, target_hash);
        assert_eq!(engine.fork_choice.head(), target_hash);

        // A failed durable publication must retain the old branch and witness set.
        engine.store_mut().db_mut().fail_batch = true;
        assert!(
            engine
                .materialise_to_fork_choice_head(Some(&RetainedBranchExecutor))
                .is_err()
        );
        assert_eq!(engine.head_hash(), current);
        assert_eq!(
            engine
                .store()
                .get_block_hash_by_height(71 + current_depth - 1)
                .unwrap(),
            Some(current)
        );
        assert!(engine.store().get_witness(&target_hash).unwrap().is_none());
        engine.store_mut().db_mut().fail_batch = false;
        assert!(
            engine
                .materialise_to_fork_choice_head(Some(&RetainedBranchExecutor))
                .unwrap()
        );
        assert_eq!(engine.head_hash(), target_hash);
        assert_eq!(engine.fork_choice_finalized(), finalized);
        assert_eq!(
            engine.store().get_block_hash_by_height(71).unwrap(),
            Some(target_hash)
        );
        assert!(
            engine
                .store()
                .get_block_hash_by_height(72)
                .unwrap()
                .is_none()
        );
        assert!(engine.store().get_witness(&target_hash).unwrap().is_some());
        assert_state_counted(&engine);
        engine.prune_finalized_history().unwrap();
        assert_state_counted(&engine);
        engine.programs = programs;
        let reopened = Engine::open(spec(), engine.store().db().clone()).unwrap();
        assert_eq!(reopened.head_hash(), target_hash);
        assert_eq!(reopened.state().root(), engine.state().root());
        assert_eq!(reopened.latest_finalized_chunk_id(), Some(69));
    }
}

#[test]
fn pruned_reorg_cannot_retract_finalized_anchor() {
    let mut engine = fixture(FaultDb::default(), 70);
    engine.prune_finalized_history().unwrap();
    let finalized = engine.head_hash();
    let parent = engine
        .store()
        .get_block_hash_by_height(69)
        .unwrap()
        .unwrap();
    let target = retained_replay_header(&mut engine, 70, 80, parent);
    assert!(matches!(
        engine.replay_to_head(target.hash(), &RetainedBranchExecutor),
        Err(crate::ImportError::ReorgPastFinalized {
            lca_height: 69,
            finalized_height: 70
        })
    ));
    assert_eq!(engine.head_hash(), finalized);
    assert_eq!(engine.latest_finalized_chunk_id(), Some(69));
    assert_eq!(
        engine.store().get_block_hash_by_height(70).unwrap(),
        Some(finalized)
    );
    assert!(
        engine
            .store()
            .get_witness(&target.hash())
            .unwrap()
            .is_none()
    );
}
