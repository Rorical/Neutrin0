//! Long-running single-validator chain.
//!
//! Walks a single validator through `N_SLOTS` consecutive
//! `try_produce_block` → `prove_block` cycles, verifying the chain
//! stays linear and the proven height keeps pace with the head
//! height across every slot. Then closes the engine, re-opens it
//! from the same database, and asserts the rehydrated state matches
//! the in-memory state.
//!
//! This is the regression gate that catches any drift between the
//! engine's in-memory head pointers, the persisted store, and the
//! runtime state trie. A bug introduced anywhere on the produce →
//! prove → flush path would show up as either a non-monotonic head
//! advance during the loop or a `head_state_root` divergence after
//! re-open.
//!
//! The whole run stays inside chunk 0 (`chunk_size = 64 > N_SLOTS`): a node
//! never produces into a later chunk before the previous one finalizes,
//! and since program sets travel in boundaries (design 20) the engine needs
//! that finality to anchor blocks of a later chunk. The mock SP1 prover
//! keeps the per-slot wall-clock under 100 ms.

#[path = "support/evm.rs"]
pub mod evm;
use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_engine::{Engine, ProductionConfig, ProposerKey};
use neutrin0_consensus_types::Body;
use neutrin0_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrin0_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrin0_storage::MemoryDatabase;

/// Number of consecutive produce/prove cycles to run. 60 slots stay
/// inside the single 64-block chunk (see the module docs) without
/// hitting CI timeouts on the mock prover.
const N_SLOTS: u64 = 60;
const CHAIN_ID: u64 = 5_555_555;
const GENESIS_SEED: [u8; 32] = [0xCE; 32];

fn proposer() -> ProposerKey {
    ProposerKey::from_ikm(&[0xA9; 32], 0).expect("derive proposer")
}

fn single_validator_set() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer().public_key_bytes(),
        withdrawal_credentials: evm::padded(0xA9),
        effective_stake: 32_000_000_000_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }]
}

fn chain_spec() -> ChainSpec {
    let validators = single_validator_set();
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash: BlockHash = [0xAB; 32];
    let consensus = ConsensusParams {
        chunk_size: 64,
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    evm::sealed(ChainSpec {
        genesis_execution: neutrin0_runtime_host::package::RuntimePackage::embedded(Vec::new())
            .expect("authenticated fixture programs")
            .programs
            .execution,
        name: BoundedBytes::new(b"m5-replay".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: neutrin0_runtime_host::embedded_runtime_code_hash(),
        genesis_chunk: neutrin0_runtime_host::package::embedded_chunk_program()
            .expect("embedded chunk Guest"),
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: GENESIS_SEED,
        genesis_state_root: ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        consensus,
        proof,
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    })
}

#[test]
fn many_slots_produce_prove_advance_monotonically_and_replay_round_trips() {
    let _ = tracing_subscriber::fmt::try_init();

    let db = MemoryDatabase::new();
    let mut engine = evm::genesis_engine(chain_spec(), db, Vec::new());
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
    // An engine-only harness pins the backend's Guests itself, as
    // `ChainBackend::new` does for a node.
    engine.set_programs(proof_system.embedded_guests());
    let executor = WasmExecutor::embedded().expect("wasm runtime");
    let proposer = proposer();

    let mut last_head_hash = engine.head_hash();
    let mut last_height = 0u64;

    for slot in 1u64..=N_SLOTS {
        let body = Body::default();
        let cfg = ProductionConfig {
            proposer: &proposer,
        };
        let outcome = engine
            .try_produce_block(slot, cfg, body, &executor)
            .expect("try_produce_block")
            .expect("single validator is eligible");

        // Monotonic advance.
        assert_eq!(outcome.block.header.height, last_height + 1);
        assert_eq!(outcome.block.header.parent_hash, last_head_hash);
        last_height = outcome.block.header.height;
        last_head_hash = outcome.block_hash;

        let prove = engine
            .prove_block(&outcome.block_hash, &proof_system)
            .expect("prove_block");
        assert_eq!(prove.block_hash, outcome.block_hash);

        assert_eq!(engine.head_height(), slot, "head height at slot {slot}");
    }

    assert_eq!(engine.head_height(), N_SLOTS);

    // Every produced block has a stored proof and a Proven FSM entry.
    let store = engine.store();
    for height in 1..=N_SLOTS {
        let hash = store
            .get_block_hash_by_height(height)
            .expect("read hash")
            .expect("height present");
        let proof = store
            .get_block_proof(&hash)
            .expect("read proof")
            .expect("proof present");
        assert_eq!(proof.height, height);
        assert_eq!(proof.block_hash, hash);
        let state = store
            .get_block_state(&hash)
            .expect("read state")
            .expect("state present");
        assert!(
            matches!(state, neutrin0_consensus_engine::BlockState::Proven),
            "block at height {height} must be at Proven (got {state:?})",
        );
    }

    // Snapshot the in-memory head invariants for the re-open round-trip.
    let recorded_head_hash = last_head_hash;
    let recorded_head_height = last_height;
    let recorded_state_root = engine.head_state_root();
    let recorded_finalized_seed = engine.finalized_seed();

    // --- Replay: re-open the engine from the same database and
    // confirm the rehydrated state matches. -----------------------
    let saved_db = engine.store().db().clone();
    drop(engine);

    let reopened = Engine::open(chain_spec(), saved_db).expect("re-open");
    assert_eq!(reopened.head_height(), recorded_head_height);
    assert_eq!(reopened.head_hash(), recorded_head_hash);
    assert_eq!(reopened.head_state_root(), recorded_state_root);
    assert_eq!(reopened.finalized_seed(), recorded_finalized_seed);

    // The block-proof column survived the close/open round-trip.
    let last_block_hash = reopened
        .store()
        .get_block_hash_by_height(N_SLOTS)
        .expect("read last block hash")
        .expect("last block height present");
    let last_proof = reopened
        .store()
        .get_block_proof(&last_block_hash)
        .expect("read last proof")
        .expect("last proof present");
    assert_eq!(last_proof.height, N_SLOTS);
    assert_eq!(last_proof.block_hash, last_block_hash);
}
