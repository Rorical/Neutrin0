//! Validators import each other's blocks from `ProvenBlock` bundles (design
//! 07): a validator executes only the blocks it produces itself, and a
//! bundle whose receipt or state diff does not hold is rejected as a unit.
//!
//! Two validators run the default `proof_follow` mode. v0 produces a
//! state-mutating block and proves it; v1 imports the bundle without
//! executing, produces the next slot on top of it, and v0 imports v1's
//! bundle the same way. Each node's executor ran exactly once, for its own
//! block, and both state tries agree.

use std::sync::Arc;

use alloy_primitives::{Address, U256};
use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_consensus_types::ProvenBlock;
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo,
    RuntimeParams, Validator, fixed_u128_from_integer,
};
use neutrin0_runtime_host::Sp1ProofSystem;
use neutrin0_storage::MemoryDatabase;
use neutrin0_sync::{SyncBackend, SyncBackendError};
use sp1_sdk::blocking::MockProver;
use std::sync::atomic::{AtomicUsize, Ordering};

#[path = "support/counting_executor.rs"]
pub mod counting_executor;
use counting_executor::CountingExecutor;
#[path = "support/evm.rs"]
pub mod evm;

const TEST_CHAIN_ID: u64 = 44_445;
const TEST_GENESIS_SEED: [u8; 32] = [0xD4; 32];
const ALICE_SEED: u8 = 40;
const BOB_ADDR: Address = Address::new([0xBC; 20]);

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn alice_addr() -> Address {
    evm::address_of(ALICE_SEED)
}

fn signed_transfer(amount: u128, nonce: u64) -> Vec<u8> {
    evm::transfer(ALICE_SEED, nonce, BOB_ADDR, amount, TEST_CHAIN_ID)
}

fn validators() -> Vec<Validator> {
    (0..2u8)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: evm::padded(0xA0 + i),
            effective_stake: 32_000_000_000_000_000_000,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect()
}

fn chain_spec_and_trie() -> (ChainSpec, neutrin0_trie::Trie) {
    let validators = validators();
    let mut spec = ChainSpec {
        genesis_execution: neutrin0_runtime_host::package::RuntimePackage::embedded(Vec::new())
            .expect("authenticated fixture programs")
            .programs
            .execution,
        name: BoundedBytes::new(b"validator-follow".to_vec()).expect("name fits"),
        chain_id: TEST_CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: neutrin0_runtime_host::embedded_runtime_code_hash(),
        genesis_chunk: neutrin0_runtime_host::package::embedded_chunk_program()
            .expect("embedded chunk Guest"),
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: TEST_GENESIS_SEED,
        genesis_state_root: neutrin0_primitives::ZERO_HASH,
        genesis_block_hash: [0xD5; 32],
        genesis_validator_set_root: validator_set_root(&validators),
        consensus: ConsensusParams {
            chunk_size: 2,
            expected_proposers_per_slot: fixed_u128_from_integer(6),
            ..ConsensusParams::default()
        },
        proof: ProofParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    };
    let trie = evm::seal_genesis(&mut spec, evm::funded(&[alice_addr()]));
    (spec, trie)
}

type Backend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

struct Node {
    backend: Arc<Backend>,
    executed: Arc<AtomicUsize>,
}

async fn build_validator(voter: ProposerKey) -> Node {
    tokio::task::spawn_blocking(move || {
        let (spec, trie) = chain_spec_and_trie();
        let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
        engine.install_genesis_state(trie).expect("genesis state");
        let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
        let backend = Arc::new(ChainBackend::new(engine, proof_system));
        let (executor, executed) = CountingExecutor::embedded();
        backend.set_block_executor(executor);
        backend.set_local_voter(voter);
        backend
            .enable_proof_follow()
            .expect("validators follow receipts");
        Node { backend, executed }
    })
    .await
    .expect("build validator")
}

/// Produce `slot` on `node`, prove it and assemble the publication bundle.
async fn produce_bundle(node: &Node, voter: ProposerKey, slot: u64) -> ProvenBlock {
    let backend = Arc::clone(&node.backend);
    tokio::task::spawn_blocking(move || {
        let outcome = backend
            .try_produce_block(slot, &voter)
            .expect("try_produce_block")
            .expect("eligible");
        backend
            .prove_block(&outcome.block_hash)
            .expect("prove_block");
        let bundle = backend
            .proven_block_for_publication(&outcome.block_hash)
            .expect("block, receipt and write set are retained");
        assert!(bundle.writes_well_formed());
        bundle
    })
    .await
    .expect("produce bundle")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn validators_follow_each_other_from_proven_block_bundles() {
    let v0_key = proposer(0);
    let v1_key = proposer(1);
    let v0 = build_validator(v0_key.clone()).await;
    let v1 = build_validator(v1_key.clone()).await;

    // v0 executes its own state-mutating block and publishes the bundle.
    v0.backend
        .submit_transaction(signed_transfer(300, 0))
        .expect("transfer admission");
    let bundle1 = produce_bundle(&v0, v0_key.clone(), 1).await;
    assert_eq!(bundle1.block.body.transactions.len(), 1);
    assert_eq!(v0.executed.load(Ordering::SeqCst), 1);

    // A tampered diff condemns the whole bundle; nothing is imported.
    let mut tampered = bundle1.clone();
    tampered.writes.pop();
    let imported = v1
        .backend
        .verify_and_import_proven_blocks(vec![tampered])
        .await;
    assert!(
        matches!(imported, Err(SyncBackendError::Rejected(_))),
        "{imported:?}"
    );
    assert_eq!(v1.backend.head_height(), 0);

    // A broken receipt is rejected the same way.
    let mut bad_proof = bundle1.clone();
    bad_proof.proof_bytes[0] ^= 1;
    assert!(matches!(
        v1.backend
            .verify_and_import_proven_blocks(vec![bad_proof])
            .await,
        Err(SyncBackendError::Rejected(_))
    ));
    assert_eq!(v1.backend.head_height(), 0);

    // The honest bundle imports without executing.
    let imported = v1
        .backend
        .verify_and_import_proven_blocks(vec![bundle1.clone()])
        .await
        .expect("v1 imports v0's bundle");
    assert_eq!(imported.new_head_hash, bundle1.block.hash());
    assert_eq!(v1.executed.load(Ordering::SeqCst), 0);
    assert!(v1.backend.engine_state_invariant_holds());

    // v1 produces on top of the followed state, executing only its own block.
    v1.backend
        .submit_transaction(signed_transfer(200, 1))
        .expect("transfer admission on v1");
    let bundle2 = produce_bundle(&v1, v1_key, 2).await;
    assert_eq!(bundle2.block.header.parent_hash, bundle1.block.hash());
    assert_eq!(v1.executed.load(Ordering::SeqCst), 1);

    v0.backend
        .verify_and_import_proven_blocks(vec![bundle2.clone()])
        .await
        .expect("v0 imports v1's bundle");
    assert_eq!(v0.executed.load(Ordering::SeqCst), 1);

    for node in [&v0, &v1] {
        let status = node.backend.local_status().await.unwrap();
        assert_eq!(status.head_block_hash, bundle2.block.hash());
        assert!(node.backend.engine_state_invariant_holds());
    }
    let roots: Vec<_> = [&v0, &v1]
        .iter()
        .map(|node| {
            node.backend
                .with_engine_mut_for_test(|engine| engine.state().root())
        })
        .collect();
    assert_eq!(roots[0], roots[1], "both validators hold the same state");
    let bob = v0
        .backend
        .with_engine_mut_for_test(|engine| evm::balance_in(engine.state(), BOB_ADDR));
    assert_eq!(bob, U256::from(500));
}
