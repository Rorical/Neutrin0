//! A follower that imports a state-mutating block keeps its state trie in
//! lockstep with `head_state_root`, so it can produce the next block from
//! the correct parent state.
//!
//! State is mutated by funding an Ethereum account at genesis and
//! mempool-submitting a transfer whose execution moves balances between
//! two accounts, so the new commitments are observable in the block header.
//!
//! 1. `state_invariant_holds_after_executor_equipped_import`: after one
//!    state-mutating import the trie root equals `head_state_root`.
//! 2. `follower_can_produce_after_importing_state_mutating_block`: v0
//!    produces a state-mutating block, v1 imports it and produces the next
//!    slot, v0 imports v1's block, and both heads converge on it.

use std::sync::Arc;

use alloy_primitives::Address;
use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_consensus_types::ProvenBlock;
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, Validator, fixed_u128_from_integer,
};
use neutrin0_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrin0_storage::MemoryDatabase;
use neutrin0_sync::SyncBackend;
use sp1_sdk::blocking::MockProver;

#[path = "support/proven.rs"]
pub mod proven;
use proven::import_blocking;
#[path = "support/evm.rs"]
pub mod evm;

const TEST_CHAIN_ID: u64 = 44444;
const TEST_GENESIS_SEED: [u8; 32] = [0xD1; 32];
const ALICE_SEED: u8 = 10;
const BOB_ADDR: Address = Address::new([0xBB; 20]);

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn alice_addr() -> Address {
    evm::address_of(ALICE_SEED)
}

fn signed_transfer(amount: u128, nonce: u64) -> Vec<u8> {
    evm::transfer(ALICE_SEED, nonce, BOB_ADDR, amount, TEST_CHAIN_ID)
}

fn validators(count: u8) -> Vec<Validator> {
    (0..count)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: evm::padded(0xA0 + i),
            effective_stake: 32_000_000_000_000_000_000,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect()
}

/// Build a chain spec whose genesis state pre-funds Alice so a transfer
/// can actually mutate state.
fn chain_spec_and_trie(count: u8) -> (ChainSpec, neutrin0_trie::Trie) {
    let validators = validators(count);
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash: BlockHash = [0xD2; 32];
    let consensus = ConsensusParams {
        chunk_size: 2,
        // High expectation so every validator reliably wins every
        // slot — the test drives production explicitly.
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 4),
        ..ConsensusParams::default()
    };
    let mut spec = ChainSpec {
        genesis_execution: neutrin0_runtime_host::package::RuntimePackage::embedded(Vec::new())
            .expect("authenticated fixture programs")
            .programs
            .execution,
        name: BoundedBytes::new(b"follower-state-replay".to_vec()).expect("name fits"),
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
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        consensus,
        proof,
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    };
    let trie = evm::seal_genesis(&mut spec, evm::funded(&[alice_addr()]));
    (spec, trie)
}

type RealBackend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

/// Real WASM executor backend with the pre-funded genesis trie
/// installed. Wrapped in `spawn_blocking` because SP1 + WASM
/// initialisation is sync-blocking.
async fn build_real_backend(local_voter: ProposerKey) -> Arc<RealBackend> {
    tokio::task::spawn_blocking(move || {
        let (spec, trie) = chain_spec_and_trie(2);
        let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
        engine.install_genesis_state(trie).expect("genesis state");
        let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
        let backend = Arc::new(ChainBackend::new(engine, proof_system));
        let executor = WasmExecutor::embedded().expect("default wasm runtime");
        backend.set_block_executor(executor);
        backend.set_local_voter(local_voter);
        backend
    })
    .await
    .expect("spawn_blocking build_real_backend")
}

/// Produce and prove slot `slot` on `backend`, returning its publication.
async fn produce_publication(
    backend: Arc<RealBackend>,
    voter: ProposerKey,
    slot: u64,
) -> ProvenBlock {
    tokio::task::spawn_blocking(move || proven::produce_publication(&backend, slot, &voter))
        .await
        .expect("spawn_blocking produce_block")
}

/// Submit a Transfer that moves `amount` to Bob through the
/// producer's mempool. Returns once the mempool accepts the tx
/// (the next produced block will drain it).
async fn submit_transfer(backend: Arc<RealBackend>, amount: u128, nonce: u64) {
    let tx_bytes = signed_transfer(amount, nonce);
    // `ChainBackend::submit_transaction` (the inherent method) is
    // synchronous; the trait-impl async version returns () and
    // swallows admission errors. Use the inherent one so the test
    // surfaces mempool rejections.
    tokio::task::spawn_blocking(move || {
        backend
            .submit_transaction(tx_bytes)
            .expect("transfer admission");
    })
    .await
    .expect("spawn_blocking submit_transaction");
}

/// Spot-check: after importing a single state-mutating block, the
/// follower's `self.state.root() == self.head_state_root()`.
#[tokio::test]
async fn state_invariant_holds_after_executor_equipped_import() {
    let v0 = proposer(0);
    let v1 = proposer(1);
    let producer_backend = build_real_backend(v0.clone()).await;
    let follower_backend = build_real_backend(v1.clone()).await;
    let (spec, _) = chain_spec_and_trie(2);
    let genesis_state_root = spec.genesis_state_root;

    // Submit a Transfer so the produced block actually mutates state.
    submit_transfer(Arc::clone(&producer_backend), 100, 0).await;
    let publication = produce_publication(Arc::clone(&producer_backend), v0.clone(), 1).await;
    let block = &publication.block;
    assert!(
        !block.body.transactions.is_empty(),
        "produced block must include the Transfer (got body {:?})",
        block.body,
    );
    assert_ne!(
        block.header.state_root, genesis_state_root,
        "Transfer must move state off the genesis root",
    );

    // Follower imports.
    import_blocking(&follower_backend, vec![publication.clone()])
        .await
        .expect("follower imports legitimate block");

    assert!(
        follower_backend.engine_state_invariant_holds(),
        "follower's state trie must agree with head_state_root after import",
    );
    assert_eq!(
        follower_backend
            .local_status()
            .await
            .unwrap()
            .head_block_hash,
        block.hash(),
        "follower's head must be the imported block",
    );
}

/// End-to-end convergence: v0 produces a state-mutating block at
/// slot 1, v1 imports, v1 produces an empty block at slot 2, v0
/// imports v1's slot 2. Both heads converge.
#[tokio::test]
async fn follower_can_produce_after_importing_state_mutating_block() {
    let v0 = proposer(0);
    let v1 = proposer(1);
    let backend_v0 = build_real_backend(v0.clone()).await;
    let backend_v1 = build_real_backend(v1.clone()).await;

    // v0's mempool gets a Transfer → slot 1 body is non-empty.
    submit_transfer(Arc::clone(&backend_v0), 200, 0).await;

    // v0 produces slot 1 (state advances on v0).
    let publication_s1 = produce_publication(Arc::clone(&backend_v0), v0.clone(), 1).await;
    let block_s1 = &publication_s1.block;
    assert_ne!(block_s1.body.transactions, [] as [std::vec::Vec<u8>; 0]);

    // v1 imports; its trie must advance with its head.
    import_blocking(&backend_v1, vec![publication_s1.clone()])
        .await
        .expect("v1 imports v0's slot 1");
    assert!(
        backend_v1.engine_state_invariant_holds(),
        "v1's state must match head_state_root after importing slot 1",
    );

    // v1 produces slot 2 against v0's block as parent, from the state
    // its import committed.
    let publication_s2 = produce_publication(Arc::clone(&backend_v1), v1.clone(), 2).await;
    let block_s2 = &publication_s2.block;
    assert_eq!(
        block_s2.header.parent_hash,
        block_s1.hash(),
        "v1's slot 2 must extend v0's slot 1",
    );

    // v0 imports v1's slot 2, which succeeds only when v1 produced from
    // the correct parent state.
    import_blocking(&backend_v0, vec![publication_s2.clone()])
        .await
        .expect("v0 imports v1's slot 2 produced from the correct parent state");

    // Convergence: both heads agree on v1's slot 2 block hash.
    assert_eq!(
        backend_v0.local_status().await.unwrap().head_block_hash,
        block_s2.hash(),
    );
    assert_eq!(
        backend_v1.local_status().await.unwrap().head_block_hash,
        block_s2.hash(),
    );

    // Both nodes' state invariants still hold.
    assert!(backend_v0.engine_state_invariant_holds());
    assert!(backend_v1.engine_state_invariant_holds());
}
