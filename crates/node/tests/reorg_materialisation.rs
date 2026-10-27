//! When the fork-choice DAG selects a head different from the materialised
//! head, the engine walks back to the lowest common ancestor, replays the
//! new branch through the executor, and commits the resulting state in
//! lockstep with the head pointer update.
//!
//! `Engine::materialise_to_fork_choice_head` (and its
//! `ChainBackend::try_materialise_to_fork_choice_head` proxy) reconcile the
//! materialised head with the fork-choice head on every import and on an
//! explicit operator trigger.
//!
//! The test is structured around two backends:
//!
//! - **`producer_v0`** produces a state-mutating block (`A1`) by submitting
//!   a transfer to its own mempool and calling `try_produce_block`. The
//!   resulting block has a non-empty body.
//! - **`producer_v1`** produces a competing empty-body block (`B1`) at the
//!   same height by reusing v0's chain spec but a different validator key.
//!   Its state root differs from A1's because the two bodies differ.
//!
//! The follower under test (`F`) imports A1 first (so its materialised head
//! is A1), gives A1 explicit support, then imports B1 (a DAG sibling, no
//! head movement), then is forced to reorg by a vote injected through
//! `fork_choice_mut_for_test().add_vote()` that weights B1 above A1. After
//! the explicit `try_materialise_to_fork_choice_head()` call, F's head is
//! B1 and its state trie matches B1's state root. Injecting the vote
//! directly isolates the replay machinery from BFT vote ingestion.

use std::sync::Arc;

use alloy_primitives::Address;
use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_consensus_fork_choice::ChunkVote;
use neutrin0_consensus_types::{Chunk, FinalityVoteData, FinalityVotePhase, ProvenBlock};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrin0_rpc::RpcBackend;
use neutrin0_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrin0_storage::MemoryDatabase;
use neutrin0_sync::SyncBackend;
use sp1_sdk::blocking::MockProver;

#[path = "support/proven.rs"]
pub mod proven;
use proven::import_blocking;
#[path = "support/evm.rs"]
pub mod evm;

const TEST_CHAIN_ID: u64 = 55555;
const TEST_GENESIS_SEED: [u8; 32] = [0xE1; 32];
const ALICE_SEED: u8 = 20;
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

fn chain_spec_and_trie(count: u8) -> (ChainSpec, neutrin0_trie::Trie) {
    let validators = validators(count);
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash: BlockHash = [0xE2; 32];
    let consensus = ConsensusParams {
        chunk_size: 1,
        // High VRF eligibility so every validator wins every slot —
        // the test drives production explicitly.
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 8),
        ..ConsensusParams::default()
    };
    let mut spec = ChainSpec {
        genesis_execution: neutrin0_runtime_host::package::RuntimePackage::embedded(Vec::new())
            .expect("authenticated fixture programs")
            .programs
            .execution,
        name: BoundedBytes::new(b"reorg-materialisation".to_vec()).expect("name fits"),
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
        genesis_state_root: ZERO_HASH,
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

type Backend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

/// Build a real-executor backend with the pre-funded genesis trie
/// installed AND persisted to disk. Reorg materialisation reads
/// `Column::TrieNodes` / `StateValues` to reconstruct the LCA's state, so
/// the explicit flush keeps the genesis state reachable for the trie walk.
///
/// Wrapped in `spawn_blocking` for SP1 / WASM init.
async fn build_backend(local_voter: ProposerKey) -> Arc<Backend> {
    tokio::task::spawn_blocking(move || {
        let (spec, trie) = chain_spec_and_trie(2);
        let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
        engine.install_genesis_state(trie).expect("genesis state");
        let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
        let backend = Arc::new(ChainBackend::new(engine, proof_system));
        let executor = WasmExecutor::embedded().expect("default wasm runtime");
        backend.set_block_executor(executor);
        backend.set_local_voter(local_voter);
        // Flush the pre-seeded genesis trie to disk so a later reorg
        // materialisation can open the genesis state from the store.
        backend.with_engine_mut_for_test(|engine| {
            engine
                .flush_trie_to_store()
                .expect("flush genesis trie to disk");
        });
        backend
    })
    .await
    .expect("spawn_blocking build_backend")
}

async fn produce_publication(backend: Arc<Backend>, voter: ProposerKey, slot: u64) -> ProvenBlock {
    tokio::task::spawn_blocking(move || proven::produce_publication(&backend, slot, &voter))
        .await
        .expect("spawn_blocking produce_block")
}

async fn submit_transfer(backend: Arc<Backend>, amount: u128, nonce: u64) {
    let tx_bytes = signed_transfer(amount, nonce);
    tokio::task::spawn_blocking(move || {
        backend
            .submit_transaction(tx_bytes)
            .expect("transfer admission");
    })
    .await
    .expect("spawn_blocking submit_transaction");
}

/// Inject a fully-weighted chunk vote for `block_hash` into the
/// follower's fork-choice DAG, moving the fork-choice head off the
/// materialised head without BFT vote ingestion.
async fn inject_vote_for(
    backend: Arc<Backend>,
    block_hash: BlockHash,
    chunk_id: u64,
    validator_index: u32,
    weight: u128,
) {
    tokio::task::spawn_blocking(move || {
        backend.with_engine_mut_for_test(|engine| {
            let dummy_chunk = Chunk {
                next_identity_sanctions_root: [0; 32],

                chunk_id,
                start_height: chunk_id,
                end_height: chunk_id + 1,
                start_state_root: ZERO_HASH,
                end_state_root: ZERO_HASH,
                start_block_hash: ZERO_HASH,
                end_block_hash: block_hash,
                block_hash_root: ZERO_HASH,
                block_proof_root: ZERO_HASH,
                vrf_proof_root: ZERO_HASH,
                active_validator_set_root: ZERO_HASH,
                next_validator_set_root: ZERO_HASH,
                da_root: ZERO_HASH,
            };
            let chunk_hash = engine.fork_choice_mut_for_test().add_chunk(&dummy_chunk);
            engine.fork_choice_mut_for_test().add_vote(
                validator_index,
                ChunkVote {
                    data: FinalityVoteData {
                        chunk_id,
                        round: 0,
                        chunk_hash,
                        selection: [0; 32],
                        phase: FinalityVotePhase::Precommit,
                    },
                    weight,
                },
            );
        });
    })
    .await
    .expect("spawn_blocking inject_vote_for");
}

/// End-to-end reorg-materialisation: v0 produces a
/// state-mutating block A1 (head advances to A1 on the follower).
/// v1 produces a competing empty-body block B1 (sibling on the
/// genesis parent). The follower imports both, then a synthetic
/// vote tips fork-choice toward B1. After the explicit
/// materialise trigger, the follower's head + state trie are at
/// B1, NOT A1.
#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep the complete fork switch and state replay in one scenario.
async fn reorg_materialises_to_new_fork_choice_head() {
    let v0 = proposer(0);
    let v1 = proposer(1);
    let producer_v0 = build_backend(v0.clone()).await;
    let producer_v1 = build_backend(v1.clone()).await;
    let follower = build_backend(v0.clone()).await;

    let (spec, _) = chain_spec_and_trie(2);
    let genesis_state_root = spec.genesis_state_root;
    let genesis_block_hash = spec.genesis_block_hash;

    // v0: state-mutating block A1.
    submit_transfer(Arc::clone(&producer_v0), 100, 0).await;
    let publication_a1 = produce_publication(Arc::clone(&producer_v0), v0.clone(), 1).await;
    let block_a1 = publication_a1.block.clone();
    assert!(
        !block_a1.body.transactions.is_empty(),
        "A1's body must include the Transfer",
    );
    assert_ne!(
        block_a1.header.state_root, genesis_state_root,
        "A1 must mutate state off the genesis root",
    );
    assert_eq!(
        block_a1.header.parent_hash, genesis_block_hash,
        "A1 must descend from genesis",
    );

    // v1: empty-body sibling (different proposer key + empty
    // body produces a distinct hash even at the same parent +
    // slot). Named `sibling_b1` to keep clippy::similar_names
    // happy alongside `block_a1`.
    let publication_sibling = produce_publication(Arc::clone(&producer_v1), v1.clone(), 1).await;
    let sibling_b1 = publication_sibling.block.clone();
    assert!(
        sibling_b1.body.transactions.is_empty(),
        "B1's body must be empty (no mempool admission on v1)",
    );
    assert_ne!(
        sibling_b1.header.state_root, block_a1.header.state_root,
        "B1's empty body must commit a different state than A1",
    );
    assert_eq!(
        sibling_b1.header.parent_hash, genesis_block_hash,
        "B1 must descend from genesis (sibling of A1)",
    );
    assert_ne!(
        block_a1.hash(),
        sibling_b1.hash(),
        "A1 and B1 must hash differently to be real siblings",
    );

    // Follower imports A1 first → materialised head = A1.
    import_blocking(&follower, vec![publication_a1.clone()])
        .await
        .expect("follower imports A1");
    assert_eq!(
        follower.local_status().await.unwrap().head_block_hash,
        block_a1.hash(),
        "after importing A1, follower head must be A1",
    );
    assert!(
        follower.engine_state_invariant_holds(),
        "follower invariant must hold after A1 import",
    );

    // Anchor A1 with explicit support instead of depending on the VRF/hash
    // tie-breaker order of these particular fixture headers.
    inject_vote_for(
        Arc::clone(&follower),
        block_a1.hash(),
        1,
        0,
        100_000_000_000,
    )
    .await;

    // Follower imports B1 → DAG sibling, no head movement.
    import_blocking(&follower, vec![publication_sibling.clone()])
        .await
        .expect("follower imports B1 as DAG sibling");
    assert_eq!(
        follower.local_status().await.unwrap().head_block_hash,
        block_a1.hash(),
        "B1 must not displace A1 while A1 has the supporting vote",
    );

    follower.with_engine_mut_for_test(|engine| {
        assert_eq!(
            engine.store().get_block_hash_by_height(1).unwrap(),
            Some(block_a1.hash())
        );
    });
    assert_eq!(
        follower
            .blocks_by_range(1, 1, block_a1.hash())
            .await
            .unwrap()
            .blocks,
        vec![publication_a1.clone()]
    );

    // Inject a heavy vote for B1 → fork-choice picks B1.
    inject_vote_for(
        Arc::clone(&follower),
        sibling_b1.hash(),
        1,
        1,
        1_000_000_000_000,
    )
    .await;
    assert_eq!(
        follower.fork_choice_head(),
        sibling_b1.hash(),
        "after vote injection, fork-choice head must be B1",
    );
    assert_eq!(
        follower.local_status().await.unwrap().head_block_hash,
        block_a1.hash(),
        "but the materialised head must still be A1 until materialise runs",
    );

    // Trigger materialise. Head + state should now match B1.
    let moved = follower
        .try_materialise_to_fork_choice_head()
        .expect("materialise must succeed");
    assert!(moved, "materialise must report a head move");

    assert_eq!(
        follower.local_status().await.unwrap().head_block_hash,
        sibling_b1.hash(),
        "after materialise, follower head must be B1",
    );
    assert!(
        follower.engine_state_invariant_holds(),
        "follower invariant must hold after reorg materialisation",
    );

    follower.with_engine_mut_for_test(|engine| {
        assert_eq!(
            engine.store().get_block_hash_by_height(1).unwrap(),
            Some(sibling_b1.hash())
        );
    });
    assert_eq!(
        follower.header_by_height(1).await.unwrap(),
        Some(sibling_b1.header.clone())
    );
    assert_eq!(
        follower
            .blocks_by_range(1, 1, sibling_b1.hash())
            .await
            .unwrap()
            .blocks,
        vec![publication_sibling.clone()]
    );
    // An in-flight query pinned before the reorg still gets the old branch.
    assert_eq!(
        follower
            .blocks_by_range(1, 1, block_a1.hash())
            .await
            .unwrap()
            .blocks,
        vec![publication_a1.clone()]
    );
    let restarted = Engine::open(spec, follower.snapshot_database()).unwrap();
    assert_eq!(
        restarted.store().get_block_hash_by_height(1).unwrap(),
        Some(sibling_b1.hash())
    );
    assert_eq!(restarted.state().root(), sibling_b1.header.state_root);
    assert!(restarted.fork_choice().block(&block_a1.hash()).is_some());
    assert!(restarted.fork_choice().block(&sibling_b1.hash()).is_some());

    // Idempotency: triggering materialise again is a no-op.
    let moved_again = follower
        .try_materialise_to_fork_choice_head()
        .expect("materialise idempotent");
    assert!(
        !moved_again,
        "materialise must report no-op when fork-choice head matches materialised head",
    );
}

/// No-op fast-path: when the fork-choice head matches the
/// materialised head, `try_materialise_to_fork_choice_head` is
/// cheap and returns `false`. Guards against accidental
/// reconstructions on every import.
#[tokio::test]
async fn materialise_is_no_op_when_heads_agree() {
    let v0 = proposer(0);
    let backend = build_backend(v0.clone()).await;

    let moved = backend
        .try_materialise_to_fork_choice_head()
        .expect("materialise at genesis is a no-op");
    assert!(!moved, "fresh backend at genesis must report no movement");

    // Produce a block, head advances normally via the linear path.
    submit_transfer(Arc::clone(&backend), 50, 0).await;
    let _ = produce_publication(Arc::clone(&backend), v0.clone(), 1).await;

    let moved = backend
        .try_materialise_to_fork_choice_head()
        .expect("materialise after linear extension is a no-op");
    assert!(
        !moved,
        "after producing a block, fork-choice head matches materialised head — no reorg needed",
    );
}
