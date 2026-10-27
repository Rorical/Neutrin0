//! A follower imports complete publications, then reconstructs the exact head
//! state through the same bounded typed-fragment RPC handlers served by
//! libp2p. Mock SP1 envelopes exercise adapter plumbing, not the real STARK gate.

use std::sync::Arc;

use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_consensus_types::ProvenBlock;
use neutrin0_consensus_types::bootstrap::StateItem;
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, StateRoot, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrin0_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrin0_storage::{Column, Database, MemoryDatabase};
use neutrin0_sync::SyncBackend;
use neutrin0_trie::Trie;
use sp1_sdk::blocking::MockProver;
#[path = "support/evm.rs"]
pub mod evm;

const CHAIN_ID: u64 = 7_777_777;
const GENESIS_SEED: [u8; 32] = [0xBE; 32];
const FUNDED_ACCOUNT: alloy_primitives::Address = alloy_primitives::Address::new([0xAC; 20]);

/// The runtime genesis of [`chain_spec`], funding [`FUNDED_ACCOUNT`].
fn genesis_state() -> Trie {
    evm::genesis_trie(&chain_spec(), evm::funded(&[FUNDED_ACCOUNT]))
}

fn proposer() -> ProposerKey {
    ProposerKey::from_ikm(&[0xC3; 32], 0).expect("derive proposer")
}

fn validators() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer().public_key_bytes(),
        withdrawal_credentials: evm::padded(0xC3),
        effective_stake: 32_000_000_000_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }]
}

fn chain_spec() -> ChainSpec {
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators());
    let genesis_block_hash: BlockHash = [0xAB; 32];
    let consensus = ConsensusParams {
        chunk_size: 3,
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    let spec = ChainSpec {
        genesis_execution: neutrin0_runtime_host::package::RuntimePackage::embedded(Vec::new())
            .expect("authenticated fixture programs")
            .programs
            .execution,
        name: BoundedBytes::new(b"typed-state-snapshot".to_vec()).expect("name fits"),
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
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    };
    evm::sealed_with(spec, evm::funded(&[FUNDED_ACCOUNT]))
}

type NodeBackend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

fn build_backend() -> Arc<NodeBackend> {
    let engine = Engine::genesis(chain_spec(), MemoryDatabase::new()).expect("genesis");
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
    Arc::new(ChainBackend::new(engine, proof_system))
}

fn build_producer() -> Arc<NodeBackend> {
    let backend = build_backend();
    backend.with_engine_mut_for_test(|engine| {
        engine
            .replace_state_with_reconstructed(&genesis_state())
            .expect("install genesis state");
        engine.flush_trie_to_store().expect("persist genesis state");
    });
    let executor = WasmExecutor::embedded().expect("wasm runtime");
    backend.set_block_executor(executor);
    backend
}

/// Run a synchronous closure that touches SP1 SDK on a blocking
/// thread so the SDK's internal tokio runtime doesn't collide with
/// the test's `#[tokio::test]` worker. The closure's return value
/// must be `Send`.
async fn run_blocking<F, R>(f: F) -> R
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .expect("spawn_blocking joined")
}

/// Reconstruct a committed state root through the production fragment handlers.
async fn import_state_from_rpc(
    producer: &NodeBackend,
    follower: &NodeBackend,
    root: StateRoot,
) -> usize {
    let mut items = vec![StateItem::node(root)];
    let mut fragments = 0;
    loop {
        let response = producer
            .state_nodes(root, &items)
            .await
            .expect("serve fragments");
        fragments += response.entries.len();
        let progress = follower
            .import_state_nodes(root, items, response.entries.to_vec())
            .await
            .expect("authenticate and import fragments");
        if progress.root_complete {
            return fragments;
        }
        items = progress.next_items;
    }
}

/// Import publications off the async worker and return the new head height.
async fn import_blocks(follower: Arc<NodeBackend>, blocks: Vec<ProvenBlock>) -> u64 {
    run_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("inner runtime");
        runtime
            .block_on(follower.verify_and_import_proven_blocks(blocks))
            .expect("follower imports publications")
            .new_head_height
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn follower_imports_publications_then_reconstructs_nonempty_state() {
    let _ = tracing_subscriber::fmt::try_init();

    let producer = run_blocking(build_producer).await;
    let follower = run_blocking(build_backend).await;
    // Without an executor the follower judges publications by receipts.
    follower
        .enable_proof_follow()
        .expect("executor-less follower follows receipts");

    // Producer builds a 3-block chain. Each slot: produce → prove.
    // Production is deterministic (fixed proposer + chain spec), so
    // the follower will reach identical hashes after import.
    for slot in 1u64..=3 {
        let backend = Arc::clone(&producer);
        let outcome = run_blocking(move || {
            backend
                .try_produce_block(slot, &proposer())
                .expect("try_produce_block")
                .expect("eligible")
        })
        .await;
        let backend = Arc::clone(&producer);
        let block_hash = outcome.block_hash;
        let _ = run_blocking(move || backend.prove_block(&block_hash).expect("prove_block")).await;
    }
    assert_eq!(producer.head_height(), 3);
    assert_eq!(producer.local_progress().await.unwrap().proven_height, 3);

    // Follower starts at genesis with no proofs.
    assert_eq!(follower.head_height(), 0);
    assert_eq!(follower.local_progress().await.unwrap().proven_height, 0);
    assert_eq!(
        follower.with_engine_mut_for_test(|engine| {
            engine
                .store()
                .db()
                .iter_column(Column::TrieNodes)
                .unwrap()
                .len()
        }),
        0
    );

    // Step 1: the producer's complete publications, exactly as the driver's
    // complete-chunk sync fetches them through `BlocksByRange`.
    let blocks_response = producer
        .blocks_by_range(
            1,
            16,
            producer.local_status().await.unwrap().head_block_hash,
        )
        .await
        .unwrap();
    assert_eq!(
        blocks_response.blocks.len(),
        3,
        "producer must return all 3 publications",
    );
    let root = blocks_response
        .blocks
        .last()
        .unwrap()
        .block
        .header
        .state_root;
    assert_ne!(root, ZERO_HASH);
    // The follower's empty trie holds neither the genesis root nor the
    // committed head root.
    assert!(!follower.engine_state_invariant_holds());

    // Step 2: snap sync reconstructs the genesis state through the typed
    // fragment handlers. This executor-less follower holds no genesis state,
    // so the reconstructed trie precedes the publications whose diffs extend
    // it; the publications then carry every later write.
    let genesis_root = follower.with_engine_mut_for_test(|engine| engine.head_state_root());
    assert_ne!(genesis_root, root, "the empty blocks still move state");
    let fragments = import_state_from_rpc(&producer, &follower, genesis_root).await;
    assert!(fragments > 0);
    assert_eq!(
        follower.with_engine_mut_for_test(|engine| evm::balance_in(engine.state(), FUNDED_ACCOUNT)),
        alloy_primitives::U256::from(evm::FUNDS)
    );
    assert!(follower.engine_state_invariant_holds());

    // Step 3: the publications import in order; every receipt is verified on
    // arrival, so proven progress follows the head.
    assert_eq!(
        import_blocks(Arc::clone(&follower), blocks_response.blocks.clone()).await,
        3
    );
    assert_eq!(follower.head_height(), 3);
    assert_eq!(follower.local_progress().await.unwrap().proven_height, 3);
    assert!(follower.engine_state_invariant_holds());
    assert_eq!(
        follower.with_engine_mut_for_test(|engine| engine.state().root()),
        root,
        "the followed diffs reproduce the committed head state",
    );
    assert_eq!(
        follower.with_engine_mut_for_test(|engine| evm::balance_in(engine.state(), FUNDED_ACCOUNT)),
        alloy_primitives::U256::from(evm::FUNDS)
    );

    // Convergence: same head, same hash, same proven height.
    assert_eq!(
        follower.head_height(),
        producer.head_height(),
        "head height"
    );
    let producer_status = producer.local_status().await.unwrap();
    let follower_status = follower.local_status().await.unwrap();
    assert_eq!(
        follower_status.head_block_hash, producer_status.head_block_hash,
        "head block hash",
    );
    assert_eq!(
        follower.local_progress().await.unwrap().proven_height,
        producer.local_progress().await.unwrap().proven_height,
        "proven height",
    );
}
