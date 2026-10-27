//! A proof-following full node (design 07) syncs state from verified Block
//! receipts and state diffs without executing any block body.
//!
//! Node A executes three single-block chunks that each move balances with a
//! Transfer, proves them and finalizes each chunk. Node B enables proof
//! following, connects, and must reach the same head, proven height, finality
//! and state trie while its executor's `execute_block` is never invoked. The
//! blocks arrive as complete publications through `BlocksByRange` from node
//! A, which retained receipts and write sets during production.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use alloy_primitives::{Address, U256};
use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_network::libp2p::identity::Keypair;
use neutrin0_network::service::{NetworkCommand, NetworkEvent, NetworkService};
use neutrin0_network::{Multiaddr, PeerId};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, Validator, fixed_u128_from_integer,
};
#[path = "support/native_chunk.rs"]
pub mod native_chunk;
use native_chunk::NativeChunkTestSystem;
use neutrin0_storage::MemoryDatabase;
use neutrin0_sync::{SyncBackend, SyncDriver, SyncDriverConfig};
use tokio::sync::mpsc;
use tokio::time::timeout;
#[path = "support/evm.rs"]
pub mod evm;

const N_BLOCKS: u64 = 3;
const CHAIN_ID: u64 = 8_585_930;
const GENESIS_SEED: [u8; 32] = [0xD3; 32];
const ALICE_SEED: u8 = 30;
const BOB_ADDR: Address = Address::new([0xBB; 20]);
const TRANSFER_AMOUNT: u128 = 1_000;

fn proposer() -> ProposerKey {
    ProposerKey::from_ikm(&[0xB8; 32], 0).expect("derive proposer")
}

fn alice_addr() -> Address {
    evm::address_of(ALICE_SEED)
}

fn signed_transfer(amount: u128, nonce: u64) -> Vec<u8> {
    evm::transfer(ALICE_SEED, nonce, BOB_ADDR, amount, CHAIN_ID)
}

fn single_validator_set() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer().public_key_bytes(),
        withdrawal_credentials: evm::padded(0xB8),
        effective_stake: 32_000_000_000_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }]
}

/// Genesis state that funds Alice so transfers mutate state.
fn genesis_trie() -> neutrin0_trie::Trie {
    evm::genesis_trie(&chain_spec(), evm::funded(&[alice_addr()]))
}

fn chain_spec() -> ChainSpec {
    let validators = single_validator_set();
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash: BlockHash = [0xCB; 32];
    let consensus = ConsensusParams {
        chunk_size: 1,
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    let spec = ChainSpec {
        genesis_execution: NativeChunkTestSystem::execution_programs(),
        name: BoundedBytes::new(b"proof-follow-sync".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: neutrin0_runtime_host::embedded_runtime_code_hash(),
        genesis_chunk: [7; 8],
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: GENESIS_SEED,
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
    evm::sealed_with(spec, evm::funded(&[alice_addr()]))
}

#[path = "support/counting_executor.rs"]
pub mod counting_executor;
use counting_executor::CountingExecutor;

type NodeBackend = ChainBackend<MemoryDatabase, NativeChunkTestSystem>;

struct NodeHandle {
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: Option<mpsc::Receiver<NetworkEvent>>,
    backend: Arc<NodeBackend>,
    executed: Arc<AtomicUsize>,
}

fn build_node(follow: bool) -> (NodeHandle, NetworkService) {
    let key = Keypair::generate_ed25519();
    let _peer_id = PeerId::from(key.public());
    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let (event_tx, event_rx) = mpsc::channel(1024);
    let svc = NetworkService::new(key, cmd_rx, event_tx).expect("network service");
    let mut engine = Engine::genesis(chain_spec(), MemoryDatabase::new()).expect("genesis");
    engine
        .install_genesis_state(genesis_trie())
        .expect("genesis state");
    let proof_system = NativeChunkTestSystem::mock().expect("mock SP1 adapter");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    let (executor, executed) = CountingExecutor::embedded();
    backend.set_block_executor(executor);
    if follow {
        backend.enable_proof_follow().expect("proof following");
    }
    (
        NodeHandle {
            cmd_tx,
            event_rx: Some(event_rx),
            backend,
            executed,
        },
        svc,
    )
}

async fn wait_for_listen_addr(rx: &mut mpsc::Receiver<NetworkEvent>) -> Multiaddr {
    timeout(Duration::from_secs(5), async {
        loop {
            if let NetworkEvent::NewListenAddr(addr) =
                rx.recv().await.expect("listener stream open")
            {
                return addr;
            }
        }
    })
    .await
    .expect("listener advertised")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn proof_following_node_syncs_state_from_receipts_and_diffs() {
    let _ = tracing_subscriber::fmt::try_init();

    let (mut producer, mut producer_svc) = tokio::task::spawn_blocking(|| build_node(false))
        .await
        .expect("build producer");
    let (mut follower, mut follower_svc) = tokio::task::spawn_blocking(|| build_node(true))
        .await
        .expect("build follower");

    // The producer executes, proves and finalizes three state-mutating
    // single-block chunks before any peering.
    for slot in 1u64..=N_BLOCKS {
        let backend = Arc::clone(&producer.backend);
        let transfer = signed_transfer(TRANSFER_AMOUNT, slot - 1);
        tokio::task::spawn_blocking(move || {
            backend
                .submit_transaction(transfer)
                .expect("transfer admission");
            let outcome = backend
                .try_produce_block(slot, &proposer())
                .expect("try_produce_block")
                .expect("eligible");
            assert!(
                !outcome.block.body.transactions.is_empty(),
                "the produced block must carry the transfer"
            );
            backend
                .prove_block(&outcome.block_hash)
                .expect("prove_block");
            backend
                .finalize_chunk(slot - 1, &proposer())
                .expect("complete chunk proof and finality");
        })
        .await
        .expect("spawn_blocking production");
    }
    assert_eq!(producer.backend.head_height(), N_BLOCKS);
    assert_eq!(
        producer.executed.load(Ordering::SeqCst),
        usize::try_from(N_BLOCKS).unwrap()
    );
    let producer_status = producer.backend.local_status().await.unwrap();
    assert_eq!(producer_status.finalized_chunk_id, Some(N_BLOCKS - 1));

    producer_svc
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("producer listen");
    follower_svc
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("follower listen");
    tokio::spawn(producer_svc.run());
    tokio::spawn(follower_svc.run());

    let producer_addr = wait_for_listen_addr(producer.event_rx.as_mut().expect("event_rx")).await;
    let _follower_addr = wait_for_listen_addr(follower.event_rx.as_mut().expect("event_rx")).await;
    follower
        .cmd_tx
        .send(NetworkCommand::Dial(producer_addr))
        .await
        .expect("dial producer");

    let producer_progress = producer.backend.local_progress().await.unwrap();
    let follower_progress = follower.backend.local_progress().await.unwrap();
    let producer_driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::clone(&producer.backend) as Arc<dyn SyncBackend>,
        producer_progress,
        producer.cmd_tx.clone(),
        producer.event_rx.take().expect("event_rx"),
    );
    let follower_driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::clone(&follower.backend) as Arc<dyn SyncBackend>,
        follower_progress,
        follower.cmd_tx.clone(),
        follower.event_rx.take().expect("event_rx"),
    );
    let producer_driver_handle = tokio::spawn(producer_driver.run());
    let follower_driver_handle = tokio::spawn(follower_driver.run());

    let converged = timeout(Duration::from_secs(60), async {
        loop {
            let status = follower.backend.local_status().await.unwrap();
            let progress = follower.backend.local_progress().await.unwrap();
            if status.head_height == N_BLOCKS
                && progress.proven_height == N_BLOCKS
                && status.finalized_chunk_id == Some(N_BLOCKS - 1)
            {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    let Ok(follower_status) = converged else {
        let progress = follower.backend.local_progress().await.unwrap();
        panic!("follower did not converge within 60s: progress = {progress:?}");
    };

    assert_eq!(
        follower_status.head_block_hash,
        producer_status.head_block_hash
    );
    assert_eq!(follower_status.finalized_chunk_id, Some(N_BLOCKS - 1));
    assert_eq!(
        follower.executed.load(Ordering::SeqCst),
        0,
        "a proof-following node never executes block bodies"
    );
    assert!(
        follower.backend.engine_state_invariant_holds(),
        "the followed state trie must match the head state root"
    );
    let (follower_root, bob_balance) = follower.backend.with_engine_mut_for_test(|engine| {
        (
            engine.state().root(),
            evm::balance_in(engine.state(), BOB_ADDR),
        )
    });
    let producer_root = producer
        .backend
        .with_engine_mut_for_test(|engine| engine.state().root());
    assert_eq!(follower_root, producer_root, "state tries converge");
    assert_eq!(
        bob_balance,
        U256::from(TRANSFER_AMOUNT * u128::from(N_BLOCKS)),
        "diffs carried the transfers"
    );

    producer_driver_handle.abort();
    follower_driver_handle.abort();
}
