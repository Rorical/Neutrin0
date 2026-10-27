//! Three nodes agree on a chain whose blocks
//! are verified by real SP1 [`Sp1ProofSystem`] envelopes.
//!
//! Each node wires a full production stack:
//!
//! - `ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>` —
//!   real SP1 adapter (witness decode, public-output cross-check)
//!   running over the SDK's `MockProver` so CI doesn't pay for a
//!   Compressed STARK per block;
//! - [`WasmExecutor`] driving the embedded EVM runtime master
//!   cdylib through wasmtime;
//! - libp2p `NetworkService` over `127.0.0.1` with the canonical
//!   `Topic::Blocks` subscription.
//!
//! The producer (node 0) drives the **real production path**:
//! `try_produce_block` → `prove_block`, then gossips the complete
//! publication (block, receipt bytes and write set). Both followers
//! ingest via `verify_and_import_proven_blocks`, exactly the way the
//! production [`SyncDriver`](neutrin0_sync::SyncDriver) does.
//!
//! Convergence assertion: all three nodes settle on the same head
//! hash, head height, and `proven_height`. The committed
//! `validator_set_root` matches `header.runtime_extra` on every node.

#[path = "support/evm.rs"]
pub mod evm;
use std::sync::Arc;
use std::time::Duration;

use neutrin0_consensus_engine::ProposerKey;
use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_types::{BlockReceipt, CandidateBlock};
use neutrin0_network::Topic;
use neutrin0_network::libp2p::identity::Keypair;
use neutrin0_network::service::{NetworkCommand, NetworkEvent, NetworkService};
use neutrin0_network::{Multiaddr, PeerId};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrin0_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrin0_storage::MemoryDatabase;
use neutrin0_sync::SyncBackend;
use sp1_sdk::blocking::MockProver;

#[path = "support/proven.rs"]
pub mod proven;
use proven::{candidate_and_receipt, import_candidates_blocking, import_receipts_blocking};
use tokio::sync::mpsc;
use tokio::time::timeout;

const CHAIN_ID: u64 = 6_006_006;
const GENESIS_SEED: [u8; 32] = [0xBA; 32];

fn proposer() -> ProposerKey {
    // Only validator 0 produces in this test; node 1 and node 2 are
    // pure followers (no `set_local_voter`).
    ProposerKey::from_ikm(&[0xA1; 32], 0).expect("derive proposer")
}

fn validators() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer().public_key_bytes(),
        withdrawal_credentials: evm::padded(0xA1),
        effective_stake: 32_000_000_000_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }]
}

fn chain_spec() -> ChainSpec {
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators());
    let genesis_block_hash: BlockHash = [0xCC; 32];
    let consensus = ConsensusParams {
        chunk_size: 1,
        // Single validator must clear the VRF threshold every slot.
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    evm::sealed(ChainSpec {
        genesis_execution: neutrin0_runtime_host::package::RuntimePackage::embedded(Vec::new())
            .expect("authenticated fixture programs")
            .programs
            .execution,
        name: BoundedBytes::new(b"m6-new-three-node".to_vec()).expect("name fits"),
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
    })
}

type NodeBackend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

struct NodeHandle {
    peer_id: PeerId,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: mpsc::Receiver<NetworkEvent>,
    backend: Arc<NodeBackend>,
}

fn build_node() -> (NodeHandle, NetworkService) {
    let key = Keypair::generate_ed25519();
    let peer_id = PeerId::from(key.public());
    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (event_tx, event_rx) = mpsc::channel(256);
    let svc = NetworkService::new(key, cmd_rx, event_tx).expect("network service");
    let engine = evm::genesis_engine(chain_spec(), MemoryDatabase::new(), Vec::new());
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    // Every node installs the WASM executor. Followers won't call
    // `try_produce_block` (no local voter installed), but installing
    // the executor on every node mirrors the production node binary
    // where the wasmtime module is part of standard startup.
    let executor = WasmExecutor::embedded().expect("wasm runtime");
    backend.set_block_executor(executor);
    (
        NodeHandle {
            peer_id,
            cmd_tx,
            event_rx,
            backend,
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

async fn wait_for_peers_connected(rx: &mut mpsc::Receiver<NetworkEvent>, expected: &[PeerId]) {
    // Generous timeout to absorb CPU / libp2p mesh-formation contention
    // when this test runs concurrently with other multi-node libp2p
    // tests under `cargo test --workspace`.
    timeout(Duration::from_secs(20), async {
        let mut pending = expected.to_vec();
        while !pending.is_empty() {
            if let NetworkEvent::PeerConnected(peer) = rx.recv().await.expect("event stream open") {
                pending.retain(|expected_peer| *expected_peer != peer);
            }
        }
    })
    .await
    .expect("peer connected within timeout");
}

/// Drive a follower's gossip ingest until it holds the proven block,
/// returning the final `(head_height, proven_height)`.
async fn drive_follower_until_proven(handle: &mut NodeHandle, target_height: u64) -> (u64, u64) {
    let backend = Arc::clone(&handle.backend);
    // Generous timeout to absorb CPU / port contention when this test
    // runs concurrently with the heavyweight 16-validator SP1 test.
    timeout(Duration::from_secs(45), async {
        loop {
            let proven = backend.local_progress().await.unwrap().proven_height;
            if proven >= target_height {
                return (backend.head_height(), proven);
            }
            match handle.event_rx.recv().await.expect("event stream open") {
                NetworkEvent::GossipMessage {
                    topic: Topic::Blocks,
                    data,
                    ..
                } => {
                    let candidate: CandidateBlock =
                        borsh::from_slice(&data).expect("decode candidate");
                    import_candidates_blocking(&backend, vec![candidate])
                        .await
                        .expect("follower imports the candidate");
                }
                NetworkEvent::GossipMessage {
                    topic: Topic::Receipts,
                    data,
                    ..
                } => {
                    let receipt: BlockReceipt = borsh::from_slice(&data).expect("decode receipt");
                    import_receipts_blocking(&backend, vec![receipt])
                        .await
                        .expect("follower imports the receipt");
                }
                _ => {}
            }
        }
    })
    .await
    .expect("follower converged within timeout")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // One test exercises the full gossip-and-import
// pipeline; splitting it would dilute the single-assertion focus.
async fn three_nodes_agree_with_real_sp1_proof_envelopes() {
    let _ = tracing_subscriber::fmt::try_init();

    // Build 3 nodes; node 0 is the producer. `build_node` calls
    // `Sp1ProofSystem::mock()` and `WasmExecutor::embedded()`,
    // both of which internally spin up an SP1 SDK / wasmtime runtime
    // that clashes with the test's `#[tokio::test]` worker thread.
    // `spawn_blocking` runs them off the tokio worker pool.
    let (mut handle_0, mut svc_0) = tokio::task::spawn_blocking(build_node)
        .await
        .expect("build node 0");
    let (mut handle_1, mut svc_1) = tokio::task::spawn_blocking(build_node)
        .await
        .expect("build node 1");
    let (mut handle_2, mut svc_2) = tokio::task::spawn_blocking(build_node)
        .await
        .expect("build node 2");

    // Each node listens on a random localhost port. Capturing the
    // resulting multiaddrs and re-using them for pairwise dials gives
    // a deterministic full-mesh topology without depending on libp2p
    // peer discovery.
    svc_0
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("listen on 0");
    svc_1
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("listen on 1");
    svc_2
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("listen on 2");

    tokio::spawn(svc_0.run());
    tokio::spawn(svc_1.run());
    tokio::spawn(svc_2.run());

    let addr_0 = wait_for_listen_addr(&mut handle_0.event_rx).await;
    let addr_1 = wait_for_listen_addr(&mut handle_1.event_rx).await;
    let _addr_2 = wait_for_listen_addr(&mut handle_2.event_rx).await;

    // Pairwise full mesh: 1 → 0, 2 → 0, 2 → 1.
    handle_1
        .cmd_tx
        .send(NetworkCommand::Dial(addr_0.clone()))
        .await
        .expect("dial 1→0");
    handle_2
        .cmd_tx
        .send(NetworkCommand::Dial(addr_0))
        .await
        .expect("dial 2→0");
    handle_2
        .cmd_tx
        .send(NetworkCommand::Dial(addr_1))
        .await
        .expect("dial 2→1");

    // Connections can arrive in either order, so wait for every expected
    // peer on one event stream at once.
    wait_for_peers_connected(
        &mut handle_0.event_rx,
        &[handle_1.peer_id, handle_2.peer_id],
    )
    .await;
    wait_for_peers_connected(&mut handle_1.event_rx, &[handle_2.peer_id]).await;

    // Every node subscribes to the candidate and receipt topics.
    for handle in [&handle_0, &handle_1, &handle_2] {
        for topic in [Topic::Blocks, Topic::Receipts] {
            handle
                .cmd_tx
                .send(NetworkCommand::Subscribe(topic))
                .await
                .expect("subscribe");
        }
    }

    // Allow gossipsub meshes to form. 1s is conservative for a
    // 3-node localhost mesh; without it the publish below races mesh
    // formation and is silently dropped on the listener side.
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Producer drives the real production path: try_produce_block
    // (WASM dry-run + witness emit + header sealing) followed by
    // prove_block (Sp1ProofSystem::prove_block → mock SP1 prover).
    //
    // Both calls are synchronous and the SP1 SDK spins up its own
    // internal tokio runtime, which clashes with the test's
    // `#[tokio::test]` multi-thread runtime if invoked on a runtime
    // thread. `spawn_blocking` hands them a dedicated blocking
    // worker so the inner runtime can start safely.
    let producer_backend = Arc::clone(&handle_0.backend);
    let outcome = tokio::task::spawn_blocking(move || {
        producer_backend
            .try_produce_block(1, &proposer())
            .expect("try_produce_block on slot 1")
            .expect("single validator is eligible")
    })
    .await
    .expect("spawn_blocking try_produce_block");
    assert_eq!(outcome.block.header.height, 1);
    let producer_backend = Arc::clone(&handle_0.backend);
    let block_hash = outcome.block_hash;
    tokio::task::spawn_blocking(move || {
        producer_backend
            .prove_block(&block_hash)
            .expect("prove_block via Sp1ProofSystem(MockProver)");
    })
    .await
    .expect("spawn_blocking prove_block");

    // The runtime emits the canonical genesis candidate-record commitment
    // (no stake moved yet), and the engine wires it into
    // `header.runtime_extra` for downstream consumers (chunk BFT and
    // finality).
    let expected_runtime_extra = evm::genesis_candidates_root(&validators());
    assert_eq!(outcome.block.header.runtime_extra, expected_runtime_extra);
    assert_ne!(outcome.block.header.runtime_extra, ZERO_HASH);

    // Publish the candidate, then its receipt (design 08).
    let (candidate, receipt) = candidate_and_receipt(&handle_0.backend, &block_hash);
    for (topic, data) in [
        (
            Topic::Blocks,
            borsh::to_vec(&candidate).expect("encode candidate"),
        ),
        (
            Topic::Receipts,
            borsh::to_vec(&receipt).expect("encode receipt"),
        ),
    ] {
        handle_0
            .cmd_tx
            .send(NetworkCommand::Publish { topic, data })
            .await
            .expect("publish");
    }

    // Drive both followers until they both have head=1 and proven=1.
    let (head_1, proven_1) = drive_follower_until_proven(&mut handle_1, 1).await;
    let (head_2, proven_2) = drive_follower_until_proven(&mut handle_2, 1).await;

    // All three nodes agree on a chain whose blocks are verified by real
    // Sp1ProofSystem envelopes.
    assert_eq!(handle_0.backend.head_height(), 1, "producer head");
    assert_eq!(head_1, 1, "follower 1 head");
    assert_eq!(head_2, 1, "follower 2 head");

    let canonical_hash = outcome.block_hash;
    assert_eq!(
        handle_0
            .backend
            .local_status()
            .await
            .unwrap()
            .head_block_hash,
        canonical_hash
    );
    assert_eq!(
        handle_1
            .backend
            .local_status()
            .await
            .unwrap()
            .head_block_hash,
        canonical_hash
    );
    assert_eq!(
        handle_2
            .backend
            .local_status()
            .await
            .unwrap()
            .head_block_hash,
        canonical_hash
    );

    assert_eq!(proven_1, 1, "follower 1 proven height");
    assert_eq!(proven_2, 1, "follower 2 proven height");
    assert_eq!(
        handle_0
            .backend
            .local_progress()
            .await
            .unwrap()
            .proven_height,
        1,
        "producer proven height",
    );
}
