//! Two-node end-to-end gossip integration test.
//!
//! Stands up two in-process [`NetworkService`] instances over TCP on
//! `127.0.0.1`, wires each one to its own [`ChainBackend`] (against an
//! in-memory database), connects them via libp2p, subscribes both to
//! `/neutrin0/blocks/borsh`, and asserts that the publication of a signed
//! VRF-eligible block (block, receipt bytes and write set) by the producer
//! is received by the follower's engine and advances the follower's head.
//!
//! A production deployment runs the same pipeline inside the
//! [`SyncDriver`] from `neutrin0-sync`; here the test plays driver to
//! keep the surface narrow and the assertion direct.

use std::sync::Arc;
use std::time::Duration;

use neutrin0_consensus_engine::body::compute_body_roots;
use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_consensus_types::{Block, BlockReceipt, Body, CandidateBlock, Header};
use neutrin0_network::Topic;
use neutrin0_network::libp2p::identity::Keypair;
use neutrin0_network::service::{NetworkCommand, NetworkEvent, NetworkService};
use neutrin0_network::{Multiaddr, PeerId};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, Height, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, Validator, ZERO_HASH,
};
use neutrin0_proof_system::MockProofSystem;
#[path = "support/proven.rs"]
pub mod proven;
use neutrin0_storage::MemoryDatabase;
use neutrin0_sync::SyncBackend;
use proven::{import_candidates_blocking, import_receipts_blocking, mock_bundle};
use tokio::sync::mpsc;
use tokio::time::timeout;

const TEST_CHAIN_ID: u64 = 31337;
const TEST_GENESIS_SEED: [u8; 32] = [0xDD; 32];
const TEST_IKM: [u8; 32] = [0xAA; 32];

fn proposer() -> ProposerKey {
    ProposerKey::from_ikm(&TEST_IKM, 0).expect("derive proposer key")
}

fn validators() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer().public_key_bytes(),
        withdrawal_credentials: [0; 32],
        effective_stake: 32_000_000_000_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }]
}

fn spec() -> ChainSpec {
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators());
    let genesis_block_hash: BlockHash = [0xAA; 32];
    ChainSpec {
        genesis_execution: neutrin0_primitives::ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
        name: BoundedBytes::new(b"two-node-test".to_vec()).expect("name fits"),
        chain_id: TEST_CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [0xCC; 32],
        genesis_chunk: [7; 8],
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: TEST_GENESIS_SEED,
        genesis_state_root: ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        consensus: ConsensusParams::default(),
        proof,
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    }
}

fn signed_block_for_slot(slot: u64, parent: BlockHash, height: Height) -> Block {
    let key = proposer();
    let body = Body::default();
    let roots = compute_body_roots(&body);
    let vrf_proof = key.vrf_eval(spec().consensus_domain(), &TEST_GENESIS_SEED, slot);

    let mut header = Header {
        height,
        slot,
        parent_hash: parent,
        proposer_index: key.validator_index(),
        vrf_proof,
        state_root: ZERO_HASH,
        transactions_root: roots.transactions_root,
        votes_root: roots.votes_root,
        da_root: roots.da_root,
        runtime_extra: ZERO_HASH,
        inputs_root: [0; 32],
        receipts_root: Body::default().artifacts.commitment(),
        gas_used: 0,
        gas_limit: 30_000_000,
        timestamp: 1_700_000_000 + slot * 4,
        signature: [0; 96],
    };
    header.inputs_root = fixture_inputs_root(&spec(), &header, &body);
    let header_hash = header.hash();
    header.signature = key.sign_proposer_message(spec().consensus_domain(), &header_hash);
    Block { header, body }
}

struct NodeHandle {
    peer_id: PeerId,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: mpsc::Receiver<NetworkEvent>,
    backend: Arc<ChainBackend<MemoryDatabase, MockProofSystem>>,
}

fn build_node() -> (NodeHandle, NetworkService) {
    let key = Keypair::generate_ed25519();
    let peer_id = PeerId::from(key.public());
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let (event_tx, event_rx) = mpsc::channel(128);
    let svc = NetworkService::new(key, cmd_rx, event_tx).expect("network service");
    let engine = Engine::genesis(spec(), MemoryDatabase::new()).expect("genesis");
    let backend = Arc::new(ChainBackend::new(engine, MockProofSystem::new()));
    backend
        .enable_proof_follow()
        .expect("executor-less nodes follow receipts");
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

/// Wait for the local node to report it has subscribed and is meshed with at
/// least one peer for the given topic, draining unrelated events along the way.
async fn wait_for_peer_connected(rx: &mut mpsc::Receiver<NetworkEvent>, expected: PeerId) {
    timeout(Duration::from_secs(5), async {
        loop {
            if let NetworkEvent::PeerConnected(peer) = rx.recv().await.expect("event stream open")
                && peer == expected
            {
                return;
            }
        }
    })
    .await
    .expect("peer connected within timeout");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // One candidate-then-receipt round trip over a real libp2p mesh.
async fn two_nodes_agree_on_gossipped_block() {
    let _ = tracing_subscriber::fmt::try_init();

    // Build two nodes; node A is the producer-equivalent, node B the follower.
    let (mut handle_a, mut svc_a) = build_node();
    let (mut handle_b, svc_b) = build_node();

    svc_a
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("listen on A");

    tokio::spawn(svc_a.run());
    tokio::spawn(svc_b.run());

    // Discover A's listening address and dial it from B.
    let addr_a = wait_for_listen_addr(&mut handle_a.event_rx).await;
    handle_b
        .cmd_tx
        .send(NetworkCommand::Dial(addr_a))
        .await
        .expect("dial command");

    // Both ends should see the peer-connected event.
    wait_for_peer_connected(&mut handle_a.event_rx, handle_b.peer_id).await;
    wait_for_peer_connected(&mut handle_b.event_rx, handle_a.peer_id).await;

    // Both nodes subscribe to the candidate and receipt topics.
    for handle in [&handle_a, &handle_b] {
        for topic in [Topic::Blocks, Topic::Receipts] {
            handle
                .cmd_tx
                .send(NetworkCommand::Subscribe(topic))
                .await
                .expect("subscribe");
        }
    }

    // Allow gossipsub meshes to form; without this delay the publish below
    // can land before B accepts A's subscription and the message is
    // dropped silently. 500ms is conservative for localhost.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Producer (A) builds the next block and publishes its candidate, then
    // its receipt, via gossip (design 08).
    let genesis_hash = handle_a
        .backend
        .local_status()
        .await
        .unwrap()
        .head_block_hash;
    let block = signed_block_for_slot(1, genesis_hash, 1);
    let (candidate, receipt) = mock_bundle(&handle_a.backend, block.clone()).split();
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
        handle_a
            .cmd_tx
            .send(NetworkCommand::Publish { topic, data })
            .await
            .expect("publish");
    }

    // Drive B's import side: drain B's event stream for the candidate and
    // the receipt and hand each to B's ChainBackend.
    let follower_backend = Arc::clone(&handle_b.backend);
    let (candidate_head, proven) = timeout(Duration::from_secs(5), async move {
        let mut candidate_head = None;
        let mut proven = None;
        while candidate_head.is_none() || proven.is_none() {
            match handle_b.event_rx.recv().await.expect("event stream open") {
                NetworkEvent::GossipMessage {
                    topic: Topic::Blocks,
                    data,
                    ..
                } => {
                    let decoded: CandidateBlock =
                        borsh::from_slice(&data).expect("decode candidate");
                    let outcome = import_candidates_blocking(&follower_backend, vec![decoded])
                        .await
                        .expect("follower imports the candidate");
                    candidate_head = Some(outcome);
                }
                NetworkEvent::GossipMessage {
                    topic: Topic::Receipts,
                    data,
                    ..
                } => {
                    let decoded: BlockReceipt = borsh::from_slice(&data).expect("decode receipt");
                    let outcome = import_receipts_blocking(&follower_backend, vec![decoded])
                        .await
                        .expect("follower imports the receipt");
                    proven = Some(outcome);
                }
                _ => {}
            }
        }
        (candidate_head.unwrap(), proven.unwrap())
    })
    .await
    .expect("follower receives and imports gossipped candidate and receipt within timeout");

    // The follower's head reflects the candidate; the receipt proved it,
    // whether it arrived before (orphan buffer) or after the candidate.
    assert_eq!(candidate_head.new_head_height, 1);
    assert_eq!(candidate_head.new_head_hash, block.hash());
    assert_eq!(proven.buffered + proven.proven.len(), 1);
    let status = handle_b.backend.local_status().await.unwrap();
    assert_eq!(status.head_height, 1);
    assert_eq!(status.head_block_hash, block.hash());
    assert_eq!(
        handle_b
            .backend
            .local_progress()
            .await
            .unwrap()
            .proven_height,
        1
    );
}

/// The inputs root the importing engine derives for a chunk-zero fixture
/// block (design 08): the mock backend installs no programs, so a genesis
/// engine of the same specification derives exactly the same commitment.
fn fixture_inputs_root(
    spec: &neutrin0_primitives::ChainSpec,
    header: &neutrin0_consensus_types::Header,
    body: &neutrin0_consensus_types::Body,
) -> neutrin0_primitives::Hash {
    neutrin0_consensus_engine::Engine::genesis(
        spec.clone(),
        neutrin0_storage::MemoryDatabase::new(),
    )
    .unwrap()
    .expected_inputs_root(header, body)
    .unwrap()
}
