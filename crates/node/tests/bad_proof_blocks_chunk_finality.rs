//! An injected invalid block proof prevents BFT finality for the affected
//! chunk.
//!
//! Topology: two validators on libp2p loopback. v0 produces and
//! proves a block legitimately (its local FSM is `Proven`), but
//! gossips a publication with **tampered** receipt bytes instead of the
//! real one. v1 rejects the publication as a unit: the receipt fails
//! `Sp1ProofSystem::verify_block`, so neither the block nor its proof
//! enters v1's store.
//!
//! As a result, v1's `maybe_open_bft_session_for_height` finds
//! `assemble_chunk` returns `None` (no block at `Proven`), and no
//! BFT session opens on v1. v0's local prevote arrives at v1 but is
//! silently dropped by `observe_finality_vote` (no session for the
//! chunk). v0 alone has 1/2 prevote stake which falls short of the
//! 2/3 quorum, so v0 cannot reach precommit either. After a generous
//! wait, neither validator's `finalized_chunk_id` advances
//! past genesis.
//!
//! Sister to `proven_block_rejection.rs` (which covers the single-node
//! rejection gate). This test extends the assertion through the
//! multi-node BFT layer.

#[path = "support/evm.rs"]
pub mod evm;
#[path = "support/proven.rs"]
pub mod proven;
use std::sync::Arc;
use std::time::Duration;

use neutrin0_consensus_engine::ProposerKey;
use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_types::{BftMessage, BftVote, BlockReceipt, CandidateBlock};
use neutrin0_network::Multiaddr;
use neutrin0_network::Topic;
use neutrin0_network::libp2p::gossipsub::MessageAcceptance;
use neutrin0_network::libp2p::identity::Keypair;
use neutrin0_network::service::{NetworkCommand, NetworkEvent, NetworkService};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrin0_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrin0_storage::MemoryDatabase;
use neutrin0_sync::SyncBackend;
use sp1_sdk::blocking::MockProver;
use tokio::sync::mpsc;
use tokio::time::timeout;

const N_VALIDATORS: u8 = 2;
const VOTE_SUBNETS: u16 = 1;
const TEST_CHAIN_ID: u64 = 2_727_272;
const TEST_GENESIS_SEED: [u8; 32] = [0xDE; 32];

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn validators(count: u8) -> Vec<Validator> {
    (0..count)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: evm::padded(0x40 + i),
            effective_stake: 32_000_000_000_000_000_000,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect()
}

fn chain_spec(count: u8) -> ChainSpec {
    let validators = validators(count);
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash: BlockHash = [0xFE; 32];
    let consensus = ConsensusParams {
        chunk_size: 1,
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 4),
        expected_aggregators_per_round: fixed_u128_from_integer(100),
        vote_subnets: VOTE_SUBNETS,
        ..ConsensusParams::default()
    };
    evm::sealed(ChainSpec {
        genesis_execution: neutrin0_runtime_host::package::RuntimePackage::embedded(Vec::new())
            .expect("authenticated fixture programs")
            .programs
            .execution,
        name: BoundedBytes::new(b"m7-new-bad-proof".to_vec()).expect("name fits"),
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
    })
}

type NodeBackend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

struct NodeHandle {
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: Option<mpsc::Receiver<NetworkEvent>>,
    backend: Arc<NodeBackend>,
}

fn build_node(validator_index: u8) -> (NodeHandle, NetworkService) {
    let key = Keypair::generate_ed25519();
    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let (event_tx, event_rx) = mpsc::channel(1024);
    let svc = NetworkService::new(key, cmd_rx, event_tx).expect("network service");
    let engine = evm::genesis_engine(chain_spec(N_VALIDATORS), MemoryDatabase::new(), Vec::new());
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    let executor = WasmExecutor::embedded().expect("wasm runtime");
    backend.set_block_executor(executor);
    backend.set_local_voter(proposer(validator_index));
    backend.set_network_publisher(cmd_tx.clone());
    (
        NodeHandle {
            cmd_tx,
            event_rx: Some(event_rx),
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

fn all_bft_topics() -> Vec<Topic> {
    vec![
        Topic::Blocks,
        Topic::Receipts,
        Topic::BftMessages,
        Topic::FinalityVotesPrevote,
        Topic::FinalityVotesPrecommit,
        Topic::AggregateFinalityVotes(0),
    ]
}

async fn subscribe_all(handle: &NodeHandle, topics: &[Topic]) {
    for topic in topics {
        handle
            .cmd_tx
            .send(NetworkCommand::Subscribe(*topic))
            .await
            .expect("subscribe");
    }
}

fn spawn_handle_driver(
    backend: Arc<NodeBackend>,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    mut event_rx: mpsc::Receiver<NetworkEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            let NetworkEvent::GossipMessage {
                propagation_source,
                topic,
                data,
                message_id,
            } = event
            else {
                continue;
            };
            let acceptance = match topic {
                Topic::Blocks => {
                    if let Ok(candidate) = borsh::from_slice::<CandidateBlock>(&data) {
                        let backend = Arc::clone(&backend);
                        let result = tokio::task::spawn_blocking(move || {
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .expect("inner runtime");
                            rt.block_on(backend.verify_and_import_candidates(vec![candidate]))
                        })
                        .await
                        .expect("spawn_blocking candidate import");
                        match result {
                            Ok(_) => MessageAcceptance::Accept,
                            Err(_) => MessageAcceptance::Reject,
                        }
                    } else {
                        MessageAcceptance::Reject
                    }
                }
                Topic::Receipts => {
                    if let Ok(receipt) = borsh::from_slice::<BlockReceipt>(&data) {
                        let backend = Arc::clone(&backend);
                        let result =
                            tokio::task::spawn_blocking(move || {
                                let rt = tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .build()
                                    .expect("inner runtime");
                                rt.block_on(backend.verify_and_import_receipts(
                                vec![receipt],
                                neutrin0_network::libp2p::identity::Keypair::generate_ed25519()
                                    .public()
                                    .to_peer_id(),
                            ))
                            })
                            .await
                            .expect("spawn_blocking receipt import");
                        match result {
                            Ok(_) => MessageAcceptance::Accept,
                            // A tampered receipt is rejected and the candidate
                            // stays unproven; this is the path the test asserts on.
                            Err(_) => MessageAcceptance::Reject,
                        }
                    } else {
                        MessageAcceptance::Reject
                    }
                }
                Topic::FinalityVotesPrevote | Topic::FinalityVotesPrecommit => {
                    if let Ok(vote) = borsh::from_slice::<BftVote>(&data) {
                        let _ = backend.ingest_bft_message(BftMessage::Vote(vote)).await;
                        MessageAcceptance::Accept
                    } else {
                        MessageAcceptance::Reject
                    }
                }
                Topic::AggregateFinalityVotes(subnet) => {
                    if let Ok(BftVote::Value(vote)) = borsh::from_slice::<BftVote>(&data) {
                        let _ = backend.ingest_aggregate_finality_vote(subnet, vote).await;
                        MessageAcceptance::Accept
                    } else {
                        MessageAcceptance::Reject
                    }
                }
                Topic::BftMessages => {
                    if let Ok(message) = borsh::from_slice::<BftMessage>(&data) {
                        let _ = backend.ingest_bft_message(message).await;
                        MessageAcceptance::Accept
                    } else {
                        MessageAcceptance::Reject
                    }
                }
                _ => MessageAcceptance::Ignore,
            };
            let _ = cmd_tx
                .send(NetworkCommand::ReportGossipValidation {
                    message_id,
                    propagation_source,
                    acceptance,
                })
                .await;
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // Multi-node libp2p + BFT setup + injection +
// assertion is one logical test by design.
async fn injected_bad_proof_prevents_chunk_finality() {
    let _ = tracing_subscriber::fmt::try_init();

    // Two validators, both with real Sp1ProofSystem<MockProver> +
    // WasmExecutor + BFT loop enabled.
    let (mut handle_0, mut svc_0) = tokio::task::spawn_blocking(|| build_node(0))
        .await
        .expect("build v0");
    let (mut handle_1, mut svc_1) = tokio::task::spawn_blocking(|| build_node(1))
        .await
        .expect("build v1");

    svc_0
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("listen 0");
    svc_1
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
        .expect("listen 1");
    tokio::spawn(svc_0.run());
    tokio::spawn(svc_1.run());

    let rx_0 = handle_0.event_rx.as_mut().expect("event_rx 0");
    let addr_0 = wait_for_listen_addr(rx_0).await;
    let rx_1 = handle_1.event_rx.as_mut().expect("event_rx 1");
    let _addr_1 = wait_for_listen_addr(rx_1).await;

    handle_1
        .cmd_tx
        .send(NetworkCommand::Dial(addr_0))
        .await
        .expect("dial 1→0");

    let rx_0 = handle_0.event_rx.as_mut().expect("event_rx 0");
    let peer_id_1 = {
        // We need v1's peer id; capture via the first PeerConnected on v0.
        timeout(Duration::from_secs(10), async {
            loop {
                if let NetworkEvent::PeerConnected(peer) =
                    rx_0.recv().await.expect("event stream open")
                {
                    return peer;
                }
            }
        })
        .await
        .expect("v0 sees v1 connect")
    };
    let rx_1 = handle_1.event_rx.as_mut().expect("event_rx 1");
    // Capture v0's peer id from v1's perspective so the helper has
    // something concrete to wait on (libp2p Dial doesn't return PeerId).
    let peer_id_0 = timeout(Duration::from_secs(10), async {
        loop {
            if let NetworkEvent::PeerConnected(peer) = rx_1.recv().await.expect("event stream open")
            {
                return peer;
            }
        }
    })
    .await
    .expect("v1 sees v0 connect");
    let _ = peer_id_0;
    let _ = peer_id_1;

    let completion_handles: Vec<_> = [&handle_0, &handle_1]
        .into_iter()
        .map(|handle| tokio::spawn(Arc::clone(&handle.backend).run_consensus_proof_notifications()))
        .collect();

    // Wire gossip drivers.
    for h in [&mut handle_0, &mut handle_1] {
        let rx = h.event_rx.take().expect("event_rx present");
        drop(spawn_handle_driver(
            Arc::clone(&h.backend),
            h.cmd_tx.clone(),
            rx,
        ));
    }

    // Subscribe to BFT topics + settle mesh.
    let topics = all_bft_topics();
    subscribe_all(&handle_0, &topics).await;
    subscribe_all(&handle_1, &topics).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    // v0 produces + proves the block legitimately. v0's local FSM
    // ends at `Proven`. v0's BFT session opens (it has its own
    // block at Proven), v0 emits its prevote — but with only 1/2
    // stake, that's below the 2/3 quorum threshold.
    let backend_0 = Arc::clone(&handle_0.backend);
    let outcome = tokio::task::spawn_blocking(move || {
        backend_0
            .try_produce_block(1, &proposer(0))
            .expect("try_produce_block")
            .expect("v0 eligible")
    })
    .await
    .expect("spawn_blocking try_produce_block");
    let backend_0 = Arc::clone(&handle_0.backend);
    let block_hash = outcome.block_hash;
    tokio::task::spawn_blocking(move || {
        backend_0
            .prove_block(&block_hash)
            .expect("prove_block legitimate");
    })
    .await
    .expect("spawn_blocking prove_block");

    // Publish the honest candidate and a TAMPERED receipt: v1's
    // `Sp1ProofSystem::verify_block` rejects the receipt, so the candidate
    // stays unproven there and no BFT session can open on it.
    let (candidate, mut tampered) = proven::candidate_and_receipt(&handle_0.backend, &block_hash);
    tampered.proof_bytes[0] ^= 0xFF;
    for (topic, data) in [
        (
            Topic::Blocks,
            borsh::to_vec(&candidate).expect("encode candidate"),
        ),
        (
            Topic::Receipts,
            borsh::to_vec(&tampered).expect("encode tampered receipt"),
        ),
    ] {
        handle_0
            .cmd_tx
            .send(NetworkCommand::Publish { topic, data })
            .await
            .expect("publish");
    }
    // v0 still opens its own BFT session locally (its FSM has the
    // block at `Proven` from the legitimate prove_block above).
    // That's the prevote that joins the quorum count.
    handle_0.backend.maybe_open_bft_session_for_height(1).await;

    // Wait long enough that, if finality were possible, both
    // validators would have reached `finalized_chunk_id == Some(0)`.
    // 20 s is a comfortable upper bound for two validators (the
    // 16-validator localnet finalises in <30 s).
    tokio::time::sleep(Duration::from_secs(20)).await;

    // Neither validator advances past genesis.
    let status_0 = handle_0.backend.local_status().await.unwrap();
    let status_1 = handle_1.backend.local_status().await.unwrap();
    assert_eq!(
        status_0.finalized_chunk_id, None,
        "v0 must not finalize chunk 0 when the gossipped proof is invalid",
    );
    assert_eq!(
        status_1.finalized_chunk_id, None,
        "v1 must not finalize chunk 0 when the gossipped proof is invalid",
    );

    // Sanity: v1 holds the honest candidate but rejected the tampered
    // receipt, so nothing is proven there. v0 has its proof locally
    // (proven_height = 1 because the tamper happened on the wire, not in
    // v0's store).
    let progress_0 = handle_0.backend.local_progress().await.unwrap();
    let progress_1 = handle_1.backend.local_progress().await.unwrap();
    assert_eq!(progress_0.proven_height, 1, "v0 has the real proof locally");
    assert_eq!(
        progress_1.proven_height, 0,
        "v1 rejects the tampered receipt",
    );
    assert_eq!(
        progress_1.head_height, 1,
        "the honest candidate is v1's pending head",
    );
    assert_eq!(
        handle_1.backend.block_state(&block_hash),
        Some(neutrin0_consensus_engine::BlockState::BlockProduced),
        "a candidate with a bad receipt stays unproven on v1",
    );
    for handle in &completion_handles {
        handle.abort();
    }
    for handle in completion_handles {
        let _ = handle.await;
    }
}
