//! Sixteen validators finalize a chunk whose blocks execute through mock
//! SP1 and whose outer consensus is checked natively.
//!
//! The test uses:
//!
//! - `NativeChunkTestSystem` on every node: mock SP1 block execution plus
//!   native full-consensus validation. This is not a real recursion test.
//! - `WasmExecutor::embedded()` on every node — the embedded
//!   EVM runtime master cdylib in wasmtime.
//! - `try_produce_block` + `prove_block` on the producer — the real
//!   production path. The block carries the runtime-emitted
//!   `validator_set_root` in `header.runtime_extra`, the proof's public
//!   values commit to it, and every follower's `verify_block` cross-checks.
//!
//! Convergence assertion: all 16 validators reach
//! `finalized_chunk_id == Some(0)` within the test window. One validator, never
//! the seat that proves chunk 0, has its incoming precommit and Chunk-proof gossip
//! omitted, so its production `SyncDriver` must recover complete finality through
//! `ChunkProofById` RPC.

#[path = "support/evm.rs"]
pub mod evm;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use neutrin0_consensus_engine::ProposerKey;
use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_types::{BftVote, FinalityVotePhase};
use neutrin0_network::libp2p::gossipsub::MessageAcceptance;
use neutrin0_network::libp2p::identity::Keypair;
use neutrin0_network::service::{NetworkCommand, NetworkEvent, NetworkService};
use neutrin0_network::{Multiaddr, PeerId};
use neutrin0_network::{Topic, rpc::RpcRequest};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
#[path = "support/native_chunk.rs"]
pub mod native_chunk;
use native_chunk::NativeChunkTestSystem;
use neutrin0_runtime_host::WasmExecutor;
use neutrin0_storage::MemoryDatabase;
use neutrin0_sync::{SyncBackend, SyncDriver, SyncDriverConfig};
use tokio::sync::mpsc;
use tokio::time::timeout;

const N_VALIDATORS: u8 = 16;
const VOTE_SUBNETS: u16 = 4;
const TEST_CHAIN_ID: u64 = 7_171_717;
const TEST_GENESIS_SEED: [u8; 32] = [0xE9; 32];

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn validators(count: u8) -> Vec<Validator> {
    (0..count)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: evm::padded(0x33 + i),
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
    let genesis_block_hash: BlockHash = [0xAA; 32];
    let consensus = ConsensusParams {
        chunk_size: 1,
        // VRF eligibility budget high enough that v0 reliably clears
        // the slot-1 threshold; only v0 produces, so we don't need
        // every validator to clear it.
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 4),
        expected_aggregators_per_round: fixed_u128_from_integer(100),
        vote_subnets: VOTE_SUBNETS,
        ..ConsensusParams::default()
    };
    evm::sealed(ChainSpec {
        genesis_execution: NativeChunkTestSystem::execution_programs(),
        name: BoundedBytes::new(b"m7-new-sixteen-validators".to_vec()).expect("name fits"),
        chain_id: TEST_CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: neutrin0_runtime_host::embedded_runtime_code_hash(),
        genesis_chunk: [7; 8],
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

type NodeBackend = ChainBackend<MemoryDatabase, NativeChunkTestSystem>;

struct NodeHandle {
    peer_id: PeerId,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: Option<mpsc::Receiver<NetworkEvent>>,
    backend: Arc<NodeBackend>,
    listen_addr: Option<Multiaddr>,
}

fn build_node(validator_index: u8) -> (NodeHandle, NetworkService) {
    let key = Keypair::generate_ed25519();
    let peer_id = PeerId::from(key.public());
    // Bounded event queues keep the 16-validator burst within capacity; the
    // mesh isn't backpressure-bottlenecked.
    let (cmd_tx, cmd_rx) = mpsc::channel(1024);
    let (event_tx, event_rx) = mpsc::channel(4096);
    let svc = NetworkService::new(key, cmd_rx, event_tx).expect("network service");
    let engine = evm::genesis_engine(chain_spec(N_VALIDATORS), MemoryDatabase::new(), Vec::new());
    let proof_system = NativeChunkTestSystem::mock().expect("mock SP1 adapter");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    let executor = WasmExecutor::embedded().expect("wasm runtime");
    backend.set_block_executor(executor);
    backend.set_local_voter(proposer(validator_index));
    backend.set_network_publisher(cmd_tx.clone());
    (
        NodeHandle {
            peer_id,
            cmd_tx,
            event_rx: Some(event_rx),
            backend,
            listen_addr: None,
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

async fn wait_for_peer_count(
    rx: &mut mpsc::Receiver<NetworkEvent>,
    expected_peers: usize,
) -> Vec<PeerId> {
    timeout(Duration::from_secs(10), async {
        let mut peers = Vec::with_capacity(expected_peers);
        while peers.len() < expected_peers {
            if let NetworkEvent::PeerConnected(peer) = rx.recv().await.expect("peer stream open")
                && !peers.contains(&peer)
            {
                peers.push(peer);
            }
        }
        peers
    })
    .await
    .expect("full peer mesh established")
}

fn all_bft_topics() -> Vec<Topic> {
    let mut topics = vec![
        Topic::Blocks,
        Topic::Receipts,
        Topic::ChunkProofs,
        Topic::BftCandidates,
        Topic::BftMessages,
        Topic::FinalityVotesPrevote,
        Topic::FinalityVotesPrecommit,
    ];
    for subnet in 0..u8::try_from(VOTE_SUBNETS).expect("subnet fits u8") {
        topics.push(Topic::AggregateFinalityVotes(subnet));
    }
    // This fixture accepts only native chunk statements; real recursion has its own gate.
    topics
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

/// The last seat that is not chunk 1's round-zero leader, which proves chunk 0
/// at once. Chunk 0 holds only block 1, whose VRF proof by v0 folds into chunk
/// 1's seed; the seed depends on the specification hash, so the leader changes
/// whenever a pinned program does.
fn isolated_validator(handle: &NodeHandle) -> usize {
    let spec = handle
        .backend
        .with_engine_mut_for_test(|engine| engine.chain_spec().clone());
    let proof = proposer(0).vrf_eval(spec.consensus_domain(), &spec.genesis_seed, 1);
    let seed = neutrin0_vrf::fold_seed(&spec.genesis_seed, &[proof]);
    let leader =
        neutrin0_consensus_types::bft_leader(spec.chain_id, 1, 0, &seed, &spec.initial_validators)
            .expect("chunk 1 has a round-zero leader");
    let last = usize::from(N_VALIDATORS - 1);
    if usize::try_from(leader).expect("seat index fits usize") == last {
        last - 1
    } else {
        last
    }
}

fn omit_finality_gossip(event: &NetworkEvent) -> bool {
    match event {
        NetworkEvent::GossipMessage {
            topic: Topic::ChunkProofs | Topic::FinalityVotesPrecommit,
            ..
        } => true,
        NetworkEvent::GossipMessage {
            topic: Topic::AggregateFinalityVotes(_),
            data,
            ..
        } => borsh::from_slice::<BftVote>(data).is_ok_and(|vote| match vote {
            BftVote::Value(vote) => vote.data.phase == FinalityVotePhase::Precommit,
            BftVote::Nil(vote) => vote.data.phase == FinalityVotePhase::Precommit,
        }),
        NetworkEvent::GossipMessage {
            topic: Topic::BftMessages,
            data,
            ..
        } => borsh::from_slice::<neutrin0_consensus_types::BftMessage>(data).is_ok_and(
            |message| matches!(message, neutrin0_consensus_types::BftMessage::Vote(BftVote::Value(vote)) if vote.data.phase == FinalityVotePhase::Precommit),
        ),
        _ => false,
    }
}

/// Replay consumed connection notices, then pass the actual network stream to
/// the production driver, including status and complete-proof RPC handling.
async fn spawn_handle_driver(
    handle: &mut NodeHandle,
    peers: Vec<PeerId>,
    backfill_peer: PeerId,
    backfill_requests: Arc<AtomicUsize>,
) -> [tokio::task::JoinHandle<()>; 2] {
    let (events, event_rx) = mpsc::channel(4096);
    for peer in peers {
        events
            .send(NetworkEvent::PeerConnected(peer))
            .await
            .expect("replay connected peer");
    }
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::clone(&handle.backend) as Arc<dyn SyncBackend>,
        handle
            .backend
            .local_progress()
            .await
            .expect("local progress"),
        handle.cmd_tx.clone(),
        event_rx,
    );
    let driver_task = tokio::spawn(async move { driver.run().await });
    let omit_gossip = handle.peer_id == backfill_peer;
    let cmd_tx = handle.cmd_tx.clone();
    let mut network_events = handle.event_rx.take().expect("event stream present");
    let relay_task = tokio::spawn(async move {
        while let Some(event) = network_events.recv().await {
            if let NetworkEvent::RpcRequestReceived {
                peer,
                request: RpcRequest::ChunkProofById(_),
                ..
            } = &event
                && *peer == backfill_peer
            {
                backfill_requests.fetch_add(1, Ordering::Relaxed);
            }
            if omit_gossip && omit_finality_gossip(&event) {
                if let NetworkEvent::GossipMessage {
                    message_id,
                    propagation_source,
                    ..
                } = event
                {
                    cmd_tx
                        .send(NetworkCommand::ReportGossipValidation {
                            message_id,
                            propagation_source,
                            acceptance: MessageAcceptance::Ignore,
                        })
                        .await
                        .expect("report omitted gossip");
                }
                continue;
            }
            if events.send(event).await.is_err() {
                return;
            }
        }
    });
    [driver_task, relay_task]
}

/// Producer (v0) drives the real production path: WASM dry-run →
/// witness emit → SP1 mock-prove → publish the complete publication → open
/// local BFT session (which records v0's own prevote and gossips
/// it). Both heavy calls live behind `spawn_blocking` so the SDK's
/// internal tokio runtime doesn't collide with the test's outer
/// runtime.
async fn produce_prove_and_publish(handle: &NodeHandle, producer_key: ProposerKey) {
    let backend = Arc::clone(&handle.backend);
    let outcome = tokio::task::spawn_blocking(move || {
        backend
            .try_produce_block(1, &producer_key)
            .expect("try_produce_block")
            .expect("v0 is eligible for slot 1")
    })
    .await
    .expect("spawn_blocking try_produce_block");

    let backend = Arc::clone(&handle.backend);
    let block_hash = outcome.block_hash;
    tokio::task::spawn_blocking(move || {
        backend.prove_block(&block_hash).expect("v0 proves block 1");
    })
    .await
    .expect("spawn_blocking prove_block");

    // Gossip the complete publication: block, receipt bytes and write set.
    let (candidate, receipt) = handle
        .backend
        .proven_block_for_publication(&block_hash)
        .expect("complete publication")
        .split();
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
        handle
            .cmd_tx
            .send(NetworkCommand::Publish { topic, data })
            .await
            .expect("publish");
    }

    // Open v0's own BFT session so v0 emits its prevote / precommit
    // through the same drivers as the peers do.
    handle.backend.maybe_open_bft_session_for_height(1).await;
}

async fn wait_for_all_finalised(
    handles: &[NodeHandle],
    deadline: tokio::time::Instant,
) -> Vec<neutrin0_primitives::CheckpointIndex> {
    loop {
        let mut indices = Vec::with_capacity(handles.len());
        let mut progress = Vec::with_capacity(handles.len());
        for h in handles {
            let snapshot = h.backend.local_progress().await.expect("local progress");
            indices.push(snapshot.finalized_chunk_id.map_or(0, |id| id + 1));
            progress.push((snapshot.head_height, snapshot.proven_height));
        }
        if indices.iter().all(|i| *i >= 1) {
            return indices;
        }
        if tokio::time::Instant::now() >= deadline {
            let sessions: Vec<_> = handles
                .iter()
                .map(|handle| {
                    handle.backend.with_engine_mut_for_test(|engine| {
                        engine.bft_session(0).map(|session| {
                            (
                                session.round(),
                                session.local_prevoted(),
                                session.local_precommitted(),
                                session.prevote_quorum_observed(),
                                session.precommit_quorum_observed(),
                            )
                        })
                    })
                })
                .collect();
            panic!(
                "16-validator BFT did not finalize chunk 0 within the test budget. \
                 Finalized indices = {indices:?}; (head, proven, body) = {progress:?}; \
                 (round, own prevote, own precommit, prevote quorum, precommit quorum) = {sessions:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[allow(clippy::too_many_lines)] // One test exercises the full 16-node libp2p + BFT + SP1
// pipeline; splitting it would dilute the assertion.
async fn sixteen_validators_finalise_chunk_zero_over_real_sp1_envelopes() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    // Build all N_VALIDATORS nodes. `build_node` calls Sp1ProofSystem
    // and wasmtime which both spin up internal runtimes; spawn_blocking
    // keeps them off the tokio worker thread.
    let build_results: Vec<(NodeHandle, NetworkService)> = {
        let mut results = Vec::with_capacity(N_VALIDATORS as usize);
        for i in 0..N_VALIDATORS {
            let pair = tokio::task::spawn_blocking(move || build_node(i))
                .await
                .expect("build node");
            results.push(pair);
        }
        results
    };
    let mut handles: Vec<NodeHandle> = Vec::with_capacity(N_VALIDATORS as usize);
    let mut services: Vec<NetworkService> = Vec::with_capacity(N_VALIDATORS as usize);
    for (h, mut s) in build_results {
        s.require_chain(
            h.backend
                .local_status()
                .await
                .expect("authenticated local status"),
        );
        handles.push(h);
        services.push(s);
    }

    let completion_handles: Vec<_> = handles
        .iter()
        .map(|handle| tokio::spawn(Arc::clone(&handle.backend).run_consensus_proof_notifications()))
        .collect();
    let bft_clock_handles: Vec<_> = handles
        .iter()
        .map(|handle| tokio::spawn(Arc::clone(&handle.backend).run_bft_round_timeouts()))
        .collect();

    // Every node listens on its own port for full-mesh dial topology
    // (avoids the star-via-v0 bottleneck on gossipsub mesh formation).
    for svc in &mut services {
        svc.listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
            .expect("listen");
    }
    let network_handles: Vec<_> = services
        .into_iter()
        .map(|service| {
            tokio::spawn(async move {
                Box::pin(service.run())
                    .await
                    .expect("network service failed");
            })
        })
        .collect();

    // Capture each node's listen address.
    for h in &mut handles {
        let rx = h.event_rx.as_mut().expect("event_rx still attached");
        let addr = wait_for_listen_addr(rx).await;
        h.listen_addr = Some(addr);
    }
    let listen_addrs: Vec<Multiaddr> = handles
        .iter()
        .map(|h| h.listen_addr.clone().expect("listen_addr captured"))
        .collect();

    // Full-mesh pairwise dials: every node dials every node with a
    // strictly smaller index.
    for (i, handle) in handles.iter().enumerate().skip(1) {
        for addr in listen_addrs.iter().take(i) {
            handle
                .cmd_tx
                .send(NetworkCommand::Dial(addr.clone()))
                .await
                .expect("pairwise dial");
        }
    }

    let mut connected_peers = Vec::with_capacity(handles.len());
    for h in &mut handles {
        let rx = h.event_rx.as_mut().expect("event_rx still attached");
        let peers = wait_for_peer_count(rx, usize::from(N_VALIDATORS - 1)).await;
        assert_eq!(
            peers.len(),
            usize::from(N_VALIDATORS - 1),
            "node did not connect to the full localnet peer mesh"
        );
        connected_peers.push(peers);
    }

    // One validator cannot receive a gossip precommit quorum or complete Chunk
    // proof. Its real driver must recover finality through ChunkProofById. It
    // may still assemble the certificate from retrievable signed artifacts
    // (design 17), so it waits out a long fallback rather than proving the
    // chunk itself.
    let isolated = isolated_validator(&handles[0]);
    let backfill_peer = handles[isolated].peer_id;
    handles[isolated]
        .backend
        .set_proving_policy(neutrin0_node::config::ProvingPolicy {
            chunk_fallback_secs: 3600,
            ..neutrin0_node::config::ProvingPolicy::default()
        });
    let backfill_requests = Arc::new(AtomicUsize::new(0));
    let mut driver_tasks = Vec::with_capacity(handles.len() * 2);
    for (handle, peers) in handles.iter_mut().zip(connected_peers) {
        driver_tasks.extend(
            spawn_handle_driver(handle, peers, backfill_peer, Arc::clone(&backfill_requests)).await,
        );
    }

    // Subscribe to BFT topics after the mesh is established.
    let topics = all_bft_topics();
    for h in &handles {
        subscribe_all(h, &topics).await;
    }
    // 5 s settle window — gossipsub heartbeats (1 s each) need a few
    // rounds to propagate topic subscriptions across the 16-node mesh.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // v0 produces, proves, and gossips block 1, then opens its
    // local BFT session. The drivers carry the rest of the loop.
    produce_prove_and_publish(&handles[0], proposer(0)).await;

    // 60 s budget: SP1 mock-verify on 15 followers plus BFT mesh
    // settle plus aggregator subnet routing leaves plenty of slack.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let indices = wait_for_all_finalised(&handles, deadline).await;

    for (i, idx) in indices.iter().enumerate() {
        assert!(
            *idx >= 1,
            "validator {i} did not finalize chunk 0 over real SP1 envelopes \
             (finalized_index = {idx})"
        );
    }
    assert!(
        backfill_requests.load(Ordering::Relaxed) > 0,
        "the gossip-isolated validator must request a complete Chunk proof over RPC"
    );
    for handle in driver_tasks
        .iter()
        .chain(&completion_handles)
        .chain(&bft_clock_handles)
        .chain(&network_handles)
    {
        handle.abort();
    }
    for handle in driver_tasks
        .into_iter()
        .chain(completion_handles)
        .chain(bft_clock_handles)
        .chain(network_handles)
    {
        let _ = handle.await;
    }
}
