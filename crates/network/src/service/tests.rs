use super::test_support::{next_listen_addr, test_node, wait_connected};
use super::*;
use crate::rpc::RpcProtocol;
use libp2p::identity;
use std::collections::HashSet;
use tokio::time::{Duration as TokDuration, timeout};
use tracing_subscriber::fmt::format::FmtSpan;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_span_events(FmtSpan::NONE)
        .try_init();
}

#[tokio::test]
#[allow(clippy::similar_names)]
async fn two_nodes_connect_and_ping() {
    init_tracing();

    let key_a = identity::Keypair::generate_ed25519();
    let peer_a = PeerId::from(key_a.public());
    let (_cmd_tx_a, cmd_rx_a) = mpsc::channel(16);
    let (event_tx_a, mut event_rx_a) = mpsc::channel(64);
    let mut svc_a = NetworkService::new(key_a, cmd_rx_a, event_tx_a).unwrap();

    let key_b = identity::Keypair::generate_ed25519();
    let peer_b = PeerId::from(key_b.public());
    let (cmd_tx_b, cmd_rx_b) = mpsc::channel(16);
    let (event_tx_b, mut event_rx_b) = mpsc::channel(64);
    let svc_b = NetworkService::new(key_b, cmd_rx_b, event_tx_b).unwrap();

    // Listen on an OS-assigned port and discover it via NewListenAddr.
    svc_a
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();

    tokio::spawn(svc_a.run());
    tokio::spawn(svc_b.run());

    // Wait for A's listener to advertise its bound address.
    let addr_a = next_listen_addr(&mut event_rx_a).await;

    cmd_tx_b.send(NetworkCommand::Dial(addr_a)).await.unwrap();

    // Both ends should see a PeerConnected event for the counterpart.
    let connected = timeout(TokDuration::from_secs(5), async {
        let mut saw_a = false;
        let mut saw_b = false;
        loop {
            tokio::select! {
                Some(ev) = event_rx_a.recv() => {
                    if let NetworkEvent::PeerConnected(p) = ev {
                        assert_eq!(p, peer_b);
                        saw_a = true;
                    }
                }
                Some(ev) = event_rx_b.recv() => {
                    if let NetworkEvent::PeerConnected(p) = ev {
                        assert_eq!(p, peer_a);
                        saw_b = true;
                    }
                }
            }
            if saw_a && saw_b {
                break;
            }
        }
    })
    .await;

    assert!(
        connected.is_ok(),
        "timed out waiting for both peers to connect"
    );
}

/// Three nodes form a chain (A↔B↔C). A publishes a block-topic message;
/// both B and C must receive it through the gossipsub mesh.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::items_after_statements
)]
async fn three_nodes_gossip_message() {
    init_tracing();

    // Channels and services.
    let make_node = || {
        let key = identity::Keypair::generate_ed25519();
        let node = test_node(key.clone(), 32, 128);
        (key, node.commands, node.events, node.service)
    };

    let (key_a, cmd_a, mut event_a, mut svc_a) = make_node();
    let (key_b, cmd_b, mut event_b, mut svc_b) = make_node();
    let (key_c, cmd_c, mut event_c, svc_c) = make_node();

    let peer_a = PeerId::from(key_a.public());
    let peer_b = PeerId::from(key_b.public());
    let peer_c = PeerId::from(key_c.public());

    svc_a
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    svc_b
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();

    tokio::spawn(svc_a.run());
    tokio::spawn(svc_b.run());
    tokio::spawn(svc_c.run());

    // Drain NewListenAddr from A and B (use the first TCP address).
    let addr_a = next_listen_addr(&mut event_a).await;
    let addr_b = next_listen_addr(&mut event_b).await;

    // Wire mesh: B dials A; C dials B. This creates path A — B — C.
    cmd_b
        .send(NetworkCommand::Dial(addr_a.clone()))
        .await
        .unwrap();
    cmd_c
        .send(NetworkCommand::Dial(addr_b.clone()))
        .await
        .unwrap();

    // All three subscribe to the Blocks topic.
    for cmd in [&cmd_a, &cmd_b, &cmd_c] {
        cmd.send(NetworkCommand::Subscribe(Topic::Blocks))
            .await
            .unwrap();
    }

    // Wait until every pair has seen its counterpart connect at least
    // once, so the gossipsub mesh has had a chance to form.
    async fn wait_for_peers(rx: &mut mpsc::Receiver<NetworkEvent>, expected: HashSet<PeerId>) {
        let mut seen = HashSet::new();
        timeout(TokDuration::from_secs(10), async {
            while seen != expected {
                if let Some(NetworkEvent::PeerConnected(p)) = rx.recv().await
                    && expected.contains(&p)
                {
                    seen.insert(p);
                }
            }
        })
        .await
        .expect("peer connections");
    }

    wait_for_peers(&mut event_a, HashSet::from([peer_b])).await;
    wait_for_peers(&mut event_b, HashSet::from([peer_a, peer_c])).await;
    wait_for_peers(&mut event_c, HashSet::from([peer_b])).await;

    // Give gossipsub heartbeats time to graft the mesh on the topic.
    tokio::time::sleep(TokDuration::from_millis(1500)).await;

    // A publishes; B and C should both receive.
    let payload = b"hello, neutrin0!".to_vec();
    cmd_a
        .send(NetworkCommand::Publish {
            topic: Topic::Blocks,
            data: payload.clone(),
        })
        .await
        .unwrap();

    /// The arrival's message id and propagation source.
    async fn expect_gossip(
        rx: &mut mpsc::Receiver<NetworkEvent>,
        expected_topic: Topic,
        expected_data: &[u8],
    ) -> (gossipsub::MessageId, PeerId) {
        timeout(TokDuration::from_secs(10), async {
            loop {
                if let Some(NetworkEvent::GossipMessage {
                    topic,
                    data,
                    message_id,
                    propagation_source,
                }) = rx.recv().await
                    && topic == expected_topic
                    && data == expected_data
                {
                    return (message_id, propagation_source);
                }
            }
        })
        .await
        .expect("gossip arrival")
    }

    // B forwards to C only once its host has validated the message, as
    // every host does; C reaches A through B alone.
    let (message_id, propagation_source) =
        expect_gossip(&mut event_b, Topic::Blocks, &payload).await;
    cmd_b
        .send(NetworkCommand::ReportGossipValidation {
            message_id,
            propagation_source,
            acceptance: gossipsub::MessageAcceptance::Accept,
        })
        .await
        .unwrap();
    expect_gossip(&mut event_c, Topic::Blocks, &payload).await;
}

/// End-to-end Status RPC: node A sends a Status request to node B; B's
/// host responds via [`crate::service::NetworkCommand::SendRpcResponse`] using the
/// [`RpcInboundId`] carried by the inbound event.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::similar_names, clippy::too_many_lines)]
async fn status_rpc_round_trip_between_two_nodes() {
    init_tracing();

    let key_a = identity::Keypair::generate_ed25519();
    let peer_a = PeerId::from(key_a.public());
    let (cmd_tx_a, cmd_rx_a) = mpsc::channel::<NetworkCommand>(16);
    let (event_tx_a, mut event_rx_a) = mpsc::channel::<NetworkEvent>(64);
    let mut svc_a = NetworkService::new(key_a, cmd_rx_a, event_tx_a).unwrap();

    let key_b = identity::Keypair::generate_ed25519();
    let peer_b = PeerId::from(key_b.public());
    let (cmd_tx_b, cmd_rx_b) = mpsc::channel::<NetworkCommand>(16);
    let (event_tx_b, mut event_rx_b) = mpsc::channel::<NetworkEvent>(64);
    let svc_b = NetworkService::new(key_b, cmd_rx_b, event_tx_b).unwrap();

    svc_a
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let metrics_a = svc_a.metrics();
    let metrics_b = svc_b.metrics();
    tokio::spawn(svc_a.run());
    tokio::spawn(svc_b.run());

    let addr_a = next_listen_addr(&mut event_rx_a).await;
    cmd_tx_b.send(NetworkCommand::Dial(addr_a)).await.unwrap();

    // Wait for the connection on both sides.
    wait_connected(&mut event_rx_a, peer_b, &mut event_rx_b, peer_a).await;

    // B's host loop: wait for an inbound Status RPC and reply with a
    // distinguishable Status payload so we can assert on it from A.
    let canned_b_status = rpc::Status {
        chain_id: 7,
        chain_spec_hash: [0xAB; 32],
        finalized_chunk_id: None,
        finalized_chunk_hash: [0; 32],
        checkpoint_hash: [0xBB; 32],
        head_block_hash: [0xCC; 32],
        head_slot: 100,
        head_height: 99,
    };
    let canned_b_clone = canned_b_status;
    let cmd_tx_b_clone = cmd_tx_b.clone();
    tokio::spawn(async move {
        while let Some(ev) = event_rx_b.recv().await {
            if let NetworkEvent::RpcRequestReceived {
                inbound_id,
                request,
                ..
            } = ev
            {
                cmd_tx_b_clone
                    .send(NetworkCommand::SendRpcResponse {
                        inbound_id,
                        response: match request {
                            RpcRequest::Status(_) => RpcResponse::Status(canned_b_clone),
                            RpcRequest::ChunkProofById(_) => RpcResponse::Error {
                                protocol: RpcProtocol::ChunkProofById,
                                error: rpc::RpcFailure::Unavailable(
                                    "chunk proof is missing".to_owned(),
                                ),
                            },
                            RpcRequest::StateByRoot(_) => RpcResponse::Error {
                                protocol: RpcProtocol::StateByRoot,
                                error: rpc::RpcFailure::Storage("invalid trie node".to_owned()),
                            },
                            _ => RpcResponse::Error {
                                protocol: request.protocol(),
                                error: rpc::RpcFailure::InvalidRequest(
                                    "unsupported request".to_owned(),
                                ),
                            },
                        },
                    })
                    .await
                    .ok();
            }
        }
    });

    // A sends a Status request to B.
    let a_status = rpc::Status {
        chain_id: 7,
        chain_spec_hash: [0xAB; 32],
        finalized_chunk_id: None,
        finalized_chunk_hash: [0; 32],
        checkpoint_hash: [0xAA; 32],
        head_block_hash: [0xDD; 32],
        head_slot: 1,
        head_height: 1,
    };
    let (resp_tx, resp_rx) = oneshot::channel();
    cmd_tx_a
        .send(NetworkCommand::SendRpcRequest {
            peer: peer_b,
            request: RpcRequest::Status(a_status),
            response_tx: resp_tx,
        })
        .await
        .unwrap();

    let response = timeout(TokDuration::from_secs(10), resp_rx)
        .await
        .expect("RPC response did not arrive")
        .expect("response_tx was not dropped");

    let response = response.expect("Status RPC succeeded");
    assert!(matches!(response, RpcResponse::Status(s) if s == canned_b_status));
    for (request, expected) in [
        (
            RpcRequest::ChunkProofById(rpc::ChunkProofByIdRequest {
                chunk_ids: vec![5],
                statement_keys: Vec::new(),
            }),
            rpc::RpcFailure::Unavailable("chunk proof is missing".to_owned()),
        ),
        (
            RpcRequest::StateByRoot(rpc::StateByRootRequest {
                state_root: [6; 32],
                items: neutrin0_consensus_types::bootstrap::StateItems::default(),
            }),
            rpc::RpcFailure::Storage("invalid trie node".to_owned()),
        ),
        (
            RpcRequest::Ping(rpc::PingPayload { nonce: 1 }),
            rpc::RpcFailure::InvalidRequest("unsupported request".to_owned()),
        ),
    ] {
        let (response_tx, response_rx) = oneshot::channel();
        cmd_tx_a
            .send(NetworkCommand::SendRpcRequest {
                peer: peer_b,
                request,
                response_tx,
            })
            .await
            .unwrap();
        let response = timeout(TokDuration::from_secs(5), response_rx)
            .await
            .expect("explicit error arrives without timeout")
            .unwrap();
        assert!(matches!(response, Err(RpcError::Remote(error)) if error == expected));
    }
    timeout(TokDuration::from_secs(5), async {
        loop {
            let mut body_a = String::new();
            let mut body_b = String::new();
            metrics_a.render(&mut body_a);
            metrics_b.render(&mut body_b);
            let complete = ["status", "chunk_proof_by_id", "state_by_root", "ping"].into_iter().all(|protocol| {
                let outcome = if protocol == "status" { "ok" } else { "remote_error" };
                [(&body_a, "outbound"), (&body_b, "inbound")].into_iter().all(|(body, direction)| {
                    body.contains(&format!("neutrin0_network_rpc_completed_total{{protocol=\"{protocol}\",direction=\"{direction}\",outcome=\"{outcome}\"}} 1"))
                        && body.contains(&format!("neutrin0_network_rpc_inflight{{protocol=\"{protocol}\",direction=\"{direction}\"}} 0"))
                        && body.contains(&format!("neutrin0_network_rpc_seconds_count{{protocol=\"{protocol}\",direction=\"{direction}\"}} 1"))
                })
            });
            if complete { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("both ends record exact RPC outcomes and release inflight");
}

/// Three concurrent requests on one bulk protocol, as many as the bulk
/// read budget admits at once, must all complete: libp2p silently drops
/// inbound streams beyond the per-protocol stream cap, which must exceed
/// the sync drivers' per-protocol parallelism.
#[tokio::test]
#[allow(
    clippy::similar_names,
    reason = "Paired channel ends of two peers are named by role and peer."
)]
async fn concurrent_requests_on_one_protocol_all_complete() {
    init_tracing();

    let key_a = identity::Keypair::generate_ed25519();
    let peer_a = PeerId::from(key_a.public());
    let (cmd_tx_a, cmd_rx_a) = mpsc::channel::<NetworkCommand>(16);
    let (event_tx_a, mut event_rx_a) = mpsc::channel::<NetworkEvent>(64);
    let mut svc_a = NetworkService::new(key_a, cmd_rx_a, event_tx_a).unwrap();

    let key_b = identity::Keypair::generate_ed25519();
    let peer_b = PeerId::from(key_b.public());
    let (cmd_tx_b, cmd_rx_b) = mpsc::channel::<NetworkCommand>(16);
    let (event_tx_b, mut event_rx_b) = mpsc::channel::<NetworkEvent>(64);
    let svc_b = NetworkService::new(key_b, cmd_rx_b, event_tx_b).unwrap();

    svc_a
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    tokio::spawn(svc_a.run());
    tokio::spawn(svc_b.run());
    let addr_a = next_listen_addr(&mut event_rx_a).await;
    cmd_tx_b.send(NetworkCommand::Dial(addr_a)).await.unwrap();
    wait_connected(&mut event_rx_a, peer_b, &mut event_rx_b, peer_a).await;

    // B answers every request with a receipt for the requested block,
    // after a short hold so the three streams really are open at once.
    let cmd_tx_b_clone = cmd_tx_b.clone();
    tokio::spawn(async move {
        while let Some(ev) = event_rx_b.recv().await {
            if let NetworkEvent::RpcRequestReceived {
                inbound_id,
                request: RpcRequest::ReceiptsByHash(request),
                ..
            } = ev
            {
                let cmd_tx = cmd_tx_b_clone.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(TokDuration::from_millis(200)).await;
                    cmd_tx
                        .send(NetworkCommand::SendRpcResponse {
                            inbound_id,
                            response: RpcResponse::ReceiptsByHash(rpc::ReceiptsByHashResponse {
                                receipts: request
                                    .block_hashes
                                    .into_iter()
                                    .map(|block_hash| neutrin0_consensus_types::BlockReceipt {
                                        block_hash,
                                        proof_bytes: Vec::new(),
                                    })
                                    .collect(),
                            }),
                        })
                        .await
                        .ok();
                });
            }
        }
    });

    let mut receivers = Vec::new();
    for nonce in 0..3_u8 {
        let (response_tx, response_rx) = oneshot::channel();
        cmd_tx_a
            .send(NetworkCommand::SendRpcRequest {
                peer: peer_b,
                request: RpcRequest::ReceiptsByHash(rpc::ReceiptsByHashRequest {
                    block_hashes: vec![[nonce; 32]],
                }),
                response_tx,
            })
            .await
            .unwrap();
        receivers.push((nonce, response_rx));
    }
    for (nonce, response_rx) in receivers {
        let response = timeout(TokDuration::from_secs(10), response_rx)
            .await
            .expect("a concurrent request is answered, not dropped")
            .expect("response_tx was not dropped")
            .expect("ReceiptsByHash RPC succeeded");
        assert!(matches!(
            response,
            RpcResponse::ReceiptsByHash(response)
                if response.receipts.len() == 1 && response.receipts[0].block_hash == [nonce; 32]
        ));
    }
}

/// Adversarial gossipsub scoring: peer A publishes a payload that
/// the host application rejects. The victim B feeds back a
/// `MessageAcceptance::Reject` verdict via
/// `NetworkCommand::ReportGossipValidation`. With the per-topic
/// `invalid_message_deliveries_weight = -160.0` configured by
/// `build_topic_score_params`, even one confirmed reject drops A's
/// score below the `-80.0` graylist threshold, demonstrating that
/// scoring is wired end-to-end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::similar_names, clippy::too_many_lines)]
async fn adversarial_peer_publishing_invalid_messages_is_graylisted() {
    init_tracing();

    let key_a = identity::Keypair::generate_ed25519();
    let peer_a = PeerId::from(key_a.public());
    let (cmd_tx_a, cmd_rx_a) = mpsc::channel::<NetworkCommand>(64);
    let (event_tx_a, mut event_rx_a) = mpsc::channel::<NetworkEvent>(128);
    let mut svc_a = NetworkService::new(key_a, cmd_rx_a, event_tx_a).unwrap();

    let key_b = identity::Keypair::generate_ed25519();
    let peer_b = PeerId::from(key_b.public());
    let (cmd_tx_b, cmd_rx_b) = mpsc::channel::<NetworkCommand>(64);
    let (event_tx_b, mut event_rx_b) = mpsc::channel::<NetworkEvent>(128);
    let svc_b = NetworkService::new(key_b, cmd_rx_b, event_tx_b).unwrap();

    svc_a
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    tokio::spawn(svc_a.run());
    tokio::spawn(svc_b.run());

    let addr_a = next_listen_addr(&mut event_rx_a).await;
    cmd_tx_b.send(NetworkCommand::Dial(addr_a)).await.unwrap();

    // Both ends see the connection.
    wait_connected(&mut event_rx_a, peer_b, &mut event_rx_b, peer_a).await;

    // Subscribe both sides to the Blocks topic; wait for mesh GRAFT.
    cmd_tx_a
        .send(NetworkCommand::Subscribe(Topic::Blocks))
        .await
        .unwrap();
    cmd_tx_b
        .send(NetworkCommand::Subscribe(Topic::Blocks))
        .await
        .unwrap();
    tokio::time::sleep(TokDuration::from_millis(2_500)).await;

    // A publishes a payload that decodes to garbage at the
    // application level. With manual validation enabled, the
    // message stays "pending" until B reports a verdict.
    let garbage: Vec<u8> = (0u16..256)
        .map(|i| u8::try_from(i & 0xFF).expect("byte") ^ 0x5A)
        .collect();
    cmd_tx_a
        .send(NetworkCommand::Publish {
            topic: Topic::Blocks,
            data: garbage.clone(),
        })
        .await
        .unwrap();

    // B receives, simulates application-level rejection, and feeds
    // the verdict back into gossipsub.
    let (msg_id, source) = timeout(TokDuration::from_secs(10), async {
        loop {
            if let Some(NetworkEvent::GossipMessage {
                propagation_source,
                topic,
                data,
                message_id,
            }) = event_rx_b.recv().await
                && topic == Topic::Blocks
                && data == garbage
            {
                return (message_id, propagation_source);
            }
        }
    })
    .await
    .expect("B received A's garbage payload");
    assert_eq!(source, peer_a, "B must see A as the propagation source");
    cmd_tx_b
        .send(NetworkCommand::ReportGossipValidation {
            message_id: msg_id,
            propagation_source: source,
            acceptance: gossipsub::MessageAcceptance::Reject,
        })
        .await
        .unwrap();

    // Give the scorer one decay interval to apply the penalty.
    tokio::time::sleep(TokDuration::from_millis(1_500)).await;

    let (score_tx, score_rx) = oneshot::channel();
    cmd_tx_b
        .send(NetworkCommand::QueryPeerScores {
            response_tx: score_tx,
        })
        .await
        .unwrap();
    let scores = timeout(TokDuration::from_secs(2), score_rx)
        .await
        .expect("score response did not arrive")
        .expect("score channel was not dropped");

    let a_score = scores
        .iter()
        .find(|(p, _)| *p == peer_a)
        .map(|(_, s)| *s)
        .expect("B must have observed A in its score table");
    // Graylist threshold is -80; per-topic invalid weight is -160.
    // A single reject must therefore push A below the threshold.
    assert!(
        a_score <= -80.0,
        "B's view of A's score should be graylisted (<= -80), got {a_score}"
    );
}
