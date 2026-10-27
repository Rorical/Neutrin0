//! Real TCP checks for handshake and actor backpressure boundaries.

use super::test_support::{next_listen_addr, test_node};
use super::*;
use tokio::time::timeout;

#[tokio::test]
async fn all_admitted_identities_can_handshake_while_bulk_capacity_is_full() {
    let mut node = test_node(Keypair::generate_ed25519(), 8, 8);
    let mut held = Vec::new();
    let peers: Vec<_> = (0..64).map(|_| PeerId::random()).collect();
    for index in 0..72 {
        let request = if index < 6 {
            RpcRequest::TransactionInventory(rpc::TransactionInventoryRequest { after: None })
        } else if index < 8 {
            RpcRequest::ChunkProofById(rpc::ChunkProofByIdRequest {
                chunk_ids: vec![0],
                statement_keys: Vec::new(),
            })
        } else {
            RpcRequest::Status(rpc::Status::default())
        };
        let (reply, receive) = oneshot::channel();
        node.service.dispatch_outbound_request(
            peers[if index < 8 { index } else { index - 8 }],
            request,
            reply,
        );
        held.push(receive);
    }
    assert_eq!(node.service.rpc.pending_outbound.len(), 72);
    let (reply, mut receive) = oneshot::channel();
    node.service.dispatch_outbound_request(
        PeerId::random(),
        RpcRequest::Status(rpc::Status::default()),
        reply,
    );
    assert!(matches!(
        receive.try_recv().unwrap(),
        Err(RpcError::LocalOverloaded)
    ));
    assert!(held.iter_mut().all(|receive| receive.try_recv().is_err()));
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "Real TCP timeout attribution checks both actors after three delayed replies."
)]
async fn delayed_host_replies_do_not_quarantine_either_honest_peer() {
    async fn request(
        commands: &mpsc::Sender<NetworkCommand>,
        peer: PeerId,
        request: RpcRequest,
    ) -> oneshot::Receiver<Result<RpcResponse, RpcError>> {
        let (response_tx, receive) = oneshot::channel();
        commands
            .send(NetworkCommand::SendRpcRequest {
                peer,
                request,
                response_tx,
            })
            .await
            .unwrap();
        receive
    }
    let status = rpc::Status {
        chain_id: 17,
        chain_spec_hash: [3; 32],
        ..rpc::Status::default()
    };
    let mut server = test_node(Keypair::generate_ed25519(), 16, 16);
    server.service.require_chain(status);
    let server_peer = *server.service.local_peer_id();
    server
        .service
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let server_task = tokio::spawn(server.service.run());
    let address = next_listen_addr(&mut server.events).await;
    let mut client = test_node(Keypair::generate_ed25519(), 16, 16);
    client.service.require_chain(status);
    let client_peer = *client.service.local_peer_id();
    let client_task = tokio::spawn(client.service.run());
    client
        .commands
        .send(NetworkCommand::Dial(address))
        .await
        .unwrap();
    timeout(Duration::from_secs(5), async {
        loop {
            if matches!(client.events.recv().await, Some(NetworkEvent::PeerConnected(peer)) if peer == server_peer) { break; }
        }
    }).await.unwrap();
    assert_eq!(
        timeout(
            Duration::from_secs(5),
            request(&client.commands, server_peer, RpcRequest::Status(status)).await
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap(),
        RpcResponse::Status(status)
    );
    let mut pending = Vec::new();
    for value in [
        RpcRequest::Metadata(rpc::MetadataRequest),
        RpcRequest::TransactionInventory(rpc::TransactionInventoryRequest { after: None }),
        RpcRequest::SignedArtifactInventoryByChunk(rpc::SignedArtifactInventoryByChunkRequest {
            chunk_id: 0,
            after: None,
        }),
    ] {
        pending.push(request(&client.commands, server_peer, value).await);
        timeout(Duration::from_secs(5), async {
            loop {
                if matches!(
                    server.events.recv().await.unwrap(),
                    NetworkEvent::RpcRequestReceived { .. }
                ) {
                    break;
                }
            }
        })
        .await
        .unwrap();
    }
    // All requests decoded correctly. The host deliberately does not answer;
    // request deadlines therefore cannot attribute invalid bytes to either peer.
    for reply in pending {
        let result = timeout(Duration::from_secs(20), reply)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(result, Err(RpcError::Outbound(_))),
            "unexpected delayed reply: {result:?}"
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    for (commands, peer) in [
        (&client.commands, server_peer),
        (&server.commands, client_peer),
    ] {
        let ping = rpc::PingPayload { nonce: 42 };
        assert_eq!(
            timeout(
                Duration::from_secs(5),
                request(commands, peer, RpcRequest::Ping(ping)).await
            )
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
            RpcResponse::Ping(ping)
        );
    }
    server_task.abort();
    client_task.abort();
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One live peer retains concurrent repair, chain and control replies through delivery."
)]
async fn one_peer_can_reconcile_transactions_while_chain_and_control_requests_are_pending() {
    async fn queue(
        commands: &mpsc::Sender<NetworkCommand>,
        peer: PeerId,
        request: RpcRequest,
    ) -> oneshot::Receiver<Result<RpcResponse, RpcError>> {
        let (response_tx, received) = oneshot::channel();
        commands
            .send(NetworkCommand::SendRpcRequest {
                peer,
                request,
                response_tx,
            })
            .await
            .unwrap();
        received
    }
    let status = rpc::Status {
        chain_id: 17,
        chain_spec_hash: [3; 32],
        ..rpc::Status::default()
    };
    let mut server = test_node(Keypair::generate_ed25519(), 16, 16);
    server.service.require_chain(status);
    let peer = *server.service.local_peer_id();
    server
        .service
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let server_task = tokio::spawn(server.service.run());
    let address = next_listen_addr(&mut server.events).await;
    let mut client = test_node(Keypair::generate_ed25519(), 16, 16);
    let client_task = tokio::spawn(client.service.run());
    client
        .commands
        .send(NetworkCommand::Dial(address))
        .await
        .unwrap();
    timeout(Duration::from_secs(5), async {
        loop { if matches!(client.events.recv().await, Some(NetworkEvent::PeerConnected(observed)) if observed == peer) { break; } }
    }).await.unwrap();
    assert_eq!(
        timeout(
            Duration::from_secs(5),
            queue(&client.commands, peer, RpcRequest::Status(status)).await
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap(),
        RpcResponse::Status(status)
    );
    let mut pending = Vec::new();
    for request in [
        RpcRequest::SignedArtifactInventoryByChunk(rpc::SignedArtifactInventoryByChunkRequest {
            chunk_id: 0,
            after: None,
        }),
        RpcRequest::TransactionInventory(rpc::TransactionInventoryRequest { after: None }),
        RpcRequest::ChunkProofById(rpc::ChunkProofByIdRequest {
            chunk_ids: vec![0],
            statement_keys: Vec::new(),
        }),
        RpcRequest::BlocksByRange(rpc::BlocksByRangeRequest {
            head_block_hash: [0; 32],
            start_height: 1,
            count: 1,
        }),
        RpcRequest::Metadata(rpc::MetadataRequest),
    ] {
        let protocol = request.protocol();
        let reply = queue(&client.commands, peer, request).await;
        let id = timeout(Duration::from_secs(5), async {
            loop {
                if let NetworkEvent::RpcRequestReceived {
                    inbound_id,
                    request,
                    ..
                } = server.events.recv().await.unwrap()
                {
                    assert_eq!(request.protocol(), protocol);
                    break inbound_id;
                }
            }
        })
        .await
        .unwrap();
        pending.push((id, reply));
    }
    assert_eq!(pending.len(), 5);
    for (inbound_id, reply) in pending {
        server
            .commands
            .send(NetworkCommand::SendRpcResponse {
                inbound_id,
                response: RpcResponse::Error {
                    protocol: inbound_id.protocol,
                    error: rpc::RpcFailure::Unavailable("test complete".into()),
                },
            })
            .await
            .unwrap();
        assert!(matches!(
            timeout(Duration::from_secs(5), reply)
                .await
                .unwrap()
                .unwrap(),
            Err(RpcError::Remote(rpc::RpcFailure::Unavailable(_)))
        ));
    }
    server_task.abort();
    client_task.abort();
}

#[tokio::test]
async fn discovery_cannot_consume_reserved_chain_requests_or_control_capacity() {
    fn request(
        service: &mut NetworkService,
        value: RpcRequest,
    ) -> oneshot::Receiver<Result<RpcResponse, RpcError>> {
        let (send, receive) = oneshot::channel();
        let peer = PeerId::from(Keypair::generate_ed25519().public());
        service.dispatch_outbound_request(peer, value, send);
        receive
    }
    let mut node = test_node(Keypair::generate_ed25519(), 8, 8);
    let mut held = Vec::new();
    for _ in 0..6 {
        held.push(request(
            &mut node.service,
            RpcRequest::SignedArtifactById(rpc::SignedArtifactByIdRequest { id: [0; 32] }),
        ));
    }
    let mut denied = request(
        &mut node.service,
        RpcRequest::SignedArtifactById(rpc::SignedArtifactByIdRequest { id: [1; 32] }),
    );
    assert!(matches!(
        denied.try_recv().unwrap(),
        Err(RpcError::LocalOverloaded)
    ));
    for _ in 0..2 {
        held.push(request(
            &mut node.service,
            RpcRequest::ChunkProofById(rpc::ChunkProofByIdRequest {
                chunk_ids: vec![0],
                statement_keys: Vec::new(),
            }),
        ));
    }
    assert_eq!(node.service.rpc.pending_outbound.len(), 8);
    held.push(request(
        &mut node.service,
        RpcRequest::Status(rpc::Status::default()),
    ));
    assert_eq!(node.service.rpc.pending_outbound.len(), 9);
    // Two maximum-sized auxiliary candidate replies exhaust its byte share,
    // while a maximum-sized chain receipt must still be admitted.
    let mut node = test_node(Keypair::generate_ed25519(), 8, 8);
    for _ in 0..2 {
        held.push(request(
            &mut node.service,
            RpcRequest::CandidateByChunk(rpc::CandidateByChunkRequest {
                chunk_id: 0,
                chunk_hash: None,
            }),
        ));
    }
    let mut denied = request(
        &mut node.service,
        RpcRequest::CandidateByChunk(rpc::CandidateByChunkRequest {
            chunk_id: 0,
            chunk_hash: None,
        }),
    );
    assert!(matches!(
        denied.try_recv().unwrap(),
        Err(RpcError::LocalOverloaded)
    ));
    held.push(request(
        &mut node.service,
        RpcRequest::ChunkProofById(rpc::ChunkProofByIdRequest {
            chunk_ids: vec![0],
            statement_keys: Vec::new(),
        }),
    ));
    assert_eq!(node.service.rpc.pending_outbound.len(), 3);
    assert_eq!(held.len(), 12);
}

#[tokio::test]
async fn full_host_mailbox_does_not_block_status_or_network_commands() {
    let mut server = test_node(Keypair::generate_ed25519(), 8, 1);
    let status = rpc::Status {
        chain_id: 17,
        chain_spec_hash: [3; 32],
        ..rpc::Status::default()
    };
    server.service.require_chain(status);
    let peer = *server.service.local_peer_id();
    let filler = server.service.event_tx.clone();
    server
        .service
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let server_task = tokio::spawn(server.service.run());
    let address = next_listen_addr(&mut server.events).await;
    filler
        .send(NetworkEvent::NewListenAddr(address.clone()))
        .await
        .unwrap();
    let mut client = test_node(Keypair::generate_ed25519(), 8, 8);
    let client_task = tokio::spawn(client.service.run());
    client
        .commands
        .send(NetworkCommand::Dial(address))
        .await
        .unwrap();
    timeout(Duration::from_secs(5), async {
        loop { if matches!(client.events.recv().await, Some(NetworkEvent::PeerConnected(observed)) if observed == peer) { break; } }
    }).await.unwrap();
    let (reply, received) = oneshot::channel();
    client
        .commands
        .send(NetworkCommand::SendRpcRequest {
            peer,
            request: RpcRequest::Status(status),
            response_tx: reply,
        })
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(5), received)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        RpcResponse::Status(status)
    );
    // A bulk request cannot wait on the host mailbox or consume the control slot.
    let (reply, received) = oneshot::channel();
    client
        .commands
        .send(NetworkCommand::SendRpcRequest {
            peer,
            request: RpcRequest::TransactionInventory(rpc::TransactionInventoryRequest {
                after: None,
            }),
            response_tx: reply,
        })
        .await
        .unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(5), received)
            .await
            .unwrap()
            .unwrap(),
        Err(RpcError::Remote(rpc::RpcFailure::Unavailable(_)))
    ));
    let (reply, received) = oneshot::channel();
    server
        .commands
        .send(NetworkCommand::QueryPeerScores { response_tx: reply })
        .await
        .unwrap();
    timeout(Duration::from_secs(2), received)
        .await
        .unwrap()
        .unwrap();
    assert!(!server_task.is_finished());
    server_task.abort();
    client_task.abort();
}

#[tokio::test]
async fn same_numeric_chain_with_different_spec_is_disconnected_before_bulk_admission() {
    let mut server = test_node(Keypair::generate_ed25519(), 8, 8);
    let status = rpc::Status {
        chain_id: 17,
        chain_spec_hash: [3; 32],
        ..rpc::Status::default()
    };
    server.service.require_chain(status);
    let peer = *server.service.local_peer_id();
    server
        .service
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let server_task = tokio::spawn(server.service.run());
    let address = next_listen_addr(&mut server.events).await;
    let mut client = test_node(Keypair::generate_ed25519(), 8, 8);
    let client_task = tokio::spawn(client.service.run());
    client
        .commands
        .send(NetworkCommand::Dial(address))
        .await
        .unwrap();
    timeout(Duration::from_secs(5), async {
        loop { if matches!(client.events.recv().await, Some(NetworkEvent::PeerConnected(observed)) if observed == peer) { break; } }
    }).await.unwrap();
    let (reply, received) = oneshot::channel();
    client
        .commands
        .send(NetworkCommand::SendRpcRequest {
            peer,
            request: RpcRequest::Status(rpc::Status {
                chain_spec_hash: [4; 32],
                ..status
            }),
            response_tx: reply,
        })
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_secs(5), received)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                server.events.recv().await,
                Some(NetworkEvent::PeerDisconnected(_))
            ) {
                break;
            }
        }
    })
    .await
    .unwrap();
    server_task.abort();
    client_task.abort();
}
