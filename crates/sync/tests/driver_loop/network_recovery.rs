use super::*;
use neutrin0_network::{
    Topic,
    libp2p::gossipsub::{MessageAcceptance, MessageId},
};

#[tokio::test(start_paused = true)]
async fn every_admitted_peer_gets_an_initial_handshake_without_waiting_for_other_replies() {
    let (commands_tx, mut commands) = mpsc::channel(128);
    let (events, events_rx) = mpsc::channel(128);
    let runner = tokio::spawn(
        SyncDriver::new(
            SyncDriverConfig::default(),
            Arc::new(MockBackend::default()),
            LocalProgress::default(),
            commands_tx,
            events_rx,
        )
        .run(),
    );
    let mut held = Vec::new();
    for _ in 0..64 {
        let peer = random_peer();
        events
            .send(NetworkEvent::PeerConnected(peer))
            .await
            .unwrap();
        let command = timeout(Duration::from_secs(1), commands.recv())
            .await
            .unwrap()
            .unwrap();
        let NetworkCommand::SendRpcRequest {
            peer: observed,
            request,
            response_tx,
        } = command
        else {
            panic!("missing initial handshake")
        };
        assert_eq!(observed, peer);
        assert!(matches!(request, RpcRequest::Status(_)));
        held.push(response_tx);
    }
    assert_eq!(held.len(), 64);
    drop(held);
    drop(events);
    runner.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn unavailable_proposal_context_is_neutral_but_bad_current_signature_is_rejected() {
    let backend = MockBackend::default();
    backend.inner.lock().unwrap().bft_sync = true;
    let (commands_tx, mut commands) = mpsc::channel(32);
    let (events, events_rx) = mpsc::channel(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend.clone()),
        LocalProgress::default(),
        commands_tx,
        events_rx,
    );
    let runner = tokio::spawn(driver.run());
    for (source, expected) in [
        (1, MessageAcceptance::Ignore),
        (0, MessageAcceptance::Reject),
    ] {
        let proposal = sample_chunk_proof(source, 1).finality_cert.proposal;
        events
            .send(NetworkEvent::GossipMessage {
                propagation_source: random_peer(),
                topic: Topic::BftMessages,
                data: borsh::to_vec(&neutrin0_consensus_types::BftMessage::Proposal(Box::new(
                    proposal,
                )))
                .unwrap(),
                message_id: MessageId::from(vec![u8::try_from(source).unwrap()]),
            })
            .await
            .unwrap();
        let NetworkCommand::ReportGossipValidation { acceptance, .. } =
            commands.recv().await.unwrap()
        else {
            panic!("missing proposal verdict")
        };
        assert_eq!(acceptance, expected);
    }
    assert_eq!(
        backend.inner.lock().unwrap().bft_messages,
        Vec::<neutrin0_consensus_types::BftMessage>::new()
    );
    drop(events);
    runner.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn full_node_retries_status_before_any_handshake_has_succeeded() {
    let backend = MockBackend::default();
    backend.inner.lock().unwrap().full_chunk_size = Some(1);
    let (commands_tx, mut commands) = mpsc::channel(64);
    let (events, events_rx) = mpsc::channel(64);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend),
        LocalProgress::default(),
        commands_tx,
        events_rx,
    );
    let runner = tokio::spawn(driver.run());
    events
        .send(NetworkEvent::PeerConnected(random_peer()))
        .await
        .unwrap();
    let (request, reply) = next_full_sync_request(&mut commands).await;
    assert!(matches!(request, RpcRequest::Status(_)));
    reply
        .send(Err(neutrin0_network::rpc::RpcError::Outbound(
            "withheld handshake".into(),
        )))
        .unwrap();
    let (request, reply) = next_full_sync_request(&mut commands).await;
    assert!(matches!(request, RpcRequest::Status(_)));
    reply
        .send(Ok(RpcResponse::Status(Status::default())))
        .unwrap();
    drop(events);
    runner.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn four_withheld_status_replies_do_not_reserve_all_bulk_response_bytes() {
    let (commands_tx, mut commands) = mpsc::channel(32);
    let (events, events_rx) = mpsc::channel(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(MockBackend::default()),
        LocalProgress::default(),
        commands_tx,
        events_rx,
    );
    let runner = tokio::spawn(driver.run());
    let mut held = Vec::new();
    for _ in 0..5 {
        let peer = random_peer();
        events
            .send(NetworkEvent::PeerConnected(peer))
            .await
            .unwrap();
        let command = timeout(Duration::from_secs(1), commands.recv())
            .await
            .unwrap()
            .unwrap();
        let NetworkCommand::SendRpcRequest {
            peer: owner,
            request,
            response_tx,
        } = command
        else {
            panic!("missing handshake")
        };
        assert_eq!(owner, peer);
        assert!(matches!(request, RpcRequest::Status(_)));
        held.push(response_tx);
    }
    drop(held);
    drop(events);
    runner.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn full_sync_keeps_status_reconciliation_alive_while_a_data_reply_is_pending() {
    let backend = MockBackend::default();
    backend.inner.lock().unwrap().full_chunk_size = Some(1);
    let (commands_tx, mut commands) = mpsc::channel(64);
    let (events, events_rx) = mpsc::channel(64);
    let runner = tokio::spawn(
        SyncDriver::new(
            SyncDriverConfig::default(),
            Arc::new(backend),
            LocalProgress::default(),
            commands_tx,
            events_rx,
        )
        .run(),
    );
    events
        .send(NetworkEvent::PeerConnected(random_peer()))
        .await
        .unwrap();
    let (request, reply) = next_full_sync_request(&mut commands).await;
    assert!(matches!(request, RpcRequest::Status(_)));
    let status = Status {
        head_height: 1,
        head_block_hash: [1; 32],
        ..Status::default()
    };
    reply.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, held) = next_full_sync_request(&mut commands).await;
    assert!(matches!(request, RpcRequest::BlocksByRange(_)));
    let (request, reply) = next_full_sync_request(&mut commands).await;
    assert!(matches!(request, RpcRequest::Status(_)));
    reply.send(Ok(RpcResponse::Status(status))).unwrap();
    drop(held);
    runner.abort();
    assert!(runner.await.unwrap_err().is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn local_rpc_pressure_does_not_cool_down_an_available_chain_provider() {
    let backend = MockBackend::default();
    backend.inner.lock().unwrap().full_chunk_size = Some(1);
    let (commands_tx, mut commands) = mpsc::channel(64);
    let (events, events_rx) = mpsc::channel(64);
    let runner = tokio::spawn(
        SyncDriver::new(
            SyncDriverConfig::default(),
            Arc::new(backend),
            LocalProgress::default(),
            commands_tx,
            events_rx,
        )
        .run(),
    );
    events
        .send(NetworkEvent::PeerConnected(random_peer()))
        .await
        .unwrap();
    let (_, reply) = next_full_sync_request(&mut commands).await;
    let status = Status {
        head_height: 1,
        head_block_hash: [1; 32],
        ..Status::default()
    };
    reply.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, reply) = next_full_sync_request(&mut commands).await;
    assert!(matches!(request, RpcRequest::BlocksByRange(_)));
    reply
        .send(Err(neutrin0_network::rpc::RpcError::LocalOverloaded))
        .unwrap();
    let (request, reply) = next_full_sync_request(&mut commands).await;
    assert!(matches!(request, RpcRequest::Status(_)));
    reply.send(Ok(RpcResponse::Status(status))).unwrap();
    let (request, held) = next_full_sync_request(&mut commands).await;
    assert!(matches!(request, RpcRequest::BlocksByRange(range) if range.start_height == 1));
    drop(held);
    runner.abort();
    assert!(runner.await.unwrap_err().is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn backend_semantic_verdict_reaches_gossip_scoring_for_every_admission_path() {
    let backend = MockBackend::default();
    let (commands_tx, mut commands) = mpsc::channel(32);
    let (events, events_rx) = mpsc::channel(32);
    let driver = SyncDriver::new(
        SyncDriverConfig::default(),
        Arc::new(backend.clone()),
        LocalProgress::default(),
        commands_tx,
        events_rx,
    );
    let runner = tokio::spawn(driver.run());
    let vote = borsh::to_vec(&neutrin0_consensus_types::BftVote::Value(
        sample_finality_vote(0),
    ))
    .unwrap();
    for error in [
        SyncBackendError::Rejected("invalid signature".into()),
        SyncBackendError::NotAvailable("state or policy".into()),
    ] {
        backend.inner.lock().unwrap().admission_error = Some(error.clone());
        for (topic, data) in [
            (
                Topic::Transactions,
                borsh::to_vec(&neutrin0_network::rpc::TransactionAnnouncement {
                    runtime: [0; 32],
                    transaction: neutrin0_primitives::BoundedBytes::new(vec![42]).unwrap(),
                })
                .unwrap(),
            ),
            (Topic::FinalityVotesPrevote, vote.clone()),
            (Topic::AggregateFinalityVotes(0), vote.clone()),
            (
                Topic::SlashingEvidence,
                borsh::to_vec(&sample_slashing_evidence()).unwrap(),
            ),
        ] {
            events
                .send(NetworkEvent::GossipMessage {
                    propagation_source: random_peer(),
                    topic,
                    data,
                    message_id: MessageId::from(vec![1]),
                })
                .await
                .unwrap();
            let NetworkCommand::ReportGossipValidation { acceptance, .. } =
                commands.recv().await.unwrap()
            else {
                panic!("missing verdict")
            };
            assert_eq!(
                acceptance,
                if matches!(error, SyncBackendError::Rejected(_)) {
                    MessageAcceptance::Reject
                } else {
                    MessageAcceptance::Ignore
                }
            );
        }
    }
    drop(events);
    runner.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn lost_history_notice_recovers_the_same_anchored_range_after_cooldown() {
    let mut pending = PendingLightRange::new().await;
    pending.unavailable();
    pending.assert_quiescent().await;
    tokio::time::advance(Duration::from_secs(31)).await;
    loop {
        let (_, request, response) = pending.next_request().await;
        match request {
            RpcRequest::Status(_) => {
                let _ = response.send(Ok(RpcResponse::Status(pending.status)));
            }
            RpcRequest::HistoryProof(request) => {
                // The opening asked for is of the client's own endpoint.
                assert_eq!(request.anchor_chunks, 1);
                assert_eq!(
                    request.checkpoint_hash,
                    pending.proof.end_checkpoint().hash()
                );
                response.send(Ok(history_reply(&pending.proof))).unwrap();
                break;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    tokio::task::yield_now().await;
    assert_eq!(pending.backend.rpc_calls(), vec!["history_import"]);
    pending.stop().await;
}
