//! Transport fixtures never authorize production consensus or proof acceptance.
use super::*;
use neutrin0_consensus_types::{
    FinalityVotePhase, NilVote, NilVoteData,
    signed_artifacts::{
        SignedArtifact, SignedArtifactInventory, SignedArtifactKind, SignedArtifactRef,
    },
};
use neutrin0_network::{
    Topic,
    rpc::{RpcError, SignedArtifactByIdResponse},
};

type Reply = tokio::sync::oneshot::Sender<Result<RpcResponse, RpcError>>;
struct Harness {
    backend: MockBackend,
    events: mpsc::Sender<NetworkEvent>,
    commands: mpsc::Receiver<NetworkCommand>,
    runner: tokio::task::JoinHandle<()>,
}
impl Harness {
    fn new() -> Self {
        let backend = MockBackend::default();
        backend.inner.lock().unwrap().availability_enabled = true;
        let (command_tx, commands) = mpsc::channel(64);
        let (events, event_rx) = mpsc::channel(64);
        let driver = SyncDriver::new(
            SyncDriverConfig::default(),
            Arc::new(backend.clone()),
            LocalProgress::default(),
            command_tx,
            event_rx,
        );
        Self {
            backend,
            events,
            commands,
            runner: tokio::spawn(driver.run()),
        }
    }
    async fn connect(&mut self, peer: PeerId) {
        self.events
            .send(NetworkEvent::PeerConnected(peer))
            .await
            .unwrap();
        let (_, request, reply) = self.rpc().await;
        assert!(matches!(request, RpcRequest::Status(_)));
        // Keep source discovery deterministic: these tests explicitly advertise
        // sources rather than mixing the unrelated status sync protocol.
        reply
            .send(Err(RpcError::Outbound("test handshake deferred".into())))
            .unwrap();
    }
    async fn rpc(&mut self) -> (PeerId, RpcRequest, Reply) {
        loop {
            match timeout(Duration::from_secs(30), self.commands.recv())
                .await
                .unwrap()
                .unwrap()
            {
                NetworkCommand::SendRpcRequest {
                    peer,
                    request,
                    response_tx,
                } => return (peer, request, response_tx),
                NetworkCommand::ReportGossipValidation { .. } => {}
                other => panic!("unexpected network command: {other:?}"),
            }
        }
    }
    async fn notice(&self, peer: PeerId, chunk_id: u64, entries: Vec<SignedArtifactRef>) {
        self.events
            .send(NetworkEvent::GossipMessage {
                propagation_source: peer,
                topic: Topic::SignedArtifacts,
                data: borsh::to_vec(&SignedArtifactInventory {
                    chunk_id,
                    entries,
                    next: None,
                })
                .unwrap(),
                message_id: neutrin0_network::libp2p::gossipsub::MessageId::from("source-notice"),
            })
            .await
            .unwrap();
    }
    async fn imported(&self) {
        timeout(
            Duration::from_secs(1),
            self.backend.availability_notified.notified(),
        )
        .await
        .unwrap();
    }
    async fn stop(self) {
        drop(self.events);
        self.runner.await.unwrap();
    }
}
fn source(chunk_id: u64, round: u32) -> SignedArtifact {
    SignedArtifact::NilVote(NilVote {
        data: NilVoteData {
            chunk_id,
            round,
            phase: FinalityVotePhase::Prevote,
        },
        aggregation_bits: neutrin0_primitives::BitVec::from_bytes(1, vec![1]).unwrap(),
        signature: [0; 96],
        attestations: Vec::new(),
    })
}
fn response(artifact: SignedArtifact) -> RpcResponse {
    RpcResponse::SignedArtifactById(Box::new(SignedArtifactByIdResponse { artifact }))
}

#[tokio::test(start_paused = true)]
async fn gossip_inventory_fetches_exact_original_source_through_rpc() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    let original = source(0, 0);
    harness.notice(peer, 0, vec![original.reference()]).await;
    let (provider, request, reply) = harness.rpc().await;
    assert_eq!(provider, peer);
    assert!(
        matches!(request, RpcRequest::SignedArtifactById(request) if request.id == original.id())
    );
    reply.send(Ok(response(original.clone()))).unwrap();
    harness.imported().await;
    assert_eq!(
        harness.backend.inner.lock().unwrap().availability_sources,
        vec![original]
    );
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn exact_source_retrieval_retries_a_different_available_provider() {
    let mut harness = Harness::new();
    let first = random_peer();
    let second = random_peer();
    harness.connect(first).await;
    harness.connect(second).await;
    let original = source(0, 0);
    harness.notice(first, 0, vec![original.reference()]).await;
    let (_, _, unavailable) = harness.rpc().await;
    harness.notice(second, 0, vec![original.reference()]).await;
    unavailable
        .send(Err(RpcError::Outbound(
            "provider lost original bytes".into(),
        )))
        .unwrap();
    let (provider, request, reply) = harness.rpc().await;
    assert_eq!(provider, second);
    assert!(
        matches!(request, RpcRequest::SignedArtifactById(request) if request.id == original.id())
    );
    reply.send(Ok(response(original.clone()))).unwrap();
    harness.imported().await;
    assert_eq!(
        harness.backend.inner.lock().unwrap().availability_sources,
        vec![original]
    );
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn stale_exact_source_callback_cannot_finish_reconnected_request() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    let original = source(0, 0);
    harness.notice(peer, 0, vec![original.reference()]).await;
    let (_, _, old) = harness.rpc().await;
    harness
        .events
        .send(NetworkEvent::PeerDisconnected(peer))
        .await
        .unwrap();
    harness.connect(peer).await;
    harness.notice(peer, 0, vec![original.reference()]).await;
    let (_, _, current) = harness.rpc().await;
    old.send(Ok(response(original.clone()))).unwrap();
    current.send(Ok(response(original.clone()))).unwrap();
    harness.imported().await;
    tokio::task::yield_now().await;
    assert_eq!(
        harness.backend.inner.lock().unwrap().availability_sources,
        vec![original]
    );
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn wrong_identity_kind_and_source_are_rejected_before_backend_ingestion() {
    for case in 0..3 {
        let mut harness = Harness::new();
        let peer = random_peer();
        harness.connect(peer).await;
        let original = source(u64::from(case == 2), 0);
        let mut reference = original.reference();
        if case == 1 {
            reference.kind = SignedArtifactKind::Vote;
        }
        harness.notice(peer, 0, vec![reference]).await;
        let (_, _, reply) = harness.rpc().await;
        let returned = if case == 0 { source(0, 1) } else { original };
        reply.send(Ok(response(returned))).unwrap();
        assert!(
            timeout(
                Duration::from_secs(1),
                harness.backend.availability_notified.notified()
            )
            .await
            .is_err()
        );
        assert_eq!(
            harness.backend.inner.lock().unwrap().availability_sources,
            Vec::<SignedArtifact>::new()
        );
        harness.stop().await;
    }
}

#[tokio::test(start_paused = true)]
async fn exact_proof_identity_cannot_complete_another_chunks_inventory_query() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    let mislabeled = SignedArtifact::BlockProof(sample_block_proof(2));
    harness.notice(peer, 0, vec![mislabeled.reference()]).await;
    let (_, _, reply) = harness.rpc().await;
    reply.send(Ok(response(mislabeled))).unwrap();
    assert!(
        timeout(
            Duration::from_secs(1),
            harness.backend.availability_notified.notified()
        )
        .await
        .is_err()
    );
    assert_eq!(
        harness.backend.inner.lock().unwrap().availability_sources,
        Vec::<SignedArtifact>::new()
    );

    let correct = SignedArtifact::BlockProof(sample_block_proof(1));
    harness.notice(peer, 0, vec![correct.reference()]).await;
    let (_, request, reply) = harness.rpc().await;
    assert!(
        matches!(request, RpcRequest::SignedArtifactById(request) if request.id == correct.id())
    );
    reply.send(Ok(response(correct.clone()))).unwrap();
    harness.imported().await;
    assert_eq!(
        harness.backend.inner.lock().unwrap().availability_sources,
        vec![correct]
    );
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn future_inventory_cannot_displace_authenticated_source_jobs() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    for round in 0..160 {
        harness
            .notice(peer, u64::MAX, vec![source(u64::MAX, round).reference()])
            .await;
        let _ = timeout(Duration::from_secs(1), harness.commands.recv())
            .await
            .unwrap()
            .unwrap();
    }
    let original = source(0, 0);
    harness.notice(peer, 0, vec![original.reference()]).await;
    let (_, request, reply) = harness.rpc().await;
    assert!(
        matches!(request, RpcRequest::SignedArtifactById(request) if request.id == original.id())
    );
    reply.send(Ok(response(original))).unwrap();
    harness.imported().await;
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn bounded_source_cache_deferral_does_not_consume_live_vote_delivery() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    harness.backend.inner.lock().unwrap().availability_deferred = true;
    let original = source(0, 0);
    harness.notice(peer, 0, vec![original.reference()]).await;
    let (_, _, reply) = harness.rpc().await;
    reply.send(Ok(response(original))).unwrap();
    let mut vote = sample_finality_vote(0);
    vote.data.phase = FinalityVotePhase::Prevote;
    harness
        .events
        .send(NetworkEvent::GossipMessage {
            propagation_source: peer,
            topic: Topic::FinalityVotesPrevote,
            data: borsh::to_vec(&neutrin0_consensus_types::BftVote::Value(vote)).unwrap(),
            message_id: neutrin0_network::libp2p::gossipsub::MessageId::from("live-vote"),
        })
        .await
        .unwrap();
    // The gossip validation response is emitted only after ordinary vote delivery.
    loop {
        let command = timeout(Duration::from_secs(1), harness.commands.recv())
            .await
            .unwrap()
            .unwrap();
        if matches!(command, NetworkCommand::ReportGossipValidation { message_id, .. } if message_id == neutrin0_network::libp2p::gossipsub::MessageId::from("live-vote"))
        {
            break;
        }
    }
    assert_eq!(harness.backend.finality_vote_count(), 1);
    assert_eq!(
        harness.backend.inner.lock().unwrap().availability_sources,
        Vec::<SignedArtifact>::new()
    );
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn authenticated_status_recovers_paginated_inventory_and_exact_sources() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness
        .events
        .send(NetworkEvent::PeerConnected(peer))
        .await
        .unwrap();
    let (_, _, status) = harness.rpc().await;
    status
        .send(Ok(RpcResponse::Status(Status::default())))
        .unwrap();
    let (_, request, page) = harness.rpc().await;
    assert!(
        matches!(request, RpcRequest::SignedArtifactInventoryByChunk(request) if request.chunk_id == 0 && request.after.is_none())
    );
    let mut originals = [source(0, 0), source(0, 1)];
    originals.sort_by_key(SignedArtifact::id);
    page.send(Ok(RpcResponse::SignedArtifactInventoryByChunk(Box::new(
        SignedArtifactInventory {
            chunk_id: 0,
            entries: vec![originals[0].reference()],
            next: Some(originals[0].id()),
        },
    ))))
    .unwrap();
    for _ in 0..3 {
        let (_, request, reply) = harness.rpc().await;
        match request {
            RpcRequest::SignedArtifactInventoryByChunk(request) => {
                assert_eq!(request.after, Some(originals[0].id()));
                reply
                    .send(Ok(RpcResponse::SignedArtifactInventoryByChunk(Box::new(
                        SignedArtifactInventory {
                            chunk_id: 0,
                            entries: vec![originals[1].reference()],
                            next: None,
                        },
                    ))))
                    .unwrap();
            }
            RpcRequest::SignedArtifactById(request) => {
                let original = originals
                    .iter()
                    .find(|artifact| artifact.id() == request.id)
                    .unwrap()
                    .clone();
                reply.send(Ok(response(original))).unwrap();
            }
            other => panic!("unexpected source query: {other:?}"),
        }
    }
    loop {
        if harness
            .backend
            .inner
            .lock()
            .unwrap()
            .availability_sources
            .len()
            == 2
        {
            break;
        }
        harness.imported().await;
    }
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn full_inventory_pages_resume_after_bounded_provider_queue_backpressure() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness
        .events
        .send(NetworkEvent::PeerConnected(peer))
        .await
        .unwrap();
    let (_, _, status) = harness.rpc().await;
    status
        .send(Ok(RpcResponse::Status(Status::default())))
        .unwrap();
    let mut originals: Vec<_> = (0..40).map(|round| source(0, round)).collect();
    originals.sort_by_key(SignedArtifact::id);
    let mut imported = 0;
    let mut repeated_page = false;
    let mut first_pages = 0;
    while imported < originals.len() {
        let (_, query, reply) = harness.rpc().await;
        match query {
            RpcRequest::SignedArtifactInventoryByChunk(query) => {
                if query.after.is_none() {
                    first_pages += 1;
                    repeated_page |= first_pages > 1;
                }
                let remaining: Vec<_> = originals
                    .iter()
                    .filter(|artifact| query.after.is_none_or(|after| artifact.id() > after))
                    .map(SignedArtifact::reference)
                    .collect();
                let entries: Vec<_> = remaining.iter().copied().take(32).collect();
                let next = (remaining.len() > entries.len()).then(|| entries.last().unwrap().id);
                reply
                    .send(Ok(RpcResponse::SignedArtifactInventoryByChunk(Box::new(
                        SignedArtifactInventory {
                            chunk_id: 0,
                            entries,
                            next,
                        },
                    ))))
                    .unwrap();
            }
            RpcRequest::SignedArtifactById(query) => {
                let original = originals
                    .iter()
                    .find(|artifact| artifact.id() == query.id)
                    .unwrap()
                    .clone();
                reply.send(Ok(response(original))).unwrap();
                harness.imported().await;
                imported += 1;
            }
            other => panic!("unexpected availability query: {other:?}"),
        }
    }
    assert!(
        repeated_page,
        "a full page must survive local provider backpressure"
    );
    assert_eq!(
        harness
            .backend
            .inner
            .lock()
            .unwrap()
            .availability_sources
            .len(),
        40
    );
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn inventory_page_cannot_reuse_or_regress_the_exclusive_cursor() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness
        .events
        .send(NetworkEvent::PeerConnected(peer))
        .await
        .unwrap();
    let (_, _, status) = harness.rpc().await;
    status
        .send(Ok(RpcResponse::Status(Status::default())))
        .unwrap();
    let (_, _, first_page) = harness.rpc().await;
    let original = source(0, 0);
    first_page
        .send(Ok(RpcResponse::SignedArtifactInventoryByChunk(Box::new(
            SignedArtifactInventory {
                chunk_id: 0,
                entries: vec![original.reference()],
                next: Some(original.id()),
            },
        ))))
        .unwrap();
    for _ in 0..2 {
        let (_, query, reply) = harness.rpc().await;
        match query {
            RpcRequest::SignedArtifactInventoryByChunk(_) => {
                // The returned identity is exactly equal to the exclusive cursor.
                reply
                    .send(Ok(RpcResponse::SignedArtifactInventoryByChunk(Box::new(
                        SignedArtifactInventory {
                            chunk_id: 0,
                            entries: vec![original.reference()],
                            next: Some(original.id()),
                        },
                    ))))
                    .unwrap();
            }
            RpcRequest::SignedArtifactById(_) => {
                reply.send(Ok(response(original.clone()))).unwrap();
            }
            other => panic!("unexpected source query: {other:?}"),
        }
    }
    harness.imported().await;
    assert_eq!(
        harness
            .backend
            .inner
            .lock()
            .unwrap()
            .availability_sources
            .len(),
        1
    );
    harness.stop().await;
}
