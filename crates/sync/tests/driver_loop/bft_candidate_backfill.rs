//! Transport regressions; node/engine tests authenticate the actual BLS and receipts.

use super::*;
use neutrin0_consensus_types::{BftCandidate, Chunk, FinalityVoteData, FinalityVotePhase};
use neutrin0_network::{Topic, rpc::CandidateByChunkResponse};

type Reply = tokio::sync::oneshot::Sender<Result<RpcResponse, neutrin0_network::rpc::RpcError>>;

fn branch_blocks(slot_offset: u64) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut parent = [0; 32];
    for height in 1..=20 {
        let mut block = sample_block(height, height + slot_offset);
        block.header.parent_hash = parent;
        parent = block.hash();
        blocks.push(block);
    }
    blocks
}

// Shared with sibling test modules without exporting from the test crate.
#[allow(clippy::redundant_pub_crate)]
pub(super) struct Harness {
    pub(super) backend: MockBackend,
    pub(super) events: mpsc::Sender<NetworkEvent>,
    commands: mpsc::Receiver<NetworkCommand>,
    deferred: std::collections::VecDeque<(PeerId, RpcRequest, Reply)>,
    /// Per-peer `Status` the harness advertises. Every reply path reads the
    /// same entry so a refreshed peer never flaps back to the default status,
    /// which would reset the driver's canonical cursor.
    statuses: std::collections::BTreeMap<PeerId, Status>,
    runner: tokio::task::JoinHandle<()>,
    blocks: Vec<Block>,
    pub(super) candidate: BftCandidate,
}

impl Harness {
    pub(super) fn new() -> Self {
        Self::with_head_height(0)
    }

    fn with_head_height(head_height: u64) -> Self {
        let backend = MockBackend::default();
        {
            let mut state = backend.inner.lock().unwrap();
            state.full_chunk_size = Some(20);
            state.candidate_sync = true;
            state.status.chain_id = 1;
            state.status.head_height = head_height;
        }
        let blocks = branch_blocks(0);
        let parent = blocks.last().unwrap().hash();
        let candidate = BftCandidate {
            round: 0,
            justification: None,
            selection: None,
            chunk: Chunk {
                next_identity_sanctions_root: [0; 32],

                chunk_id: 0,
                start_height: 1,
                end_height: 20,
                start_state_root: [0; 32],
                end_state_root: [1; 32],
                start_block_hash: blocks[0].hash(),
                end_block_hash: parent,
                block_hash_root: [2; 32],
                block_proof_root: [3; 32],
                vrf_proof_root: [4; 32],
                active_validator_set_root: [5; 32],
                next_validator_set_root: [5; 32],
                da_root: [6; 32],
            },
        };
        let progress = LocalProgress {
            chain_id: 1,
            head_height,
            head_block_hash: if head_height == 0 {
                [0; 32]
            } else {
                branch_blocks(100).last().unwrap().hash()
            },
            head_slot: if head_height == 0 {
                0
            } else {
                head_height + 100
            },
            proven_height: head_height,
            ..LocalProgress::default()
        };
        if head_height > 0 {
            let mut state = backend.inner.lock().unwrap();
            state.local_progress_override = Some(progress);
            state.status.head_block_hash = progress.head_block_hash;
            state.status.head_slot = progress.head_slot;
            state.proven_height = head_height;
        }
        let (command_tx, commands) = mpsc::channel(64);
        let (events, event_rx) = mpsc::channel(64);
        let driver = SyncDriver::new(
            SyncDriverConfig::default(),
            Arc::new(backend.clone()),
            progress,
            command_tx,
            event_rx,
        );
        Self {
            backend,
            events,
            commands,
            deferred: std::collections::VecDeque::new(),
            statuses: std::collections::BTreeMap::new(),
            runner: tokio::spawn(driver.run()),
            blocks,
            candidate,
        }
    }

    async fn raw_request(&mut self) -> (PeerId, RpcRequest, Reply) {
        if let Some(request) = self.deferred.pop_front() {
            return request;
        }
        loop {
            match timeout(Duration::from_secs(1), self.commands.recv())
                .await
                .unwrap()
                .unwrap()
            {
                NetworkCommand::SendRpcRequest {
                    peer,
                    request,
                    response_tx,
                } => return (peer, request, response_tx),
                NetworkCommand::Subscribe(_) | NetworkCommand::ReportGossipValidation { .. } => {}
                other => panic!("unexpected command {other:?}"),
            }
        }
    }

    fn status_for(&self, peer: &PeerId) -> Status {
        self.statuses.get(peer).copied().unwrap_or_else(|| Status {
            chain_id: 1,
            ..Status::default()
        })
    }

    pub(super) async fn request(&mut self) -> (PeerId, RpcRequest, Reply) {
        loop {
            let (peer, request, reply) = self.raw_request().await;
            if matches!(request, RpcRequest::Status(_)) {
                reply
                    .send(Ok(RpcResponse::Status(self.status_for(&peer))))
                    .unwrap();
            } else {
                return (peer, request, reply);
            }
        }
    }

    pub(super) async fn connect(&mut self, peer: PeerId) {
        self.events
            .send(NetworkEvent::PeerConnected(peer))
            .await
            .unwrap();
        let (owner, request, reply) = self.raw_request().await;
        assert_eq!(owner, peer);
        assert!(matches!(request, RpcRequest::Status(_)));
        // No ordinary canonical backfill is needed. The candidate is a different availability path.
        reply
            .send(Ok(RpcResponse::Status(self.status_for(&peer))))
            .unwrap();
    }

    pub(super) async fn gossip(&mut self, peer: PeerId, topic: Topic, data: Vec<u8>) {
        self.events
            .send(NetworkEvent::GossipMessage {
                topic,
                data,
                propagation_source: peer,
                message_id: neutrin0_network::libp2p::gossipsub::MessageId::from(
                    b"candidate".to_vec(),
                ),
            })
            .await
            .unwrap();
        loop {
            match timeout(Duration::from_secs(1), self.commands.recv())
                .await
                .unwrap()
                .unwrap()
            {
                NetworkCommand::ReportGossipValidation { .. } => break,
                NetworkCommand::Subscribe(_) => {}
                NetworkCommand::SendRpcRequest {
                    peer,
                    request: RpcRequest::Status(_),
                    response_tx,
                } => {
                    response_tx
                        .send(Ok(RpcResponse::Status(self.status_for(&peer))))
                        .unwrap();
                }
                NetworkCommand::SendRpcRequest {
                    peer,
                    request,
                    response_tx,
                } => self.deferred.push_back((peer, request, response_tx)),
                other => panic!("unexpected gossip barrier command {other:?}"),
            }
        }
    }

    async fn refresh_candidate_status(&mut self, peer: PeerId) {
        let refreshed = self.backend.inner.lock().unwrap().status;
        self.statuses.insert(peer, refreshed);
        // Only a notice beyond local finality refreshes its source.
        let announcement = neutrin0_network::rpc::CheckpointAnnouncement {
            chunk_count: refreshed.finalized_chunks() + 1,
            checkpoint_hash: [91; 32],
        };
        self.events
            .send(NetworkEvent::GossipMessage {
                topic: Topic::Checkpoints,
                data: borsh::to_vec(&announcement).unwrap(),
                propagation_source: peer,
                message_id: neutrin0_network::libp2p::gossipsub::MessageId::from(
                    b"refresh-status".to_vec(),
                ),
            })
            .await
            .unwrap();
        let mut validated = false;
        let mut answered = false;
        while !validated || !answered {
            match timeout(Duration::from_secs(1), self.commands.recv())
                .await
                .unwrap()
                .unwrap()
            {
                NetworkCommand::ReportGossipValidation { .. } => validated = true,
                NetworkCommand::Subscribe(_) => {}
                NetworkCommand::SendRpcRequest {
                    peer: owner,
                    request: RpcRequest::Status(_),
                    response_tx,
                } => {
                    // Other peers may be re-handshaked concurrently; answer them
                    // consistently and keep waiting for the refreshed peer.
                    response_tx
                        .send(Ok(RpcResponse::Status(self.status_for(&owner))))
                        .unwrap();
                    if owner == peer {
                        answered = true;
                    }
                }
                NetworkCommand::SendRpcRequest {
                    peer,
                    request,
                    response_tx,
                } => self.deferred.push_back((peer, request, response_tx)),
                other => panic!("unexpected status refresh command {other:?}"),
            }
        }
    }

    async fn finish_canonical_backfill(&mut self, peer: PeerId) {
        // Local progress is already proven to the head, so the complete-
        // consensus cursor fetches nothing again (design 21); only candidate
        // discovery asks, and nothing is advertised yet.
        self.refresh_candidate_status(peer).await;
        while let Ok(Some(command)) = timeout(Duration::from_secs(1), self.commands.recv()).await {
            match command {
                NetworkCommand::SendRpcRequest {
                    request: RpcRequest::CandidateByChunk(_),
                    response_tx,
                    ..
                } => response_tx
                    .send(Err(neutrin0_network::rpc::RpcError::Remote(
                        neutrin0_network::rpc::RpcFailure::Unavailable(
                            "no candidate advertised yet".into(),
                        ),
                    )))
                    .unwrap(),
                NetworkCommand::SendRpcRequest { request, .. } => {
                    panic!("unexpected canonical request {request:?}")
                }
                _ => {}
            }
        }
    }

    pub(super) fn blocks_reply(&self, request: &RpcRequest) -> RpcResponse {
        let RpcRequest::BlocksByRange(request) = request else {
            panic!("expected branch blocks")
        };
        assert_eq!(request.head_block_hash, self.candidate.chunk.end_block_hash);
        let first = usize::try_from(request.start_height - 1).unwrap();
        let count = usize::try_from(request.count).unwrap();
        RpcResponse::BlocksByRange(BlocksByRangeResponse {
            blocks: super::proven_all(&self.blocks[first..first + count]),
            candidates: Vec::new(),
        })
    }

    pub(super) async fn finish(&mut self) {
        for _ in 0..2 {
            let (_, request, reply) = self.request().await;
            reply.send(Ok(self.blocks_reply(&request))).unwrap();
        }
        self.wait_completed().await;
        assert_eq!(
            self.backend.inner.lock().unwrap().candidate_replacements,
            vec![self.candidate.clone()]
        );
        assert_eq!(self.backend.proofs_imported_count(), 2);
    }

    async fn wait_completed(&self) {
        timeout(Duration::from_secs(1), async {
            loop {
                if !self
                    .backend
                    .inner
                    .lock()
                    .unwrap()
                    .candidate_replacements
                    .is_empty()
                {
                    return;
                }
                self.backend.candidate_notified.notified().await;
            }
        })
        .await
        .unwrap();
    }

    pub(super) async fn stop(self) {
        drop(self.events);
        self.runner.await.unwrap();
    }
}

#[tokio::test]
async fn exact_candidate_endpoint_backfills_bounded_pages_before_retarget() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&harness.candidate).unwrap(),
        )
        .await;
    harness.finish().await;
    harness.stop().await;
}

#[tokio::test]
async fn a_locally_held_candidate_branch_is_considered_without_downloading_it() {
    let mut harness = Harness::new();
    harness.backend.inner.lock().unwrap().held_candidate_branch = true;
    let peer = random_peer();
    harness.connect(peer).await;
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&harness.candidate).unwrap(),
        )
        .await;
    harness.wait_completed().await;
    assert_eq!(
        harness.backend.inner.lock().unwrap().candidate_replacements,
        vec![harness.candidate.clone()]
    );
    assert_eq!(harness.backend.proofs_imported_count(), 0);
    harness.stop().await;
}

#[tokio::test]
async fn disconnect_failover_ignores_old_candidate_response_without_releasing_new_request() {
    let mut harness = Harness::new();
    let first = random_peer();
    let second = random_peer();
    harness.connect(first).await;
    harness.connect(second).await;
    harness
        .gossip(
            first,
            Topic::BftCandidates,
            borsh::to_vec(&harness.candidate).unwrap(),
        )
        .await;
    let (provider, _, old_reply) = harness.request().await;
    assert_eq!(provider, first);
    harness
        .events
        .send(NetworkEvent::PeerDisconnected(first))
        .await
        .unwrap();
    let (provider, request, new_reply) = harness.request().await;
    assert_eq!(provider, second);
    old_reply
        .send(Ok(RpcResponse::BlocksByRange(
            BlocksByRangeResponse::default(),
        )))
        .unwrap();
    new_reply.send(Ok(harness.blocks_reply(&request))).unwrap();
    let (_, request, reply) = harness.request().await;
    reply.send(Ok(harness.blocks_reply(&request))).unwrap();
    harness.wait_completed().await;
    assert_eq!(harness.backend.proofs_imported_count(), 2);
    harness.stop().await;
}

#[tokio::test]
async fn unknown_vote_queries_source_exact_target_and_rejects_substituted_candidate() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    let vote = FinalityVote {
        proof_manifests: vec![],
        aggregation_bits: neutrin0_primitives::BitVec::default(),
        signature: [0; 96],
        attestations: vec![],
        data: FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: harness.candidate.chunk.hash(),
            selection: [0; 32],
            phase: FinalityVotePhase::Prevote,
        },
    };
    harness
        .gossip(
            peer,
            Topic::FinalityVotesPrevote,
            borsh::to_vec(&neutrin0_consensus_types::BftVote::Value(vote.clone())).unwrap(),
        )
        .await;
    let (source, request, reply) = harness.request().await;
    assert_eq!(source, peer);
    assert!(
        matches!(request, RpcRequest::CandidateByChunk(query) if query.chunk_hash == Some(vote.data.chunk_hash))
    );
    let mut wrong = harness.candidate.clone();
    wrong.chunk.end_block_hash = [99; 32];
    reply
        .send(Ok(RpcResponse::CandidateByChunk(Box::new(
            CandidateByChunkResponse { candidate: wrong },
        ))))
        .unwrap();
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&harness.candidate).unwrap(),
        )
        .await;
    harness.finish().await;
    // The saved vote is replayed after the exact branch was installed.
    assert_eq!(harness.backend.finality_vote_count(), 2);
    harness.stop().await;
}

#[tokio::test]
async fn candidate_backfill_accepts_honest_contiguous_prefixes_under_response_budget() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&harness.candidate).unwrap(),
        )
        .await;
    let (_, request, reply) = harness.request().await;
    let RpcResponse::BlocksByRange(mut payload) = harness.blocks_reply(&request) else {
        unreachable!()
    };
    payload.blocks.truncate(3);
    reply.send(Ok(RpcResponse::BlocksByRange(payload))).unwrap();
    let (_, request, reply) = harness.request().await;
    assert!(matches!(&request, RpcRequest::BlocksByRange(range) if range.start_height == 4));
    reply.send(Ok(harness.blocks_reply(&request))).unwrap();
    let (_, request, reply) = harness.request().await;
    assert!(matches!(&request, RpcRequest::BlocksByRange(range) if range.start_height == 20));
    reply.send(Ok(harness.blocks_reply(&request))).unwrap();
    harness.wait_completed().await;
    assert_eq!(harness.backend.inner.lock().unwrap().proven_height, 20);
    harness.stop().await;
}

#[tokio::test]
async fn unsigned_round_metadata_cannot_poison_a_later_legitimate_candidate_hint() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    let mut impossible = harness.candidate.clone();
    impossible.round = u32::MAX;
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&impossible).unwrap(),
        )
        .await;
    let mut later_bare = harness.candidate.clone();
    later_bare.round = 16;
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&later_bare).unwrap(),
        )
        .await;
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&harness.candidate).unwrap(),
        )
        .await;
    harness.finish().await;
    harness.stop().await;
}

#[tokio::test]
async fn invalid_same_round_quorum_does_not_displace_authenticated_candidate_quorum() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    let quorum = neutrin0_consensus_types::QuorumCertificate {
        data: FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: harness.candidate.chunk.hash(),
            selection: [0; 32],
            phase: FinalityVotePhase::Prevote,
        },
        aggregate: neutrin0_consensus_types::AggregatedVote {
            aggregation_bits: neutrin0_primitives::BitVec::from_bytes(1, vec![1]).unwrap(),
            signature: [77; 96],
        },
    };
    harness.candidate.round = 1;
    harness.candidate.justification = Some(quorum);
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&harness.candidate).unwrap(),
        )
        .await;
    let mut malformed = harness.candidate.clone();
    malformed
        .justification
        .as_mut()
        .unwrap()
        .aggregate
        .signature = [0; 96];
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&malformed).unwrap(),
        )
        .await;
    let mut bare = harness.candidate.clone();
    bare.justification = None;
    bare.round = 16;
    harness
        .gossip(peer, Topic::BftCandidates, borsh::to_vec(&bare).unwrap())
        .await;
    harness.finish().await;
    harness.stop().await;
}

#[tokio::test]
async fn candidate_discovery_backlog_cannot_starve_known_branch_payload_pages() {
    let mut harness = Harness::new();
    let peer = random_peer();
    harness.connect(peer).await;
    harness
        .gossip(
            peer,
            Topic::BftCandidates,
            borsh::to_vec(&harness.candidate).unwrap(),
        )
        .await;
    let (_, first_page, first_reply) = harness.request().await;
    assert!(matches!(&first_page, RpcRequest::BlocksByRange(range) if range.start_height == 1));
    // Queue three independent discoveries while one known branch page is held.
    // Each gossip's validation response is a deterministic driver barrier.
    for target in [90, 91, 92] {
        let vote = FinalityVote {
            proof_manifests: vec![],
            aggregation_bits: neutrin0_primitives::BitVec::default(),
            signature: [0; 96],
            attestations: vec![],
            data: FinalityVoteData {
                chunk_id: 0,
                round: 0,
                chunk_hash: [target; 32],
                selection: [0; 32],
                phase: FinalityVotePhase::Prevote,
            },
        };
        harness
            .gossip(
                peer,
                Topic::FinalityVotesPrevote,
                borsh::to_vec(&neutrin0_consensus_types::BftVote::Value(vote.clone())).unwrap(),
            )
            .await;
    }
    first_reply
        .send(Ok(harness.blocks_reply(&first_page)))
        .unwrap();
    let (_, query, reply) = harness.request().await;
    assert!(matches!(query, RpcRequest::CandidateByChunk(_)));
    reply
        .send(Err(neutrin0_network::rpc::RpcError::Remote(
            neutrin0_network::rpc::RpcFailure::Unavailable("target unavailable".into()),
        )))
        .unwrap();
    let (_, page, reply) = harness.request().await;
    assert!(matches!(&page, RpcRequest::BlocksByRange(range) if range.start_height == 17));
    reply.send(Ok(harness.blocks_reply(&page))).unwrap();
    harness.wait_completed().await;
    assert_eq!(
        harness.backend.inner.lock().unwrap().candidate_replacements,
        vec![harness.candidate.clone()]
    );
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn status_refreshed_failing_candidate_cannot_starve_an_obtainable_second_target() {
    // Canonical heads are already caught up. These are two separate candidate
    // availability paths; ordinary header synchronization cannot finish either.
    let mut harness = Harness::with_head_height(20);
    let bad_provider = random_peer();
    let honest_provider = random_peer();
    harness.connect(bad_provider).await;
    harness.connect(honest_provider).await;
    harness.finish_canonical_backfill(bad_provider).await;
    let initial_proof_imports = harness.backend.proofs_imported_count();
    let mut unavailable = harness.candidate.clone();
    unavailable.chunk.start_block_hash = [99; 32];
    unavailable.chunk.end_block_hash = [98; 32];
    harness
        .gossip(
            bad_provider,
            Topic::BftCandidates,
            borsh::to_vec(&unavailable).unwrap(),
        )
        .await;
    let (_, first_page, mut reply) = harness.request().await;
    assert!(matches!(&first_page, RpcRequest::BlocksByRange(range)
        if range.head_block_hash == unavailable.chunk.end_block_hash));
    harness
        .gossip(
            honest_provider,
            Topic::BftCandidates,
            borsh::to_vec(&harness.candidate).unwrap(),
        )
        .await;

    let mut page = first_page;
    let mut good_pages = 0;
    for _ in 0..24 {
        match &page {
            RpcRequest::CandidateByChunk(_) => {
                reply
                    .send(Ok(RpcResponse::CandidateByChunk(Box::new(
                        CandidateByChunkResponse {
                            candidate: unavailable.clone(),
                        },
                    ))))
                    .unwrap();
            }
            RpcRequest::BlocksByRange(range)
                if range.head_block_hash == unavailable.chunk.end_block_hash =>
            {
                // Refresh the failed peer's compatible Status on every attempt.
                // Its renewed eligibility must not keep this target at the front.
                // Status hints are debounced; exercise a genuine later refresh.
                tokio::time::sleep(Duration::from_secs(5)).await;
                harness.refresh_candidate_status(bad_provider).await;
                reply
                    .send(Err(neutrin0_network::rpc::RpcError::Remote(
                        neutrin0_network::rpc::RpcFailure::Unavailable(
                            "candidate unavailable".into(),
                        ),
                    )))
                    .unwrap();
            }
            RpcRequest::BlocksByRange(_) => {
                reply.send(Ok(harness.blocks_reply(&page))).unwrap();
                good_pages += 1;
                if good_pages == 2 {
                    break;
                }
            }
            other => panic!("unexpected candidate request {other:?}"),
        }
        let (_, next, response) = harness.request().await;
        page = next;
        reply = response;
    }
    assert_eq!(good_pages, 2, "failing target starved the honest branch");
    harness.wait_completed().await;
    assert_eq!(
        harness.backend.inner.lock().unwrap().candidate_replacements,
        vec![harness.candidate.clone()]
    );
    assert_eq!(
        harness.backend.proofs_imported_count() - initial_proof_imports,
        2
    );
    harness.stop().await;
}

#[tokio::test]
async fn certified_candidate_fetches_exact_certificate_and_fails_over_without_finalizing() {
    for empty in [false, true] {
        let mut harness = Harness::new();
        harness.backend.inner.lock().unwrap().certified_sync = true;
        let first = random_peer();
        let second = random_peer();
        harness.connect(first).await;
        harness.connect(second).await;
        let candidate = borsh::to_vec(&harness.candidate).unwrap();
        harness
            .gossip(first, Topic::BftCandidates, candidate.clone())
            .await;
        harness
            .gossip(second, Topic::BftCandidates, candidate)
            .await;
        harness.finish().await;
        let (failed, request, reply) = harness.request().await;
        assert!(
            matches!(request, RpcRequest::FinalityCertByChunk(ref query) if query.chunk_ids == vec![0])
        );
        let mut certificate = sample_chunk_proof(0, 20).finality_cert;
        certificate.chunk_hash = harness.candidate.chunk.hash();
        certificate.proposal.chunk = harness.candidate.chunk.clone();
        let mut wrong = certificate.clone();
        wrong.chunk_hash = [255; 32];
        reply
            .send(Ok(RpcResponse::FinalityCertByChunk(
                neutrin0_network::rpc::FinalityCertByChunkResponse {
                    certs: if empty { vec![] } else { vec![wrong] },
                },
            )))
            .unwrap();
        let (provider, request, reply) = harness.request().await;
        assert_ne!(provider, failed);
        assert!(matches!(request, RpcRequest::FinalityCertByChunk(_)));
        assert_eq!(
            harness.backend.inner.lock().unwrap().execution_certificates,
            [] as [neutrin0_consensus_types::FinalityCert; 0]
        );
        reply
            .send(Ok(RpcResponse::FinalityCertByChunk(
                neutrin0_network::rpc::FinalityCertByChunkResponse {
                    certs: vec![certificate.clone()],
                },
            )))
            .unwrap();
        timeout(Duration::from_secs(1), async {
            loop {
                if !harness
                    .backend
                    .inner
                    .lock()
                    .unwrap()
                    .execution_certificates
                    .is_empty()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        {
            let state = harness.backend.inner.lock().unwrap();
            assert_eq!(state.execution_certificates, vec![certificate]);
            assert_eq!(state.certified_sync_height, Some(40));
            assert_eq!(state.chunk_proof_imports, [] as [u64; 0]);
            assert_eq!(state.status.finalized_chunk_id, None);
        }
        harness.stop().await;
    }
}
