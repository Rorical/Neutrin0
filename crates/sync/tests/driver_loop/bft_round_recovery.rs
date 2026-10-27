//! Signed-round transport recovery; native/Guest tests authenticate actual BLS.

use super::bft_candidate_backfill::Harness;
use super::*;
use neutrin0_consensus_types::{BftMessage, BftProposal, RoundChangeCertificate};
use neutrin0_network::{Topic, rpc::BftRoundByChunkResponse};

fn harness(branch_ready: bool) -> Harness {
    let harness = Harness::new();
    {
        let mut state = harness.backend.inner.lock().unwrap();
        state.bft_sync = true;
        state.bft_branch_ready = branch_ready;
    }
    harness
}

fn proposal(harness: &Harness, round: u32) -> BftProposal {
    BftProposal {
        chunk: harness.candidate.chunk.clone(),
        round,
        proposer_index: 0,
        valid_quorum: None,
        round_change_certificate: (round != 0).then_some(certificate(round)),
        proposal_slot: 0,
        receipts: Vec::new(),
        ratified_chunk_proofs: Vec::new(),
        signature: [88; 96],
    }
}

const fn certificate(round: u32) -> RoundChangeCertificate {
    RoundChangeCertificate {
        chunk_id: 0,
        round,
        reports: Vec::new(),
    }
}

async fn wait_messages(backend: &MockBackend, count: usize) {
    timeout(Duration::from_secs(1), async {
        loop {
            let notified = backend.bft_notified.notified();
            if backend.inner.lock().unwrap().bft_messages.len() >= count {
                return;
            }
            notified.await;
        }
    })
    .await
    .unwrap();
}

async fn barrier(harness: &mut Harness, peer: PeerId) {
    let mut bad = proposal(harness, 0);
    bad.signature = [0; 96];
    harness
        .gossip(
            peer,
            Topic::BftMessages,
            borsh::to_vec(&BftMessage::Proposal(Box::new(bad))).unwrap(),
        )
        .await;
}

#[tokio::test]
async fn lost_round_gossip_recovers_certificate_before_exact_signed_proposal() {
    let mut harness = harness(true);
    let peer = random_peer();
    harness.connect(peer).await;
    let (_, request, reply) = harness.request().await;
    assert!(matches!(request, RpcRequest::BftRoundByChunk(request) if request.chunk_id == 0));
    let proposal = proposal(&harness, 2);
    let certificate = certificate(2);
    reply
        .send(Ok(RpcResponse::BftRoundByChunk(Box::new(
            BftRoundByChunkResponse {
                proposal: Some(proposal.clone()),
                round_change: Some(certificate.clone()),
            },
        ))))
        .unwrap();
    wait_messages(&harness.backend, 2).await;
    assert_eq!(
        harness.backend.inner.lock().unwrap().bft_messages,
        vec![
            BftMessage::RoundChangeCertificate(certificate),
            BftMessage::Proposal(Box::new(proposal)),
        ]
    );
    harness.stop().await;
}

#[tokio::test]
async fn higher_round_signed_proposal_replays_after_branch_backfill_without_separate_round_gossip()
{
    let mut harness = harness(false);
    let peer = random_peer();
    harness.connect(peer).await;
    let (_, request, reply) = harness.request().await;
    assert!(matches!(request, RpcRequest::BftRoundByChunk(_)));
    reply
        .send(Ok(RpcResponse::BftRoundByChunk(Box::new(
            BftRoundByChunkResponse {
                proposal: None,
                round_change: None,
            },
        ))))
        .unwrap();
    let proposal = proposal(&harness, 1);
    harness
        .gossip(
            peer,
            Topic::BftMessages,
            borsh::to_vec(&BftMessage::Proposal(Box::new(proposal.clone()))).unwrap(),
        )
        .await;
    assert_eq!(
        harness.backend.inner.lock().unwrap().bft_messages,
        Vec::<BftMessage>::new()
    );
    for _ in 0..2 {
        let (_, request, reply) = harness.request().await;
        let response = harness.blocks_reply(&request);
        reply.send(Ok(response)).unwrap();
    }
    wait_messages(&harness.backend, 1).await;
    {
        let state = harness.backend.inner.lock().unwrap();
        assert_eq!(state.bft_round, 1);
        assert_eq!(
            state.bft_messages,
            vec![BftMessage::Proposal(Box::new(proposal))]
        );
    }
    harness.stop().await;
}

#[tokio::test]
async fn disconnected_round_response_cannot_release_reconnected_request() {
    let mut harness = harness(true);
    let peer = random_peer();
    harness.connect(peer).await;
    let (_, _, old) = harness.request().await;
    harness
        .events
        .send(NetworkEvent::PeerDisconnected(peer))
        .await
        .unwrap();
    harness.connect(peer).await;
    let (_, request, current) = harness.request().await;
    assert!(matches!(request, RpcRequest::BftRoundByChunk(_)));
    old.send(Ok(RpcResponse::BftRoundByChunk(Box::new(
        BftRoundByChunkResponse {
            proposal: Some(proposal(&harness, 1)),
            round_change: None,
        },
    ))))
    .unwrap();
    barrier(&mut harness, peer).await;
    assert_eq!(
        harness.backend.inner.lock().unwrap().bft_messages,
        Vec::<BftMessage>::new()
    );
    let proposal = proposal(&harness, 2);
    current
        .send(Ok(RpcResponse::BftRoundByChunk(Box::new(
            BftRoundByChunkResponse {
                proposal: Some(proposal.clone()),
                round_change: None,
            },
        ))))
        .unwrap();
    wait_messages(&harness.backend, 1).await;
    assert_eq!(
        harness.backend.inner.lock().unwrap().bft_messages,
        vec![BftMessage::Proposal(Box::new(proposal))]
    );
    harness.stop().await;
}

#[tokio::test]
async fn wrong_source_round_response_and_unauthenticated_proposal_never_enter_live_bft() {
    let mut harness = harness(true);
    let peer = random_peer();
    harness.connect(peer).await;
    let (_, _, reply) = harness.request().await;
    let mut wrong = proposal(&harness, 1);
    wrong.chunk.chunk_id = 1;
    reply
        .send(Ok(RpcResponse::BftRoundByChunk(Box::new(
            BftRoundByChunkResponse {
                proposal: Some(wrong),
                round_change: None,
            },
        ))))
        .unwrap();
    barrier(&mut harness, peer).await;
    assert_eq!(
        harness.backend.inner.lock().unwrap().bft_messages,
        Vec::<BftMessage>::new()
    );
    assert_eq!(
        harness.backend.inner.lock().unwrap().candidate_replacements,
        Vec::<neutrin0_consensus_types::BftCandidate>::new()
    );
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn an_early_empty_reply_cannot_strand_a_lagger_after_peers_enter_a_later_round() {
    let mut harness = harness(true);
    let peer = random_peer();
    harness.connect(peer).await;
    let (_, request, early) = harness.request().await;
    assert!(matches!(request, RpcRequest::BftRoundByChunk(_)));
    early
        .send(Ok(RpcResponse::BftRoundByChunk(Box::new(
            BftRoundByChunkResponse {
                proposal: None,
                round_change: None,
            },
        ))))
        .unwrap();
    barrier(&mut harness, peer).await;
    assert_eq!(harness.backend.inner.lock().unwrap().bft_round, 0);
    tokio::time::advance(Duration::from_secs(5)).await;
    let (_, request, recovered) = harness.request().await;
    assert!(matches!(request, RpcRequest::BftRoundByChunk(request) if request.chunk_id == 0));
    recovered
        .send(Ok(RpcResponse::BftRoundByChunk(Box::new(
            BftRoundByChunkResponse {
                proposal: Some(proposal(&harness, 1)),
                round_change: Some(certificate(1)),
            },
        ))))
        .unwrap();
    wait_messages(&harness.backend, 2).await;
    assert_eq!(harness.backend.inner.lock().unwrap().bft_round, 1);
    harness.stop().await;
}

#[tokio::test]
async fn a_deferred_proposal_fetches_its_named_receipts_from_the_relay_and_retries() {
    let mut harness = harness(false);
    let named = [0x51; 32];
    harness.backend.inner.lock().unwrap().missing_receipts = vec![named];
    let peer = random_peer();
    harness.connect(peer).await;
    let (_, request, reply) = harness.request().await;
    assert!(matches!(request, RpcRequest::BftRoundByChunk(_)));
    reply
        .send(Ok(RpcResponse::BftRoundByChunk(Box::new(
            BftRoundByChunkResponse {
                proposal: None,
                round_change: None,
            },
        ))))
        .unwrap();
    let proposal = proposal(&harness, 0);
    harness
        .gossip(
            peer,
            Topic::BftMessages,
            borsh::to_vec(&BftMessage::Proposal(Box::new(proposal.clone()))).unwrap(),
        )
        .await;
    // The proposal names a receipt this node lacks: the driver asks the peer
    // that relayed it (design 08, voter rule 1) before branch backfill.
    let (owner, request, reply) = harness.request().await;
    assert_eq!(owner, peer);
    assert!(
        matches!(&request, RpcRequest::ReceiptsByHash(request) if request.block_hashes == vec![named]),
        "{request:?}"
    );
    reply
        .send(Ok(RpcResponse::ReceiptsByHash(
            neutrin0_network::rpc::ReceiptsByHashResponse {
                receipts: vec![neutrin0_consensus_types::BlockReceipt {
                    block_hash: named,
                    proof_bytes: vec![1],
                }],
            },
        )))
        .unwrap();
    // The fetched receipt is imported and the kept proposal is retried.
    wait_messages(&harness.backend, 1).await;
    assert_eq!(
        harness.backend.inner.lock().unwrap().bft_messages,
        vec![BftMessage::Proposal(Box::new(proposal))]
    );
    harness.stop().await;
}
