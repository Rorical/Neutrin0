//! Bounded leader-proposal backfill and authenticated round recovery.

use super::{OutboundOutcome, SyncDriver, candidates};
use crate::SyncBackendError;
use alloc::collections::BTreeMap;
use neutrin0_consensus_types::{BftCandidate, BftMessage, BftProposal, BftVote};
use neutrin0_network::{
    PeerId,
    rpc::{
        BftRoundByChunkRequest, CandidateByChunkRequest, ChunkProofByIdRequest,
        MAX_CHUNK_PROOFS_PER_RESPONSE, MAX_RECEIPTS_PER_RESPONSE, ReceiptsByHashRequest, RpcError,
        RpcRequest, RpcResponse, Status,
    },
};
use tokio::time::{Duration, Instant};

const MAX_PENDING_PROPOSALS: usize = 8;
const MAX_ROUND_REQUESTS: usize = 4;
const MAX_PROVIDERS: usize = 256;
const ROUND_RETRY_DELAY: Duration = Duration::from_secs(5);
/// Outstanding fetches of artifacts deferred proposals name, across peers.
const MAX_ARTIFACT_REQUESTS: usize = 8;

#[derive(Default)]
pub(super) struct BftSync {
    pending: Vec<BftProposal>,
    connections: BTreeMap<PeerId, u64>,
    next_connection: u64,
    nonce: u64,
    requests: BTreeMap<PeerId, Request>,
    tried: BTreeMap<PeerId, Instant>,
    statuses: BTreeMap<PeerId, Status>,
    source_round: Option<(u64, u32)>,
    artifacts: BTreeMap<(PeerId, ArtifactKind), ArtifactRequest>,
}

/// What a proposal-artifact fetch retrieves (design 08, voter rules 1 and 4).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum ArtifactKind {
    /// Block receipts by block hash.
    Receipts,
    /// Chunk proofs by chunk id and statement key.
    ChunkProofs,
}

/// One outstanding fetch of artifacts a deferred proposal names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ArtifactRequest {
    peer: PeerId,
    connection: u64,
    nonce: u64,
    kind: ArtifactKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Request {
    peer: PeerId,
    connection: u64,
    nonce: u64,
    chunk_id: u64,
}

pub(super) fn on_connect(driver: &mut SyncDriver, peer: PeerId) {
    let Some(generation) = driver.bft.next_connection.checked_add(1) else {
        return;
    };
    driver.bft.next_connection = generation;
    driver.bft.connections.insert(peer, generation);
    driver.bft.tried.remove(&peer);
}

pub(super) fn on_disconnect(driver: &mut SyncDriver, peer: PeerId) {
    driver.bft.connections.remove(&peer);
    driver.bft.requests.remove(&peer);
    driver.bft.artifacts.retain(|(owner, _), _| *owner != peer);
    driver.bft.tried.remove(&peer);
    driver.bft.statuses.remove(&peer);
}

pub(super) fn reset_after_bootstrap(driver: &mut SyncDriver) {
    let nonce = driver.bft.nonce;
    let next_connection = driver.bft.next_connection;
    driver.bft = BftSync {
        next_connection,
        nonce,
        ..BftSync::default()
    };
    for peer in driver.connected_peers.clone() {
        on_connect(driver, peer);
    }
}

pub(super) async fn on_status(driver: &mut SyncDriver, peer: PeerId, status: Status) {
    if !driver.backend.supports_bft_message_sync() {
        return;
    }
    let Ok(local) = driver.backend.local_status().await else {
        return;
    };
    if !super::same_chain(&status, &local) {
        return;
    }
    let Some(connection) = driver.bft.connections.get(&peer).copied() else {
        return;
    };
    if !driver.bft.statuses.contains_key(&peer) && driver.bft.statuses.len() >= MAX_PROVIDERS {
        return;
    }
    driver.bft.statuses.insert(peer, status);
    let Some(source_round) = driver.backend.current_bft_round().await else {
        return;
    };
    if driver.bft.source_round != Some(source_round) {
        driver.bft.source_round = Some(source_round);
        driver.bft.tried.clear();
    }
    retry_pending(driver).await;
    if driver.bft.requests.len() >= MAX_ROUND_REQUESTS
        || driver.bft.requests.contains_key(&peer)
        || driver
            .bft
            .tried
            .get(&peer)
            .is_some_and(|last| last.elapsed() < ROUND_RETRY_DELAY)
        || (!driver.bft.tried.contains_key(&peer) && driver.bft.tried.len() >= MAX_PROVIDERS)
    {
        return;
    }
    let Some(nonce) = driver.bft.nonce.checked_add(1) else {
        return;
    };
    driver.bft.nonce = nonce;
    let request = Request {
        peer,
        connection,
        nonce,
        chunk_id: source_round.0,
    };
    driver.bft.tried.insert(peer, Instant::now());
    driver.bft.requests.insert(peer, request);
    if !driver
        .send_rpc(
            peer,
            RpcRequest::BftRoundByChunk(BftRoundByChunkRequest {
                chunk_id: request.chunk_id,
            }),
            move |_, response| OutboundOutcome::BftRound { request, response },
        )
        .await
    {
        driver.bft.requests.remove(&peer);
    }
}

/// Retry certified round recovery with bounded network backoff. Empty replies
/// before a partition heals cannot permanently strand an earlier round.
pub(super) async fn on_retry(driver: &mut SyncDriver) {
    if !driver.backend.supports_bft_message_sync() {
        return;
    }
    let mut peers: Vec<_> = driver
        .bft
        .statuses
        .iter()
        .map(|(peer, status)| (*peer, *status))
        .collect();
    peers.sort_by_key(|(peer, _)| driver.bft.tried.get(peer).copied());
    for (peer, status) in peers {
        on_status(driver, peer, status).await;
    }
}

pub(super) async fn on_message(
    driver: &mut SyncDriver,
    peer: PeerId,
    message: BftMessage,
) -> Result<(), SyncBackendError> {
    if !driver.backend.supports_bft_message_sync() {
        return Err(SyncBackendError::NotAvailable(
            "BFT protocol disabled".into(),
        ));
    }
    if let BftMessage::Proposal(proposal) = &message {
        // A signed bad quorum claim may still be objective leader equivocation
        // evidence. Source authentication is separate from live admission.
        driver
            .backend
            .ingest_signed_artifact(
                neutrin0_consensus_types::signed_artifacts::SignedArtifact::Proposal(
                    proposal.clone(),
                ),
            )
            .await;
        driver.backend.validate_bft_proposal_hint(proposal).await?;
        let result = driver.backend.ingest_bft_message(message.clone()).await;
        if matches!(result, Err(SyncBackendError::NotAvailable(_))) {
            retain_proposal(driver, proposal).await;
            request_artifacts(driver, peer, proposal).await;
            candidates::on_hint(
                driver,
                peer,
                BftCandidate {
                    chunk: proposal.chunk.clone(),
                    round: proposal.round,
                    justification: proposal.valid_quorum.clone(),
                    selection: proposal
                        .valid_quorum
                        .is_some()
                        .then(|| proposal.payment_selection()),
                },
            )
            .await;
            return Ok(());
        }
        return result;
    }
    if let BftMessage::Vote(BftVote::Value(vote)) = &message {
        candidates::on_vote(driver, peer, None, vote).await;
    }
    // Only the quorum's exact target is needed after the message moves into the backend.
    let quorum_target = match &message {
        BftMessage::RoundChange(report) => report.highest_quorum.as_ref(),
        BftMessage::RoundChangeCertificate(certificate) => certificate.highest_quorum(),
        _ => None,
    }
    .map(|quorum| CandidateByChunkRequest {
        chunk_id: quorum.data.chunk_id,
        chunk_hash: Some(quorum.data.chunk_hash),
    });
    driver.backend.ingest_bft_message(message).await?;
    if let Some(query) = quorum_target {
        candidates::request_quorum(driver, peer, query).await;
    }
    retry_pending(driver).await;
    Ok(())
}

/// Fetch the receipts and chunk proofs a deferred proposal names from the
/// peer that relayed it; the relaying leader or voter holds what it named.
/// Branch data the node lacks altogether arrives by candidate backfill.
async fn request_artifacts(driver: &mut SyncDriver, peer: PeerId, proposal: &BftProposal) {
    let missing = driver.backend.missing_proposal_artifacts(proposal).await;
    let Some(connection) = driver.bft.connections.get(&peer).copied() else {
        return;
    };
    let receipt_limit = usize::try_from(MAX_RECEIPTS_PER_RESPONSE).unwrap_or(usize::MAX);
    let proof_limit = usize::try_from(MAX_CHUNK_PROOFS_PER_RESPONSE).unwrap_or(usize::MAX);
    let receipts: Vec<_> = missing.receipts.into_iter().take(receipt_limit).collect();
    let chunk_proofs: Vec<_> = missing.chunk_proofs.into_iter().take(proof_limit).collect();
    let fetches = [
        (!receipts.is_empty()).then_some((
            ArtifactKind::Receipts,
            RpcRequest::ReceiptsByHash(ReceiptsByHashRequest {
                block_hashes: receipts,
            }),
        )),
        (!chunk_proofs.is_empty()).then(|| {
            let (chunk_ids, statement_keys) = chunk_proofs.into_iter().unzip();
            (
                ArtifactKind::ChunkProofs,
                RpcRequest::ChunkProofById(ChunkProofByIdRequest {
                    chunk_ids,
                    statement_keys,
                }),
            )
        }),
    ];
    for (kind, rpc) in fetches.into_iter().flatten() {
        if driver.bft.artifacts.len() >= MAX_ARTIFACT_REQUESTS
            || driver.bft.artifacts.contains_key(&(peer, kind))
        {
            continue;
        }
        let Some(nonce) = driver.bft.nonce.checked_add(1) else {
            return;
        };
        driver.bft.nonce = nonce;
        let request = ArtifactRequest {
            peer,
            connection,
            nonce,
            kind,
        };
        driver.bft.artifacts.insert((peer, kind), request);
        if !driver
            .send_rpc(peer, rpc, move |_, response| {
                OutboundOutcome::BftArtifacts { request, response }
            })
            .await
        {
            driver.bft.artifacts.remove(&(peer, kind));
        }
    }
}

/// Import fetched proposal artifacts, then retry the deferred proposals.
/// Each artifact is verified like a gossiped one; an invalid one is refused.
pub(super) async fn on_artifact_response(
    driver: &mut SyncDriver,
    request: ArtifactRequest,
    response: Result<RpcResponse, RpcError>,
) {
    if driver.bft.artifacts.get(&(request.peer, request.kind)) != Some(&request)
        || driver.bft.connections.get(&request.peer) != Some(&request.connection)
    {
        return;
    }
    driver.bft.artifacts.remove(&(request.peer, request.kind));
    match (request.kind, response) {
        (ArtifactKind::Receipts, Ok(RpcResponse::ReceiptsByHash(reply))) => {
            if let Err(error) = driver
                .backend
                .verify_and_import_receipts(reply.receipts, request.peer)
                .await
            {
                tracing::debug!(peer = %request.peer, ?error, "fetched proposal receipts refused");
            }
        }
        (ArtifactKind::ChunkProofs, Ok(RpcResponse::ChunkProofById(reply))) => {
            for proof in reply.proofs {
                if let Err(error) = driver
                    .backend
                    .verify_and_import_chunk_proof(proof, request.peer)
                    .await
                {
                    tracing::debug!(peer = %request.peer, ?error, "fetched chunk proof refused");
                }
            }
        }
        _ => return,
    }
    retry_pending(driver).await;
}

async fn retain_proposal(driver: &mut SyncDriver, proposal: &BftProposal) {
    let Some((chunk_id, round)) = driver.backend.current_bft_round().await else {
        return;
    };
    driver
        .bft
        .pending
        .retain(|pending| pending.chunk.chunk_id == chunk_id && pending.round >= round);
    if proposal.chunk.chunk_id != chunk_id
        || proposal.round < round
        || driver.bft.pending.contains(proposal)
    {
        return;
    }
    driver.bft.pending.push(proposal.clone());
    driver
        .bft
        .pending
        .sort_by_key(|pending| (pending.round, pending.chunk.hash()));
    driver.bft.pending.truncate(MAX_PENDING_PROPOSALS);
}

/// Called after branch arrivals and authenticated catchup, without timer polling.
pub(super) async fn retry_pending(driver: &mut SyncDriver) {
    let Some((id, round)) = driver.backend.current_bft_round().await else {
        return;
    };
    let pending = core::mem::take(&mut driver.bft.pending);
    for proposal in pending {
        if proposal.chunk.chunk_id != id || proposal.round < round {
            continue;
        }
        if matches!(
            driver
                .backend
                .ingest_bft_message(BftMessage::Proposal(Box::new(proposal.clone())))
                .await,
            Err(SyncBackendError::NotAvailable(_))
        ) {
            driver.bft.pending.push(proposal);
        }
    }
}

pub(super) async fn on_response(
    driver: &mut SyncDriver,
    request: Request,
    response: Result<RpcResponse, RpcError>,
) {
    if driver.bft.requests.get(&request.peer) != Some(&request)
        || driver.bft.connections.get(&request.peer) != Some(&request.connection)
    {
        return;
    }
    driver.bft.requests.remove(&request.peer);
    let Ok(RpcResponse::BftRoundByChunk(reply)) = response else {
        return;
    };
    if let Some(certificate) = reply.round_change {
        if certificate.chunk_id != request.chunk_id {
            return;
        }
        let _ = on_message(
            driver,
            request.peer,
            BftMessage::RoundChangeCertificate(certificate),
        )
        .await;
    }
    if let Some(proposal) = reply.proposal {
        if proposal.chunk.chunk_id != request.chunk_id {
            return;
        }
        let _ = on_message(
            driver,
            request.peer,
            BftMessage::Proposal(Box::new(proposal)),
        )
        .await;
    }
}
