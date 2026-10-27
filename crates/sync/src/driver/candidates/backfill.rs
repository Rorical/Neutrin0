//! Download rounds for discovered targets: quorum queries, block pages,
//! execution certificates and the votes released once a branch is held.

use super::{MAX_VOTE_BYTES, Request, Step, record_hint};
use crate::driver::{OutboundOutcome, SyncDriver};
use alloc::collections::BTreeSet;
use neutrin0_network::{
    PeerId,
    rpc::{BlocksByRangeRequest, FinalityCertByChunkRequest, RpcError, RpcRequest, RpcResponse},
};
use neutrin0_primitives::Hash;

async fn reconcile(driver: &mut SyncDriver) {
    let Ok(Some(current)) = driver.backend.consensus_sync_target().await else {
        return;
    };
    driver
        .candidates
        .targets
        .retain(|target| target.candidate.chunk.chunk_id == current.chunk_id);
    driver
        .candidates
        .votes
        .retain(|(_, vote)| vote.data.chunk_id == current.chunk_id);
    driver.candidates.vote_bytes = driver
        .candidates
        .votes
        .iter()
        .map(|(_, vote)| borsh::object_length(vote).unwrap_or(MAX_VOTE_BYTES))
        .sum();
}

pub(super) async fn drive(driver: &mut SyncDriver) {
    if driver.candidates.active.is_some()
        || driver.fsm.mode() == neutrin0_network::SyncMode::LightClient
    {
        return;
    }
    reconcile(driver).await;
    finish_ready(driver).await;
    let payload = next_payload(driver);
    if (driver.candidates.query_turn || payload.is_none())
        && let Some((peer, query)) = driver.candidates.queries.pop()
    {
        driver.candidates.query_turn = false;
        send(
            driver,
            peer,
            Step::Query(query),
            RpcRequest::CandidateByChunk(query),
        )
        .await;
        return;
    }
    if let Some((peer, step, rpc)) = payload {
        // Keep advancing a known branch even if availability hints keep the
        // discovery queue continuously nonempty.
        driver.candidates.query_turn = true;
        // Repeated availability from an unsuccessful provider cannot hold the
        // first target indefinitely ahead of an obtainable quorum dependency.
        if let Step::Blocks { hash, .. } | Step::Certificate { hash, .. } = step
            && let Some(index) = driver
                .candidates
                .targets
                .iter()
                .position(|target| target.candidate.chunk.hash() == hash)
        {
            let attempted = driver.candidates.targets.remove(index);
            driver.candidates.targets.push(attempted);
        }
        send(driver, peer, step, rpc).await;
    }
}

fn next_payload(driver: &SyncDriver) -> Option<(PeerId, Step, RpcRequest)> {
    let available: BTreeSet<_> = driver.candidates.connections.keys().copied().collect();
    for target in &driver.candidates.targets {
        if target.blocks_complete && !driver.backend.supports_certified_execution_sync() {
            continue;
        }
        let provider = target
            .providers
            .iter()
            .chain(available.iter())
            .copied()
            .find(|peer| available.contains(peer) && !target.tried.contains(peer));
        let Some(peer) = provider else {
            continue;
        };
        let head = target.candidate.chunk.end_block_hash;
        let hash = target.candidate.chunk.hash();
        let (step, rpc) = if target.blocks_complete {
            let chunk_id = target.candidate.chunk.chunk_id;
            (
                Step::Certificate { hash, chunk_id },
                RpcRequest::FinalityCertByChunk(FinalityCertByChunkRequest {
                    chunk_ids: vec![chunk_id],
                }),
            )
        } else {
            let start = target.next_block;
            let (count, end) = crate::driver::page(
                start,
                target.candidate.chunk.end_height,
                neutrin0_network::rpc::MAX_BLOCKS_PER_RESPONSE,
            );
            (
                Step::Blocks { hash, start, end },
                RpcRequest::BlocksByRange(BlocksByRangeRequest {
                    head_block_hash: head,
                    start_height: start,
                    count,
                }),
            )
        };
        return Some((peer, step, rpc));
    }
    None
}

async fn send(driver: &mut SyncDriver, peer: PeerId, step: Step, rpc: RpcRequest) {
    let Some(connection) = driver.candidates.connections.get(&peer).copied() else {
        return;
    };
    let Some(nonce) = driver.candidates.nonce.checked_add(1) else {
        return;
    };
    driver.candidates.nonce = nonce;
    let request = Request {
        peer,
        connection,
        nonce,
        step,
    };
    driver.candidates.active = Some(request);
    if !driver
        .send_rpc(peer, rpc, move |_, response| OutboundOutcome::Candidate {
            request,
            response,
        })
        .await
    {
        driver.candidates.active = None;
    }
}

async fn finish_ready(driver: &mut SyncDriver) {
    let ready: Vec<_> = driver
        .candidates
        .targets
        .iter()
        .filter(|target| target.blocks_complete && !target.considered)
        .map(|target| target.candidate.clone())
        .collect();
    for candidate in ready {
        if driver
            .backend
            .consider_bft_candidate(candidate.clone())
            .await
            .is_err()
        {
            continue;
        }
        let hash = candidate.chunk.hash();
        if driver.backend.supports_certified_execution_sync() {
            if let Some(target) = driver
                .candidates
                .targets
                .iter_mut()
                .find(|target| target.candidate.chunk.hash() == hash)
            {
                target.considered = true;
            }
        } else {
            driver
                .candidates
                .targets
                .retain(|target| target.candidate.chunk.hash() != hash);
        }
        let votes = core::mem::take(&mut driver.candidates.votes);
        for (subnet, vote) in votes {
            if vote.data.chunk_hash != hash {
                driver.candidates.votes.push((subnet, vote));
                continue;
            }
            if let Some(subnet) = subnet {
                let _ = driver
                    .backend
                    .ingest_aggregate_finality_vote(subnet, vote)
                    .await;
            } else {
                let _ = driver.backend.ingest_finality_vote(vote).await;
            }
        }
        driver.candidates.vote_bytes = driver
            .candidates
            .votes
            .iter()
            .map(|(_, vote)| borsh::object_length(vote).unwrap_or(MAX_VOTE_BYTES))
            .sum();
    }
    crate::driver::bft::retry_pending(driver).await;
}

pub(in crate::driver) async fn on_response(
    driver: &mut SyncDriver,
    request: Request,
    response: Result<RpcResponse, RpcError>,
) {
    if driver.candidates.active != Some(request)
        || driver.candidates.connections.get(&request.peer) != Some(&request.connection)
    {
        return;
    }
    driver.candidates.active = None;
    let accepted = match (request.step, response) {
        (Step::Query(query), Ok(RpcResponse::CandidateByChunk(reply))) => {
            reply.candidate.chunk.chunk_id == query.chunk_id
                && query
                    .chunk_hash
                    .is_none_or(|hash| reply.candidate.chunk.hash() == hash)
                && record_hint(driver, request.peer, reply.candidate).await
        }
        (Step::Blocks { hash, start, end }, Ok(RpcResponse::BlocksByRange(reply))) => {
            import_blocks(driver, hash, start, end, reply.blocks).await
        }
        (Step::Certificate { hash, chunk_id }, Ok(RpcResponse::FinalityCertByChunk(mut reply))) => {
            if reply.certs.len() == 1
                && reply.certs[0].chunk_id == chunk_id
                && reply.certs[0].chunk_hash == hash
                && driver
                    .backend
                    .verify_and_import_execution_certificate(reply.certs.remove(0))
                    .await
                    .is_ok()
            {
                driver
                    .candidates
                    .targets
                    .retain(|target| target.candidate.chunk.hash() != hash);
                true
            } else {
                false
            }
        }
        _ => false,
    };
    if !accepted {
        let hash = match request.step {
            Step::Blocks { hash, .. } | Step::Certificate { hash, .. } => Some(hash),
            Step::Query(_) => None,
        };
        if let Some(target) = driver
            .candidates
            .targets
            .iter_mut()
            .find(|target| Some(target.candidate.chunk.hash()) == hash)
            && target.tried.len() < crate::driver::HISTORY_PROVIDER_ATTEMPT_LIMIT
        {
            target.tried.insert(request.peer);
        }
    }
    drive(driver).await;
}

async fn import_blocks(
    driver: &mut SyncDriver,
    hash: Hash,
    start: u64,
    end: u64,
    blocks: Vec<neutrin0_consensus_types::ProvenBlock>,
) -> bool {
    let Some(target) = driver
        .candidates
        .targets
        .iter()
        .find(|target| target.candidate.chunk.hash() == hash)
    else {
        return false;
    };
    let Some(returned_end) = u64::try_from(blocks.len())
        .ok()
        .filter(|count| *count > 0)
        .and_then(|count| start.checked_add(count - 1))
        .filter(|last| *last <= end)
    else {
        return false;
    };
    if target.next_block != start || target.blocks_complete {
        return false;
    }
    let mut previous = start
        .checked_sub(1)
        .and_then(|height| target.hashes.get(&height))
        .copied();
    let mut hashes = Vec::new();
    for (height, block) in (start..=returned_end).zip(&blocks) {
        let block_hash = block.block.hash();
        if block.block.header.height != height
            || previous.is_some_and(|parent| block.block.header.parent_hash != parent)
            || (height == target.candidate.chunk.start_height
                && block_hash != target.candidate.chunk.start_block_hash)
            || (height == target.candidate.chunk.end_height
                && block_hash != target.candidate.chunk.end_block_hash)
        {
            return false;
        }
        hashes.push((height, block_hash));
        previous = Some(block_hash);
    }
    if driver
        .backend
        .verify_and_import_proven_blocks(blocks)
        .await
        .is_err()
    {
        return false;
    }
    let target = driver
        .candidates
        .targets
        .iter_mut()
        .find(|target| target.candidate.chunk.hash() == hash)
        .expect("target retained during await");
    target.hashes.extend(hashes);
    target.next_block = returned_end.saturating_add(1);
    target.blocks_complete = returned_end == target.candidate.chunk.end_height;
    true
}
