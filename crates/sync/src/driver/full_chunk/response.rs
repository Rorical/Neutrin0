//! Applying a provider's block page or chunk proof and deciding whether it
//! keeps serving.

use super::{Step, request::request_best};
use crate::backend::SyncBackendError;
use crate::driver::SyncDriver;
use neutrin0_network::{
    PeerId,
    rpc::{RpcError, RpcFailure, RpcResponse},
};

fn record_pruning_floor(
    driver: &mut SyncDriver,
    peer: PeerId,
    connection: u64,
    response: &Result<RpcResponse, RpcError>,
) -> bool {
    let Err(RpcError::Remote(RpcFailure::Pruned {
        retained_from_chunk,
        ..
    })) = response
    else {
        return false;
    };
    if driver.full_chunks.connections.get(&peer).copied() == Some(connection) {
        driver
            .full_chunks
            .retained_from_chunk
            .insert(peer, *retained_from_chunk);
    }
    true
}

pub(super) fn release_request(
    driver: &mut SyncDriver,
    peer: PeerId,
    connection: u64,
    step: Step,
) -> bool {
    if driver.full_chunks.connections.get(&peer).copied() != Some(connection)
        || driver.full_chunks.active_request != Some((peer, connection, step))
    {
        return false;
    }
    driver.full_chunks.active_request = None;
    driver.full_chunks.in_flight = false;
    true
}

pub(in crate::driver) async fn on_response(
    driver: &mut SyncDriver,
    peer: PeerId,
    connection: u64,
    step: Step,
    response: Result<RpcResponse, RpcError>,
) {
    if !release_request(driver, peer, connection, step) {
        return;
    }
    driver.full_chunks.observation = None;
    if matches!(response, Err(RpcError::LocalOverloaded)) {
        // Local pressure is not a provider failure. Keep its cursor; the
        // independent Status tick retries without a provider cooldown.
        return;
    }
    if record_pruning_floor(driver, peer, connection, &response) {
        driver.metrics().full_chunk_pruned(step.metric_kind());
        return;
    }
    let transport_failed = response.as_ref().is_err_and(RpcError::is_transport);
    let mut advance = None;
    let mut downloaded = Vec::new();
    // An empty proven page leaves the cursor where it is.
    let mut keep_cursor = false;
    if let Err(error) = &response {
        tracing::debug!(%peer, ?step, ?error, "complete chunk RPC failed");
    }
    let result = match (step, response) {
        (Step::Blocks { head, start, end }, Ok(RpcResponse::BlocksByRange(payload)))
            if blocks_match(driver, peer, head, start, end, &payload.blocks) =>
        {
            let (next, hashes) = page_extent(&payload.blocks);
            downloaded = hashes;
            advance = Some((head, next));
            import_block_page(driver, peer, payload).await
        }
        (Step::Blocks { .. }, Ok(RpcResponse::BlocksByRange(payload)))
            if payload.blocks.is_empty() =>
        {
            // Nothing is proven past the cursor yet: receipts are still in
            // flight. Its candidates keep the pending chain current.
            keep_cursor = true;
            import_trailing_candidates(driver, peer, payload.candidates).await;
            Err(SyncBackendError::NotAvailable(
                "no proven blocks past the cursor yet".to_owned(),
            ))
        }
        (Step::Finality(id), Ok(RpcResponse::ChunkProofById(payload)))
            if payload.proofs.len() == 1 =>
        {
            import_finality_response(driver, peer, id, payload).await
        }
        _ => Err(SyncBackendError::NotAvailable(
            "missing or mismatched consensus sync response".to_owned(),
        )),
    };
    record_response_result(driver, step, transport_failed, &result);
    // Only proven misbehaviour or an unreachable provider cools it down. An
    // honest provider can lag, reorganize or hold only candidates; its cursor
    // restarts and the next status tick retries it.
    if !transport_failed
        && let Err(error) = &result
        && !matches!(error, SyncBackendError::Rejected(_))
    {
        if !keep_cursor {
            driver.full_chunks.cursors.remove(&peer);
        }
        driver.full_chunks.providers.unproductive(peer);
        tracing::debug!(%peer, ?step, %error, "complete chunk provider has nothing usable yet");
        return;
    }
    continue_after_response(driver, peer, advance, downloaded, &result).await;
}

/// The height past a non-empty page and the `(height, hash)` of every block
/// it supplied.
fn page_extent(blocks: &[neutrin0_consensus_types::ProvenBlock]) -> (u64, Vec<(u64, [u8; 32])>) {
    let next = blocks
        .last()
        .expect("nonempty checked")
        .block
        .header
        .height
        .saturating_add(1);
    let downloaded = blocks
        .iter()
        .map(|block| (block.block.header.height, block.block.hash()))
        .collect();
    (next, downloaded)
}

async fn import_block_page(
    driver: &SyncDriver,
    peer: PeerId,
    payload: neutrin0_network::rpc::BlocksByRangeResponse,
) -> Result<(), SyncBackendError> {
    let imported = driver
        .backend
        .verify_and_import_proven_blocks(payload.blocks)
        .await
        .map(|_| ());
    // Candidates past the proven page keep the pending chain current;
    // they never gate the complete chunk sync they follow.
    if imported.is_ok() {
        import_trailing_candidates(driver, peer, payload.candidates).await;
    }
    imported
}

/// Credit a served page and move on to the best provider, or back this one
/// off after proven misbehaviour or an unreachable connection.
async fn continue_after_response(
    driver: &mut SyncDriver,
    peer: PeerId,
    advance: Option<([u8; 32], u64)>,
    downloaded: Vec<(u64, [u8; 32])>,
    result: &Result<(), SyncBackendError>,
) {
    if result.is_ok() {
        record_progress(driver, peer, advance, downloaded);
        // The next page goes to whoever has served fastest, which is this
        // provider only while no other has been faster.
        request_best(driver, None).await;
    } else {
        driver
            .full_chunks
            .providers
            .failed(peer, tokio::time::Instant::now());
        tracing::debug!(?result, "complete chunk provider backing off");
        request_best(driver, Some(peer)).await;
    }
}

/// Credit `peer` with a served request and move its cursor past the blocks
/// it supplied along `head`.
fn record_progress(
    driver: &mut SyncDriver,
    peer: PeerId,
    advance: Option<([u8; 32], u64)>,
    downloaded: Vec<(u64, [u8; 32])>,
) {
    if let Some(sent_at) = driver.full_chunks.sent_at {
        driver.full_chunks.providers.served(peer, sent_at.elapsed());
    }
    if let Some((head, next)) = advance
        && let Some(cursor) = driver
            .full_chunks
            .cursors
            .get_mut(&peer)
            .filter(|cursor| cursor.head_block_hash == head)
    {
        cursor.blocks.extend(downloaded);
        cursor.next_block = next;
    }
}

async fn import_trailing_candidates(
    driver: &SyncDriver,
    peer: PeerId,
    candidates: Vec<neutrin0_consensus_types::CandidateBlock>,
) {
    if !candidates.is_empty()
        && let Err(error) = driver
            .backend
            .verify_and_import_candidates(candidates)
            .await
    {
        tracing::debug!(%peer, ?error, "candidate page not imported");
    }
}

fn record_response_result(
    driver: &SyncDriver,
    step: Step,
    transport_failed: bool,
    result: &Result<(), SyncBackendError>,
) {
    if transport_failed {
        driver
            .metrics()
            .full_chunk_transport_error(step.metric_kind());
    } else {
        driver
            .metrics()
            .full_chunk_result(step.metric_kind(), result);
    }
}

async fn import_finality_response(
    driver: &SyncDriver,
    peer: PeerId,
    id: u64,
    payload: neutrin0_network::rpc::ChunkProofByIdResponse,
) -> Result<(), SyncBackendError> {
    let proof = payload.proofs.into_iter().next().expect("length checked");
    if proof.chunk_id == id
        && driver.full_chunks.cursors.get(&peer).is_some_and(|cursor| {
            cursor.chunk_id == id
                // An end block proven locally from gossip was never paged;
                // the backend then checks the proof against its own chain.
                && cursor
                    .blocks
                    .get(&proof.public_inputs.end_height)
                    .is_none_or(|hash| *hash == proof.public_inputs.end_block_hash)
        })
        && driver.full_chunks.peers.get(&peer).is_some_and(|status| {
            status.finalized_chunk_id != Some(id) || status.finalized_chunk_hash == proof.chunk_hash
        })
    {
        driver
            .backend
            .verify_and_import_chunk_proof(proof, peer)
            .await
            .map(|_| ())
    } else {
        // The provider's head or branch moved past this cursor.
        Err(SyncBackendError::NotAvailable(
            "chunk proof does not close the downloaded branch".to_owned(),
        ))
    }
}

fn blocks_match(
    driver: &SyncDriver,
    peer: PeerId,
    head: [u8; 32],
    start: u64,
    end: u64,
    blocks: &[neutrin0_consensus_types::ProvenBlock],
) -> bool {
    !blocks.is_empty()
        && blocks.iter().enumerate().all(|(offset, block)| {
            u64::try_from(offset)
                .ok()
                .and_then(|offset| start.checked_add(offset))
                == Some(block.block.header.height)
                && block.block.header.height <= end
        })
        && blocks
            .windows(2)
            .all(|pair| pair[1].block.header.parent_hash == pair[0].block.hash())
        && driver.full_chunks.cursors.get(&peer).is_some_and(|cursor| {
            cursor.head_block_hash == head
                && blocks.first().is_some_and(|block| {
                    cursor
                        .blocks
                        .get(&start.saturating_sub(1))
                        .is_none_or(|parent| block.block.header.parent_hash == *parent)
                })
        })
        && driver.full_chunks.peers.get(&peer).is_some_and(|status| {
            blocks.last().is_some_and(|block| {
                block.block.header.height != status.head_height || block.block.hash() == head
            })
        })
}
