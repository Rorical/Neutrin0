//! Choosing the next bounded block page or finality fetch and the provider
//! that serves it.

use super::{Cursor, Step, response::release_request};
use crate::driver::{OutboundOutcome, SyncDriver};
use neutrin0_network::{
    PeerId,
    rpc::{BlocksByRangeRequest, ChunkProofByIdRequest, RpcRequest, Status},
};

/// Ask the provider that has served fastest, a peer never asked first,
/// skipping `except` and any backed off. A peer's advertised height alone
/// never keeps the request with it.
pub(super) async fn request_best(driver: &mut SyncDriver, except: Option<PeerId>) {
    let ranked = driver.full_chunks.providers.ranked(
        driver
            .full_chunks
            .peers
            .keys()
            .copied()
            .filter(|peer| Some(*peer) != except),
        tokio::time::Instant::now(),
    );
    for peer in ranked {
        if driver.full_chunks.in_flight {
            return;
        }
        request_next(driver, peer).await;
    }
}

async fn request_next(driver: &mut SyncDriver, peer: PeerId) {
    if driver
        .full_chunks
        .providers
        .cooling(&peer, tokio::time::Instant::now())
    {
        return;
    }
    let Some(connection) = driver.full_chunks.connections.get(&peer).copied() else {
        return;
    };
    let Some(remote) = driver.full_chunks.peers.get(&peer).copied() else {
        return;
    };
    let Ok(Some(target)) = driver.backend.consensus_sync_target().await else {
        return;
    };
    if driver
        .full_chunks
        .retained_from_chunk
        .get(&peer)
        .is_some_and(|floor| target.chunk_id < *floor)
    {
        return;
    }
    let Ok(local) = driver.backend.local_status().await else {
        return;
    };
    if local.finalized_chunk_id.is_some_and(|id| {
        remote
            .finalized_chunk_id
            .is_none_or(|remote_id| remote_id < id)
    }) {
        return;
    }
    let proven_height = driver
        .backend
        .local_progress()
        .await
        .map_or(0, |progress| progress.proven_height);
    let next_block = advance_cursor(driver, peer, target, remote.head_block_hash, proven_height);
    let available = driver
        .backend
        .certified_execution_sync_height()
        .await
        .unwrap_or(target.end_height)
        .max(target.end_height)
        .min(remote.head_height);
    let Some((request, step)) = select_step(target, remote, next_block, available) else {
        return;
    };
    send_request(driver, peer, connection, request, step).await;
}

/// Re-point `peer`'s cursor at `target` along the provider's advertised head
/// and return the next height still to download.
fn advance_cursor(
    driver: &mut SyncDriver,
    peer: PeerId,
    target: crate::backend::ConsensusSyncTarget,
    head_block_hash: [u8; 32],
    proven_height: u64,
) -> u64 {
    let cursor = driver
        .full_chunks
        .cursors
        .entry(peer)
        .or_insert_with(|| Cursor::new(target, head_block_hash));
    if cursor.chunk_id == target.chunk_id {
        // A provider's head moves with every block. Blocks already fetched
        // stay valid while the new head extends them; a page that no longer
        // links to them resets this cursor instead.
        cursor.head_block_hash = head_block_hash;
    } else {
        *cursor = Cursor::new(target, head_block_hash);
    }
    // Blocks this node already proved, from gossip or an earlier page, are
    // never fetched again.
    cursor.next_block = cursor.next_block.max(proven_height.saturating_add(1));
    cursor.next_block
}

/// The one request `target` needs from `remote` next: its chunk proof once
/// every block is held, else the next block page within `available`.
fn select_step(
    target: crate::backend::ConsensusSyncTarget,
    remote: Status,
    next_block: u64,
    available: u64,
) -> Option<(RpcRequest, Step)> {
    let finality_ready = next_block > target.end_height
        && remote
            .finalized_chunk_id
            .is_some_and(|id| id >= target.chunk_id);
    if finality_ready {
        return Some((
            RpcRequest::ChunkProofById(ChunkProofByIdRequest {
                chunk_ids: vec![target.chunk_id],
                statement_keys: Vec::new(),
            }),
            Step::Finality(target.chunk_id),
        ));
    }
    if next_block > available {
        return None;
    }
    let (count, end) = crate::driver::page(
        next_block,
        available,
        neutrin0_network::rpc::MAX_BLOCKS_PER_RESPONSE,
    );
    Some((
        RpcRequest::BlocksByRange(BlocksByRangeRequest {
            head_block_hash: remote.head_block_hash,
            start_height: next_block,
            count,
        }),
        Step::Blocks {
            head: remote.head_block_hash,
            start: next_block,
            end,
        },
    ))
}

async fn send_request(
    driver: &mut SyncDriver,
    peer: PeerId,
    connection: u64,
    request: RpcRequest,
    step: Step,
) {
    tracing::debug!(%peer, ?step, "requesting complete chunk data");
    driver.full_chunks.in_flight = true;
    driver.full_chunks.active_request = Some((peer, connection, step));
    driver.full_chunks.sent_at = Some(tokio::time::Instant::now());
    driver.metrics().full_chunk_request(step.metric_kind());
    let sent = driver
        .send_rpc(peer, request, move |peer, response| {
            OutboundOutcome::Consensus {
                peer,
                connection,
                step,
                response,
            }
        })
        .await;
    if !sent {
        driver
            .metrics()
            .full_chunk_transport_error(step.metric_kind());
        release_request(driver, peer, connection, step);
    }
}
