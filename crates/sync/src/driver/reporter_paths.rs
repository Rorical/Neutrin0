//! Dormant reporter paths refreshed from peers (design 18).
//!
//! A reporter that snapshot-bootstrapped keeps every record it retained, but
//! paths under its old count cannot follow the appends it skipped. The backend
//! names one dormant chunk at a time with its own latest endpoint; any provider
//! still holding that record's path under the same endpoint answers with an
//! anchor opening of it, which the backend checks against its stored leaf.

use super::{OutboundOutcome, SyncDriver};
use neutrin0_network::rpc::{HistoryProofRequest, RpcError, RpcRequest, RpcResponse};
use tokio::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Default)]
pub(super) struct ReporterPathSync {
    nonce: u64,
    cursor: usize,
    active: Option<u64>,
    retry_at: Option<Instant>,
}

#[derive(Clone, Debug)]
pub(super) struct Request {
    nonce: u64,
    target: HistoryProofRequest,
}

pub(super) async fn on_retry(driver: &mut SyncDriver) {
    if driver.reporter_paths.active.is_some()
        || driver
            .reporter_paths
            .retry_at
            .is_some_and(|at| Instant::now() < at)
    {
        return;
    }
    let Some(target) = driver.backend.dormant_reporter_path().await else {
        driver.reporter_paths.retry_at = Some(Instant::now() + POLL_INTERVAL);
        return;
    };
    // Archives open every path; full nodes only their record window.
    let mut peers: Vec<_> = driver
        .connected_peers
        .iter()
        .copied()
        .filter(|peer| super::metadata::is_archive(driver, peer))
        .collect();
    if peers.is_empty() || driver.reporter_paths.cursor % 2 == 1 {
        peers = driver.connected_peers.iter().copied().collect();
    }
    if peers.is_empty() {
        return;
    }
    let peer = peers[driver.reporter_paths.cursor % peers.len()];
    let Some(nonce) = driver.reporter_paths.nonce.checked_add(1) else {
        return;
    };
    driver.reporter_paths.nonce = nonce;
    driver.reporter_paths.active = Some(nonce);
    let request = Request { nonce, target };
    let callback = request.clone();
    if !driver
        .send_rpc(
            peer,
            RpcRequest::HistoryProof(request.target.clone()),
            move |_, response| OutboundOutcome::ReporterPath {
                request: callback,
                response,
            },
        )
        .await
    {
        finish(driver, &request, false);
    }
}

/// Close `request`; a peer that could not open the path is skipped next time.
fn finish(driver: &mut SyncDriver, request: &Request, refreshed: bool) {
    if driver.reporter_paths.active != Some(request.nonce) {
        return;
    }
    driver.reporter_paths.active = None;
    if !refreshed {
        driver.reporter_paths.cursor = driver.reporter_paths.cursor.wrapping_add(1);
        driver.reporter_paths.retry_at = Some(Instant::now() + POLL_INTERVAL);
    }
}

pub(super) async fn on_response(
    driver: &mut SyncDriver,
    request: Request,
    response: Result<RpcResponse, RpcError>,
) {
    let opening = match response {
        Ok(RpcResponse::HistoryProof(payload))
            if payload.proof.end_checkpoint().hash() == request.target.checkpoint_hash =>
        {
            payload.anchor
        }
        _ => None,
    };
    let refreshed = match opening {
        Some(opening) => driver.backend.refresh_reporter_path(opening).await,
        None => false,
    };
    finish(driver, &request, refreshed);
}
