//! Manifest and state requests of the snapshot bootstrap, and the
//! installation they end in.

use super::{
    BootstrapSync, Request, can_serve_manifest, manifest_provider, resume_source_replay,
    snapshot_reach,
};
use crate::driver::{OutboundOutcome, SyncDriver};
use alloc::vec::Vec;
use neutrin0_consensus_types::bootstrap::StateItems;
use neutrin0_network::{
    PeerId,
    rpc::{HistoryProofRequest, RpcRequest, RpcResponse, StateByRootRequest, Status},
};
use neutrin0_primitives::Hash;

pub(super) async fn drive(driver: &mut SyncDriver) {
    if driver.bootstrap.active.is_some() {
        return;
    }
    let Some(origin) = driver.backend.bootstrap_origin().await else {
        return;
    };
    let Ok(local) = driver.backend.local_status().await else {
        return;
    };
    let local_count = local
        .finalized_chunk_id
        .map_or(0, |id| id.saturating_add(1));
    let reach = local_count.saturating_add(snapshot_reach(local_count));
    let pending = match driver.backend.bootstrap_state().await {
        Ok(pending) => pending,
        Err(error) => {
            driver.bootstrap.fetching = true;
            driver.metrics().bootstrap_error(&error);
            tracing::warn!(%error,"cannot restore state bootstrap progress");
            return;
        }
    };
    driver.bootstrap.observed_pending = pending.is_some();
    driver
        .metrics()
        .bootstrap_pending(pending.as_ref().map_or(0, |(_, items)| items.len()));
    let origin_count = origin.boundary.next_chunk_id;
    let origin_hash = origin.hash();
    let Some((peer, status, use_manifest)) =
        select_provider(driver, pending.is_some(), reach, origin_count, origin_hash)
    else {
        return;
    };
    driver.metrics().bootstrap_target(status.finalized_chunks());
    let request = if use_manifest {
        driver
            .bootstrap
            .manifests
            .insert(peer, status.checkpoint_hash);
        Request::History {
            anchor: origin_count,
            end: status.finalized_chunks(),
            checkpoint: status.checkpoint_hash,
        }
    } else {
        let (root, mut items) = pending.expect("snapshot selected only while pending");
        // Bytes of one object come from one provider, so a content mismatch
        // blames only it: another provider, or this one after a restart,
        // fetches a partly received object again from byte zero.
        if driver.bootstrap.fragment_provider != Some(peer)
            && items.iter().any(|item| item.offset > 0)
        {
            if let Err(error) = driver.backend.restart_state_fragments(&items).await {
                driver.metrics().bootstrap_error(&error);
                tracing::warn!(%error, "cannot restart partly received state objects");
                return;
            }
            for item in &mut items {
                item.offset = 0;
            }
        }
        Request::State { root, items }
    };
    send_request(driver, peer, request).await;
}

/// The provider to ask next and whether to request its manifest rather
/// than the pending state roots.
fn select_provider(
    driver: &SyncDriver,
    pending: bool,
    reach: u64,
    origin_count: u64,
    origin_hash: Hash,
) -> Option<(PeerId, Status, bool)> {
    let now = tokio::time::Instant::now();
    let connected: Vec<(PeerId, Status)> = driver
        .bootstrap
        .peers
        .iter()
        .filter(|(peer, _)| driver.connected_peers.contains(peer))
        .map(|(peer, status)| (*peer, *status))
        .collect();
    let serves_manifest = |status: &Status| {
        status.finalized_chunks() > reach && can_serve_manifest(status, origin_count, origin_hash)
    };
    let provider = if pending {
        // A partly received object is finished from the provider that began
        // it; otherwise any provider may hold the pending roots, the fastest
        // so far first.
        let ranked = driver
            .bootstrap
            .providers
            .ranked(connected.iter().map(|(peer, _)| *peer), now);
        driver
            .bootstrap
            .fragment_provider
            .filter(|peer| !driver.bootstrap.providers.cooling(peer, now))
            .and_then(|peer| connected.iter().find(|(connected, _)| *connected == peer))
            .or_else(|| {
                ranked
                    .first()
                    .and_then(|first| connected.iter().find(|(peer, _)| peer == first))
            })
            .copied()
    } else {
        manifest_provider(
            &driver.bootstrap.providers,
            connected.iter().copied().filter(|(peer, status)| {
                !driver.bootstrap.providers.cooling(peer, now) && serves_manifest(status)
            }),
        )
    };
    // A lost or expired snapshot can resume at a newer authenticated endpoint.
    // Try each advertised manifest once, even from a provider backed off for
    // the old roots; an unavailable root cannot busy-loop.
    match provider {
        Some((peer, status)) => Some((peer, status, !pending)),
        None if pending => {
            let (peer, status) = manifest_provider(
                &driver.bootstrap.providers,
                connected.iter().copied().filter(|(peer, status)| {
                    driver.bootstrap.manifests.get(peer) != Some(&status.checkpoint_hash)
                        && serves_manifest(status)
                }),
            )?;
            Some((peer, status, true))
        }
        None => None,
    }
}

async fn send_request(driver: &mut SyncDriver, peer: PeerId, request: Request) {
    let manifest = matches!(request, Request::History { .. });
    let rpc = match &request {
        Request::History {
            anchor,
            end,
            checkpoint,
        } => RpcRequest::HistoryProof(HistoryProofRequest {
            anchor_chunks: *anchor,
            end_chunks: *end,
            checkpoint_hash: *checkpoint,
            bootstrap: true,
        }),
        Request::State { root, items } => {
            let Ok(items) = StateItems::new(items.clone()) else {
                return;
            };
            RpcRequest::StateByRoot(StateByRootRequest {
                state_root: *root,
                items,
            })
        }
    };
    let Some(nonce) = driver.bootstrap.nonce.checked_add(1) else {
        return;
    };
    driver.bootstrap.nonce = nonce;
    let kind = request.metric_kind();
    driver.bootstrap.active = Some((peer, nonce, kind));
    driver.bootstrap.sent_at = Some(tokio::time::Instant::now());
    driver.metrics().bootstrap_request(kind);
    let sent = driver
        .send_rpc(peer, rpc, move |peer, response| {
            OutboundOutcome::Bootstrap {
                peer,
                nonce,
                request,
                response,
            }
        })
        .await;
    if !sent {
        driver.bootstrap.active = None;
        driver.metrics().bootstrap_transport_error(kind);
        return;
    }
    // Enter the fetch barrier only once a manifest request is outstanding:
    // every early return above leaves both the local flag and the backend
    // untouched. Its response is handled by this task after this returns, so
    // the barrier still precedes any bootstrap installation.
    if manifest {
        driver.bootstrap.fetching = true;
        driver.backend.bootstrap_fetch(true).await;
    }
}

pub(in crate::driver) async fn on_response(
    driver: &mut SyncDriver,
    peer: PeerId,
    nonce: u64,
    request: Request,
    response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
) {
    if !matches!(driver.bootstrap.active, Some((owner, active, _)) if owner == peer && active == nonce)
        || !driver.connected_peers.contains(&peer)
    {
        return;
    }
    driver.bootstrap.active = None;
    let kind = request.metric_kind();
    let transport_failed = response
        .as_ref()
        .is_err_and(neutrin0_network::rpc::RpcError::is_transport);
    let state_entries = match &response {
        Ok(RpcResponse::StateByRoot(payload)) => payload.entries.len(),
        _ => 0,
    };
    let result = import_response(driver, request, response).await;
    if transport_failed {
        driver.metrics().bootstrap_transport_error(kind);
    } else {
        driver.metrics().bootstrap_result(kind, &result);
    }
    if let Ok(progress) = &result {
        driver.bootstrap.observed_pending = !progress.root_complete;
        driver
            .metrics()
            .bootstrap_pending(progress.next_items.len());
        driver.metrics().bootstrap_state_entries(state_entries);
    }
    match result {
        Ok(progress) if progress.root_complete => complete_installation(driver).await,
        Ok(progress) => {
            if let Some(sent_at) = driver.bootstrap.sent_at {
                driver.bootstrap.providers.served(peer, sent_at.elapsed());
            }
            driver.bootstrap.fragment_provider = progress
                .next_items
                .iter()
                .any(|item| item.offset > 0)
                .then_some(peer);
            drive(driver).await;
        }
        Err(error) => {
            tracing::warn!(%error,%peer,"bootstrap provider failed; retaining authenticated download progress");
            let now = tokio::time::Instant::now();
            driver.bootstrap.fragment_provider = None;
            driver.bootstrap.providers.failed(peer, now);
            drive(driver).await;
            resume_source_replay(driver).await;
        }
    }
}

/// Verify one bootstrap reply against the request that named it and hand
/// the authenticated payload to the backend.
async fn import_response(
    driver: &SyncDriver,
    request: Request,
    response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
) -> Result<crate::backend::StateProgress, crate::SyncBackendError> {
    match (request, response) {
        (
            Request::History {
                end, checkpoint, ..
            },
            Ok(RpcResponse::HistoryProof(payload)),
        ) => {
            let neutrin0_network::rpc::HistoryProofResponse {
                proof,
                anchor,
                bootstrap,
            } = *payload;
            if proof.end_checkpoint().hash() != checkpoint || proof.end().next_chunk_id != end {
                Err(crate::SyncBackendError::Rejected(
                    "bootstrap endpoint differs from request".into(),
                ))
            } else if let Some(data) = bootstrap {
                if data.history == proof {
                    driver.backend.begin_bootstrap(anchor, data).await
                } else {
                    Err(crate::SyncBackendError::Rejected(
                        "bootstrap context names another History proof".into(),
                    ))
                }
            } else {
                Err(crate::SyncBackendError::NotAvailable(
                    "provider did not supply bootstrap context".into(),
                ))
            }
        }
        (Request::State { root, items }, Ok(RpcResponse::StateByRoot(payload))) => {
            driver
                .backend
                .import_state_nodes(root, items, payload.entries.to_vec())
                .await
        }
        (_, other) => Err(crate::SyncBackendError::NotAvailable(format!(
            "bootstrap response unavailable: {other:?}"
        ))),
    }
}

/// Adopt the installed snapshot: every phase restarts from the new local
/// boundary and each connected peer is handshaken again.
async fn complete_installation(driver: &mut SyncDriver) {
    driver.metrics().bootstrap_installed();
    driver.bootstrap = BootstrapSync {
        nonce: driver.bootstrap.nonce,
        ..BootstrapSync::default()
    };
    crate::driver::full_chunk::reset_after_bootstrap(driver);
    crate::driver::candidates::reset_after_bootstrap(driver);
    crate::driver::bft::reset_after_bootstrap(driver);
    crate::driver::availability::reset_after_bootstrap(driver);
    // Refresh canonical cursors only after the engine's atomic installation.
    if let Ok(progress) = driver.backend.local_progress().await {
        driver.fsm.refresh_local_progress(progress);
    }
    driver.reset_and_rehandshake().await;
}
