//! Program artifacts fetched from peers by identity (design 20).
//!
//! The backend names one artifact it needs at a time: a runtime by its code
//! hash or a Guest by its verifying key, retrieved through the `StateByRoot`
//! program namespaces snapshot bootstrap already uses. Providers serve these
//! independently of any state root, so the request names none. The backend
//! accepts the assembled bytes only when their runtime hash or locally
//! derived key is the one it asked for.

use super::{OutboundOutcome, SyncDriver, providers::Providers};
use alloc::collections::BTreeSet;
use neutrin0_consensus_types::bootstrap::{StateItem, StateItemKind, StateItems};
use neutrin0_network::{
    PeerId,
    rpc::{RpcError, RpcRequest, RpcResponse, StateByRootRequest},
};
use neutrin0_primitives::{Hash, ZERO_HASH};
use tokio::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Default)]
pub(super) struct ProgramSync {
    nonce: u64,
    active: Option<u64>,
    retry_at: Option<Instant>,
    /// Fragments go to the fastest provider not backed off, a peer never
    /// asked first, so a slow or failing one loses the fetch.
    providers: Providers,
    /// The artifact being assembled and the peers that served its bytes.
    assembly: Option<(StateItemKind, Hash)>,
    contributors: BTreeSet<PeerId>,
}

#[derive(Clone, Debug)]
pub(super) struct Request {
    nonce: u64,
    peer: PeerId,
    item: StateItem,
    sent_at: Instant,
}

pub(super) async fn on_retry(driver: &mut SyncDriver) {
    if driver.programs.active.is_some()
        || driver
            .programs
            .retry_at
            .is_some_and(|at| Instant::now() < at)
    {
        return;
    }
    let Some(item) = driver.backend.wanted_program_fragment().await else {
        driver.programs.retry_at = Some(Instant::now() + POLL_INTERVAL);
        return;
    };
    let now = Instant::now();
    let identity = (item.kind, item.hash);
    if driver.programs.assembly != Some(identity) {
        driver.programs.assembly = Some(identity);
        driver.programs.contributors.clear();
    } else if item.offset == 0 {
        // The backend restarted this artifact: its bytes did not reproduce
        // the identity, or never installed. Every peer that served them
        // backs off, so the next assembly comes from others.
        for peer in core::mem::take(&mut driver.programs.contributors) {
            driver.programs.providers.failed(peer, now);
        }
    }
    let ranked = driver
        .programs
        .providers
        .ranked(driver.connected_peers.iter().copied(), now);
    let Some(&peer) = ranked.first() else {
        driver.programs.retry_at = Some(now + POLL_INTERVAL);
        return;
    };
    let Some(nonce) = driver.programs.nonce.checked_add(1) else {
        return;
    };
    let Ok(items) = StateItems::new(vec![item]) else {
        return;
    };
    driver.programs.nonce = nonce;
    driver.programs.active = Some(nonce);
    let request = Request {
        nonce,
        peer,
        item,
        sent_at: now,
    };
    let callback = request.clone();
    if !driver
        .send_rpc(
            peer,
            RpcRequest::StateByRoot(StateByRootRequest {
                state_root: ZERO_HASH,
                items,
            }),
            move |_, response| OutboundOutcome::ProgramFragment {
                request: callback,
                response,
            },
        )
        .await
    {
        finish(driver, &request, false);
    }
}

/// Close `request`; a peer that failed it backs off.
fn finish(driver: &mut SyncDriver, request: &Request, served: bool) {
    if driver.programs.active != Some(request.nonce) {
        return;
    }
    driver.programs.active = None;
    if served {
        driver
            .programs
            .providers
            .served(request.peer, request.sent_at.elapsed());
        driver.programs.contributors.insert(request.peer);
    } else {
        driver
            .programs
            .providers
            .failed(request.peer, Instant::now());
        driver.programs.retry_at = Some(Instant::now() + POLL_INTERVAL);
    }
}

pub(super) async fn on_response(
    driver: &mut SyncDriver,
    request: Request,
    response: Result<RpcResponse, RpcError>,
) {
    let entry = match response {
        Ok(RpcResponse::StateByRoot(reply)) => reply.entries.first().cloned(),
        _ => None,
    };
    let served = match entry {
        Some(entry) if entry.validate_for(&request.item) => {
            driver.backend.import_program_fragment(entry).await
        }
        _ => false,
    };
    finish(driver, &request, served);
}
