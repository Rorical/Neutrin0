//! Pending-pool repair independent of gossip mesh membership and message caching.

use super::{OutboundOutcome, SyncDriver, providers::Providers};
use alloc::collections::{BTreeMap, VecDeque};
use neutrin0_network::{
    PeerId,
    rpc::{
        MAX_TRANSACTION_BYTES, MAX_TRANSACTION_INVENTORY, MAX_TRANSACTIONS_PER_REQUEST, RpcError,
        RpcRequest, RpcResponse, Status, TransactionInventoryRequest, TransactionsByHashRequest,
    },
};
use neutrin0_primitives::{Hash, blake3_256};
use tokio::time::{Duration, Instant};

const MAX_PEERS: usize = 256;
const MAX_ACTIVE: usize = 4;
const POLL_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Default)]
pub(super) struct TransactionSync {
    peers: BTreeMap<PeerId, Peer>,
    /// A peer whose bodies were all refused backs off, across reconnects, so
    /// none can keep this node validating junk; a useful page clears it.
    providers: Providers,
    nonce: u64,
    cursor: usize,
}

struct Peer {
    same_chain: bool,
    after: Option<Hash>,
    missing: VecDeque<Hash>,
    active: Option<u64>,
    retry_at: Instant,
}

#[derive(Clone, Debug)]
pub(super) struct Request {
    peer: PeerId,
    nonce: u64,
    step: Step,
}

#[derive(Clone, Debug)]
enum Step {
    Inventory(Option<Hash>),
    Bodies(Vec<Hash>),
}

pub(super) fn on_connect(driver: &mut SyncDriver, peer: PeerId) {
    if driver.transactions.peers.len() < MAX_PEERS {
        driver.transactions.peers.insert(
            peer,
            Peer {
                same_chain: false,
                after: None,
                missing: VecDeque::new(),
                active: None,
                retry_at: Instant::now(),
            },
        );
    }
}

pub(super) fn on_disconnect(driver: &mut SyncDriver, peer: PeerId) {
    // Nonces never reset, so callbacks from an earlier connection cannot
    // complete a new request to the same peer after reconnection.
    driver.transactions.peers.remove(&peer);
}

pub(super) async fn on_status(driver: &mut SyncDriver, peer: PeerId, status: Status) {
    if !driver.backend.supports_transaction_sync() {
        return;
    }
    let Ok(local) = driver.backend.local_status().await else {
        return;
    };
    if let Some(state) = driver.transactions.peers.get_mut(&peer) {
        state.same_chain = super::same_chain(&local, &status);
    }
    drive(driver, peer).await;
}

pub(super) async fn on_retry(driver: &mut SyncDriver) {
    if !driver.backend.supports_transaction_sync() {
        return;
    }
    let peers: Vec<_> = driver.transactions.peers.keys().copied().collect();
    if peers.is_empty() {
        return;
    }
    let start = driver.transactions.cursor % peers.len();
    driver.transactions.cursor = start.wrapping_add(1);
    for offset in 0..peers.len() {
        drive(driver, peers[(start + offset) % peers.len()]).await;
    }
}

async fn drive(driver: &mut SyncDriver, peer: PeerId) {
    if driver
        .transactions
        .peers
        .values()
        .filter(|state| state.active.is_some())
        .count()
        >= MAX_ACTIVE
    {
        return;
    }
    let Some(state) = driver.transactions.peers.get_mut(&peer) else {
        return;
    };
    if !state.same_chain
        || state.active.is_some()
        || Instant::now() < state.retry_at
        || driver.transactions.providers.cooling(&peer, Instant::now())
    {
        return;
    }
    let Some(nonce) = driver.transactions.nonce.checked_add(1) else {
        return;
    };
    driver.transactions.nonce = nonce;
    let step = if state.missing.is_empty() {
        Step::Inventory(state.after)
    } else {
        Step::Bodies(
            state
                .missing
                .drain(..state.missing.len().min(MAX_TRANSACTIONS_PER_REQUEST))
                .collect(),
        )
    };
    state.active = Some(nonce);
    let request = Request { peer, nonce, step };
    let wire = match &request.step {
        Step::Inventory(after) => {
            RpcRequest::TransactionInventory(TransactionInventoryRequest { after: *after })
        }
        Step::Bodies(hashes) => RpcRequest::TransactionsByHash(TransactionsByHashRequest {
            hashes: hashes.clone(),
        }),
    };
    let callback = request.clone();
    if !driver
        .send_rpc(peer, wire, move |_, response| {
            OutboundOutcome::Transactions {
                request: callback,
                response,
            }
        })
        .await
    {
        finish(driver, &request);
    }
}

fn finish(driver: &mut SyncDriver, request: &Request) -> bool {
    let Some(state) = driver.transactions.peers.get_mut(&request.peer) else {
        return false;
    };
    if state.active != Some(request.nonce) {
        return false;
    }
    state.active = None;
    state.retry_at = Instant::now() + POLL_INTERVAL;
    true
}

pub(super) async fn on_response(
    driver: &mut SyncDriver,
    request: Request,
    response: Result<RpcResponse, RpcError>,
) {
    if !finish(driver, &request) {
        return;
    }
    match (&request.step, response) {
        (Step::Inventory(after), Ok(RpcResponse::TransactionInventory(page))) => {
            if page.hashes.len() > MAX_TRANSACTION_INVENTORY
                || page.hashes.windows(2).any(|pair| pair[0] >= pair[1])
                || page
                    .hashes
                    .first()
                    .is_some_and(|hash| after.is_some_and(|cursor| *hash <= cursor))
            {
                return;
            }
            let next = (page.hashes.len() == MAX_TRANSACTION_INVENTORY)
                .then(|| *page.hashes.last().expect("full page"));
            let missing = driver.backend.missing_transactions(&page.hashes).await;
            let state = driver
                .transactions
                .peers
                .get_mut(&request.peer)
                .expect("active peer");
            state.after = next;
            state.missing = missing
                .into_iter()
                .filter(|hash| page.hashes.binary_search(hash).is_ok())
                .take(MAX_TRANSACTION_INVENTORY)
                .collect();
        }
        (Step::Bodies(hashes), Ok(RpcResponse::TransactionsByHash(page))) => {
            if page.transactions.len() > hashes.len() {
                return;
            }
            let mut seen = alloc::collections::BTreeSet::new();
            if page.transactions.iter().any(|bytes| {
                let hash = blake3_256(bytes);
                bytes.len() > MAX_TRANSACTION_BYTES || !hashes.contains(&hash) || !seen.insert(hash)
            }) {
                return;
            }
            let served = page.transactions.len();
            let mut admitted = 0_usize;
            for bytes in page.transactions {
                // Ordinary admission rechecks signatures, current runtime,
                // fees, nonce dependencies and pool/replacement capacity.
                if driver.backend.submit_transaction(bytes).await.is_ok() {
                    admitted += 1;
                }
            }
            // Bodies the pool refuses are not the provider's proven fault (its
            // runtime or head may differ), so this only paces it: a page
            // mostly refused backs it off instead of chaining at once, and
            // only a mostly useful page clears that.
            if admitted.saturating_mul(2) < served {
                driver
                    .transactions
                    .providers
                    .failed(request.peer, Instant::now());
                if let Some(state) = driver.transactions.peers.get_mut(&request.peer) {
                    state.missing.clear();
                }
                return;
            }
            driver
                .transactions
                .providers
                .served(request.peer, Duration::ZERO);
        }
        _ => return,
    }
    if let Some(state) = driver.transactions.peers.get_mut(&request.peer)
        && !state.missing.is_empty()
    {
        state.retry_at = Instant::now();
        drive(driver, request.peer).await;
    }
}
