//! Event-driven snapshot bootstrap from a peer's History proof, independent of
//! ordinary chunk finality sync.

use super::{SyncDriver, providers::Providers};
use crate::metrics::BootstrapKind;
use alloc::{collections::BTreeMap, vec::Vec};
use neutrin0_consensus_types::{bootstrap::StateItem, history::HISTORY_RETENTION_CHUNKS};
use neutrin0_network::{PeerId, SyncMode, rpc::Status};
use neutrin0_primitives::Hash;

mod requests;

pub(super) use requests::on_response;

#[derive(Default)]
pub(super) struct BootstrapSync {
    peers: BTreeMap<PeerId, Status>,
    /// Measured service and backoff of every provider, kept across
    /// reconnects and notices until an installation.
    providers: Providers,
    manifests: BTreeMap<PeerId, Hash>,
    active: Option<(PeerId, u64, BootstrapKind)>,
    sent_at: Option<tokio::time::Instant>,
    observed_pending: bool,
    fetching: bool,
    nonce: u64,
    /// Provider of every fragment staged so far of the partly received
    /// objects; any other provider restarts them from byte zero.
    fragment_provider: Option<PeerId>,
}

#[derive(Clone, Debug)]
pub(super) enum Request {
    History {
        anchor: u64,
        end: u64,
        checkpoint: Hash,
    },
    State {
        root: Hash,
        items: Vec<StateItem>,
    },
}

impl Request {
    const fn metric_kind(&self) -> BootstrapKind {
        match self {
            Self::History { .. } => BootstrapKind::History,
            Self::State { .. } => BootstrapKind::State,
        }
    }
}

pub(super) const fn is_syncing(driver: &SyncDriver) -> bool {
    driver.bootstrap.active.is_some()
        || driver.bootstrap.observed_pending
        || driver.bootstrap.fetching
}

/// Kind of the bootstrap request currently awaiting a response.
pub(super) fn active_kind(driver: &SyncDriver) -> Option<BootstrapKind> {
    driver.bootstrap.active.map(|(_, _, kind)| kind)
}

/// Finalized chunks a peer must hold beyond `local_count` before this node
/// snapshots to it: any for a fresh node; otherwise more than the window
/// peers retain, within which sequential complete-chunk sync catches up.
const fn snapshot_reach(local_count: u64) -> u64 {
    if local_count == 0 {
        0
    } else {
        HISTORY_RETENTION_CHUNKS
    }
}

pub(super) async fn on_status(driver: &mut SyncDriver, peer: PeerId, status: Status) -> bool {
    if driver.fsm.mode() != SyncMode::Snap {
        return false;
    }
    let Some(origin) = driver.backend.bootstrap_origin().await else {
        return false;
    };
    let Ok(local) = driver.backend.local_status().await else {
        return true;
    };
    if !super::same_chain(&status, &local) {
        return true;
    }
    if driver.bootstrap.peers.len() < super::HISTORY_PROVIDER_ATTEMPT_LIMIT
        || driver.bootstrap.peers.contains_key(&peer)
    {
        driver.bootstrap.peers.insert(peer, status);
    }
    // Prefer state bootstrap whenever a provider has finalized beyond what
    // this node can reach sequentially. No finalized chunk still permits
    // ordinary genesis startup.
    let local_count = local
        .finalized_chunk_id
        .map_or(0, |id| id.saturating_add(1));
    let reach = local_count.saturating_add(snapshot_reach(local_count));
    let active = driver
        .backend
        .bootstrap_state()
        .await
        .inspect_err(|error| driver.metrics().bootstrap_error(error))
        .ok()
        .flatten()
        .is_some()
        || driver
            .bootstrap
            .peers
            .values()
            .any(|status| status.finalized_chunks() > reach);
    if !active {
        if driver.bootstrap.active.is_none() && origin.boundary.next_chunk_id == 0 {
            driver.bootstrap.fetching = false;
            driver.backend.bootstrap_fetch(false).await;
        }
        return driver.bootstrap.active.is_some() || origin.boundary.next_chunk_id > local_count;
    }
    requests::drive(driver).await;
    // An archive can replay sources when the bounded manifest is unavailable.
    if can_replay_from_genesis(driver).await {
        driver.bootstrap.fetching = false;
        driver.backend.bootstrap_fetch(false).await;
        return false;
    }
    true
}

async fn can_replay_from_genesis(driver: &SyncDriver) -> bool {
    driver.bootstrap.active.is_none()
        && driver
            .backend
            .bootstrap_state()
            .await
            .inspect_err(|error| driver.metrics().bootstrap_error(error))
            .ok()
            .flatten()
            .is_none()
        && driver
            .backend
            .bootstrap_origin()
            .await
            .is_some_and(|origin| origin.boundary.next_chunk_id == 0)
        && driver.bootstrap.peers.iter().all(|(peer, status)| {
            driver
                .bootstrap
                .providers
                .cooling(peer, tokio::time::Instant::now())
                || status.finalized_chunks() == 0
        })
}

async fn resume_source_replay(driver: &mut SyncDriver) {
    if !can_replay_from_genesis(driver).await {
        return;
    }
    driver.bootstrap.fetching = false;
    driver.backend.bootstrap_fetch(false).await;
    if let Some((&peer, &status)) = driver
        .bootstrap
        .peers
        .iter()
        .find(|(peer, _)| driver.connected_peers.contains(peer))
        && !super::full_chunk::on_status(driver, peer, status).await
    {
        let commands = driver
            .fsm
            .on_event(neutrin0_network::sync::SyncEvent::PeerStatus { peer, status });
        driver.dispatch_sync_commands(commands).await;
    }
}

pub(super) async fn on_disconnect(driver: &mut SyncDriver, peer: PeerId) {
    driver.bootstrap.peers.remove(&peer);
    driver.bootstrap.manifests.remove(&peer);
    if let Some((owner, _, kind)) = driver.bootstrap.active
        && owner == peer
    {
        driver.bootstrap.providers.unproductive(peer);
        driver.bootstrap.active = None;
        driver.metrics().bootstrap_cancelled(kind);
    }
    requests::drive(driver).await;
    resume_source_replay(driver).await;
}

pub(super) fn on_connect(driver: &mut SyncDriver, peer: PeerId) {
    driver.bootstrap.manifests.remove(&peer);
}

/// The provider of the next manifest among `candidates`: the highest
/// endpoint at least two peers advertise identically, else the highest any
/// advertises, so one peer's claim alone never outranks what others agree
/// on; within it, the provider that has served fastest.
fn manifest_provider(
    providers: &Providers,
    candidates: impl IntoIterator<Item = (PeerId, Status)>,
) -> Option<(PeerId, Status)> {
    let mut endpoints: BTreeMap<(u64, Hash), Vec<(PeerId, Status)>> = BTreeMap::new();
    for (peer, status) in candidates {
        endpoints
            .entry((status.finalized_chunks(), status.checkpoint_hash))
            .or_default()
            .push((peer, status));
    }
    let endpoint = endpoints
        .iter()
        .filter(|(_, advertisers)| advertisers.len() >= 2)
        .map(|(endpoint, _)| *endpoint)
        .max()
        .or_else(|| endpoints.keys().max().copied())?;
    let advertisers = endpoints.remove(&endpoint)?;
    let mut peers: Vec<_> = advertisers.iter().map(|(peer, _)| *peer).collect();
    providers.order(&mut peers);
    let first = *peers.first()?;
    advertisers.into_iter().find(|(peer, _)| *peer == first)
}

fn can_serve_manifest(status: &Status, origin_count: u64, origin_hash: Hash) -> bool {
    status.finalized_chunks() > origin_count
        || (status.finalized_chunks() == origin_count
            && origin_count != 0
            && status.checkpoint_hash == origin_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        PeerId::from(neutrin0_network::libp2p::identity::Keypair::generate_ed25519().public())
    }

    fn advertising(count: u64, hash: u8) -> Status {
        Status {
            finalized_chunk_id: count.checked_sub(1),
            checkpoint_hash: [hash; 32],
            ..Status::default()
        }
    }

    #[test]
    fn one_peer_claiming_more_never_outranks_an_endpoint_others_agree_on() {
        let providers = Providers::default();
        let (liar, honest, other) = (peer(), peer(), peer());
        let peers = [
            (liar, advertising(u64::MAX - 1, 9)),
            (honest, advertising(5, 1)),
            (other, advertising(5, 1)),
        ];
        let (chosen, status) = manifest_provider(&providers, peers).unwrap();
        assert!(chosen == honest || chosen == other);
        assert_eq!(status.finalized_chunks(), 5);
        // A lone advertiser is still used when nothing is agreed.
        let (chosen, _) = manifest_provider(&providers, [(liar, advertising(9, 9))]).unwrap();
        assert_eq!(chosen, liar);
        // Within the agreed endpoint, the provider that served fastest leads.
        let mut providers = Providers::default();
        providers.served(honest, core::time::Duration::from_secs(9));
        providers.served(other, core::time::Duration::from_millis(100));
        let (chosen, _) = manifest_provider(&providers, peers).unwrap();
        assert_eq!(chosen, other);
    }
}
