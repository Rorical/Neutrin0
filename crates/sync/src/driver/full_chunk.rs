//! Sequential sync across proven validator, randomness and penalty boundaries.

use super::{SyncDriver, providers::Providers};
use crate::metrics::{FullChunkKind, Observation};
use alloc::collections::BTreeMap;
use neutrin0_network::{PeerId, rpc::Status, service::NetworkCommand, topic::Topic};

mod request;
mod response;

pub(super) use response::on_response;

#[derive(Default)]
pub(super) struct FullChunkSync {
    pub(super) enabled: bool,
    observation: Option<LocalObservation>,
    pub(super) in_flight: bool,
    active_request: Option<(PeerId, u64, Step)>,
    pub(super) retry_cursor: usize,
    peers: BTreeMap<PeerId, Status>,
    cursors: BTreeMap<PeerId, Cursor>,
    retained_from_chunk: BTreeMap<PeerId, u64>,
    connections: BTreeMap<PeerId, u64>,
    next_connection: u64,
    /// Measured service and backoff of every provider, kept across
    /// reconnects and installations.
    providers: Providers,
    sent_at: Option<tokio::time::Instant>,
}

#[derive(Clone, Copy)]
struct LocalObservation {
    at: tokio::time::Instant,
    progress: Option<neutrin0_network::LocalProgress>,
    target: Option<crate::backend::ConsensusSyncTarget>,
}

pub(super) async fn observe_local(
    driver: &mut SyncDriver,
) -> (
    Option<neutrin0_network::LocalProgress>,
    Option<crate::backend::ConsensusSyncTarget>,
) {
    if let Some(observation) = driver.full_chunks.observation
        && observation.at.elapsed() < std::time::Duration::from_secs(1)
    {
        return (observation.progress, observation.target);
    }
    let progress = driver
        .backend
        .local_progress()
        .await
        .inspect_err(|_| {
            driver
                .metrics()
                .observation_error(Observation::LocalProgress);
        })
        .ok();
    let target = driver
        .backend
        .consensus_sync_target()
        .await
        .inspect_err(|_| {
            driver
                .metrics()
                .observation_error(Observation::ConsensusTarget);
        })
        .ok()
        .flatten();
    driver.full_chunks.observation = Some(LocalObservation {
        at: tokio::time::Instant::now(),
        progress,
        target,
    });
    (progress, target)
}

#[derive(Clone)]
struct Cursor {
    chunk_id: u64,
    head_block_hash: [u8; 32],
    next_block: u64,
    blocks: BTreeMap<u64, [u8; 32]>,
}

impl Cursor {
    /// Download nothing yet of `target` along the branch ending at `head_block_hash`.
    const fn new(target: crate::backend::ConsensusSyncTarget, head_block_hash: [u8; 32]) -> Self {
        Self {
            chunk_id: target.chunk_id,
            head_block_hash,
            next_block: target.start_height,
            blocks: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Step {
    Blocks {
        head: [u8; 32],
        start: u64,
        end: u64,
    },
    Finality(u64),
}

impl Step {
    const fn metric_kind(self) -> FullChunkKind {
        match self {
            Self::Blocks { .. } => FullChunkKind::Blocks,
            Self::Finality(_) => FullChunkKind::Finality,
        }
    }
}

/// Blocks a following node may trail its peers by and still count as synced.
const FOLLOW_LAG_BLOCKS: u64 = 2;

/// Observe verified local progress without changing the protocol FSM. Peer
/// status is only a download target; it cannot certify completed local work.
pub(super) fn is_syncing(
    driver: &SyncDriver,
    local: Option<&neutrin0_network::LocalProgress>,
    target: Option<&crate::backend::ConsensusSyncTarget>,
) -> bool {
    let (Some(local), Some(target)) = (local, target) else {
        return true;
    };
    // An outstanding block page means blocks are missing; a finality fetch
    // is routine following.
    if driver.full_chunks.peers.is_empty()
        || matches!(
            driver.full_chunks.active_request,
            Some((_, _, Step::Blocks { .. }))
        )
    {
        return true;
    }
    let fsm_behind = match driver.fsm.state() {
        neutrin0_network::SyncState::HistoryFetch { target_index, .. } => {
            local.finalized_chunks() < *target_index
        }
        neutrin0_network::SyncState::Stalled { .. } => true,
        neutrin0_network::SyncState::Init | neutrin0_network::SyncState::Following => false,
    };
    fsm_behind
        || driver
            .full_chunks
            .peers
            .iter()
            .filter(|(peer, _)| {
                !driver
                    .full_chunks
                    .providers
                    .cooling(peer, tokio::time::Instant::now())
            })
            .any(|(_, remote)| {
                // A followed head trails a peer's by a block or so, and the
                // current chunk's finality lands at slightly different times;
                // only lag beyond that counts, so the answer does not flap.
                let remote_chunks = remote
                    .finalized_chunk_id
                    .map_or(0, |id| id.saturating_add(1));
                let local_chunks = local
                    .finalized_chunk_id
                    .map_or(0, |id| id.saturating_add(1));
                remote.head_height > local.head_height.saturating_add(FOLLOW_LAG_BLOCKS)
                    || remote.head_height.min(target.end_height)
                        > local.proven_height.saturating_add(FOLLOW_LAG_BLOCKS)
                    || remote_chunks > local_chunks.saturating_add(1)
            })
}

pub(super) fn publish_metrics(driver: &SyncDriver) {
    let selected = driver
        .full_chunks
        .active_request
        .map(|(peer, _, _)| peer)
        .or_else(|| {
            driver
                .full_chunks
                .cursors
                .iter()
                .max_by_key(|(_, cursor)| (cursor.chunk_id, cursor.next_block))
                .map(|(peer, _)| *peer)
        });
    let cursors = selected
        .and_then(|peer| driver.full_chunks.cursors.get(&peer))
        .map_or([0; 2], |cursor| [cursor.next_block, cursor.chunk_id]);
    let target = selected
        .and_then(|peer| driver.full_chunks.peers.get(&peer))
        .map_or(0, |status| status.head_height);
    driver.metrics().publish_full_chunk(
        driver.full_chunks.enabled,
        driver.full_chunks.in_flight,
        cursors,
        target,
    );
}

/// Invalidate every old request while preserving monotonic connection generations.
pub(super) fn reset_after_bootstrap(driver: &mut SyncDriver) {
    if let Some((_, _, step)) = driver.full_chunks.active_request {
        driver.metrics().full_chunk_cancelled(step.metric_kind());
    }
    let next_connection = driver.full_chunks.next_connection;
    let providers = core::mem::take(&mut driver.full_chunks.providers);
    driver.full_chunks = FullChunkSync {
        next_connection,
        providers,
        ..FullChunkSync::default()
    };
    let peers: Vec<_> = driver.connected_peers.iter().copied().collect();
    for peer in peers {
        on_connect(driver, peer);
    }
}

pub(super) fn on_connect(driver: &mut SyncDriver, peer: PeerId) {
    if let Some(connection) = driver.full_chunks.next_connection.checked_add(1) {
        driver.full_chunks.next_connection = connection;
        driver.full_chunks.connections.insert(peer, connection);
    }
}

pub(super) fn on_disconnect(driver: &mut SyncDriver, peer: PeerId) {
    if let Some((owner, _, step)) = driver.full_chunks.active_request
        && owner == peer
    {
        driver.full_chunks.providers.unproductive(peer);
        driver.metrics().full_chunk_cancelled(step.metric_kind());
        driver.full_chunks.active_request = None;
        driver.full_chunks.in_flight = false;
    }
    driver.full_chunks.peers.remove(&peer);
    driver.full_chunks.cursors.remove(&peer);
    driver.full_chunks.retained_from_chunk.remove(&peer);
    driver.full_chunks.connections.remove(&peer);
    // Keep a bounded backoff across reconnects; changing a socket does not
    // make an unchanged unavailable branch a useful provider.
}

pub(super) async fn on_status(driver: &mut SyncDriver, peer: PeerId, status: Status) -> bool {
    driver.full_chunks.observation = None;
    if driver.fsm.mode() == neutrin0_network::SyncMode::LightClient {
        return false;
    }
    match driver.backend.consensus_sync_target().await {
        Ok(None) => return false,
        Err(error) => {
            tracing::warn!(%error, "cannot load consensus sync target");
            return true;
        }
        Ok(Some(_)) => {}
    }
    let Ok(local) = driver.backend.local_status().await else {
        return true;
    };
    if !super::same_chain(&status, &local) {
        return true;
    }
    if !driver.full_chunks.enabled {
        driver.full_chunks.enabled = true;
        for topic in Topic::all_default() {
            let _ = driver.cmd_tx.send(NetworkCommand::Subscribe(topic)).await;
        }
    }
    tracing::debug!(%peer, head = status.head_height, finalized = ?status.finalized_chunk_id, "full sync provider status");
    driver.full_chunks.peers.insert(peer, status);
    if !driver.full_chunks.in_flight {
        request::request_best(driver, None).await;
    }
    true
}

/// Remember the first chunk `peer` still serves completely, from its
/// `Pruned` answer or its advertised metadata.
pub(super) fn record_retention(driver: &mut SyncDriver, peer: PeerId, retained_from_chunk: u64) {
    if driver.full_chunks.connections.contains_key(&peer) {
        driver
            .full_chunks
            .retained_from_chunk
            .insert(peer, retained_from_chunk);
    }
}
