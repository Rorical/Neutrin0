//! Bounded, event-driven discovery and backfill of exact BFT candidate branches.

use super::SyncDriver;
use alloc::collections::{BTreeMap, BTreeSet};
use neutrin0_consensus_types::{BftCandidate, FinalityVote, FinalityVotePhase};
use neutrin0_network::{
    PeerId,
    rpc::{CandidateByChunkRequest, Status},
};
use neutrin0_primitives::Hash;

mod backfill;

pub(super) use backfill::on_response;

const MAX_TARGETS: usize = 8;
const MAX_QUERIES: usize = 16;
const MAX_VOTES: usize = 128;
const MAX_VOTE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Default)]
pub(super) struct CandidateSync {
    targets: Vec<Target>,
    queries: Vec<(PeerId, CandidateByChunkRequest)>,
    active: Option<Request>,
    nonce: u64,
    connections: BTreeMap<PeerId, u64>,
    next_connection: u64,
    query_turn: bool,
    votes: Vec<(Option<u8>, FinalityVote)>,
    vote_bytes: usize,
}

struct Target {
    candidate: BftCandidate,
    providers: BTreeSet<PeerId>,
    tried: BTreeSet<PeerId>,
    next_block: u64,
    blocks_complete: bool,
    considered: bool,
    hashes: BTreeMap<u64, Hash>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Step {
    Query(CandidateByChunkRequest),
    Blocks { hash: Hash, start: u64, end: u64 },
    Certificate { hash: Hash, chunk_id: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Request {
    peer: PeerId,
    connection: u64,
    nonce: u64,
    step: Step,
}

pub(super) fn on_connect(driver: &mut SyncDriver, peer: PeerId) {
    if let Some(generation) = driver.candidates.next_connection.checked_add(1) {
        driver.candidates.next_connection = generation;
        driver.candidates.connections.insert(peer, generation);
    }
}

pub(super) async fn on_disconnect(driver: &mut SyncDriver, peer: PeerId) {
    driver.candidates.connections.remove(&peer);
    for target in &mut driver.candidates.targets {
        target.providers.remove(&peer);
    }
    driver
        .candidates
        .queries
        .retain(|(provider, _)| *provider != peer);
    if driver
        .candidates
        .active
        .is_some_and(|request| request.peer == peer)
    {
        driver.candidates.active = None;
    }
    backfill::drive(driver).await;
}

pub(super) fn reset_after_bootstrap(driver: &mut SyncDriver) {
    let nonce = driver.candidates.nonce;
    let next_connection = driver.candidates.next_connection;
    driver.candidates = CandidateSync {
        nonce,
        next_connection,
        ..CandidateSync::default()
    };
    for peer in driver.connected_peers.clone() {
        on_connect(driver, peer);
    }
}

pub(super) async fn on_status(driver: &mut SyncDriver, peer: PeerId, status: Status) {
    if !driver.backend.supports_bft_candidate_sync() {
        return;
    }
    let Ok(local) = driver.backend.local_status().await else {
        return;
    };
    if !super::same_chain(&status, &local) {
        return;
    }
    let Ok(Some(target)) = driver.backend.consensus_sync_target().await else {
        return;
    };
    if status.head_height < target.end_height {
        return;
    }
    for target in &mut driver.candidates.targets {
        target.tried.remove(&peer);
    }
    enqueue_query(
        driver,
        peer,
        CandidateByChunkRequest {
            chunk_id: target.chunk_id,
            chunk_hash: None,
        },
    );
    backfill::drive(driver).await;
}

fn enqueue_query(driver: &mut SyncDriver, peer: PeerId, query: CandidateByChunkRequest) {
    if !driver.candidates.connections.contains_key(&peer)
        || driver.candidates.queries.contains(&(peer, query))
        || driver
            .candidates
            .active
            .is_some_and(|active| active.peer == peer && active.step == Step::Query(query))
        || driver.candidates.queries.len() >= MAX_QUERIES
    {
        return;
    }
    driver.candidates.queries.push((peer, query));
}

/// Discover the exact candidate named by an authenticated quorum.
pub(super) async fn request_quorum(
    driver: &mut SyncDriver,
    peer: PeerId,
    query: CandidateByChunkRequest,
) {
    enqueue_query(driver, peer, query);
    backfill::drive(driver).await;
}

pub(super) async fn on_vote(
    driver: &mut SyncDriver,
    peer: PeerId,
    subnet: Option<u8>,
    vote: &FinalityVote,
) {
    if !driver.backend.bft_vote_needs_candidate(vote).await {
        return;
    }
    let size = borsh::object_length(vote).unwrap_or(MAX_VOTE_BYTES + 1);
    if driver.candidates.votes.len() < MAX_VOTES
        && size <= MAX_VOTE_BYTES.saturating_sub(driver.candidates.vote_bytes)
    {
        driver.candidates.vote_bytes += size;
        driver.candidates.votes.push((subnet, vote.clone()));
    }
    enqueue_query(
        driver,
        peer,
        CandidateByChunkRequest {
            chunk_id: vote.data.chunk_id,
            chunk_hash: Some(vote.data.chunk_hash),
        },
    );
    backfill::drive(driver).await;
}

pub(super) async fn on_hint(
    driver: &mut SyncDriver,
    peer: PeerId,
    candidate: BftCandidate,
) -> bool {
    if !record_hint(driver, peer, candidate).await {
        return false;
    }
    backfill::drive(driver).await;
    true
}

async fn record_hint(driver: &mut SyncDriver, peer: PeerId, mut candidate: BftCandidate) -> bool {
    if !driver.candidates.connections.contains_key(&peer) {
        return false;
    }
    let Ok(Some(local)) = driver.backend.consensus_sync_target().await else {
        return false;
    };
    if candidate.chunk.chunk_id != local.chunk_id
        || candidate.chunk.start_height != local.start_height
        || candidate.chunk.end_height != local.end_height
        || candidate.justification.as_ref().is_some_and(|qc| {
            qc.data.chunk_id != local.chunk_id
                || qc.data.chunk_hash != candidate.chunk.hash()
                || qc.data.phase != FinalityVotePhase::Prevote
                || qc.data.round >= candidate.round
        })
    {
        return false;
    }
    if !driver.backend.validate_bft_candidate_hint(&candidate).await {
        return false;
    }
    if let Some(qc) = &candidate.justification {
        let Some(round) = qc.data.round.checked_add(1) else {
            return false;
        };
        candidate.round = round;
    }
    let hash = candidate.chunk.hash();
    if let Some(target) = driver
        .candidates
        .targets
        .iter_mut()
        .find(|target| target.candidate.chunk.hash() == hash)
    {
        // Only authenticated quorum rounds have ordering significance. Bare
        // unsigned metadata never suppresses a later legitimate lower hint.
        let replace = match (&candidate.justification, &target.candidate.justification) {
            (Some(incoming), Some(current)) => incoming.data.round >= current.data.round,
            (_, None) => true,
            (None, Some(_)) => false,
        };
        if replace {
            target.candidate = candidate;
        }
        if target.providers.len() < super::HISTORY_PROVIDER_ATTEMPT_LIMIT {
            target.providers.insert(peer);
        }
        target.tried.remove(&peer);
        return true;
    }
    if driver.candidates.targets.len() == MAX_TARGETS {
        let active = driver.candidates.active.map(|request| request.step);
        let index = driver.candidates.targets.iter().position(|target| !matches!(active,
            Some(Step::Blocks {hash, ..} | Step::Certificate {hash, ..}) if hash == target.candidate.chunk.hash()));
        let Some(index) = index else {
            return false;
        };
        driver.candidates.targets.remove(index);
    }
    // A branch already held locally (gossip imported it) is considered
    // without downloading its range again.
    let held = driver.backend.holds_bft_candidate_branch(&candidate).await;
    driver.candidates.targets.push(Target {
        next_block: if held {
            candidate.chunk.end_height.saturating_add(1)
        } else {
            local.start_height
        },
        candidate,
        providers: BTreeSet::from([peer]),
        tried: BTreeSet::new(),
        hashes: BTreeMap::new(),
        blocks_complete: held,
        considered: false,
    });
    true
}
