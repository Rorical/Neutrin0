//! Bounded exact-source retrieval with provider retries and stale callback fencing.

use super::SyncDriver;
use alloc::collections::BTreeMap;
use neutrin0_consensus_types::{
    FinalityVote,
    signed_artifacts::{SignedArtifactInventory, SignedArtifactRef},
};
use neutrin0_network::{PeerId, rpc::Status};
use neutrin0_primitives::Hash;

mod requests;

pub(super) use requests::{on_response, on_retry};

const MAX_JOBS: usize = 128;
const MAX_PROVIDER_JOBS: usize = 32;
const MAX_ACTIVE: usize = 4;
const MAX_PROVIDERS: usize = 4;
const MAX_PROVIDER_ATTEMPTS: u8 = 3;

#[derive(Default)]
pub(super) struct AvailabilitySync {
    jobs: BTreeMap<Query, Job>,
    connections: BTreeMap<PeerId, u64>,
    generation: u64,
    nonce: u64,
    local_head: Hash,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum Query {
    Inventory {
        chunk: u64,
        after: Option<Hash>,
    },
    Artifact {
        chunk: u64,
        reference: SignedArtifactRef,
    },
}
impl Query {
    const fn chunk(self) -> u64 {
        match self {
            Self::Inventory { chunk, .. } | Self::Artifact { chunk, .. } => chunk,
        }
    }
}
struct Job {
    providers: BTreeMap<PeerId, u8>,
    active: Option<Request>,
    retry_after: tokio::time::Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Request {
    peer: PeerId,
    generation: u64,
    nonce: u64,
    query: Query,
}

pub(super) fn on_connect(driver: &mut SyncDriver, peer: PeerId) {
    if let Some(generation) = driver.availability.generation.checked_add(1) {
        driver.availability.generation = generation;
        driver.availability.connections.insert(peer, generation);
    }
}

pub(super) async fn on_disconnect(driver: &mut SyncDriver, peer: PeerId) {
    driver.availability.connections.remove(&peer);
    for job in driver.availability.jobs.values_mut() {
        job.providers.remove(&peer);
        if job.active.is_some_and(|request| request.peer == peer) {
            job.active = None;
        }
    }
    requests::drive(driver).await;
}

pub(super) fn reset_after_bootstrap(driver: &mut SyncDriver) {
    let nonce = driver.availability.nonce;
    let generation = driver.availability.generation;
    driver.availability = AvailabilitySync {
        generation,
        nonce,
        ..AvailabilitySync::default()
    };
    for peer in driver.connected_peers.clone() {
        on_connect(driver, peer);
    }
}

pub(super) async fn on_status(driver: &mut SyncDriver, peer: PeerId, status: Status) {
    if !driver.backend.supports_signed_artifact_sync() {
        return;
    }
    let Ok(local) = driver.backend.local_status().await else {
        return;
    };
    if !super::same_chain(&local, &status) {
        return;
    }
    let Some(next) = local
        .finalized_chunk_id
        .map_or(Some(0), |chunk| chunk.checked_add(1))
    else {
        return;
    };
    for chunk in
        next.saturating_sub(neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS)..=next
    {
        if driver.backend.signed_artifact_source_known(chunk).await {
            enqueue(driver, peer, Query::Inventory { chunk, after: None });
        }
    }
    requests::drive(driver).await;
}

pub(super) async fn on_notice(
    driver: &mut SyncDriver,
    peer: PeerId,
    inventory: SignedArtifactInventory,
) -> bool {
    if inventory.entries.len() > neutrin0_consensus_types::signed_artifacts::MAX_ARTIFACT_INVENTORY
        || !driver
            .backend
            .signed_artifact_source_known(inventory.chunk_id)
            .await
    {
        return false;
    }
    absorb_inventory(driver, peer, inventory).await;
    requests::drive(driver).await;
    true
}

pub(super) async fn on_vote(driver: &mut SyncDriver, peer: PeerId, vote: &FinalityVote) {
    if !driver.backend.supports_signed_artifact_sync()
        || !driver
            .backend
            .signed_artifact_source_known(vote.data.chunk_id)
            .await
    {
        return;
    }
    for reference in driver
        .backend
        .missing_vote_artifacts(vote)
        .await
        .into_iter()
        .take(MAX_JOBS)
    {
        enqueue(
            driver,
            peer,
            Query::Artifact {
                chunk: vote.data.chunk_id,
                reference,
            },
        );
    }
    // Earlier locked votes have no content hash in a later signed declaration;
    // bounded source inventories provide their immutable identities.
    enqueue(
        driver,
        peer,
        Query::Inventory {
            chunk: vote.data.chunk_id,
            after: None,
        },
    );
    requests::drive(driver).await;
}

fn enqueue(driver: &mut SyncDriver, peer: PeerId, query: Query) -> bool {
    if !driver.availability.connections.contains_key(&peer) {
        return false;
    }
    if !driver.availability.jobs.contains_key(&query) && driver.availability.jobs.len() >= MAX_JOBS
    {
        return false;
    }
    if !driver.availability.jobs.contains_key(&query)
        && driver
            .availability
            .jobs
            .values()
            .filter(|job| job.providers.contains_key(&peer))
            .count()
            >= MAX_PROVIDER_JOBS
    {
        return false;
    }
    let job = driver
        .availability
        .jobs
        .entry(query)
        .or_insert_with(|| Job {
            providers: BTreeMap::new(),
            active: None,
            retry_after: tokio::time::Instant::now(),
        });
    if job.providers.len() < MAX_PROVIDERS || job.providers.contains_key(&peer) {
        job.providers.entry(peer).or_insert(0);
    }
    true
}

async fn absorb_inventory(
    driver: &mut SyncDriver,
    peer: PeerId,
    inventory: SignedArtifactInventory,
) -> bool {
    let mut complete = true;
    for reference in inventory.entries {
        if driver
            .backend
            .signed_artifact_by_id(reference.id)
            .await
            .is_err()
        {
            complete &= enqueue(
                driver,
                peer,
                Query::Artifact {
                    chunk: inventory.chunk_id,
                    reference,
                },
            );
        }
    }
    if complete && let Some(after) = inventory.next {
        complete = enqueue(
            driver,
            peer,
            Query::Inventory {
                chunk: inventory.chunk_id,
                after: Some(after),
            },
        );
    }
    complete
}
