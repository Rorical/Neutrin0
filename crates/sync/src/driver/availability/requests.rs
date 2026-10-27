//! Bounded request rounds for queued inventory and artifact jobs.

use super::{
    MAX_ACTIVE, MAX_JOBS, MAX_PROVIDER_ATTEMPTS, Query, Request, absorb_inventory, enqueue,
};
use crate::EvidenceProofAcceptance;
use crate::driver::{OutboundOutcome, SyncDriver};
use alloc::collections::BTreeSet;
use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
use neutrin0_network::{
    PeerId,
    rpc::{
        RpcError, RpcRequest, RpcResponse, SignedArtifactByIdRequest,
        SignedArtifactInventoryByChunkRequest,
    },
};

pub(in crate::driver) async fn on_retry(driver: &mut SyncDriver) {
    if let Ok(status) = driver.backend.local_status().await
        && status.head_block_hash != driver.availability.local_head
    {
        driver.availability.local_head = status.head_block_hash;
        for job in driver.availability.jobs.values_mut() {
            for attempts in job.providers.values_mut() {
                *attempts = 0;
            }
            job.retry_after = tokio::time::Instant::now();
        }
    }
    drive(driver).await;
}

pub(super) async fn drive(driver: &mut SyncDriver) {
    if !driver.backend.supports_signed_artifact_sync() {
        return;
    }
    prune_jobs(driver).await;
    while driver
        .availability
        .jobs
        .values()
        .filter(|job| job.active.is_some())
        .count()
        < MAX_ACTIVE
    {
        let Some((query, peer)) = select_request(driver) else {
            break;
        };
        let Some(nonce) = driver.availability.nonce.checked_add(1) else {
            break;
        };
        driver.availability.nonce = nonce;
        let request = Request {
            peer,
            generation: driver.availability.connections[&peer],
            nonce,
            query,
        };
        let job = driver
            .availability
            .jobs
            .get_mut(&query)
            .expect("selected source job");
        *job.providers.get_mut(&peer).expect("selected provider") += 1;
        job.active = Some(request);
        let rpc = rpc_for(query);
        if !driver
            .send_rpc(peer, rpc, move |_peer, response| {
                OutboundOutcome::SignedArtifact { request, response }
            })
            .await
        {
            if let Some(job) = driver.availability.jobs.get_mut(&query)
                && job.active == Some(request)
            {
                job.active = None;
            }
            break;
        }
    }
}

/// Forget jobs no provider can still serve and jobs whose source chunk is
/// no longer authenticated locally.
async fn prune_jobs(driver: &mut SyncDriver) {
    // Expired exhausted hints cannot occupy the whole bounded queue forever.
    driver.availability.jobs.retain(|_, job| {
        job.active.is_some()
            || job.retry_after > tokio::time::Instant::now()
            || job
                .providers
                .values()
                .any(|attempts| *attempts < MAX_PROVIDER_ATTEMPTS)
    });
    // Many jobs share a source chunk; authenticate each chunk once.
    let chunks: BTreeSet<u64> = driver
        .availability
        .jobs
        .keys()
        .map(|query| query.chunk())
        .collect();
    let mut stale = BTreeSet::new();
    for chunk in chunks {
        if !driver.backend.signed_artifact_source_known(chunk).await {
            stale.insert(chunk);
        }
    }
    if !stale.is_empty() {
        driver
            .availability
            .jobs
            .retain(|query, _| !stale.contains(&query.chunk()));
    }
}

/// The idle job due for a retry and its least-tried connected provider.
fn select_request(driver: &SyncDriver) -> Option<(Query, PeerId)> {
    driver.availability.jobs.iter().find_map(|(query, job)| {
        if job.active.is_some() || job.retry_after > tokio::time::Instant::now() {
            return None;
        }
        job.providers
            .iter()
            .filter(|(peer, attempts)| {
                **attempts < MAX_PROVIDER_ATTEMPTS
                    && driver.availability.connections.contains_key(peer)
            })
            .min_by_key(|(_, attempts)| **attempts)
            .map(|(peer, _)| (*query, *peer))
    })
}

const fn rpc_for(query: Query) -> RpcRequest {
    match query {
        Query::Inventory { chunk, after } => {
            RpcRequest::SignedArtifactInventoryByChunk(SignedArtifactInventoryByChunkRequest {
                chunk_id: chunk,
                after,
            })
        }
        Query::Artifact { reference, .. } => {
            RpcRequest::SignedArtifactById(SignedArtifactByIdRequest { id: reference.id })
        }
    }
}

pub(in crate::driver) async fn on_response(
    driver: &mut SyncDriver,
    request: Request,
    response: Result<RpcResponse, RpcError>,
) {
    if driver.availability.connections.get(&request.peer) != Some(&request.generation)
        || driver
            .availability
            .jobs
            .get(&request.query)
            .and_then(|job| job.active)
            != Some(request)
    {
        return;
    }
    let job = driver
        .availability
        .jobs
        .get_mut(&request.query)
        .expect("active source job");
    job.active = None;
    job.retry_after = tokio::time::Instant::now() + core::time::Duration::from_secs(5);
    match (request.query, response) {
        (
            Query::Inventory { chunk, after },
            Ok(RpcResponse::SignedArtifactInventoryByChunk(inventory)),
        ) if inventory.chunk_id == chunk
            && inventory
                .entries
                .first()
                .is_none_or(|entry| after.is_none_or(|cursor| entry.id > cursor)) =>
        {
            if absorb_inventory(driver, request.peer, *inventory).await {
                driver.availability.jobs.remove(&request.query);
            }
        }
        (Query::Artifact { chunk, reference }, Ok(RpcResponse::SignedArtifactById(payload))) => {
            let artifact = payload.artifact;
            if artifact.id() == reference.id && artifact.kind() == reference.kind {
                let source_matches = driver
                    .backend
                    .signed_artifact_matches_source(&artifact, chunk)
                    .await;
                if source_matches
                    && driver
                        .backend
                        .ingest_signed_artifact(artifact.clone())
                        .await
                        == EvidenceProofAcceptance::Accepted
                {
                    driver.availability.jobs.remove(&request.query);
                    if let SignedArtifact::Vote(vote) = artifact {
                        for missing in driver
                            .backend
                            .missing_vote_artifacts(&vote)
                            .await
                            .into_iter()
                            .take(MAX_JOBS)
                        {
                            enqueue(
                                driver,
                                request.peer,
                                Query::Artifact {
                                    chunk,
                                    reference: missing,
                                },
                            );
                        }
                    }
                }
            }
        }
        _ => {}
    }
    drive(driver).await;
}
