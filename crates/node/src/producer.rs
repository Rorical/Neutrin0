//! Validator block-production loop for the node binary.

#![allow(clippy::redundant_pub_crate)]

use std::sync::Arc;
use std::time::Duration;

use borsh::to_vec;
use neutrin0_consensus_engine::{ProductionError, ProposerKey};
use neutrin0_network::Topic;
use neutrin0_network::service::NetworkCommand;
use neutrin0_runtime_host::{ProgramProver, Sp1ProofSystem};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Retry proving-input or dissemination-size failures, retaining every mandatory
/// lane and all queued users. The final attempt is system-only; no attempt
/// reserves a proposer signature before the engine's size guards succeed.
pub(crate) fn with_witness_backoff<T, E>(
    body: &neutrin0_consensus_types::Body,
    mut produce: impl FnMut(neutrin0_consensus_types::Body) -> Result<T, ProductionError<E>>,
) -> Result<T, ProductionError<E>> {
    let users = body
        .transactions
        .iter()
        .filter(|bytes| {
            matches!(
                borsh::from_slice::<neutrin0_runtime_abi::RuntimeTransaction>(bytes),
                Ok(neutrin0_runtime_abi::RuntimeTransaction::User(_))
            )
        })
        .count();
    let limits = [users, users / 2, users / 4, 0];
    for (attempt, keep) in limits.into_iter().enumerate() {
        let mut candidate = body.clone();
        let mut seen = 0;
        candidate.transactions.retain(|bytes| {
            if matches!(
                borsh::from_slice::<neutrin0_runtime_abi::RuntimeTransaction>(bytes),
                Ok(neutrin0_runtime_abi::RuntimeTransaction::User(_))
            ) {
                seen += 1;
                seen <= keep
            } else {
                true
            }
        });
        match produce(candidate) {
            Err(error)
                if attempt < 3
                    && (matches!(
                        &error,
                        ProductionError::WitnessTooLarge { .. }
                            | ProductionError::BodyTooLarge { .. }
                            | ProductionError::StateDiffTooLarge { .. }
                    ) || matches!(&error, ProductionError::Executor(message) if message.contains("block proving input exceeds"))) =>
                {}
            result => return result,
        }
    }
    unreachable!("fourth bounded production attempt always returns")
}

use crate::chain_backend::ChainBackend;
use crate::db::NodeDb;

// Scheduling only: this never grants signing authority or substitutes for a receipt.
pub(crate) const fn fallback_ready(
    preferred: bool,
    authenticated_start: u64,
    delay: u64,
    now: u64,
) -> bool {
    preferred
        || delay == 0
        || now < authenticated_start
        || now.saturating_sub(authenticated_start) >= delay
}

/// Whether a chunk proof should wait for this node's block proofs.
///
/// Block proofs are latency-critical (production waits on them) and a running
/// chunk proof cannot be preempted, so while `pending_block_proofs` holds the
/// chunk proof yields, but for at most `bound_secs` after the certificate at
/// `certified_at` so finality is never starved.
pub(crate) const fn chunk_proof_deferred(
    prioritize: bool,
    pending_block_proofs: bool,
    certified_at: u64,
    bound_secs: u64,
    now: u64,
) -> bool {
    prioritize && pending_block_proofs && now.saturating_sub(certified_at) < bound_secs
}

/// Configuration for local block production and proving.
pub(crate) struct BlockProducerConfig {
    /// Proposer key of a validator; `None` runs the proof loop alone for a
    /// node that proves candidates it did not produce (design 08).
    pub(crate) proposer: Option<ProposerKey>,
    /// The validator's next key, which a key rotation seats in the
    /// proposer's place (design 19).
    pub(crate) standby: Option<ProposerKey>,
    /// Bounds queued and concurrent proof work.
    pub(crate) proving: crate::config::ProvingConfig,
    /// Slot-0 Unix timestamp.
    pub(crate) genesis_time_secs: u64,
    /// Slot duration in seconds.
    pub(crate) slot_duration_secs: u64,
}

/// Run validator production until the network command channel closes or the
/// task is aborted during node shutdown.
pub(crate) async fn run_block_producer<P: ProgramProver + 'static>(
    backend: Arc<ChainBackend<NodeDb, Sp1ProofSystem<P>>>,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    config: BlockProducerConfig,
) {
    let mut last_attempted_slot = current_slot(
        config.genesis_time_secs,
        config.slot_duration_secs,
        crate::now_secs(),
    )
    .saturating_sub(1);
    let mut last_session_check_slot = last_attempted_slot;
    announce_production_mode(&config);

    let mut jobs =
        crate::proof_queue::ProofQueue::new(config.proving.concurrency, config.proving.capacity);
    let mut failed = std::collections::BTreeSet::new();
    let mut tick = tokio::time::Instant::now();
    loop {
        jobs.retain_pending(|hash| backend.needs_block_proof(hash));
        let available = jobs.available();
        let foreign = foreign_proof_slots(available, config.proposer.is_some());
        for hash in backend.pending_block_proofs(available, foreign, |hash| {
            jobs.contains(hash) || failed.contains(hash)
        }) {
            jobs.push(hash, hash);
        }
        backend.set_block_proof_backlog(jobs.pending() + jobs.running());
        let worker = Arc::clone(&backend);
        jobs.start(move |hash| worker.prove_block(&hash));
        let metrics = backend.metrics();
        metrics
            .block_proof_queue_pending
            .store(jobs.pending() as u64, std::sync::atomic::Ordering::Relaxed);
        metrics
            .block_proof_queue_launched
            .store(jobs.running() as u64, std::sync::atomic::Ordering::Relaxed);
        tokio::select! {
            () = cmd_tx.closed() => break,
            (hash, result) = jobs.completed(), if jobs.is_running() => {
                match result {
                    Ok(Ok(proven)) => {
                        publish_proven_block(&backend, &cmd_tx, hash, proven.public_inputs.height).await;
                    }
                    Ok(Err(error)) => { failed.insert(hash); warn!(%error, ?hash, "block proof failed; retry on next slot"); }
                    Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
                    Err(error) => { failed.insert(hash); warn!(%error, ?hash, "block prover cancelled; retry on next slot"); }
                }
            }
            () = tokio::time::sleep_until(tick) => {
                let now = crate::now_secs();
                let slot = current_slot(config.genesis_time_secs, config.slot_duration_secs, now);
                if slot > last_attempted_slot { failed.clear(); }
                // Candidates past their exclusive window stop selecting the
                // head before this slot's production extends it.
                backend.refresh_stale_candidates();
                if slot > last_session_check_slot {
                    last_session_check_slot = slot;
                    backend.maybe_open_next_bft_session().await;
                }
                if let Some(proposer) = &config.proposer
                    && slot > last_attempted_slot
                    && jobs.available() > 0
                    && !backend.storage_pressure()
                {
                    attempt_slot(&backend, &cmd_tx, proposer, slot).await;
                    last_attempted_slot = slot;
                }
                // Also service proof fallback deadlines for imported blocks in
                // long slots. The extra tick does not grant another proposal.
                tick = tokio::time::Instant::now() + sleep_until_next_slot(
                    config.genesis_time_secs, config.slot_duration_secs, now).min(Duration::from_secs(1));
            }
        }
    }
}

fn announce_production_mode(config: &BlockProducerConfig) {
    if let Some(proposer) = &config.proposer {
        info!(
            proposer_index = proposer.validator_index(),
            slot_duration_secs = config.slot_duration_secs,
            "validator block production enabled"
        );
    } else {
        info!(
            slot_duration_secs = config.slot_duration_secs,
            "block prover enabled without production"
        );
    }
}

/// A block proof completed: let the chunk open if it can, then publish the
/// receipt.
async fn publish_proven_block<P: ProgramProver + 'static>(
    backend: &Arc<ChainBackend<NodeDb, Sp1ProofSystem<P>>>,
    cmd_tx: &mpsc::Sender<NetworkCommand>,
    hash: neutrin0_primitives::Hash,
    height: u64,
) {
    // Any completion can make the chunk ready, including an
    // earlier block that finished after its chunk's last block.
    backend.maybe_open_bft_session_for_height(height).await;
    // The candidate went out at production; the receipt
    // follows on its own topic (design 08).
    if let Some(receipt) = backend.receipt_for_publication(&hash)
        && let Ok(data) = to_vec(&receipt)
    {
        let _ = cmd_tx
            .send(NetworkCommand::Publish {
                topic: Topic::Receipts,
                data,
            })
            .await;
    }
    info!(height, ?hash, "proved block and published its receipt");
}

/// The time-driven chain rules every non-light node applies (design 08).
///
/// Candidates unproven past their exclusive window turn stale and leave the
/// head, and the next chunk's session opens once its receipt window allows.
/// A producer applies them in its own loop.
pub(crate) async fn run_chain_timers<P: ProgramProver + 'static>(
    backend: Arc<ChainBackend<NodeDb, Sp1ProofSystem<P>>>,
    genesis_time_secs: u64,
    slot_duration_secs: u64,
) {
    let mut last_session_check_slot =
        current_slot(genesis_time_secs, slot_duration_secs, crate::now_secs()).saturating_sub(1);
    loop {
        let now = crate::now_secs();
        let slot = current_slot(genesis_time_secs, slot_duration_secs, now);
        backend.refresh_stale_candidates();
        if slot > last_session_check_slot {
            last_session_check_slot = slot;
            backend.maybe_open_next_bft_session().await;
        }
        tokio::time::sleep(
            sleep_until_next_slot(genesis_time_secs, slot_duration_secs, now)
                .min(Duration::from_secs(1)),
        )
        .await;
    }
}

async fn attempt_slot<P: ProgramProver + 'static>(
    backend: &Arc<ChainBackend<NodeDb, Sp1ProofSystem<P>>>,
    cmd_tx: &mpsc::Sender<NetworkCommand>,
    proposer: &ProposerKey,
    slot: u64,
) {
    if slot == 0 {
        return;
    }
    let worker = Arc::clone(backend);
    let proposer = proposer.clone();
    match tokio::task::spawn_blocking(move || worker.try_produce_block(slot, &proposer)).await {
        Ok(Ok(Some(outcome))) => {
            // Reserve foreground demand before the header wakes early facts;
            // the producer queues this candidate's proof on its next pass.
            backend.set_block_proof_backlog(1);
            backend.queue_header_facts(&outcome.block.header);
            // The candidate is published as soon as it is executed (design
            // 08); its receipt follows when the proof completes.
            if let Some(candidate) = backend.candidate_for_publication(&outcome.block_hash)
                && let Ok(data) = to_vec(&candidate)
            {
                let _ = cmd_tx
                    .send(NetworkCommand::Publish {
                        topic: Topic::Blocks,
                        data,
                    })
                    .await;
            }
            info!(slot, height = outcome.block.header.height,
                hash = ?outcome.block_hash, "produced and published candidate; queued for proving");
            backend
                .metrics()
                .blocks_produced
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Ok(Ok(None)) => debug!(slot, "validator not eligible for slot"),
        Ok(Err(ProductionError::NonMonotonicSlot { parent_slot, .. })) => {
            debug!(slot, parent_slot, "slot already covered by local head");
        }
        Ok(Err(error)) => warn!(slot, %error, "block production failed"),
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(error) => warn!(slot, %error, "block production task cancelled"),
    }
}

/// Free proof slots that candidates other nodes produced may take.
///
/// A producer keeps one slot for its own next block: production waits for
/// capacity, so other candidates may never take all of it.
const fn foreign_proof_slots(available: usize, producing: bool) -> usize {
    if producing {
        available.saturating_sub(1)
    } else {
        available
    }
}

fn current_slot(genesis_time_secs: u64, slot_duration_secs: u64, now_secs: u64) -> u64 {
    if now_secs <= genesis_time_secs {
        0
    } else {
        (now_secs - genesis_time_secs) / slot_duration_secs.max(1)
    }
}

fn sleep_until_next_slot(
    genesis_time_secs: u64,
    slot_duration_secs: u64,
    now_secs: u64,
) -> Duration {
    let slot_duration_secs = slot_duration_secs.max(1);
    if now_secs < genesis_time_secs {
        return Duration::from_secs((genesis_time_secs - now_secs).min(slot_duration_secs));
    }
    let elapsed = now_secs - genesis_time_secs;
    let remainder = elapsed % slot_duration_secs;
    let sleep_secs = if remainder == 0 {
        slot_duration_secs
    } else {
        slot_duration_secs - remainder
    };
    Duration::from_secs(sleep_secs.max(1))
}

#[cfg(test)]
mod tests;
