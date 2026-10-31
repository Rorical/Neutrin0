//! Opportunistic early fact compression. BFT never waits on a proof.

use super::{ChainBackend, reporter_retention};
use crate::metrics::NodeMetrics;
use crate::proof_metrics::{BacklogGuard, FACT_QUEUE_CAPACITY, ProofStage};
use crate::proving_budget::ProvingBudget;
use neutrin0_consensus_types::history_proof::VkDigest;
use neutrin0_proof_system::ProofSystem;
use neutrin0_prover_chunk::facts::{FactRequest, MAX_FACTS};
use neutrin0_storage::Database;
use std::sync::{Arc, atomic::Ordering};
use tokio::sync::mpsc;

pub(super) struct FactJob {
    program: VkDigest,
    requests: Vec<FactRequest>,
    pending: BacklogGuard,
}

async fn run_fact_worker<P: ProofSystem + Send + Sync + 'static>(
    mut rx: mpsc::Receiver<FactJob>,
    prover: Arc<P>,
    budget: Arc<ProvingBudget>,
) {
    let mut carried = None;
    while let Some(job) = match carried.take() {
        Some(job) => Some(job),
        None => rx.recv().await,
    } {
        // Coalesce after the foreground queue drains, so waiting work joins
        // one batch instead of taking the device between every pair of blocks.
        budget.wait_for_block_proofs().await;
        let FactJob {
            program,
            mut requests,
            pending,
        } = job;
        let mut pending = vec![pending];
        for _ in 0..FACT_QUEUE_CAPACITY {
            let Ok(next) = rx.try_recv() else {
                break;
            };
            if next.program == program {
                requests.extend(next.requests);
                pending.push(next.pending);
            } else {
                carried = Some(next);
                break;
            }
        }
        let prover = Arc::clone(&prover);
        let budget = Arc::clone(&budget);
        match tokio::task::spawn_blocking(move || {
            drop(pending);
            budget.prove(ProofStage::Fact, || {
                prover.preprove_facts(&program, &requests)
            })
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::debug!(%error, "early fact proof unavailable; evidence will prove on demand");
            }
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(error) => tracing::warn!(%error, "early fact worker cancelled"),
        }
    }
}

fn enqueue_fact_groups(
    sender: &mpsc::Sender<FactJob>,
    program: VkDigest,
    requests: &[FactRequest],
    metrics: &NodeMetrics,
) {
    let groups = requests.chunks(MAX_FACTS);
    let count = groups.len();
    for (index, group) in groups.enumerate() {
        let pipeline = &metrics.proof_pipeline;
        if !borsh::object_length(&group).is_ok_and(|bytes| bytes <= 2 * 1024 * 1024) {
            pipeline
                .fact_dropped_oversize
                .fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let job = FactJob {
            program,
            requests: group.to_vec(),
            pending: pipeline.fact_backlog.track(group.len()),
        };
        let remaining = u64::try_from(count - index).unwrap_or(u64::MAX);
        match sender.try_send(job) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                pipeline
                    .fact_dropped_full
                    .fetch_add(remaining, Ordering::Relaxed);
                break;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                pipeline
                    .fact_dropped_closed
                    .fetch_add(remaining, Ordering::Relaxed);
                break;
            }
        }
    }
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(super) fn queue_facts(&self, requests: &[FactRequest]) {
        if requests.is_empty() || self.fact_program().is_none() {
            return;
        }
        // Facts are proven under the fact program of the chunk being built,
        // the one whose chunk proof will consume the receipts.
        let Ok(fact_program) = self.with_engine(|engine| {
            engine
                .programs_at_chunk(engine.finalized_next_chunk_id())
                .map(|programs| programs.execution.fact)
        }) else {
            return;
        };
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let mut guard = self.fact_jobs.lock().expect("fact queue mutex");
        if guard.as_ref().is_none_or(mpsc::Sender::is_closed) {
            let (tx, rx) = mpsc::channel::<FactJob>(FACT_QUEUE_CAPACITY);
            self.spawn_supervised(
                "facts",
                true,
                run_fact_worker(
                    rx,
                    Arc::clone(&self.proof_system),
                    Arc::clone(&self.proving_budget),
                ),
            );
            *guard = Some(tx);
        }
        let sender = guard.as_ref().expect("initialized fact queue").clone();
        drop(guard);
        enqueue_fact_groups(&sender, fact_program, requests, &self.metrics);
    }

    /// Validators that signed material for `chunk_id`: the historical record
    /// when the chunk is finalized and recent, otherwise the active set.
    fn fact_validators_for_chunk(
        &self,
        chunk_id: u64,
    ) -> Option<(
        neutrin0_primitives::ConsensusDomain,
        Vec<neutrin0_primitives::Validator>,
    )> {
        self.with_engine(|engine| {
            let next = engine.finalized_next_chunk_id();
            let historical = engine.store().historical_chunk(chunk_id).ok().flatten();
            if chunk_id < next
                && !neutrin0_consensus_types::history::is_recent_history_index(chunk_id, next)
                && !(reporter_retention(engine) && historical.is_some())
            {
                return None;
            }
            let validators = historical.map_or_else(
                || engine.active_validator_set().to_vec(),
                |record| record.validators,
            );
            Some((engine.chain_spec().consensus_domain(), validators))
        })
    }

    /// Pre-prove a leader proposal's signature and round-change certificate.
    pub(super) fn queue_proposal_facts(&self, proposal: &neutrin0_consensus_types::BftProposal) {
        if let Some((domain, validators)) = self.fact_validators_for_chunk(proposal.chunk.chunk_id)
        {
            self.queue_facts(&neutrin0_prover_chunk::facts::proposal_requests(
                domain,
                &validators,
                proposal,
            ));
        }
    }

    /// Pre-prove a round-change report and its carried quorum.
    pub(super) fn queue_round_change_facts(&self, report: &neutrin0_consensus_types::RoundChange) {
        if let Some((domain, validators)) = self.fact_validators_for_chunk(report.chunk_id) {
            self.queue_facts(&neutrin0_prover_chunk::facts::round_change_requests(
                domain,
                &validators,
                report,
            ));
        }
    }

    /// Pre-prove every report inside a round-change certificate.
    pub(super) fn queue_round_change_certificate_facts(
        &self,
        certificate: &neutrin0_consensus_types::RoundChangeCertificate,
    ) {
        if let Some((domain, validators)) = self.fact_validators_for_chunk(certificate.chunk_id) {
            self.queue_facts(
                &neutrin0_prover_chunk::facts::round_change_certificate_requests(
                    domain,
                    &validators,
                    certificate,
                ),
            );
        }
    }

    pub(super) fn queue_vote_facts(&self, vote: &neutrin0_consensus_types::FinalityVote) {
        if self.fact_program().is_none() {
            return;
        }
        let requests = self.with_engine(|engine| {
            let next = engine.finalized_next_chunk_id();
            if vote.data.chunk_id < next
                && !neutrin0_consensus_types::history::is_recent_history_index(
                    vote.data.chunk_id,
                    next,
                )
            {
                return Vec::new();
            }
            let validators = engine
                .store()
                .historical_chunk(vote.data.chunk_id)
                .ok()
                .flatten()
                .map_or_else(
                    || engine.active_validator_set().to_vec(),
                    |record| record.validators,
                );
            neutrin0_prover_chunk::facts::vote_requests(
                engine.chain_spec().consensus_domain(),
                &validators,
                vote,
            )
        });
        self.queue_facts(&requests);
    }

    pub(crate) fn queue_header_facts(&self, header: &neutrin0_consensus_types::Header) {
        if self.fact_program().is_none() {
            return;
        }
        let requests = self.with_engine(|engine| {
            let id =
                header.height.saturating_sub(1) / engine.chain_spec().consensus.chunk_size.max(1);
            let next = engine.finalized_next_chunk_id();
            if id < next && !neutrin0_consensus_types::history::is_recent_history_index(id, next) {
                return Vec::new();
            }
            let Ok((validators, seed)) = engine.validator_context_for_height(header.height) else {
                return Vec::new();
            };
            neutrin0_prover_chunk::facts::header_requests(
                engine.chain_spec().consensus_domain(),
                &validators,
                &seed,
                header,
            )
        });
        self.queue_facts(&requests);
    }
}

#[cfg(test)]
mod metrics_tests;
