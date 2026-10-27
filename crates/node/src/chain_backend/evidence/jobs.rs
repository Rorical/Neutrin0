//! Selecting raw reports and liveness omissions to prove, and running the
//! background evidence worker over them.

use neutrin0_consensus_types::evidence::{EvidenceArtifact, EvidenceReport};
use neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS;
use neutrin0_consensus_types::history_proof::ExecutionPrograms;
use neutrin0_network::{Topic, service::NetworkCommand};
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_prover_chunk::{
    evidence::{EvidenceClaim, EvidenceWitness},
    history::{PENALTY_INACTIVITY, penalty_id},
};
use neutrin0_runtime_abi::operational::{EvidenceCoverageRequest, EvidencePolicy};
use neutrin0_storage::Database;
use std::sync::{Arc, atomic::Ordering};
use tokio::sync::mpsc;

use super::ChainBackend;
use super::policy::{coverage, evidence_policy, finalized_evidence_policy};
use super::reports::{ready_artifacts, safety_identity_covered};
use super::worker::prove_and_install_evidence;

type Engine<DB> = neutrin0_consensus_engine::Engine<DB>;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Triggered by evidence arrival, finalization and block-production events.
    /// Proving never holds the engine lock or blocks the BFT message task.
    pub(in crate::chain_backend) fn start_evidence_jobs(&self) {
        self.refresh_reporter_tracking();
        let Some(executor) = self.block_executor_snapshot() else {
            return;
        };
        if self.block_program().is_none() {
            return;
        }
        // Evidence is proven under the execution programs of the chunk being
        // built, which is where its admission will be checked.
        let Some(execution) = self.with_engine(|engine| {
            engine
                .head_height()
                .checked_add(1)
                .and_then(|height| engine.programs_for_height(height).ok())
                .map(|programs| programs.execution)
        }) else {
            return;
        };
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        if self.evidence_job_running.swap(true, Ordering::AcqRel) {
            self.metrics
                .proof_pipeline
                .evidence_busy
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let witnesses = self.select_evidence_jobs(execution.block);
        if witnesses.is_empty() {
            self.evidence_job_running.store(false, Ordering::Release);
            return;
        }
        self.spawn_evidence_worker(witnesses, execution, executor);
    }

    /// Prove `witnesses` on a blocking worker and publish the resulting
    /// reports; the running flag is released whatever the outcome.
    fn spawn_evidence_worker(
        &self,
        witnesses: Vec<EvidenceWitness>,
        execution: ExecutionPrograms,
        executor: Arc<dyn ErasedBlockExecutor>,
    ) {
        let engine = Arc::clone(&self.engine);
        let prover = Arc::clone(&self.proof_system);
        let chunk = self.with_engine(|engine| engine.chain_spec().genesis_chunk);
        let programs = neutrin0_consensus_types::history_proof::GuestPrograms { execution, chunk };
        let budget = Arc::clone(&self.proving_budget);
        let running = Arc::clone(&self.evidence_job_running);
        let publisher = self.publisher_snapshot();
        let metrics = Arc::clone(&self.metrics);
        let pending = metrics
            .proof_pipeline
            .evidence_backlog
            .track(witnesses.len());
        self.spawn_supervised("evidence", false, async move {
            let result = tokio::task::spawn_blocking(move || {
                let _program_lease = match budget.setup(|| prover.lease_programs(&programs)) {
                    Ok(lease) => lease,
                    Err(error) => {
                        tracing::warn!(?error, "evidence programs unavailable");
                        return Vec::new();
                    }
                };
                prove_and_install_evidence(
                    engine.as_ref(),
                    prover.as_ref(),
                    &budget,
                    &metrics,
                    witnesses,
                    pending,
                    &execution,
                    executor.as_ref(),
                )
            })
            .await;
            running.store(false, Ordering::Release);
            match result {
                Ok(reports) => publish_evidence_reports(publisher, reports).await,
                Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
                Err(error) => tracing::warn!(
                    ?error,
                    "evidence worker failed; raw evidence retained for retry"
                ),
            }
        });
    }

    /// Raw signed-misconduct reports worth proving now, rotating through the
    /// persistent raw pool so no report starves. Signature/proof checking is
    /// expensive and happens in the worker; the content commitment deduplicates
    /// queued copies. A raw report has no age: a safety claim is admissible
    /// once per identity whenever it arrives.
    fn raw_report_jobs(
        &self,
        engine: &Engine<DB>,
        pooled: &[EvidenceArtifact],
        block_key: [u32; 8],
    ) -> Vec<EvidenceWitness> {
        let anchor_program = engine
            .head_height()
            .checked_add(1)
            .and_then(|height| engine.evidence_anchor(height).ok())
            .map(|anchor| anchor.evidence_guest_vk_digest);
        let raw = engine.store().iter_slashing_evidence().unwrap_or_default();
        let offset = self.evidence_job_cursor.fetch_add(8, Ordering::Relaxed);
        let mut witnesses = Vec::new();
        for (_, evidence) in raw
            .iter()
            .cycle()
            .skip(if raw.is_empty() {
                0
            } else {
                offset % raw.len()
            })
            .take(raw.len())
        {
            if witnesses.len() >= 8 {
                break;
            }
            let Ok(mut witness) = engine.evidence_witness(evidence) else {
                continue;
            };
            witness.reporter = self.reporter_recipient();
            // Re-proving an old offence uses the admission chunk's execution
            // program. Its source record separately binds the historical key.
            witness.block_guest_vk_digest = block_key;
            let Some(accused) = witness
                .source
                .validators
                .get(evidence.offender_index() as usize)
            else {
                continue;
            };
            if self.block_executor_snapshot().is_none_or(|executor| {
                safety_identity_covered(
                    engine,
                    executor.as_ref(),
                    pooled,
                    anchor_program,
                    &accused.pubkey,
                    None,
                )
            }) {
                continue;
            }
            let facts = neutrin0_consensus_types::evidence::commitment(&witness.claim);
            if !pooled
                .iter()
                .any(|item| item.statement.facts_commitment == facts)
            {
                witnesses.push(witness);
            }
        }
        witnesses
    }

    fn select_evidence_jobs(&self, block_key: [u32; 8]) -> Vec<EvidenceWitness> {
        let Some(executor) = self.block_executor_snapshot() else {
            return Vec::new();
        };
        self.with_engine_mut(|engine| {
            let Some(policy) = evidence_policy(engine, executor.as_ref()) else {
                return Vec::new();
            };
            let next_chunk = engine.finalized_next_chunk_id();
            if next_chunk == 0 {
                return Vec::new();
            }
            prune_released_artifacts(engine, executor.as_ref());
            let existing = ready_artifacts(engine).unwrap_or_default();
            let mut witnesses = self.raw_report_jobs(engine, &existing, block_key);
            self.inactivity_jobs(
                engine,
                executor.as_ref(),
                &policy,
                &existing,
                block_key,
                &mut witnesses,
            );
            self.abandonment_jobs(
                engine,
                executor.as_ref(),
                &policy,
                &existing,
                block_key,
                &mut witnesses,
            );
            witnesses
        })
    }

    /// Liveness omissions in the retained window whose challenge period has
    /// passed, up to sixteen witnesses in all.
    fn inactivity_jobs(
        &self,
        engine: &Engine<DB>,
        executor: &dyn ErasedBlockExecutor,
        policy: &EvidencePolicy,
        existing: &[EvidenceArtifact],
        block_key: [u32; 8],
        witnesses: &mut Vec<EvidenceWitness>,
    ) {
        let next_chunk = engine.finalized_next_chunk_id();
        let known = |id: &[u8; 32]| {
            existing.iter().any(|item| item.statement.offence_id == *id)
                || coverage(
                    engine,
                    executor,
                    &EvidenceCoverageRequest {
                        identity: [0; 48],
                        offence_id: Some(*id),
                        liveness: None,
                    },
                )
                .is_none_or(|status| status.admitted)
        };
        for chunk_id in next_chunk.saturating_sub(HISTORY_RETENTION_CHUNKS)..next_chunk {
            if chunk_id
                .checked_add(
                    neutrin0_consensus_types::participation::PARTICIPATION_CHALLENGE_CHUNKS,
                )
                .is_none_or(|deadline| next_chunk <= deadline)
            {
                continue;
            }
            let Ok(Some(source)) = engine.store().historical_chunk(chunk_id) else {
                continue;
            };
            // Absence follows the certificate explicitly selected by the
            // following chunk, not this node's first-arriving finality subset.
            let Ok(Some(certificate)) = engine.selected_participation_certificate(chunk_id) else {
                continue;
            };
            if engine
                .head_height()
                .saturating_add(1)
                .saturating_sub(source.chunk.end_height)
                > policy.evidence_max_age_blocks
            {
                continue;
            }
            for (index, validator) in source.validators.iter().enumerate() {
                if witnesses.len() >= 16 {
                    return;
                }
                let Ok(index) = u32::try_from(index) else {
                    continue;
                };
                let id = penalty_id(PENALTY_INACTIVITY, validator, source.chunk.chunk_id, 0);
                if validator.effective_stake == 0
                    || known(&id)
                    || certificate.aggregate.aggregation_bits.get(index) != Some(false)
                {
                    continue;
                }
                if !coverage(
                    engine,
                    executor,
                    &EvidenceCoverageRequest {
                        identity: validator.pubkey,
                        offence_id: Some(id),
                        liveness: Some((chunk_id, validator.withdrawal_credentials)),
                    },
                )
                .is_some_and(|status| status.liveness_eligible)
                {
                    continue;
                }
                witnesses.push(EvidenceWitness {
                    chain_spec: engine.chain_spec().clone(),
                    source: source.clone(),
                    claim: EvidenceClaim::Inactivity {
                        validator_index: index,
                        certificate: certificate.clone(),
                    },
                    block_guest_vk_digest: block_key,
                    reporter: self.reporter_recipient(),
                });
            }
        }
    }
}

/// Drop pooled receipts that finalized facts release: admitted or aged out
/// under the finalized policy, or proven under programs no block can use.
fn prune_released_artifacts<DB: Database>(
    engine: &mut Engine<DB>,
    executor: &dyn ErasedBlockExecutor,
) where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let finalized_height = engine
        .latest_finalized_chunk_id()
        .and_then(|id| id.checked_add(1))
        .and_then(|n| n.checked_mul(engine.chain_spec().consensus.chunk_size))
        .unwrap_or(0);
    // Only finalized facts release pooled receipts, including the
    // governed age window: a reorg of the head must never lose
    // evidence, so an unreadable finalized policy prunes nothing.
    if let Some(policy) = finalized_evidence_policy(engine, executor) {
        // A receipt is admissible only under the programs of the
        // first unfinalized chunk or of the head's next block; a
        // switch between them is at most one chunk boundary away.
        let mut usable: Vec<_> = [finalized_height, engine.head_height().saturating_add(1)]
            .into_iter()
            .filter_map(|height| engine.programs_for_height(height).ok())
            .map(|programs| programs.execution)
            .collect();
        usable.dedup();
        if let Err(error) = engine.store_mut().prune_evidence_artifacts(
            finalized_height,
            policy.evidence_max_age_blocks,
            &usable,
        ) {
            tracing::warn!(?error, "evidence pool pruning failed");
        }
    } else {
        tracing::warn!("finalized evidence policy unavailable; pruning skipped");
    }
}

/// Gossip each proven report on the evidence lane, when a publisher is installed.
async fn publish_evidence_reports(
    publisher: Option<mpsc::Sender<NetworkCommand>>,
    reports: Vec<EvidenceReport>,
) {
    if let Some(publisher) = publisher {
        for report in reports {
            if let Ok(data) = borsh::to_vec(&report) {
                let _ = publisher
                    .send(NetworkCommand::Publish {
                        topic: Topic::EvidenceProofs,
                        data,
                    })
                    .await;
            }
        }
    }
}
