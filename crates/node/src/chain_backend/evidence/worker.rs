//! The blocking evidence prover: batches are proven, split on invalid
//! witnesses and installed under the engine lock.

use neutrin0_consensus_types::evidence::{EvidenceArtifact, EvidenceReport};
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_prover_chunk::evidence::EvidenceWitness;
use neutrin0_storage::Database;
use neutrin0_sync::EvidenceProofAcceptance;
use std::sync::{Arc, atomic::Ordering};

use super::reports::ready_report;

/// Prove independently retryable batches and install receipts under the engine lock.
#[allow(
    clippy::too_many_arguments,
    reason = "Every shared handle of the proving pipeline is passed explicitly to the worker."
)]
pub(super) fn prove_and_install_evidence<DB: Database, P: ProofSystem>(
    engine: &std::sync::Mutex<neutrin0_consensus_engine::Engine<DB>>,
    prover: &P,
    budget: &Arc<crate::proving_budget::ProvingBudget>,
    metrics: &crate::metrics::NodeMetrics,
    witnesses: Vec<EvidenceWitness>,
    pending: crate::proof_metrics::BacklogGuard,
    execution: &neutrin0_consensus_types::history_proof::ExecutionPrograms,
    executor: &dyn ErasedBlockExecutor,
) -> Vec<EvidenceReport> {
    let mut produced = Vec::new();
    let mut batches = vec![(witnesses, pending)];
    while let Some((batch, pending)) = batches.pop() {
        drop(pending);
        let result = budget.prove(crate::proof_metrics::ProofStage::Evidence, || {
            prover.prove_evidence_batch(&batch, execution)
        });
        let artifacts = match result {
            Ok(artifacts) => artifacts,
            Err(neutrin0_proof_system::ProofError::InvalidWitness) if batch.len() > 1 => {
                let middle = batch.len() / 2;
                let right = batch[middle..].to_vec();
                let left = batch[..middle].to_vec();
                batches.push((
                    right,
                    metrics
                        .proof_pipeline
                        .evidence_backlog
                        .track(batch.len() - middle),
                ));
                batches.push((left, metrics.proof_pipeline.evidence_backlog.track(middle)));
                continue;
            }
            Err(_) => continue,
        };
        for artifact in artifacts {
            // The backend returns verified artifacts. Storage/network
            // readers verify independently at their trust boundary.
            if artifact.evidence_guest_vk_digest != execution.evidence {
                metrics
                    .proof_pipeline
                    .local_evidence_outcome(EvidenceProofAcceptance::Rejected, false);
                continue;
            }
            let report = {
                let mut engine = engine.lock().expect("engine mutex");
                match install_local_artifact(&mut engine, executor, artifact) {
                    Ok((report, fresh)) => {
                        metrics
                            .proof_pipeline
                            .local_evidence_outcome(EvidenceProofAcceptance::Accepted, fresh);
                        if fresh && report.artifact.statement.reporter.is_some() {
                            metrics.reporter.submitted.fetch_add(1, Ordering::Relaxed);
                        }
                        report
                    }
                    Err(outcome) => {
                        metrics
                            .proof_pipeline
                            .local_evidence_outcome(outcome, false);
                        continue;
                    }
                }
            };
            produced.push(report);
        }
    }
    produced
}

/// Attach a local opening and check the tip again after background proving.
fn install_local_artifact<DB: Database>(
    engine: &mut neutrin0_consensus_engine::Engine<DB>,
    executor: &dyn ErasedBlockExecutor,
    artifact: EvidenceArtifact,
) -> Result<(EvidenceReport, bool), EvidenceProofAcceptance> {
    let submission = engine
        .evidence_submission(artifact.statement.clone())
        .map_err(|_| EvidenceProofAcceptance::Deferred)?;
    let mut report = EvidenceReport {
        artifact,
        history: submission.history,
    };
    // Proving may span finalization or a program switch. Check admission and
    // pool coverage before attaching the path and receipt to durable storage.
    let (submission, _) = ready_report(engine, executor, &report)?;
    report.history = submission.history;
    let fresh = engine
        .store_mut()
        .put_evidence_report(&report)
        .map_err(|_| EvidenceProofAcceptance::Deferred)?;
    Ok((report, fresh))
}
