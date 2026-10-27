//! Admission of proven evidence reports into the persistent receipt pool and
//! the coverage rules that make a receipt redundant.

use neutrin0_consensus_types::evidence::{
    EvidenceAnchor, EvidenceArtifact, EvidenceReport, EvidenceSubmission, SanctionKind,
};
use neutrin0_consensus_types::history::is_recent_history_index;
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_storage::Database;
use neutrin0_sync::EvidenceProofAcceptance;
use std::sync::Arc;

use super::ChainBackend;
use super::policy::{coverage, evidence_policy, statement_coverage};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Authenticate the supplied history path before verifying the receipt
    /// outside engine locks, then refresh it again before durable installation.
    pub(in crate::chain_backend) async fn accept_evidence_report(
        &self,
        report: EvidenceReport,
    ) -> EvidenceProofAcceptance {
        let outcome = self.accept_evidence_report_inner(report).await;
        self.metrics.proof_pipeline.evidence_outcome(outcome);
        outcome
    }

    async fn accept_evidence_report_inner(
        &self,
        report: EvidenceReport,
    ) -> EvidenceProofAcceptance {
        use EvidenceProofAcceptance::{Accepted, Deferred, Rejected};
        if report.artifact.proof_bytes.is_empty()
            || report.artifact.proof_bytes.len()
                > neutrin0_consensus_types::evidence::MAX_EVIDENCE_PROOF_BYTES
        {
            return Rejected;
        }
        let evidence_program = match self.with_engine(|engine| {
            self.block_executor_snapshot()
                .ok_or(EvidenceProofAcceptance::Deferred)
                .and_then(|executor| ready_report(engine, executor.as_ref(), &report))
        }) {
            Ok((_, anchor)) => anchor.evidence_guest_vk_digest,
            Err(outcome) => return outcome,
        };
        let prover = Arc::clone(&self.proof_system);
        let metrics = Arc::clone(&self.metrics);
        let result = tokio::task::spawn_blocking(move || {
            metrics
                .proof_pipeline
                .evidence_verification
                .time(|| {
                    prover.verify_evidence(
                        &report.artifact.proof_bytes,
                        &report.artifact.membership.batch,
                        &evidence_program,
                    )
                })
                .map(|()| report)
        })
        .await;
        let mut report = match result {
            Ok(Ok(report)) => report,
            Ok(Err(_)) => return Rejected,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(_) => return Deferred,
        };
        self.with_engine_mut(|engine| {
            let (submission, _) = match self
                .block_executor_snapshot()
                .ok_or(EvidenceProofAcceptance::Deferred)
                .and_then(|executor| ready_report(engine, executor.as_ref(), &report))
            {
                Ok(ready) => ready,
                Err(outcome) => return outcome,
            };
            report.history = submission.history;
            if engine.store_mut().put_evidence_report(&report).is_ok() {
                Accepted
            } else {
                Deferred
            }
        })
    }
}

/// `false` for a liveness claim against a validator its chunk's certified
/// precommit counted or whose positive signature was acknowledged. Enabled
/// claims also wait two following chunks for challenges; the default policy
/// disables certificate-omission deductions entirely.
pub(super) fn liveness_certified<DB: Database>(
    engine: &neutrin0_consensus_engine::Engine<DB>,
    executor: &dyn ErasedBlockExecutor,
    statement: &neutrin0_consensus_types::evidence::EvidenceStatement,
) -> bool {
    statement.kind != SanctionKind::Inactivity
        || coverage(engine, executor, &statement_coverage(statement))
            .is_some_and(|status| status.liveness_eligible)
}

/// A liveness receipt whose challenge window is open and that the runtime
/// still does not admit: its source certificate counted the validator, or a
/// positive signature was acknowledged. Neither changes after the window.
fn liveness_never_admissible<DB: Database>(
    engine: &neutrin0_consensus_engine::Engine<DB>,
    executor: &dyn ErasedBlockExecutor,
    statement: &neutrin0_consensus_types::evidence::EvidenceStatement,
) -> bool {
    use neutrin0_consensus_types::participation::PARTICIPATION_CHALLENGE_CHUNKS;
    statement.kind == SanctionKind::Inactivity
        && statement
            .context
            .chunk_id
            .checked_add(PARTICIPATION_CHALLENGE_CHUNKS)
            .is_some_and(|deadline| engine.finalized_next_chunk_id() > deadline)
        && !liveness_certified(engine, executor, statement)
}

pub(super) fn ready_artifacts<DB: Database>(
    engine: &neutrin0_consensus_engine::Engine<DB>,
) -> Result<Vec<EvidenceArtifact>, neutrin0_consensus_engine::FinalizeError<DB::Error>> {
    let count = engine.finalized_next_chunk_id();
    let height = engine
        .head_height()
        .checked_add(1)
        .ok_or(neutrin0_proof_system::ProofError::InvalidWitness)?;
    let execution = engine.programs_for_height(height)?.execution;
    Ok(engine
        .store()
        .evidence_reports()?
        .into_iter()
        .filter(|report| {
            report.history.count == count
                && report.artifact.evidence_guest_vk_digest == execution.evidence
                && report.artifact.membership.batch.fact_guest_vk_digest == execution.fact
                && report.artifact.statement.block_guest_vk_digest == execution.block
        })
        .map(|report| report.artifact)
        .collect())
}

/// Authenticate admission from locally trusted programs and roots without
/// opening the source record in the receiver's historical tree.
pub(super) fn ready_report<DB: Database>(
    engine: &neutrin0_consensus_engine::Engine<DB>,
    executor: &dyn ErasedBlockExecutor,
    report: &EvidenceReport,
) -> Result<(EvidenceSubmission, EvidenceAnchor), EvidenceProofAcceptance> {
    use EvidenceProofAcceptance::{Deferred, Rejected};
    let artifact = &report.artifact;
    if artifact.statement.chain_id != engine.chain_spec().chain_id
        || artifact.statement.chain_spec_hash != engine.chain_spec().hash()
    {
        return Err(Rejected);
    }
    let height = engine.head_height().checked_add(1).ok_or(Deferred)?;
    let anchor = engine.evidence_anchor(height).map_err(|_| Deferred)?;
    if !artifact.binds(
        &artifact.statement,
        &anchor.evidence_guest_vk_digest,
        &anchor.fact_guest_vk_digest,
    ) {
        return Err(Rejected);
    }
    let max_age = evidence_policy(engine, executor)
        .ok_or(Deferred)?
        .evidence_max_age_blocks;
    receipt_window(&anchor, &artifact.statement, height, max_age)?;
    // A redundant receipt is valid but cannot add an admission. Preserve
    // the exact pooled statement so restarted reporters can refresh its path.
    let pooled = ready_artifacts(engine).map_err(|_| Deferred)?;
    if redundant_receipt(
        engine,
        executor,
        &pooled,
        Some(anchor.evidence_guest_vk_digest),
        &artifact.statement,
    ) {
        return Err(Deferred);
    }
    if artifact.statement.context.chunk_id >= engine.finalized_next_chunk_id() {
        return Err(Deferred);
    }
    // Anyone can prove absence from some sub-quorum of a real certificate.
    // Once the challenge window is open the runtime's verdict is final, so a
    // receipt it would never admit does not take pool space.
    if liveness_never_admissible(engine, executor, &artifact.statement) {
        return Err(Rejected);
    }
    let submission = engine
        .evidence_submission_with_path(&artifact.statement, &report.history)
        .map_err(|error| match error {
            neutrin0_consensus_engine::FinalizeError::Backend(
                neutrin0_proof_system::ProofError::InvalidWitness,
            ) => Rejected,
            _ => Deferred,
        })?;
    let execution = engine
        .evidence_submission_for_execution(height, &artifact.statement, &submission.history)
        .map_err(|_| Deferred)?;
    if !execution.binds(engine.chain_spec().chain_id, height, &anchor)
        || !execution.within_age(height, max_age)
    {
        return Err(Rejected);
    }
    Ok((submission, anchor))
}

/// Whether a receipt could be admitted at `height` as far as windows go. A
/// safety receipt about any finalized chunk is admissible; one about a chunk
/// not yet finalized here is not wrong and is deferred. A liveness receipt
/// outside the eight-chunk rule can never bind and is rejected; one outside
/// the governable age, or about the future, is deferred.
const fn receipt_window(
    anchor: &neutrin0_consensus_types::evidence::EvidenceAnchor,
    statement: &neutrin0_consensus_types::evidence::EvidenceStatement,
    height: u64,
    max_age: u64,
) -> Result<(), EvidenceProofAcceptance> {
    use EvidenceProofAcceptance::{Deferred, Rejected};
    let source = statement.context.chunk_id;
    let end = statement.context.end_height;
    if statement.kind.is_safety() {
        if source >= anchor.chunk_id || end >= height {
            return Err(Deferred);
        }
    } else {
        if source < anchor.chunk_id && !is_recent_history_index(source, anchor.chunk_id) {
            return Err(Rejected);
        }
        if end >= height || height - end > max_age {
            return Err(Deferred);
        }
    }
    Ok(())
}

/// A safety identity is accountable once. A tombstone at the head, a finalized
/// safety sanction, or a pooled safety receipt (other than `except`) under the
/// program the next block anchors already covers every offence the identity
/// could still answer for, so further reports and receipts against it are
/// redundant. A receipt under a superseded program shields nothing.
pub(super) fn safety_identity_covered<DB: Database>(
    engine: &neutrin0_consensus_engine::Engine<DB>,
    executor: &dyn ErasedBlockExecutor,
    pooled: &[EvidenceArtifact],
    anchor_program: Option<[u32; 8]>,
    pubkey: &neutrin0_primitives::BlsPublicKey,
    except: Option<&neutrin0_consensus_types::evidence::EvidenceStatement>,
) -> bool {
    coverage(
        engine,
        executor,
        &neutrin0_runtime_abi::operational::EvidenceCoverageRequest {
            identity: *pubkey,
            offence_id: None,
            liveness: None,
        },
    )
    .is_none_or(|status| status.tombstoned)
        || engine.store().is_identity_slashed(pubkey).unwrap_or(false)
        || pooled.iter().any(|item| {
            item.statement.kind == SanctionKind::Slash
                && item.statement.offender.pubkey == *pubkey
                && Some(item.evidence_guest_vk_digest) == anchor_program
                && except.is_none_or(|statement| item.statement != *statement)
        })
}

/// Whether the head state, finalized history or the pool already covers what a
/// receipt could admit: a liveness offence is admitted once, a safety identity
/// is sanctioned once. The exact pooled statement is not redundant, so
/// restarts and re-encodings still re-verify and answer `Accepted`.
fn redundant_receipt<DB: Database>(
    engine: &neutrin0_consensus_engine::Engine<DB>,
    executor: &dyn ErasedBlockExecutor,
    pooled: &[EvidenceArtifact],
    anchor_program: Option<[u32; 8]>,
    statement: &neutrin0_consensus_types::evidence::EvidenceStatement,
) -> bool {
    coverage(engine, executor, &statement_coverage(statement))
        .is_none_or(|status| status.admitted || status.tombstoned)
        || engine
            .store()
            .is_offence_finalized(&statement.offence_id)
            .unwrap_or(false)
        || (statement.kind == SanctionKind::Slash
            && safety_identity_covered(
                engine,
                executor,
                pooled,
                anchor_program,
                &statement.offender.pubkey,
                Some(statement),
            ))
}
