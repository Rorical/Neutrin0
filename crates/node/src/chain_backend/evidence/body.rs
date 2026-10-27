//! Selection of pooled evidence admissions and ordinary transactions into a
//! produced body under the runtime's gas and byte budgets.

use neutrin0_consensus_types::Body;
use neutrin0_consensus_types::evidence::{EvidenceAnchor, SanctionKind};
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_runtime_abi::operational::EvidencePolicy;
use neutrin0_storage::Database;

use super::ChainBackend;
use super::policy::{coverage, evidence_policy, statement_coverage};
use super::reports::liveness_certified;

/// Encoded bytes a produced body may spend on evidence admissions and ordinary
/// transactions together, counting four length-prefix bytes per item.
// Leave room for historical signature challenges, upgrade pieces and receipts.
// Actual full-envelope size is checked before signing; user-only backoff retains
// this evidence prefix and the pool's original entries.
const BODY_BYTE_BUDGET: usize = 4 * 1024 * 1024;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Select bounded, replay-free proof admissions. Runtime queue work gets its
    /// gas reservation before these admissions and ordinary transactions.
    pub(in crate::chain_backend) fn select_evidence_body(
        &self,
        transactions: &[Vec<u8>],
    ) -> (Body, usize) {
        let Some(executor) = self.block_executor_snapshot() else {
            return (Body::default(), 0);
        };
        self.with_engine(|engine| {
            let mut body = Body::default();
            let Some(policy) = evidence_policy(engine, executor.as_ref()) else {
                return (body, 0);
            };
            let Some(height) = engine.head_height().checked_add(1) else {
                return (body, 0);
            };
            let Ok(anchor) = engine.evidence_anchor(height) else {
                return (body, 0);
            };
            let bytes = select_evidence_admissions(
                engine,
                executor.as_ref(),
                &policy,
                height,
                &anchor,
                &mut body,
            );
            let ordinary_count = append_ordinary_transactions(&mut body, transactions, bytes);
            (body, ordinary_count)
        })
    }
}

/// Push every admissible pooled receipt into `body` in pool order, with its
/// `SubmitEvidence` transaction, and return the body bytes used.
fn select_evidence_admissions<DB: Database>(
    engine: &neutrin0_consensus_engine::Engine<DB>,
    executor: &dyn ErasedBlockExecutor,
    policy: &EvidencePolicy,
    height: u64,
    anchor: &EvidenceAnchor,
    body: &mut Body,
) -> usize
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let queued = usize::try_from(policy.pending_count).expect("u32 count");
    let mut selected = 0_usize;
    let mut bytes = 0_usize;
    for report in engine.store().evidence_reports().unwrap_or_default() {
        if report.history.count != engine.finalized_next_chunk_id() {
            continue;
        }
        let artifact = report.artifact;
        if selected >= policy.evidence_admissions_per_block as usize {
            break;
        }
        // A tombstoned identity or an already admitted liveness
        // offence cannot be admitted again; neither can a second safety
        // claim against an identity selected earlier in this body.
        if coverage(engine, executor, &statement_coverage(&artifact.statement))
            .is_none_or(|status| status.tombstoned || status.admitted)
            || (artifact.statement.kind == SanctionKind::Slash
                && body.evidence_proofs.iter().any(|selected| {
                    selected.statement.kind == SanctionKind::Slash
                        && selected.statement.offender.pubkey == artifact.statement.offender.pubkey
                }))
        {
            continue;
        }
        // The runtime refuses a block admitting a disabled liveness class.
        if !liveness_certified(engine, executor, &artifact.statement)
            || (artifact.statement.kind == SanctionKind::Abandonment
                && policy.abandonment_penalty_amount == 0)
        {
            continue;
        }
        let Ok(submission) =
            engine.evidence_submission_for_execution(height, &artifact.statement, &report.history)
        else {
            continue;
        };
        if !submission.binds(engine.chain_spec().chain_id, height, anchor)
            || !submission.within_age(height, policy.evidence_max_age_blocks)
        {
            continue;
        }
        if !artifact.binds(
            &submission.statement,
            &anchor.evidence_guest_vk_digest,
            &anchor.fact_guest_vk_digest,
        ) {
            continue;
        }
        let executions = (queued + selected + 1).min(policy.evidence_executions_per_block as usize);
        if queued + selected + 1 - executions > policy.evidence_max_pending as usize {
            break;
        }
        let gas = (executions as u64)
            .saturating_mul(policy.execution_gas)
            .saturating_add((selected as u64 + 1).saturating_mul(policy.admission_gas));
        if gas > engine.chain_spec().genesis_gas_limit {
            break;
        }
        let Ok(tx) = borsh::to_vec(&neutrin0_runtime_abi::RuntimeTransaction::SubmitEvidence(
            Box::new(submission),
        )) else {
            continue;
        };
        let Ok(attachment_bytes) = borsh::object_length(&artifact) else {
            continue;
        };
        if bytes + tx.len() + attachment_bytes + 4 > BODY_BYTE_BUDGET {
            continue;
        }
        bytes += tx.len() + attachment_bytes + 4;
        body.transactions.push(tx);
        body.evidence_proofs.push(artifact);
        selected += 1;
    }
    bytes
}

/// Append ordinary transactions after the evidence prefix while the byte
/// budget holds; returns how many were taken.
fn append_ordinary_transactions(
    body: &mut Body,
    transactions: &[Vec<u8>],
    mut bytes: usize,
) -> usize {
    let mut ordinary_count = 0;
    for tx in transactions {
        if bytes.saturating_add(tx.len()).saturating_add(4) > BODY_BYTE_BUDGET {
            break;
        }
        bytes += tx.len() + 4;
        body.transactions.push(tx.clone());
        ordinary_count += 1;
    }
    ordinary_count
}
