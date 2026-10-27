//! Runtime queries for the governed evidence policy and offence coverage.

use neutrin0_consensus_types::evidence::SanctionKind;
use neutrin0_proof_system::ErasedBlockExecutor;
use neutrin0_runtime_abi::operational::{
    EvidenceCoverage, EvidenceCoverageRequest, EvidencePolicy, QUERY_EVIDENCE_COVERAGE,
    QUERY_EVIDENCE_POLICY,
};
use neutrin0_storage::Database;

pub(super) fn runtime_query<T: borsh::BorshDeserialize, DB: Database>(
    engine: &neutrin0_consensus_engine::Engine<DB>,
    executor: &dyn ErasedBlockExecutor,
    method: &str,
    args: Vec<u8>,
) -> Option<T> {
    let runtime = engine.runtime_code_hash_for(engine.head_height()).ok()?;
    let response = executor
        .query(
            &neutrin0_runtime_abi::QueryRequest {
                method: method.into(),
                args,
            },
            runtime,
            engine.state(),
        )
        .ok()?;
    response
        .is_ok()
        .then(|| borsh::from_slice(&response.payload).ok())
        .flatten()
}
pub(super) fn evidence_policy<DB: Database>(
    engine: &neutrin0_consensus_engine::Engine<DB>,
    executor: &dyn ErasedBlockExecutor,
) -> Option<EvidencePolicy> {
    let policy: EvidencePolicy =
        runtime_query(engine, executor, QUERY_EVIDENCE_POLICY, Vec::new())?;
    valid_policy(engine, policy)
}
fn valid_policy<DB: Database>(
    engine: &neutrin0_consensus_engine::Engine<DB>,
    policy: EvidencePolicy,
) -> Option<EvidencePolicy> {
    (policy.evidence_max_age_blocks > 0
        && policy.evidence_max_age_blocks < engine.chain_spec().runtime.unbonding_delay_blocks
        && policy.evidence_admissions_per_block > 0
        && policy.evidence_admissions_per_block <= neutrin0_runtime_abi::MAX_EVIDENCE_ADMISSIONS
        && policy.evidence_executions_per_block > 0
        && policy.pending_count <= policy.evidence_max_pending
        && policy.admission_gas > 0
        && policy.execution_gas > 0)
        .then_some(policy)
}
pub(super) fn finalized_evidence_policy<DB: Database>(
    engine: &neutrin0_consensus_engine::Engine<DB>,
    executor: &dyn ErasedBlockExecutor,
) -> Option<EvidencePolicy>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let boundary = engine
        .canonical_boundary(engine.finalized_next_chunk_id())
        .ok()?;
    let state =
        crate::chain_backend::rpc_queries::read_state_at(engine, boundary.state_root).ok()?;
    let runtime = engine.runtime_code_hash_for(boundary.height).ok()?;
    let response = executor
        .query(
            &neutrin0_runtime_abi::QueryRequest {
                method: QUERY_EVIDENCE_POLICY.into(),
                args: Vec::new(),
            },
            runtime,
            &state,
        )
        .ok()?;
    if !response.is_ok() {
        return None;
    }
    valid_policy(engine, borsh::from_slice(&response.payload).ok()?)
}
pub(super) fn statement_coverage(
    statement: &neutrin0_consensus_types::evidence::EvidenceStatement,
) -> EvidenceCoverageRequest {
    EvidenceCoverageRequest {
        identity: statement.offender.pubkey,
        offence_id: Some(statement.offence_id),
        liveness: (statement.kind == SanctionKind::Inactivity).then_some((
            statement.context.chunk_id,
            statement.offender.withdrawal_credentials,
        )),
    }
}
pub(super) fn coverage<DB: Database>(
    engine: &neutrin0_consensus_engine::Engine<DB>,
    executor: &dyn ErasedBlockExecutor,
    request: &EvidenceCoverageRequest,
) -> Option<EvidenceCoverage> {
    let response: Vec<EvidenceCoverage> = runtime_query(
        engine,
        executor,
        QUERY_EVIDENCE_COVERAGE,
        borsh::to_vec(&vec![*request]).ok()?,
    )?;
    (response.len() == 1).then(|| response[0])
}
