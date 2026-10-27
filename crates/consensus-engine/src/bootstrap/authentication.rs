//! Authentication of a snapshot's history, records and endpoint before
//! installation, and the state that opens the chunk after it.

use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::history::{HISTORY_RETENTION_CHUNKS, HistoryFrontier};
use neutrin0_consensus_types::history_proof::{ConsensusBoundary, HistoryProof};
use neutrin0_consensus_types::{ChunkProof, Header};
use neutrin0_primitives::{ConsensusDomain, ConsensusParams, Validator};
use neutrin0_proof_system::ProofError;
use neutrin0_prover_chunk::{
    consensus::{as_chunk, context_boundary, genesis_context},
    history::{HistoricalOpening, HistoryWitness},
};
use neutrin0_trie::Trie;

/// The verified receipt as the retained proof of its chunk under the
/// certificate the last authenticated record carries, so this node serves
/// History proofs and holds the proof the next certificate ratifies.
pub(super) fn bootstrap_chunk_proof(
    history: &HistoryProof,
    previous: &ConsensusBoundary,
    recent: &[HistoricalOpening],
) -> Result<ChunkProof, ProofError> {
    let receipt = &history.statement;
    let statement = &receipt.statement;
    let last = recent.last().ok_or(ProofError::InvalidWitness)?;
    let chunk = as_chunk(&statement.chunk);
    if last.record.chunk != chunk
        || last.record.start_boundary != previous.commitment()
        || commitment(&last.record.finality) != statement.finality_cert_hash
    {
        return Err(ProofError::PublicInputMismatch);
    }
    Ok(ChunkProof {
        finality_cert: last.record.finality.clone(),
        chunk_id: chunk.chunk_id,
        chunk_hash: chunk.hash(),
        public_inputs: statement.chunk.clone(),
        prover_address: receipt.chunk_prover_address,
        proof_bytes: history.receipt.as_ref().to_vec(),
    })
}

pub(super) fn covered_reports(
    executor: &dyn neutrin0_proof_system::ErasedBlockExecutor,
    runtime: neutrin0_primitives::Hash,
    state: &Trie,
    reports: &[neutrin0_consensus_types::evidence::EvidenceReport],
) -> Option<Vec<neutrin0_primitives::Hash>> {
    use neutrin0_runtime_abi::operational::{
        EvidenceCoverage, EvidenceCoverageRequest, QUERY_EVIDENCE_COVERAGE,
    };
    let requests = reports
        .iter()
        .map(|report| {
            let statement = &report.artifact.statement;
            EvidenceCoverageRequest {
                identity: statement.offender.pubkey,
                offence_id: Some(statement.offence_id),
                liveness: None,
            }
        })
        .collect::<Vec<_>>();
    let response = executor
        .query(
            &neutrin0_runtime_abi::QueryRequest {
                method: QUERY_EVIDENCE_COVERAGE.into(),
                args: borsh::to_vec(&requests).ok()?,
            },
            runtime,
            state,
        )
        .ok()?;
    if !response.is_ok() {
        return None;
    }
    let statuses: Vec<EvidenceCoverage> = borsh::from_slice(&response.payload).ok()?;
    if statuses.len() != reports.len() {
        return None;
    }
    Some(
        statuses
            .into_iter()
            .zip(reports)
            .filter(|(status, report)| {
                status.admitted
                    || (status.tombstoned
                        && report.artifact.statement.kind
                            == neutrin0_consensus_types::evidence::SanctionKind::Slash)
            })
            .map(|(_, report)| report.artifact.statement_id())
            .collect(),
    )
}

/// The retained records must be exactly the chunks before `count` within the
/// retention window, in order.
pub(super) fn check_recent_indices(
    count: u64,
    recent: &[HistoricalOpening],
) -> Result<(), ProofError> {
    if recent.len()
        != usize::try_from(count.min(HISTORY_RETENTION_CHUNKS))
            .map_err(|_| ProofError::InvalidWitness)?
    {
        return Err(ProofError::PublicInputMismatch);
    }
    let first = count.saturating_sub(HISTORY_RETENTION_CHUNKS);
    if recent.iter().enumerate().any(|(offset, opening)| {
        u64::try_from(offset)
            .ok()
            .and_then(|offset| first.checked_add(offset))
            != Some(opening.record.chunk.chunk_id)
    }) {
        return Err(ProofError::InvalidWitness);
    }
    Ok(())
}

/// The consensus state that opens the chunk after `end` under `spec`, which
/// must derive `end` back exactly.
pub(super) fn opening_state(
    spec: &neutrin0_primitives::ChainSpec,
    end: &ConsensusBoundary,
    validators: &[Validator],
    frontier: &HistoryFrontier,
) -> Result<crate::full_chunk::ConsensusState, ProofError> {
    let mut context = genesis_context(spec, end.programs);
    context.seed = end.seed;
    context.chunk_id = end.next_chunk_id;
    context.parent_block_hash = end.block_hash;
    context.pre_state_root = end.state_root;
    context.parent_slot = end.slot;
    context.active_validators = validators.to_vec();
    context.history_root = end.history_root;
    context.participation = end.participation;
    context.proving = end.proving;
    context.identity_sanctions_root = end.identity_sanctions_root;
    context.fork = end.fork;
    if context_boundary(&context, end.seed).map_err(|_| ProofError::InvalidWitness)? != *end {
        return Err(ProofError::PublicInputMismatch);
    }
    Ok(crate::full_chunk::ConsensusState {
        boundary: *end,
        next_context: context,
        next_seed: end.seed,
        frontier: frontier.clone(),
    })
}

pub(super) fn authenticate_history(
    domain: ConsensusDomain,
    params: &ConsensusParams,
    end: &ConsensusBoundary,
    header: &Header,
    frontier: &HistoryFrontier,
    recent: &[HistoricalOpening],
) -> Result<(), ProofError> {
    let history = HistoryWitness {
        frontier: frontier.clone(),
        records: recent.iter().map(Into::into).collect(),
    };
    history
        .authenticate(end.next_chunk_id, end.history_root)
        .map_err(|_| ProofError::InvalidWitness)?;
    for opening in recent {
        neutrin0_prover_chunk::finality::verify_finality(
            domain,
            params,
            &opening.record.validators,
            &opening.record.seed,
            &opening.record.chunk,
            &opening.record.finality,
        )
        .map_err(|_| ProofError::InvalidWitness)?;
    }
    let last = recent.last().ok_or(ProofError::InvalidWitness)?;
    if last.record.chunk.end_block_hash != end.block_hash
        || last.record.chunk.end_height != end.height
        || last.record.chunk.end_state_root != end.state_root
        || last.record.chunk.next_validator_set_root != end.validators_root
        || last.record.chunk.next_identity_sanctions_root != end.identity_sanctions_root
    {
        return Err(ProofError::PublicInputMismatch);
    }
    crate::verify_header_signature(header, &last.record.validators, domain)
        .map_err(|_| ProofError::InvalidWitness)?;
    Ok(())
}
