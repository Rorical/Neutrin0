//! Read-only runtime queries.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::BlsPublicKey;
use neutrin0_runtime_abi::{QueryRequest, QueryResponse, QueryStatus};
use neutrin0_runtime_core::StateBackend;

use crate::state::{
    Validator, load_consensus_candidates, load_participation, load_runtime_policy, load_validator,
    load_validator_registration, load_validator_set, load_withdrawal_queue, read_record,
    validator_key,
};
use crate::{Address, accountability, governance};

/// Query method: return the runtime-side [`Validator`] record at the
/// supplied address, or `None` if the validator does not exist.
///
/// Args wire format: the raw 32-byte address.
/// Payload wire format: `borsh(Option<Validator>)`.
///
/// Note: this returns the *runtime* [`Validator`] (stake + active
/// flag), not the consensus-side
/// `neutrin0_primitives::Validator` (which carries the BLS pubkey
/// and consensus metadata). The consensus-side view is served by
/// the RPC `active_validator_set` method.
pub const QUERY_METHOD_VALIDATOR_GET: &str = "validator_get";

/// Query method: return the canonical [`ValidatorSet`](crate::ValidatorSet)
/// snapshot, sorted by address ascending.
///
/// Args wire format: empty (no payload expected).
/// Payload wire format: `borsh(ValidatorSet)`.
pub const QUERY_METHOD_VALIDATOR_SET: &str = "validator_set";

/// Query method: return the runtime metadata advertised by this
/// runtime.
///
/// Args wire format: empty.
/// Payload wire format:
/// `borsh(neutrin0_primitives::RuntimeInfo)`.
pub const QUERY_METHOD_RUNTIME_INFO: &str = "runtime_info";

/// Query method: return the validator's [`WithdrawalQueue`](crate::WithdrawalQueue).
///
/// Args wire format: the raw 32-byte address.
/// Payload wire format: `borsh(WithdrawalQueue)` — empty queues are
/// returned as `WithdrawalQueue::default()` (empty entries vector),
/// not as a missing key.
pub const QUERY_METHOD_PENDING_WITHDRAWALS: &str = "pending_withdrawals";

/// Query method: return the [`ValidatorRegistration`](crate::ValidatorRegistration) recorded by
/// [`SystemAction::Register`](crate::system::SystemAction::Register) at the
/// supplied address, or `None` if it holds none.
///
/// Args wire format: the raw 32-byte address.
/// Payload wire format: `borsh(Option<ValidatorRegistration>)`.
pub const QUERY_METHOD_VALIDATOR_REGISTRATION: &str = "validator_registration";
/// Query method: open upgrade proposal and enacted switch.
///
/// Args: none. Returns a borsh [`UpgradeStatus`](crate::UpgradeStatus).
pub const QUERY_METHOD_UPGRADE_STATUS: &str = "upgrade_status";
/// Query method: the governable [`RuntimePolicy`](crate::RuntimePolicy) in force.
///
/// Args: none. Returns a borsh [`RuntimePolicy`](crate::RuntimePolicy).
pub const QUERY_METHOD_RUNTIME_POLICY: &str = "runtime_policy";
/// Query method: the consensus-facing
/// [`ConsensusCandidates`](neutrin0_consensus_types::runtime::ConsensusCandidates) record.
///
/// Args: none. Returns a borsh [`ConsensusCandidates`](neutrin0_consensus_types::runtime::ConsensusCandidates).
pub const QUERY_METHOD_CONSENSUS_CANDIDATES: &str = "consensus_candidates";
/// Query method: the latest certified
/// [`ParticipationReport`](neutrin0_consensus_types::participation::ParticipationReport) consumed.
///
/// Args: none. Returns a borsh `Option<ParticipationReport>`.
pub const QUERY_METHOD_PARTICIPATION: &str = "participation";

/// Encoded length of a maximal [`ReporterStatusRequest`]: the borsh `u32`
/// count followed by that many fixed-size identities.
const MAX_REPORTER_STATUS_ARGS_LEN: usize = size_of::<u32>()
    + MAX_REPORTER_STATUS_IDENTITIES * (size_of::<BlsPublicKey>() + size_of::<Address>());

pub use neutrin0_runtime_abi::operational::{
    MAX_REPORTER_STATUS_IDENTITIES, QUERY_METHOD_ACCOUNTABILITY_METRICS,
    QUERY_METHOD_REPORTER_STATUS, ReporterIdentity, ReporterStatus, ReporterStatusRequest,
};

/// Dispatch a [`QueryRequest`] against `state`.
///
/// Returns a [`QueryResponse`] carrying the runtime-defined result.
/// Implementations MUST be read-only: this function never writes to `state`
/// (`StateBackend::read` is the only access used). The host additionally
/// enforces the read-only invariant by rejecting any `state_write` /
/// `state_delete` call from the WASM guest with
/// `QueryStatus::PermissionDenied`.
///
/// Unknown methods return [`QueryStatus::UnknownMethod`] with the offending
/// method name as the payload bytes.
pub fn query<B: StateBackend>(request: &QueryRequest, state: &mut B) -> QueryResponse {
    match request.method.as_str() {
        neutrin0_runtime_abi::operational::QUERY_PROGRAMS => query_programs(&request.args, state),
        neutrin0_runtime_abi::operational::QUERY_EVIDENCE_POLICY => {
            let policy = load_runtime_policy(state);
            let queue = accountability::load_queue(state);
            ok_borsh(&neutrin0_runtime_abi::operational::EvidencePolicy {
                evidence_max_age_blocks: policy.evidence_max_age_blocks,
                evidence_max_pending: policy.evidence_max_pending,
                evidence_admissions_per_block: policy.evidence_admissions_per_block,
                evidence_executions_per_block: policy.evidence_executions_per_block,
                pending_count: u32::try_from(queue.len()).expect("bounded system FIFO"),
                admission_gas: accountability::GAS_EVIDENCE_ADMISSION,
                execution_gas: crate::GAS_SANCTION,
                abandonment_penalty_amount: policy.abandonment_penalty_amount,
            })
        }
        neutrin0_runtime_abi::operational::QUERY_EVIDENCE_COVERAGE => {
            query_evidence_coverage(&request.args, state)
        }
        QUERY_METHOD_VALIDATOR_GET => query_validator_get(&request.args, state),
        QUERY_METHOD_VALIDATOR_SET => ok_borsh(&load_validator_set(state)),
        QUERY_METHOD_RUNTIME_INFO => ok_borsh(&neutrin0_primitives::RuntimeInfo::default()),
        QUERY_METHOD_PENDING_WITHDRAWALS => query_pending_withdrawals(&request.args, state),
        QUERY_METHOD_REPORTER_STATUS => query_reporter_status(&request.args, state),
        QUERY_METHOD_ACCOUNTABILITY_METRICS => {
            if request.args.is_empty() {
                ok_borsh(&accountability::settlement::snapshot(state))
            } else {
                invalid_args()
            }
        }
        QUERY_METHOD_VALIDATOR_REGISTRATION => query_validator_registration(&request.args, state),
        QUERY_METHOD_CONSENSUS_CANDIDATES => ok_borsh(&load_consensus_candidates(state)),
        QUERY_METHOD_PARTICIPATION => ok_borsh(&load_participation(state)),
        QUERY_METHOD_RUNTIME_POLICY => ok_borsh(&load_runtime_policy(state)),
        QUERY_METHOD_UPGRADE_STATUS => ok_borsh(&governance::status(state)),
        unknown => QueryResponse::err(QueryStatus::UnknownMethod, unknown.as_bytes().to_vec()),
    }
}

/// Successful response carrying the canonical encoding of `value`.
fn ok_borsh<T: BorshSerialize>(value: &T) -> QueryResponse {
    QueryResponse::ok(borsh::to_vec(value).expect("borsh encoding into memory never fails"))
}

/// Malformed arguments, reported with an empty payload.
fn invalid_args() -> QueryResponse {
    QueryResponse::err(QueryStatus::InvalidArguments, Vec::new())
}

/// The raw 32-byte address argument, if `args` is exactly one.
fn address_arg(args: &[u8]) -> Option<Address> {
    <Address as BorshDeserialize>::try_from_slice(args).ok()
}

fn query_programs<B: StateBackend>(args: &[u8], state: &mut B) -> QueryResponse {
    // Stored proposals leave their slot only on its next write, so
    // the caller names the next block's anchor liveness is judged at.
    let Ok(anchor) = neutrin0_consensus_types::evidence::EvidenceAnchor::try_from_slice(args)
    else {
        return invalid_args();
    };
    let (chunk, min_lead) = (
        anchor.chunk_id,
        governance::upgrade_min_lead_chunks(&anchor),
    );
    let status = governance::status(state);
    let set = load_validator_set(state);
    let mut programs = Vec::new();
    // Nodes prepare the artifacts of one proposal: the live program
    // switch with the most support, the smallest id among equals.
    if let Some((_, _, identities, artifacts)) = status
        .proposals
        .iter()
        .filter(|proposal| proposal.is_live(chunk, min_lead))
        .filter_map(|proposal| match proposal.action {
            governance::ProposalAction::Programs {
                programs,
                artifacts,
                ..
            } => Some((
                proposal.voted_stake(&set),
                proposal.id(),
                programs,
                artifacts,
            )),
            governance::ProposalAction::Policy(_)
            | governance::ProposalAction::Cancel { .. }
            | governance::ProposalAction::Fork(_)
            | governance::ProposalAction::CancelFork(_) => None,
        })
        .max_by(|left, right| left.0.cmp(&right.0).then(right.1.cmp(&left.1)))
    {
        programs.push(neutrin0_runtime_abi::operational::ProgramDistribution {
            enacted: false,
            programs: identities,
            artifacts,
        });
    }
    if let Some(scheduled) = status.scheduled {
        programs.push(neutrin0_runtime_abi::operational::ProgramDistribution {
            enacted: true,
            programs: scheduled.programs,
            artifacts: scheduled.artifacts,
        });
    }
    ok_borsh(&programs)
}

fn query_evidence_coverage<B: StateBackend>(args: &[u8], state: &mut B) -> QueryResponse {
    let Ok(requests) =
        borsh::from_slice::<Vec<neutrin0_runtime_abi::operational::EvidenceCoverageRequest>>(args)
    else {
        return invalid_args();
    };
    if requests.len() > MAX_REPORTER_STATUS_IDENTITIES {
        return invalid_args();
    }
    let statuses: Vec<_> = requests
        .into_iter()
        .map(|request| {
            let liveness_eligible = request.liveness.is_none_or(|(chunk, address)| {
                if crate::state::load_runtime_policy(state).inactivity_leak_amount == 0 {
                    return false;
                }
                crate::state::load_participation(state)
                    .and_then(|report| report.chunk_id.checked_add(1))
                    .is_some_and(|incoming| {
                        crate::state::liveness_eligible(
                            state,
                            incoming,
                            chunk,
                            &request.identity,
                            &address,
                        )
                    })
            });
            neutrin0_runtime_abi::operational::EvidenceCoverage {
                participated: request.liveness.is_some_and(|(chunk, _)| {
                    crate::state::participation_acknowledged(state, chunk, &request.identity)
                }),
                tombstoned: state
                    .read(&accountability::slashed_key(&request.identity))
                    .is_some(),
                admitted: request
                    .offence_id
                    .is_some_and(|id| state.read(&accountability::offence_key(&id)).is_some()),
                liveness_eligible,
            }
        })
        .collect();
    ok_borsh(&statuses)
}

fn query_validator_get<B: StateBackend>(args: &[u8], state: &mut B) -> QueryResponse {
    let Some(address) = address_arg(args) else {
        return invalid_args();
    };
    ok_borsh(&read_record::<Validator, _>(
        state,
        &validator_key(&address),
    ))
}

fn query_pending_withdrawals<B: StateBackend>(args: &[u8], state: &mut B) -> QueryResponse {
    let Some(address) = address_arg(args) else {
        return invalid_args();
    };
    ok_borsh(&load_withdrawal_queue(state, &address))
}

fn query_reporter_status<B: StateBackend>(args: &[u8], state: &mut B) -> QueryResponse {
    let Some(count) = args.first_chunk::<4>() else {
        return invalid_args();
    };
    let count = usize::try_from(u32::from_le_bytes(*count)).unwrap_or(usize::MAX);
    if count > MAX_REPORTER_STATUS_IDENTITIES || args.len() > MAX_REPORTER_STATUS_ARGS_LEN {
        return invalid_args();
    }
    let Ok(request) = ReporterStatusRequest::try_from_slice(args) else {
        return invalid_args();
    };
    let pending: BTreeSet<BlsPublicKey> = accountability::load_queue(state)
        .into_iter()
        .map(|item| item.sanction.offender.pubkey)
        .collect();
    let statuses: Vec<ReporterStatus> = request
        .identities
        .into_iter()
        .map(|identity| ReporterStatus {
            slashable_balance: load_validator(state, &identity.withdrawal_credentials)
                .stake
                .saturating_add(
                    load_withdrawal_queue(state, &identity.withdrawal_credentials).total(),
                ),
            tombstoned: state
                .read(&accountability::slashed_key(&identity.pubkey))
                .is_some(),
            pending: pending.contains(&identity.pubkey),
            identity,
        })
        .collect();
    ok_borsh(&statuses)
}

fn query_validator_registration<B: StateBackend>(args: &[u8], state: &mut B) -> QueryResponse {
    let Some(address) = address_arg(args) else {
        return invalid_args();
    };
    ok_borsh(&load_validator_registration(state, &address))
}
