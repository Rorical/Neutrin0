//! Validator records and their projection into the consensus candidate
//! record: storing, retiring, unbonding and the safety-tombstone removals.

use neutrin0_consensus_types::runtime::{BlsIdentity, ConsensusCandidate};
use neutrin0_runtime_core::StateBackend;

use crate::Address;
use crate::state::{
    Validator, Withdrawal, bonding_key, load_consensus_candidates, load_validator_record,
    load_validator_registration, load_withdrawal_queue, registration_key,
    store_consensus_candidates, store_validator, store_validator_registration,
    store_withdrawal_queue, validator_key, withdrawal_key,
};

/// Keep the consensus projection bounded while retaining separate runtime
/// economic records, and return it as stored.
///
/// A genesis full exit stays projected at zero until consensus has recorded
/// its finite exit epoch. Tombstoned identities left when they were
/// tombstoned, so no block reads a tombstone per candidate.
pub fn prune_consensus_candidates<B: StateBackend>(
    state: &mut B,
    active: &[neutrin0_primitives::Validator],
) -> neutrin0_consensus_types::runtime::ConsensusCandidates {
    let mut candidates = load_consensus_candidates(state);
    let before = candidates.entries.len();
    candidates.entries.retain(|candidate| {
        candidate.stake > 0
            || active.iter().any(|seat| {
                seat.withdrawal_credentials == candidate.address && seat.exit_epoch == u64::MAX
            })
    });
    if candidates.entries.len() != before {
        store_consensus_candidates(state, &candidates);
    }
    candidates
}

/// Hold the address a safety offence names at admission, as if its key had
/// never rotated: a registration that a rotation moved to another key after
/// the offence returns to the offending (now tombstoned) key, so the address
/// can neither bond, rotate nor be projected again, exactly like an address
/// whose registered key itself was tombstoned (design 19). Its candidate
/// entry leaves with it. The registration keeps the rotated key's PoP, which
/// nothing reads again: the tombstone is permanent and a tombstoned
/// registration is never projected. A genesis seat has no registration; one
/// is written for its tombstoned key, so the address is held all the same.
pub(crate) fn hold_offender<B: StateBackend>(
    state: &mut B,
    offender: &neutrin0_primitives::Validator,
) {
    let address = &offender.withdrawal_credentials;
    match load_validator_registration(state, address) {
        Some(mut registration) if registration.bls_pubkey != offender.pubkey => {
            registration.bls_pubkey = offender.pubkey;
            store_validator_registration(state, &registration);
        }
        Some(_) => {}
        None => store_validator_registration(
            state,
            &crate::state::ValidatorRegistration {
                address: *address,
                bls_pubkey: offender.pubkey,
                pop_signature: [0; 96],
                registered_at_height: 0,
            },
        ),
    }
    let record = load_validator_record(state, address);
    sync_consensus_candidate(state, address, record.as_ref());
    forget_tombstoned_identity(state, &offender.pubkey);
}

/// Remove every candidate carrying `pubkey`, whose identity was just
/// tombstoned. Consensus never seats it again, so neither the projection nor
/// a later candidate sync may carry it.
pub(crate) fn forget_tombstoned_identity<B: StateBackend>(
    state: &mut B,
    pubkey: &neutrin0_primitives::BlsPublicKey,
) {
    let mut candidates = load_consensus_candidates(state);
    let before = candidates.entries.len();
    candidates.entries.retain(|candidate| {
        candidate
            .identity
            .is_none_or(|identity| identity.pubkey != *pubkey)
    });
    if candidates.entries.len() != before {
        store_consensus_candidates(state, &candidates);
    }
}

/// Store `validator` and mirror it into the consensus-facing candidate record.
pub(super) fn commit_validator<B: StateBackend>(
    state: &mut B,
    address: &Address,
    validator: &Validator,
) {
    store_validator(state, address, validator);
    sync_consensus_candidate(state, address, Some(validator));
}

/// Project `addr`'s validator record and registration into the candidate
/// record. Every path that changes either calls this with the validator record
/// it just stored (`None` once deleted), so the record is a pure function of
/// the runtime's own state.
pub(super) fn sync_consensus_candidate<B: StateBackend>(
    state: &mut B,
    addr: &Address,
    validator: Option<&Validator>,
) {
    let registration = load_validator_registration(state, addr);
    // A tombstoned identity is never projected again (see
    // [`forget_tombstoned_identity`]).
    let tombstoned = registration.as_ref().is_some_and(|registration| {
        state
            .read(&crate::accountability::slashed_key(
                &registration.bls_pubkey,
            ))
            .is_some()
    });
    let mut candidates = load_consensus_candidates(state);
    if tombstoned || (validator.is_none() && registration.is_none()) {
        if candidates.remove(addr) {
            store_consensus_candidates(state, &candidates);
        }
        return;
    }
    candidates.upsert(ConsensusCandidate {
        address: *addr,
        stake: validator.map_or(0, |validator| validator.stake),
        identity: registration.map(|registration| BlsIdentity {
            pubkey: registration.bls_pubkey,
            pop_signature: registration.pop_signature,
        }),
    });
    store_consensus_candidates(state, &candidates);
}

/// Drop every runtime record of a validator whose stake and withdrawal
/// queue are both empty. The caller has already verified that no sanction
/// is pending against `addr`. Consensus observed the zero stake at a chunk
/// boundary before this point because the unbonding delay exceeds the
/// chunk size, so the deleted record cannot resurrect stake. A registration
/// holding a tombstoned key stays: it is the address's permanent hold.
pub(super) fn retire_validator<B: StateBackend>(state: &mut B, addr: &Address) {
    state.delete(&validator_key(addr));
    state.delete(&withdrawal_key(addr));
    state.delete(&bonding_key(addr));
    let held = load_validator_registration(state, addr).is_some_and(|registration| {
        state
            .read(&crate::accountability::slashed_key(
                &registration.bls_pubkey,
            ))
            .is_some()
    });
    if !held {
        state.delete(&registration_key(addr));
    }
    sync_consensus_candidate(state, addr, None);
}

/// Move `withdrawal.amount` out of slashable stake into the validator's
/// withdrawal queue.
///
/// The amount leaves slashable stake at once, so a slash after this block
/// cannot reach it until the queued entry is claimed; a later withdrawal
/// drains matured entries back into the account.
pub(super) fn unbond<B: StateBackend>(
    state: &mut B,
    address: &Address,
    mut validator: Validator,
    withdrawal: Withdrawal,
) {
    let mut queue = load_withdrawal_queue(state, address);
    // Unbonds maturing at the same height share one entry, so a validator
    // adds at most one entry per block however many unstakes it submits.
    // Same-maturity entries are always the queue's tail, and deductions and
    // withdrawals only depend on the amount queued at each maturity.
    match queue.entries.last_mut() {
        Some(last) if last.mature_at_height == withdrawal.mature_at_height => {
            last.amount = last.amount.saturating_add(withdrawal.amount);
        }
        _ => queue.entries.push(withdrawal),
    }
    validator.stake -= withdrawal.amount;
    commit_validator(state, address, &validator);
    store_withdrawal_queue(state, address, &queue);
}
