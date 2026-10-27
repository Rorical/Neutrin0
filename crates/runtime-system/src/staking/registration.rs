//! BLS identity registration and rotation.

use neutrin0_runtime_core::StateBackend;

use super::StakingContext;
use super::checks::{
    authenticate, check_bondable, check_payer, require_amount, require_bonded, require_stake_room,
};
use super::records::{commit_validator, sync_consensus_candidate, unbond};
use crate::state::{
    Validator, ValidatorRegistration, Withdrawal, load_consensus_candidates, load_validator,
    load_validator_registration, store_account, store_validator_registration,
};
use crate::{Address, ReceiptStatus};

/// Register the caller's BLS identity with `deposit_amount` of initial stake.
///
/// The duplicate gate refuses an address that already has either a runtime
/// `Validator` record or a `ValidatorRegistration` row: the validator
/// transition keys on `withdrawal_credentials` and would otherwise see two
/// competing BLS pubkeys for the same address. The possession check is exactly the one
/// consensus applies before seating: without it an unseatable registration
/// would hold a committee slot, reserve its BLS key and carry unslashable
/// runtime stake. The registration's gas pays for the pairing. A safety
/// tombstone refuses the key outright: consensus never seats it again.
///
/// A full committee does not refuse a registration: the registrant waits,
/// and rotation gives seats by current stake (design 09), so arrival order
/// cannot hold seats against more stake and no registration can force a
/// seated validator's stake out. When the candidate record itself is full, a
/// registrant staking strictly more than the lowest waiting (unseated)
/// candidate takes its place; that candidate's stake leaves as a voluntary
/// exit would.
pub(crate) fn apply_register_validator<B: StateBackend>(
    state: &mut B,
    context: &StakingContext<'_>,
    validator: &Address,
    bls_pubkey: &neutrin0_primitives::BlsPublicKey,
    pop_signature: &neutrin0_primitives::BlsSignature,
    deposit_amount: u128,
) -> Result<(), ReceiptStatus> {
    authenticate(state, validator)?;
    let mut depositor = check_payer(state, validator, deposit_amount)?;
    if state
        .read(&crate::accountability::slashed_key(bls_pubkey))
        .is_some()
    {
        return Err(ReceiptStatus::Unauthorized);
    }
    // A held address or an exiting seat may not come back under a new key.
    check_bondable(state, validator, context.active)?;
    require_amount(deposit_amount)?;
    require_bonded(deposit_amount, context.min_validator_stake)?;
    require_stake_room(state, context.active, deposit_amount)?;
    if load_validator_registration(state, validator).is_some() {
        return Err(ReceiptStatus::InsufficientBalance);
    }
    let existing = load_validator(state, validator);
    if existing.stake > 0 {
        return Err(ReceiptStatus::InsufficientBalance);
    }
    let candidates = load_consensus_candidates(state);
    if key_in_use(context, &candidates, bls_pubkey) {
        return Err(ReceiptStatus::Unauthorized);
    }
    let displaced = if candidates.entries.len() >= neutrin0_primitives::MAX_CONSENSUS_VALIDATORS {
        Some(lowest_waiting(state, context, &candidates, deposit_amount)?)
    } else {
        None
    };
    // The pairing runs only once every cheaper refusal has passed, and before
    // anything is written.
    if !neutrin0_prover_chunk::bls::verify_registration_pop(bls_pubkey, validator, pop_signature) {
        return Err(ReceiptStatus::Unauthorized);
    }
    if let Some(displaced) = displaced {
        unbond(
            state,
            &displaced.address,
            displaced.record,
            displaced.withdrawal,
        );
    }

    // Mint the validator record. Mirrors `apply_stake` but the validator
    // did not exist before this call; the shared check refused a zero
    // amount, so the new validator is active (any stake is).
    let record = Validator {
        stake: deposit_amount,
    };
    depositor.balance -= deposit_amount;

    // The POP verified above is checked again by the chunk validator
    // transition before it lifts this entry into the active set.
    store_validator_registration(
        state,
        &ValidatorRegistration {
            address: *validator,
            bls_pubkey: *bls_pubkey,
            pop_signature: *pop_signature,
            registered_at_height: context.block_height,
        },
    );
    store_account(state, validator, &depositor);
    // The candidate projection reads the registration stored above.
    commit_validator(state, validator, &record);
    Ok(())
}

/// Whether `key` is seated or any candidate carries it.
fn key_in_use(
    context: &StakingContext<'_>,
    candidates: &neutrin0_consensus_types::runtime::ConsensusCandidates,
    key: &neutrin0_primitives::BlsPublicKey,
) -> bool {
    context.active.iter().any(|seat| seat.pubkey == *key)
        || candidates.entries.iter().any(|candidate| {
            candidate
                .identity
                .is_some_and(|identity| identity.pubkey == *key)
        })
}

/// Replace the caller's BLS identity with `bls_pubkey`, proven by
/// `pop_signature` for the caller's address. Consensus seats the new key in
/// the caller's seat at the next chunk boundary and keeps its stake. The old
/// key stays accountable for what it signed: sanctions deduct from the
/// address the offence names, whatever key is registered there now.
///
/// Refused for a caller without stake, whose seat is exiting or whose
/// address a safety admission holds (see [`hold_offender`](super::hold_offender)),
/// while an earlier
/// rotation is not yet seated (the caller's seat still holds another key than
/// its registration), and for a key that is tombstoned, seated or carried by
/// any candidate, as a registration is. A genesis validator, which has no
/// registration, gets one dated at genesis.
pub(crate) fn apply_rotate_key<B: StateBackend>(
    state: &mut B,
    context: &StakingContext<'_>,
    validator: &Address,
    bls_pubkey: &neutrin0_primitives::BlsPublicKey,
    pop_signature: &neutrin0_primitives::BlsSignature,
) -> Result<(), ReceiptStatus> {
    authenticate(state, validator)?;
    check_bondable(state, validator, context.active)?;
    let record = load_validator(state, validator);
    if record.stake == 0
        || state
            .read(&crate::accountability::slashed_key(bls_pubkey))
            .is_some()
    {
        return Err(ReceiptStatus::Unauthorized);
    }
    let registration = load_validator_registration(state, validator);
    let seat = context
        .active
        .iter()
        .find(|seat| seat.withdrawal_credentials == *validator);
    if let (Some(seat), Some(registration)) = (seat, &registration)
        && seat.pubkey != registration.bls_pubkey
    {
        return Err(ReceiptStatus::Unauthorized);
    }
    if key_in_use(context, &load_consensus_candidates(state), bls_pubkey) {
        return Err(ReceiptStatus::Unauthorized);
    }
    if !neutrin0_prover_chunk::bls::verify_registration_pop(bls_pubkey, validator, pop_signature) {
        return Err(ReceiptStatus::Unauthorized);
    }
    store_validator_registration(
        state,
        &ValidatorRegistration {
            address: *validator,
            bls_pubkey: *bls_pubkey,
            pop_signature: *pop_signature,
            registered_at_height: registration
                .map_or(0, |registration| registration.registered_at_height),
        },
    );
    sync_consensus_candidate(state, validator, Some(&record));
    Ok(())
}

/// A waiting candidate a registration displaces, and the withdrawal its whole
/// stake becomes.
struct Displaced {
    address: Address,
    record: Validator,
    withdrawal: Withdrawal,
}

/// The candidate record a registrant bringing `deposit_amount` frees when the
/// record is full: the waiting candidate with the lowest stake, then the
/// lowest address, if the registrant stakes strictly more. Its stake leaves
/// as a voluntary exit would. Seated validators are never displaced here;
/// rotation alone retires seats, by current stake. Nothing is written.
fn lowest_waiting<B: StateBackend>(
    state: &mut B,
    context: &StakingContext<'_>,
    candidates: &neutrin0_consensus_types::runtime::ConsensusCandidates,
    deposit_amount: u128,
) -> Result<Displaced, ReceiptStatus> {
    let lowest = candidates
        .entries
        .iter()
        .filter(|candidate| {
            candidate.stake > 0
                && context
                    .active
                    .iter()
                    .all(|seat| seat.withdrawal_credentials != candidate.address)
        })
        .min_by_key(|candidate| (candidate.stake, candidate.address))
        .ok_or(ReceiptStatus::Unauthorized)?;
    if deposit_amount <= lowest.stake {
        return Err(ReceiptStatus::Unauthorized);
    }
    let address = lowest.address;
    let record = load_validator(state, &address);
    if record.stake == 0 {
        return Err(ReceiptStatus::Unauthorized);
    }
    let mature_at_height = context
        .block_height
        .checked_add(context.unbonding_delay)
        .ok_or(ReceiptStatus::Overflow)?;
    Ok(Displaced {
        address,
        withdrawal: Withdrawal {
            amount: record.stake,
            mature_at_height,
        },
        record,
    })
}
