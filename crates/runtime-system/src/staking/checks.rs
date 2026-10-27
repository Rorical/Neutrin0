//! Checks shared by the staking actions, each holding every refusal up to
//! the action's first state mutation.

use neutrin0_runtime_core::StateBackend;

use super::StakingContext;
use crate::state::{
    Account, Validator, load_account, load_consensus_candidates, load_validator,
    load_validator_record, load_validator_registration,
};
use crate::{Address, ReceiptStatus};

pub(super) fn check_bondable<B: StateBackend>(
    state: &mut B,
    address: &Address,
    active: &[neutrin0_primitives::Validator],
) -> Result<(), ReceiptStatus> {
    if load_validator_registration(state, address).is_some_and(|registration| {
        state
            .read(&crate::accountability::slashed_key(
                &registration.bls_pubkey,
            ))
            .is_some()
    }) {
        return Err(ReceiptStatus::Unauthorized);
    }
    if active
        .iter()
        .any(|seat| seat.withdrawal_credentials == *address && seat.exit_epoch != u64::MAX)
    {
        return Err(ReceiptStatus::Unauthorized);
    }
    Ok(())
}

/// A full unbond must leave another funded, currently seated identity. Pending
/// entrants and seats already in their exit handoff do not satisfy this guard.
pub(super) fn check_exit_handoff<B: StateBackend>(
    state: &mut B,
    address: &Address,
    remaining: u128,
    active: &[neutrin0_primitives::Validator],
) -> Result<(), ReceiptStatus> {
    if remaining > 0
        || !active.iter().any(|seat| {
            seat.withdrawal_credentials == *address
                && seat.effective_stake > 0
                && seat.exit_epoch == u64::MAX
        })
    {
        return Ok(());
    }
    for seat in active {
        if seat.withdrawal_credentials == *address
            || seat.effective_stake == 0
            || seat.exit_epoch != u64::MAX
        {
            continue;
        }
        if state
            .read(&crate::accountability::slashed_key(&seat.pubkey))
            .is_some()
        {
            continue;
        }
        let validator = load_validator(state, &seat.withdrawal_credentials);
        if validator.stake > 0
            && load_validator_registration(state, &seat.withdrawal_credentials)
                .is_none_or(|registration| registration.bls_pubkey == seat.pubkey)
        {
            return Ok(());
        }
    }
    Err(ReceiptStatus::Unauthorized)
}

/// Refuse a staking action that moves nothing.
///
/// A zero amount changes no balance or stake but would still write records:
/// an unstake would append an empty withdrawal entry, and a stake or
/// registration would mint a zero-stake validator and consensus candidate.
/// The shared checks reject it before any state access, reported like any
/// other amount the caller cannot back.
pub(super) const fn require_amount(amount: u128) -> Result<(), ReceiptStatus> {
    if amount == 0 {
        Err(ReceiptStatus::InsufficientBalance)
    } else {
        Ok(())
    }
}

/// Refuse a validator stake that is neither zero nor at least the governed
/// minimum, so every consensus candidate entry is backed by real, slashable
/// stake rather than dust. A full exit to zero is always allowed.
pub(super) const fn require_bonded(stake: u128, min_stake: u128) -> Result<(), ReceiptStatus> {
    if stake != 0 && stake < min_stake {
        Err(ReceiptStatus::InsufficientBalance)
    } else {
        Ok(())
    }
}

/// Refuse stake that would lift what consensus can weigh above
/// [`neutrin0_primitives::MAX_TOTAL_STAKE`], so every successor set's total
/// stays exact.
///
/// Rotation weighs a seat by its runtime stake, except that a full exit keeps
/// its last weight until its exit epoch and an unrecorded genesis seat keeps
/// its genesis weight. Each seat in `active` therefore counts the larger of
/// its stake and its weight: unstaking never raises the total, so fresh funds
/// cannot be staked over weight an exit keeps in consensus, however often
/// within one exit window.
pub(super) fn require_stake_room<B: StateBackend>(
    state: &mut B,
    active: &[neutrin0_primitives::Validator],
    added: u128,
) -> Result<(), ReceiptStatus> {
    let candidates = load_consensus_candidates(state);
    let staked = candidates
        .entries
        .iter()
        .try_fold(0_u128, |total, candidate| {
            total.checked_add(candidate.stake)
        });
    let retained = active.iter().try_fold(0_u128, |total, seat| {
        let backing = candidates
            .get(&seat.withdrawal_credentials)
            .map_or(0, |candidate| candidate.stake);
        total.checked_add(seat.effective_stake.saturating_sub(backing))
    });
    staked
        .zip(retained)
        .and_then(|(staked, retained)| staked.checked_add(retained))
        .and_then(|total| total.checked_add(added))
        .filter(|total| *total <= neutrin0_primitives::MAX_TOTAL_STAKE)
        .map(|_| ())
        .ok_or(ReceiptStatus::Overflow)
}

/// The action's subject must be the caller the engine authenticated. There
/// is no other authorization path: a backend without an authenticated caller
/// executes no economic action.
pub(super) fn authenticate<B: StateBackend>(
    state: &B,
    caller: &Address,
) -> Result<(), ReceiptStatus> {
    if state.authenticated_caller() == Some(*caller) {
        Ok(())
    } else {
        Err(ReceiptStatus::Unauthorized)
    }
}

/// The payer's account, provided its balance covers `amount`.
pub(super) fn check_payer<B: StateBackend>(
    state: &mut B,
    payer: &Address,
    amount: u128,
) -> Result<Account, ReceiptStatus> {
    let account = load_account(state, payer);
    if account.balance < amount {
        return Err(ReceiptStatus::InsufficientBalance);
    }
    Ok(account)
}

/// Funding checks of a stake: the funder pays `amount` and
/// `validator`'s stake absorbs it, ending at or above `min_stake`. Returns
/// the funder's account and the validator record as it will be stored.
///
/// `validator` must already hold a record, created by genesis or by a
/// registration. Bonding a fresh address would mint a validator with neither
/// a consensus identity nor a registration age, which governance would
/// otherwise mistake for a genesis validator.
pub(super) fn check_bond<B: StateBackend>(
    state: &mut B,
    context: &StakingContext<'_>,
    funder: &Address,
    validator: &Address,
    amount: u128,
) -> Result<(Account, Validator), ReceiptStatus> {
    let account = check_payer(state, funder, amount)?;
    require_amount(amount)?;
    let mut bonded = load_validator_record(state, validator).ok_or(ReceiptStatus::Unauthorized)?;
    bonded.stake = bonded
        .stake
        .checked_add(amount)
        .ok_or(ReceiptStatus::Overflow)?;
    require_bonded(bonded.stake, context.min_validator_stake)?;
    require_stake_room(state, context.active, amount)?;
    Ok((account, bonded))
}
