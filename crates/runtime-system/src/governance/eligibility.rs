//! Who may propose and vote, and with what weight: aged registrations and
//! bonds, seated stake and the caller checks every governance action shares.

#![allow(
    clippy::redundant_pub_crate,
    reason = "The bonding hook stays explicitly crate-scoped inside this private module."
)]

use alloc::vec::Vec;

use neutrin0_runtime_core::StateBackend;

use super::{BlockContext, UPGRADE_VOTER_MIN_AGE_BLOCKS};
use crate::state::{
    Bonding, load_bonding, load_validator_registration, load_validator_set, store_bonding,
};
use crate::{Address, ReceiptStatus, ValidatorSet};

/// `true` once [`UPGRADE_VOTER_MIN_AGE_BLOCKS`] have passed since `since`.
fn aged(since: u64, height: u64) -> bool {
    since
        .checked_add(UPGRADE_VOTER_MIN_AGE_BLOCKS)
        .is_some_and(|mature| height >= mature)
}

/// Part of `addr`'s `bonded` stake that counts in governance at `height`.
///
/// Nothing counts until the registration has aged. A validator without one
/// is a genesis validator: stake only adds to an existing record,
/// so only genesis and registration create one. Stake added after that is
/// left out until it has aged too, so freshly bonded funds cannot decide an
/// upgrade. A later unstake or deduction is charged against the counted
/// stake first, which only ever undercounts.
fn governance_weight<B: StateBackend>(
    state: &mut B,
    addr: &Address,
    bonded: u128,
    height: u64,
) -> u128 {
    if load_validator_registration(state, addr)
        .is_some_and(|registration| !aged(registration.registered_at_height, height))
    {
        return 0;
    }
    load_bonding(state, addr)
        .filter(|bonding| !aged(bonding.since_height, height))
        .map_or(bonded, |bonding| bonded.saturating_sub(bonding.amount))
}

/// Record `amount` newly bonded behind `addr` at `height`.
///
/// Unaged additions share one record whose clock restarts with each of them,
/// so governance reads a single key per validator however often stake is
/// added.
pub(crate) fn record_bond<B: StateBackend>(
    state: &mut B,
    addr: &Address,
    amount: u128,
    height: u64,
) {
    let unaged = load_bonding(state, addr)
        .filter(|bonding| !aged(bonding.since_height, height))
        .map_or(0, |bonding| bonding.amount);
    store_bonding(
        state,
        addr,
        &Bonding {
            amount: unaged.saturating_add(amount),
            since_height: height,
        },
    );
}

/// The validators eligible for governance in `block`, each weighted by its
/// [`governance_weight`]; the quorum denominator is their counted stake, not
/// the whole runtime set's.
///
/// Only runtime validators holding a weighted, unslashed seat in the block's
/// authenticated consensus set count. A runtime record consensus has not
/// seated (pending activation, banned identity, full exit) answers to no
/// consensus offence, so its stake must not decide the program set.
fn governance_set<B: StateBackend>(state: &mut B, block: &BlockContext<'_>) -> ValidatorSet {
    let mut set = load_validator_set(state);
    let mut counted = Vec::with_capacity(set.entries.len());
    for entry in &set.entries {
        if !block
            .seats
            .iter()
            .any(|seat| seat.withdrawal_credentials == entry.address && seat.effective_stake > 0)
        {
            continue;
        }
        let weight = governance_weight(state, &entry.address, entry.stake, block.height);
        if weight > 0 {
            counted.push(crate::ValidatorSetEntry {
                stake: weight,
                ..*entry
            });
        }
    }
    set.entries = counted;
    set
}

/// Caller checks shared by every governance action: the engine must have
/// authenticated `signer`, who must hold an eligible, weighted seat. Returns
/// the governance set on success.
pub(super) fn authorize_caller<B: StateBackend>(
    state: &mut B,
    signer: &Address,
    block: &BlockContext<'_>,
) -> Result<ValidatorSet, ReceiptStatus> {
    if state.authenticated_caller() != Some(*signer) {
        return Err(ReceiptStatus::Unauthorized);
    }
    let set = governance_set(state, block);
    if set
        .entries
        .binary_search_by(|entry| entry.address.cmp(signer))
        .is_err()
    {
        return Err(ReceiptStatus::Unauthorized);
    }
    Ok(set)
}
