//! Stake sums, bitmap weights and quorum arithmetic over the active set.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Crate-visible helpers of a private module; `pub` would be unreachable."
)]

use neutrin0_consensus_types::{FinalityVote, NilVote};
use neutrin0_primitives::{BitVec, Validator};

use crate::BftError;

pub(crate) fn nil_stake(validators: &[Validator], vote: &NilVote) -> Result<u128, BftError> {
    bitmap_stake(validators, &vote.aggregation_bits)
}

pub(crate) const fn validate_quorum((numerator, denominator): (u64, u64)) -> Result<(), BftError> {
    if !neutrin0_primitives::quorum_fraction_valid(numerator, denominator) {
        return Err(BftError::InvalidQuorum);
    }
    Ok(())
}

pub(crate) fn total_active_stake(active_set: &[Validator]) -> Result<u128, BftError> {
    let mut total = 0_u128;
    for validator in active_set {
        if validator.effective_stake == 0 {
            continue;
        }
        total = total
            .checked_add(validator.effective_stake)
            .ok_or(BftError::StakeOverflow)?;
    }
    if total == 0 {
        return Err(BftError::ZeroTotalStake);
    }
    Ok(total)
}

pub(crate) fn vote_stake(active_set: &[Validator], vote: &FinalityVote) -> Result<u128, BftError> {
    bitmap_stake(active_set, &vote.aggregation_bits)
}

pub(crate) fn bitmap_stake(
    active_set: &[Validator],
    aggregation_bits: &BitVec,
) -> Result<u128, BftError> {
    if aggregation_bits.bit_len()
        != u32::try_from(active_set.len()).expect("active set length prevalidated as u32")
    {
        return Err(BftError::InvalidAggregationBits);
    }

    let mut stake = 0_u128;
    for (index, validator) in active_set.iter().enumerate() {
        if aggregation_bits
            .get(u32::try_from(index).expect("active set length prevalidated as u32"))
            .unwrap_or(false)
        {
            if validator.effective_stake == 0 {
                return Err(BftError::InvalidAggregationBits);
            }
            stake = stake
                .checked_add(validator.effective_stake)
                .ok_or(BftError::StakeOverflow)?;
        }
    }
    if stake == 0 {
        return Err(BftError::EmptyVote);
    }
    Ok(stake)
}

pub(crate) const fn quorum_reached(
    stake: u128,
    total_stake: u128,
    (numerator, denominator): (u64, u64),
) -> bool {
    neutrin0_primitives::quorum_reached(stake, total_stake, numerator, denominator)
}
