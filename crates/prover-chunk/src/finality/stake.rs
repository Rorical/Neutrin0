//! Stake arithmetic and quorum fractions shared by every certificate check.
#![allow(clippy::redundant_pub_crate)] // Crate-internal helpers re-exported by the parent module.

use alloc::vec::Vec;
use neutrin0_primitives::{BitVec, BlsPublicKey, ConsensusParams, Validator};

/// Whether a validator carries consensus weight: unslashed with positive stake.
pub(crate) const fn is_active(validator: &Validator) -> bool {
    validator.effective_stake > 0
}

/// Sum of effective stake; `None` when it is zero or exceeds `u128`.
pub(crate) fn active_stake_total(validators: &[Validator]) -> Option<u128> {
    validators
        .iter()
        .try_fold(0_u128, |total, validator| {
            total.checked_add(validator.effective_stake)
        })
        .filter(|total| *total > 0)
}

/// Ordered keys and summed stake of the validators marked in `bits`.
///
/// `None` when an index does not fit `u32` or a marked validator is not
/// [`is_active`], or the sum exceeds `u128`.
pub(crate) fn signers(
    validators: &[Validator],
    bits: &BitVec,
) -> Option<(Vec<BlsPublicKey>, u128)> {
    let mut keys = Vec::new();
    let mut stake = 0_u128;
    for (index, validator) in validators.iter().enumerate() {
        if bits.get(u32::try_from(index).ok()?) == Some(true) {
            if !is_active(validator) {
                return None;
            }
            stake = stake.checked_add(validator.effective_stake)?;
            keys.push(validator.pubkey);
        }
    }
    Some((keys, stake))
}

/// Prevote quorum fraction, which also weighs every carried value QC.
pub(crate) const fn prevote_fraction(params: &ConsensusParams) -> (u64, u64) {
    (
        params.bft_prevote_quorum_numerator,
        params.bft_prevote_quorum_denominator,
    )
}

pub(super) const fn precommit_fraction(params: &ConsensusParams) -> (u64, u64) {
    (
        params.bft_precommit_quorum_numerator,
        params.bft_precommit_quorum_denominator,
    )
}
