//! Fixed-point values and exact wide arithmetic over wei amounts.

use crate::{FixedU128, Hash};

/// Fractional bits in `FixedU128`.
pub const FIXED_U128_FRAC_BITS: u32 = 64;
/// `1.0` as `Q64.64`.
pub const FIXED_U128_ONE: FixedU128 = 1_u128 << FIXED_U128_FRAC_BITS;

/// Converts an integer into `Q64.64`.
pub const fn fixed_u128_from_integer(value: u64) -> FixedU128 {
    (value as u128) << FIXED_U128_FRAC_BITS
}

/// Whether `numerator / denominator` is a valid BFT quorum fraction: both
/// terms nonzero, at most one, and at least two thirds. The two-thirds
/// comparison is evaluated in `u128`, so it cannot overflow.
#[must_use]
pub const fn quorum_fraction_valid(numerator: u64, denominator: u64) -> bool {
    numerator != 0
        && denominator != 0
        && numerator <= denominator
        && (numerator as u128) * 3 >= (denominator as u128) * 2
}

/// Whether `stake` is a BFT quorum of `total_stake`: strictly more than two
/// thirds, and at least the configured `numerator / denominator`.
///
/// Two quorums then overlap in strictly more than one third of the stake, so
/// conflicting quorums need more than one third faulty, including the
/// boundary of exactly one third that an inclusive two-thirds threshold
/// admits. A configured fraction above two thirds raises the threshold
/// further. Stakes are wei; both comparisons are exact 256-bit products, so
/// no `u128` operand can overflow them.
#[must_use]
pub const fn quorum_reached(
    stake: u128,
    total_stake: u128,
    numerator: u64,
    denominator: u64,
) -> bool {
    wide_gt(widening_mul(stake, 3), widening_mul(total_stake, 2))
        && !wide_gt(
            widening_mul(total_stake, numerator as u128),
            widening_mul(stake, denominator as u128),
        )
}

/// Upper bound on any total of stake, in wei.
///
/// The genesis validator set stays within it, and so do the runtime's stakes
/// together with the weight each consensus seat holds beyond its stake (a full
/// exit's kept weight, an unrecorded genesis seat's specification weight).
/// Rotation weighs each seat by at most the larger of the two, so a rotated
/// set's total stays within this bound, and every consensus total (quorums,
/// leader and proposer draws, fork-choice weight) is exact.
/// It is about 1.7 × 10^20 whole tokens.
pub const MAX_TOTAL_STAKE: u128 = u128::MAX / 2;

/// `a * b` as an exact 256-bit `(high, low)` pair.
#[must_use]
pub const fn widening_mul(a: u128, b: u128) -> (u128, u128) {
    const MASK: u128 = u64::MAX as u128;
    let (a_low, a_high) = (a & MASK, a >> 64);
    let (b_low, b_high) = (b & MASK, b >> 64);
    let low_low = a_low * b_low;
    let low_high = a_low * b_high;
    let high_low = a_high * b_low;
    // Each term is below 2^64, so the sum stays below 3 * 2^64.
    let middle = (low_low >> 64) + (low_high & MASK) + (high_low & MASK);
    let low = (low_low & MASK) | ((middle & MASK) << 64);
    let high = a_high * b_high + (low_high >> 64) + (high_low >> 64) + (middle >> 64);
    (high, low)
}

/// Whether the 256-bit `left` exceeds `right`.
const fn wide_gt(left: (u128, u128), right: (u128, u128)) -> bool {
    left.0 > right.0 || (left.0 == right.0 && left.1 > right.1)
}

/// `floor(value * numerator / denominator)`, exact over the 256-bit product;
/// `None` when `denominator` is zero or the quotient exceeds `u128`.
///
/// Pro-rata shares of wei amounts by wei stakes need this: both factors may
/// use most of `u128`. A quotient whose numerator does not exceed its
/// denominator never exceeds `value`.
#[must_use]
pub const fn mul_div_floor(value: u128, numerator: u128, denominator: u128) -> Option<u128> {
    if denominator == 0 {
        return None;
    }
    let (high, low) = widening_mul(value, numerator);
    if high == 0 {
        return Some(low / denominator);
    }
    if high >= denominator {
        return None;
    }
    // Binary long division of the 256-bit product; the remainder stays below
    // `denominator`, and `carry` holds the bit a doubling shifts out of it.
    let mut remainder = high;
    let mut quotient = 0_u128;
    let mut bit = 128;
    while bit > 0 {
        bit -= 1;
        let carry = remainder >> 127;
        remainder = (remainder << 1) | ((low >> bit) & 1);
        quotient <<= 1;
        if carry == 1 || remainder >= denominator {
            remainder = remainder.wrapping_sub(denominator);
            quotient |= 1;
        }
    }
    Some(quotient)
}

/// The big-endian 256-bit `value` modulo `modulus`, exact; `None` when
/// `modulus` is zero.
///
/// A draw reduced from a whole digest this way is uniform up to a bias of at
/// most `modulus / 2^256`, where a reduction of only its first 128 bits is
/// biased toward small results once `modulus` exceeds `2^127`.
#[must_use]
pub const fn wide_remainder(value: &Hash, modulus: u128) -> Option<u128> {
    if modulus == 0 {
        return None;
    }
    // Binary long division as in `mul_div_floor`: the remainder stays below
    // `modulus`, and `carry` holds the bit a doubling shifts out of it.
    let mut remainder = 0_u128;
    let mut index = 0;
    while index < 256 {
        let bit = (value[index / 8] >> (7 - index % 8)) & 1;
        let carry = remainder >> 127;
        remainder = (remainder << 1) | bit as u128;
        if carry == 1 || remainder >= modulus {
            remainder = remainder.wrapping_sub(modulus);
        }
        index += 1;
    }
    Some(remainder)
}
