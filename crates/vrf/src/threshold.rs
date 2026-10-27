//! Stake-weighted proposer-eligibility threshold (Algorand/Praos-style).

use neutrin0_primitives::FixedU128;

use crate::eval::VrfOutput;

/// Returns `true` iff `output` falls below the validator's stake-weighted
/// threshold.
///
/// The reference specification (see `docs/design/15-randomness.md`) is
///
/// ```text
/// threshold = floor((2^256 - 1) * E * stake / total_stake)
/// eligible  = U256(output) < threshold
/// ```
///
/// where `U256(output)` is the big-endian interpretation of the 32-byte
/// VRF output and `E = expected_proposers_per_slot / 2^64`. When the
/// implied probability `p = E * stake / total_stake` is at least `1.0`,
/// the threshold saturates to `2^256 - 1`, so every output except the
/// all-ones boundary value is eligible under the strict `<` comparison.
///
/// Returns `false` for the pathological inputs `stake == 0` and
/// `total_stake == 0`; the latter would otherwise divide by zero.
///
/// # Implementation
///
/// The comparison is evaluated without allocating a big-integer type.
/// For `0 < n < d`, where `n = expected_fp * stake` and
/// `d = total_stake * 2^64`, the check
/// `U256(output) < floor((2^256 - 1) * n / d)` is equivalent to
/// `(U256(output) + 1) * d <= (2^256 - 1) * n`. Stakes are wei, so both
/// sides are evaluated in eight 64-bit limbs: `n < d < 2^192` in that
/// branch.
#[must_use]
pub fn is_eligible(
    output: &VrfOutput,
    stake: u128,
    total_stake: u128,
    expected_proposers_per_slot: FixedU128,
) -> bool {
    if stake == 0 || total_stake == 0 {
        return false;
    }

    let numerator = neutrin0_primitives::widening_mul(expected_proposers_per_slot, stake);
    let denominator = (total_stake >> 64, total_stake << 64);

    if numerator >= denominator {
        return !is_max_output(output);
    }
    if numerator == (0, 0) {
        return false;
    }

    let lhs: [u64; 8] = mul_limbs(&u256_plus_one_limbs(output), &u256_limbs(denominator));
    let rhs: [u64; 8] = mul_limbs(&[u64::MAX; 4], &u256_limbs(numerator));

    limbs_le_cmp(&lhs, &rhs).is_le()
}

fn is_max_output(output: &VrfOutput) -> bool {
    output.iter().all(|&byte| byte == 0xFF)
}

fn u256_plus_one_limbs(output: &VrfOutput) -> [u64; 5] {
    let mut limbs = [0_u64; 5];
    for (index, chunk) in output.rchunks_exact(8).enumerate() {
        let bytes: [u8; 8] = chunk
            .try_into()
            .expect("VrfOutput chunks are exactly 8 bytes");
        limbs[index] = u64::from_be_bytes(bytes);
    }

    let mut carry = 1_u64;
    for limb in &mut limbs[..4] {
        let (sum, overflow) = limb.overflowing_add(carry);
        *limb = sum;
        carry = u64::from(overflow);
        if carry == 0 {
            break;
        }
    }
    limbs[4] = carry;
    limbs
}

/// Little-endian limbs of a 256-bit `(high, low)` pair.
fn u256_limbs((high, low): (u128, u128)) -> [u64; 4] {
    [
        low_u64(low),
        low_u64(low >> 64),
        low_u64(high),
        low_u64(high >> 64),
    ]
}

/// Schoolbook product of little-endian limbs; the caller sizes `N` so the
/// product fits.
fn mul_limbs<const N: usize>(a: &[u64], b: &[u64]) -> [u64; N] {
    let mut out = [0_u64; N];
    for (i, &a_limb) in a.iter().enumerate() {
        if a_limb == 0 {
            continue;
        }

        let mut carry = 0_u128;
        for (j, &b_limb) in b.iter().enumerate() {
            let k = i + j;
            let product = u128::from(a_limb) * u128::from(b_limb);
            let total = u128::from(out[k]) + product + carry;
            out[k] = low_u64(total);
            carry = total >> 64;
        }

        let mut k = i + b.len();
        while carry != 0 {
            let total = u128::from(out[k]) + carry;
            out[k] = low_u64(total);
            carry = total >> 64;
            k += 1;
        }
    }
    out
}

fn low_u64(value: u128) -> u64 {
    u64::try_from(value & MASK_LO_64).expect("value is masked to 64 bits")
}

fn limbs_le_cmp<const N: usize>(a: &[u64; N], b: &[u64; N]) -> core::cmp::Ordering {
    for index in (0..N).rev() {
        match a[index].cmp(&b[index]) {
            core::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    core::cmp::Ordering::Equal
}

const MASK_LO_64: u128 = 0xFFFF_FFFF_FFFF_FFFF;

#[cfg(test)]
mod tests;
