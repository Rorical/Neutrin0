use super::*;
use neutrin0_primitives::{DEFAULT_EXPECTED_PROPOSERS_PER_SLOT, FIXED_U128_ONE};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

const E_ONE: FixedU128 = FIXED_U128_ONE;

fn zero_output() -> VrfOutput {
    [0_u8; 32]
}

fn max_output() -> VrfOutput {
    [0xFF_u8; 32]
}

fn almost_max_output() -> VrfOutput {
    let mut output = max_output();
    output[31] = 0xFE;
    output
}

fn decrement_output(mut output: VrfOutput) -> VrfOutput {
    for byte in output.iter_mut().rev() {
        if *byte == 0 {
            *byte = 0xFF;
        } else {
            *byte -= 1;
            break;
        }
    }
    output
}

fn next_u128(rng: &mut ChaCha20Rng) -> u128 {
    let mut bytes = [0_u8; 16];
    rng.fill_bytes(&mut bytes);
    u128::from_le_bytes(bytes)
}

#[test]
fn zero_stake_is_never_eligible() {
    assert!(!is_eligible(&zero_output(), 0, 100, E_ONE));
    assert!(!is_eligible(&max_output(), 0, 100, E_ONE));
}

#[test]
fn zero_total_stake_is_never_eligible() {
    assert!(!is_eligible(&zero_output(), 10, 0, E_ONE));
}

#[test]
fn full_stake_with_default_expectation_saturates_threshold() {
    // p == 1.0 saturates the threshold to 2^256 - 1. The strict `<`
    // comparison rejects only the all-ones output.
    assert!(is_eligible(
        &zero_output(),
        100,
        100,
        DEFAULT_EXPECTED_PROPOSERS_PER_SLOT
    ));
    assert!(is_eligible(
        &almost_max_output(),
        100,
        100,
        DEFAULT_EXPECTED_PROPOSERS_PER_SLOT
    ));
    assert!(!is_eligible(
        &max_output(),
        100,
        100,
        DEFAULT_EXPECTED_PROPOSERS_PER_SLOT
    ));
}

#[test]
fn zero_expectation_is_never_eligible() {
    assert!(!is_eligible(&zero_output(), 100, 100, 0));
    assert!(!is_eligible(&max_output(), 100, 100, 0));
}

#[test]
fn expectation_greater_than_one_saturates_threshold() {
    let e_two = E_ONE.saturating_mul(2);
    assert!(is_eligible(&almost_max_output(), 100, 100, e_two));
    assert!(!is_eligible(&max_output(), 100, 100, e_two));
    // Even a slim majority stake with E=2 still floods over the cap.
    assert!(is_eligible(&almost_max_output(), 60, 100, e_two));
    assert!(!is_eligible(&max_output(), 60, 100, e_two));
}

#[test]
fn threshold_boundary_is_strict_less_than() {
    // p = 0.5: floor((2^256 - 1) / 2) = 2^255 - 1.
    let mut threshold = max_output();
    threshold[0] = 0x7F;
    assert!(!is_eligible(&threshold, 1, 2, E_ONE));
    assert!(is_eligible(&decrement_output(threshold), 1, 2, E_ONE));
}

#[test]
fn exact_threshold_uses_all_256_bits() {
    // p = 1/3: floor((2^256 - 1) / 3) is the repeating 0x55 value.
    // A top-64-bit-only comparison would reject the just-below value.
    let threshold = [0x55_u8; 32];
    assert!(!is_eligible(&threshold, 1, 3, E_ONE));
    assert!(is_eligible(&decrement_output(threshold), 1, 3, E_ONE));
}

#[test]
fn tiny_fixed_point_probability_still_has_nonzero_threshold() {
    // This is below one Q64.64 unit after multiplying by stake / total,
    // but the 256-bit threshold is still nonzero.
    assert!(is_eligible(&zero_output(), 1, u128::from(u64::MAX), 1));
    assert!(!is_eligible(&max_output(), 1, u128::from(u64::MAX), 1));
}

#[test]
fn does_not_panic_on_extreme_inputs() {
    let e_max = FixedU128::MAX;
    assert!(is_eligible(&almost_max_output(), u128::MAX, 1, e_max));
    assert!(!is_eligible(&max_output(), u128::MAX, 1, e_max));
    assert!(is_eligible(
        &almost_max_output(),
        u128::MAX,
        u128::MAX,
        e_max
    ));
    assert!(!is_eligible(&max_output(), u128::MAX, u128::MAX, e_max));
    let _ = is_eligible(&max_output(), 1, u128::MAX, E_ONE);
    let _ = is_eligible(&zero_output(), 1, u128::MAX, E_ONE);
}

#[test]
fn u256_plus_one_handles_257_bit_carry() {
    assert_eq!(u256_plus_one_limbs(&zero_output()), [1, 0, 0, 0, 0]);
    assert_eq!(u256_plus_one_limbs(&max_output()), [0, 0, 0, 0, 1]);
}

#[test]
fn limb_multiplication_handles_max_u256_times_one() {
    assert_eq!(
        mul_limbs::<8>(&[u64::MAX; 4], &[1]),
        [u64::MAX, u64::MAX, u64::MAX, u64::MAX, 0, 0, 0, 0]
    );
}

#[test]
fn limb_multiplication_matches_small_native_product() {
    assert_eq!(
        mul_limbs::<8>(&[3, 0, 0, 0, 0], &u256_limbs((0, 5))),
        [15, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn wei_stakes_keep_exact_proportions() {
    // 32-token stakes in wei exceed u64; p = 1/3 still lands exactly on
    // the repeating 0x55 threshold.
    let stake = 32 * neutrin0_primitives::WEI_PER_TOKEN;
    let threshold = [0x55_u8; 32];
    assert!(!is_eligible(&threshold, stake, 3 * stake, E_ONE));
    assert!(is_eligible(
        &decrement_output(threshold),
        stake,
        3 * stake,
        E_ONE
    ));
    assert!(!is_eligible(
        &threshold,
        u128::MAX / 3,
        u128::MAX / 3 * 3,
        E_ONE
    ));
}

#[test]
fn eligibility_rate_tracks_probability_for_uniform_outputs() {
    // Statistical sanity check: with p = 0.1, sample 10_000 uniform
    // outputs; eligible count must lie within ±5σ ≈ ±150 of 1000.
    let stake = 1_u128;
    let total_stake = 10_u128;
    let n = 10_000_usize;
    let expected = 1_000_usize;
    let tolerance = 150_usize;

    let mut rng = ChaCha20Rng::seed_from_u64(0x00C0_FFEE_AABB_CCDD);
    let mut count = 0_usize;
    for _ in 0..n {
        let mut output = [0_u8; 32];
        rng.fill_bytes(&mut output);
        if is_eligible(&output, stake, total_stake, E_ONE) {
            count += 1;
        }
    }
    let diff = count.abs_diff(expected);
    assert!(
        diff < tolerance,
        "eligible count {count} too far from expected {expected} (±{tolerance})"
    );
}

#[test]
fn eligibility_rate_zero_when_p_is_zero() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    for _ in 0..256 {
        let mut output = [0_u8; 32];
        rng.fill_bytes(&mut output);
        assert!(!is_eligible(&output, 1, 100, 0));
    }
}

#[test]
fn higher_stake_strictly_dominates_lower_stake() {
    // For any fixed output, a validator with strictly more stake is
    // eligible whenever the lower-stake validator is.
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    for _ in 0..1024 {
        let mut output = [0_u8; 32];
        rng.fill_bytes(&mut output);
        let low = is_eligible(&output, 10, 100, E_ONE);
        let high = is_eligible(&output, 20, 100, E_ONE);
        if low {
            assert!(
                high,
                "monotonicity violated: low_stake eligible but high_stake not"
            );
        }
    }
}

#[test]
fn half_stake_eligibility_rate_is_near_one_half() {
    // Stake = total/2, E=1.0 -> p = 0.5. Sample and check ~50%.
    let n = 4_096_usize;
    let mut rng = ChaCha20Rng::seed_from_u64(0xDEAD_BEEF);
    let mut count = 0_usize;
    for _ in 0..n {
        let mut output = [0_u8; 32];
        rng.fill_bytes(&mut output);
        if is_eligible(&output, 50, 100, E_ONE) {
            count += 1;
        }
    }
    // 5σ for n=4096, p=0.5: σ = sqrt(1024) = 32. ±5σ = 160.
    let diff = count.abs_diff(n / 2);
    assert!(diff < 160, "expected ~{}, got {count}", n / 2);
}

#[test]
fn saturation_path_triggers_at_probability_one() {
    assert!(is_eligible(&almost_max_output(), 7, 7, E_ONE));
    assert!(!is_eligible(&max_output(), 7, 7, E_ONE));

    let barely_below_one = E_ONE - 1;
    assert!(!is_eligible(&max_output(), 7, 7, barely_below_one));
}

#[test]
fn random_eligibility_inputs_do_not_panic() {
    // Smoke test against arbitrary (potentially overflowing) inputs.
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    for _ in 0..256 {
        let mut output = [0_u8; 32];
        rng.fill_bytes(&mut output);
        let stake = next_u128(&mut rng);
        let total = next_u128(&mut rng);
        let e = next_u128(&mut rng);
        let _ = is_eligible(&output, stake, total, e);
    }
}
