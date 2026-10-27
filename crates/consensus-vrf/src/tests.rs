use super::*;
use neutrin0_crypto::bls::SecretKey;
use neutrin0_primitives::{
    DEFAULT_EXPECTED_PROPOSERS_PER_SLOT, FIXED_U128_ONE, Validator, fixed_u128_from_integer,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const DOMAIN: ConsensusDomain = ConsensusDomain::new(7, [1; 32]);
const SEED: Seed = [0x42; 32];
const SLOT: Slot = 11;

fn secret_key(seed: u64) -> SecretKey {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    SecretKey::generate(&mut rng)
}

fn validator(pubkey: BlsPublicKey, stake: u128) -> Validator {
    Validator {
        pubkey,
        withdrawal_credentials: neutrin0_primitives::runtime_account([0x11; 20]),
        effective_stake: stake,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }
}

fn header(proposer_index: ValidatorIndex, proof: BlsSignature) -> Header {
    Header {
        height: 1,
        slot: SLOT,
        parent_hash: [0x01; 32],
        proposer_index,
        vrf_proof: proof,
        state_root: [0x02; 32],
        transactions_root: [0x03; 32],
        votes_root: [0x04; 32],
        da_root: [0x07; 32],
        runtime_extra: [0x08; 32],
        inputs_root: [0; 32],
        receipts_root: [0x0A; 32],
        gas_used: 9,
        gas_limit: 10,
        timestamp: 12,
        signature: [0x09; 96],
    }
}

#[test]
fn verify_header_accepts_valid_proposer() {
    let sk = secret_key(1);
    let pk = sk.public_key().to_bytes();
    let (proof, expected_output) = neutrin0_vrf::eval(&sk, DOMAIN, &SEED, SLOT);
    let active_set = [validator(pk, 100)];
    let header = header(0, proof.to_bytes());

    let eligibility = verify_header_proposer(
        &header,
        &active_set,
        DOMAIN,
        &SEED,
        DEFAULT_EXPECTED_PROPOSERS_PER_SLOT,
    )
    .expect("valid proposer verifies");

    assert_eq!(eligibility.validator_index, 0);
    assert_eq!(eligibility.vrf_output, expected_output);
}

#[test]
fn verify_header_rejects_wrong_seed() {
    let sk = secret_key(2);
    let pk = sk.public_key().to_bytes();
    let (proof, _) = neutrin0_vrf::eval(&sk, DOMAIN, &SEED, SLOT);
    let mut wrong_seed = SEED;
    wrong_seed[0] ^= 0x01;
    let active_set = [validator(pk, 100)];
    let header = header(0, proof.to_bytes());

    assert_eq!(
        verify_header_proposer(
            &header,
            &active_set,
            DOMAIN,
            &wrong_seed,
            DEFAULT_EXPECTED_PROPOSERS_PER_SLOT,
        ),
        Err(VrfError::InvalidProof)
    );
}

#[test]
fn verify_header_rejects_ineligible_output() {
    let sk = secret_key(3);
    let pk = sk.public_key().to_bytes();
    let (proof, _) = neutrin0_vrf::eval(&sk, DOMAIN, &SEED, SLOT);
    let active_set = [validator(pk, 100)];
    let header = header(0, proof.to_bytes());

    assert_eq!(
        verify_header_proposer(&header, &active_set, DOMAIN, &SEED, 0),
        Err(VrfError::NotEligible)
    );
}

#[test]
fn verify_header_rejects_zero_stake_or_missing_validator() {
    let sk = secret_key(4);
    let pk = sk.public_key().to_bytes();
    let (proof, _) = neutrin0_vrf::eval(&sk, DOMAIN, &SEED, SLOT);
    let mut slashed = validator(pk, 100);
    slashed.effective_stake = 0;

    assert_eq!(
        verify_header_proposer(
            &header(0, proof.to_bytes()),
            &[slashed],
            DOMAIN,
            &SEED,
            DEFAULT_EXPECTED_PROPOSERS_PER_SLOT,
        ),
        Err(VrfError::ZeroTotalStake)
    );
    assert!(matches!(
        verify_header_proposer(
            &header(1, proof.to_bytes()),
            &[validator(pk, 100)],
            DOMAIN,
            &SEED,
            DEFAULT_EXPECTED_PROPOSERS_PER_SLOT,
        ),
        Err(VrfError::ValidatorIndexOutOfBounds { index: 1, len: 1 })
    ));
}

#[test]
fn aggregator_output_binds_chunk_round_and_index() {
    let base = aggregator_selection_output(&SEED, 1, 2, 3);

    assert_ne!(base, aggregator_selection_output(&SEED, 2, 2, 3));
    assert_ne!(base, aggregator_selection_output(&SEED, 1, 3, 3));
    assert_ne!(base, aggregator_selection_output(&SEED, 1, 2, 4));
}

#[test]
fn shuffled_index_is_a_seeded_permutation() {
    let count = 16;
    let pivots = shuffle_pivots(&SEED);
    let mut shuffled: Vec<_> = (0..count)
        .map(|index| compute_shuffled_index(index, count, &SEED, &pivots))
        .collect::<Option<_>>()
        .expect("valid indices");
    let identity: Vec<_> = (0..count).collect();

    assert_ne!(shuffled, identity);
    shuffled.sort_unstable();
    assert_eq!(shuffled, identity);
    assert_eq!(compute_shuffled_index(count, count, &SEED, &pivots), None);
    assert_eq!(compute_shuffled_index(0, 0, &SEED, &pivots), None);
}

/// Reference shuffle: a heap message per digest and a fresh pivot hash in
/// every round of every index.
fn reference_digest(seed: &Seed, round: u8, position_window: Option<u32>) -> Hash {
    let mut message = Vec::with_capacity(seed.len() + 1 + 4);
    message.extend_from_slice(seed);
    message.push(round);
    if let Some(position_window) = position_window {
        message.extend_from_slice(&position_window.to_le_bytes());
    }
    sha256(&message)
}

fn reference_shuffled_index(index: u32, validator_count: u32, seed: &Seed) -> Option<u32> {
    if validator_count == 0 || index >= validator_count {
        return None;
    }
    let mut index = u64::from(index);
    let count = u64::from(validator_count);
    for round in 0..SHUFFLE_ROUND_COUNT {
        let digest = reference_digest(seed, round, None);
        let pivot = u64::from_le_bytes(digest[..8].try_into().unwrap()) % count;
        let flip = (pivot + count - index) % count;
        let position = index.max(flip);
        let window = u32::try_from(position / 256).unwrap();
        let source = reference_digest(seed, round, Some(window));
        let byte = source[usize::try_from((position % 256) / 8).unwrap()];
        if (byte >> (position % 8)) & 1 == 1 {
            index = flip;
        }
    }
    Some(u32::try_from(index).unwrap())
}

#[test]
fn precomputed_pivots_and_stack_digests_match_the_reference_shuffle() {
    for seed_byte in [0x00, 0x42, 0xFF] {
        let seed = [seed_byte; 32];
        for round in [0, 1, 89] {
            for window in [None, Some(0), Some(1), Some(u32::MAX)] {
                assert_eq!(
                    shuffle_digest(&seed, round, window),
                    reference_digest(&seed, round, window)
                );
            }
        }
        let pivots = shuffle_pivots(&seed);
        for count in [0, 1, 2, 3, 7, 16, 255, 256, 257, 300] {
            for index in (0..count).chain([count, count + 1]) {
                assert_eq!(
                    compute_shuffled_index(index, count, &seed, &pivots),
                    reference_shuffled_index(index, count, &seed),
                    "seed {seed_byte:#x}, index {index}/{count}"
                );
            }
        }
    }
}

#[test]
fn is_aggregator_answers_committee_membership_with_the_same_errors() {
    let pk = secret_key(10).public_key().to_bytes();
    let mut active_set: Vec<_> = (1..=24).map(|stake| validator(pk, stake * 7)).collect();
    active_set[3].effective_stake = 0;
    active_set[11].effective_stake = 0;
    for seed_byte in [0x01, 0x42, 0x99] {
        let seed = [seed_byte; 32];
        for (chunk_id, round) in [(0, 0), (9, 1), (1_000, 7)] {
            for expected in [1, 4, 30].map(fixed_u128_from_integer) {
                let committee = aggregator_committee(&active_set, &seed, chunk_id, round, expected)
                    .expect("committee selected");
                for index in 0..30 {
                    let member = committee.iter().any(|s| s.validator_index == index);
                    assert_eq!(
                        is_aggregator(&active_set, &seed, chunk_id, round, index, expected),
                        Ok(member),
                        "seed {seed_byte:#x}, chunk {chunk_id}, round {round}, index {index}"
                    );
                }
            }
        }
    }
    let overflow = [validator(pk, u128::MAX), validator(pk, 1)];
    for set in [&[][..], &overflow[..]] {
        assert_eq!(
            is_aggregator(set, &SEED, 0, 0, 0, FIXED_U128_ONE),
            aggregator_committee(set, &SEED, 0, 0, FIXED_U128_ONE).map(|_| true)
        );
    }
}

#[test]
fn aggregator_committee_is_deterministic_and_filters_inactive_stake() {
    let pk = secret_key(7).public_key().to_bytes();
    let mut slashed = validator(pk, 50);
    slashed.effective_stake = 0;
    let active_set = [
        validator(pk, 10),
        validator(pk, 20),
        validator(pk, 0),
        slashed,
    ];

    let first = aggregator_committee(&active_set, &SEED, 9, 1, fixed_u128_from_integer(4))
        .expect("committee selected");
    let second = aggregator_committee(&active_set, &SEED, 9, 1, fixed_u128_from_integer(4))
        .expect("committee selected");

    assert_eq!(first, second);
    assert_eq!(first.len(), 2);
    assert_eq!(first[0].validator_index, 0);
    assert_eq!(first[1].validator_index, 1);
    assert!(
        first
            .iter()
            .all(|selection| selection.selection_output != [0xFF; 32])
    );
}

#[test]
fn total_active_stake_rejects_empty_and_overflow() {
    let pk = secret_key(8).public_key().to_bytes();
    assert_eq!(total_active_stake(&[]), Err(VrfError::ZeroTotalStake));
    assert_eq!(
        total_active_stake(&[validator(pk, u128::MAX), validator(pk, 1)]),
        Err(VrfError::StakeOverflow)
    );
}

#[test]
fn verify_proposer_rejects_zero_stake_and_bad_key() {
    let sk = secret_key(9);
    let (proof, _) = neutrin0_vrf::eval(&sk, DOMAIN, &SEED, SLOT);
    let bad_key: BlsPublicKey = [0x00; 48];

    assert_eq!(
        verify_proposer(ProposerClaim {
            public_key: &sk.public_key().to_bytes(),
            stake: 0,
            total_stake: 100,
            domain: DOMAIN,
            finalized_seed: &SEED,
            slot: SLOT,
            vrf_proof: &proof.to_bytes(),
            expected_proposers_per_slot: FIXED_U128_ONE,
        }),
        Err(VrfError::ZeroValidatorStake)
    );
    assert_eq!(
        verify_proposer(ProposerClaim {
            public_key: &bad_key,
            stake: 100,
            total_stake: 100,
            domain: DOMAIN,
            finalized_seed: &SEED,
            slot: SLOT,
            vrf_proof: &proof.to_bytes(),
            expected_proposers_per_slot: FIXED_U128_ONE,
        }),
        Err(VrfError::InvalidPublicKey)
    );
}
