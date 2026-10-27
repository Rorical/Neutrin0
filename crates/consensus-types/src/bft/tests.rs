use super::*;
use neutrin0_primitives::{Seed, Validator, blake3_256};

const fn validator(byte: u8, effective_stake: u128) -> Validator {
    Validator {
        pubkey: [byte; 48],
        withdrawal_credentials: neutrin0_primitives::runtime_account([byte; 20]),
        effective_stake,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }
}

/// Incoming seed of every test chunk.
const SEED: Seed = [0x5e; 32];

/// The leader `draw` index of the documented preimage and weights.
fn reference_leader(chunk_id: u64, round: u32, validators: &[Validator]) -> Option<u32> {
    let root = neutrin0_primitives::validators_root(validators);
    let mut remaining: Vec<(u32, u128)> = validators
        .iter()
        .enumerate()
        .filter(|(_, validator)| validator.effective_stake > 0)
        .map(|(index, validator)| (u32::try_from(index).unwrap(), validator.effective_stake))
        .collect();
    let position = u64::from(round) % u64::try_from(remaining.len()).ok()?;
    let mut leader = None;
    for draw in 0..=position {
        let mut input = Vec::from(neutrin0_primitives::DOMAIN_LEADER_DRAW);
        input.extend_from_slice(&7_u64.to_le_bytes());
        input.extend_from_slice(&borsh::to_vec(&(chunk_id, root, SEED)).unwrap());
        input.extend_from_slice(&draw.to_le_bytes());
        let total: u128 = remaining.iter().map(|(_, stake)| stake).sum();
        // The whole big-endian digest modulo the small test total.
        let mut target = blake3_256(&input)
            .iter()
            .fold(0, |target, byte| (target * 256 + u128::from(*byte)) % total);
        let mut picked = 0;
        for (at, (_, stake)) in remaining.iter().enumerate() {
            if target < *stake {
                picked = at;
                break;
            }
            target -= stake;
        }
        leader = Some(remaining.remove(picked).0);
    }
    leader
}

#[test]
fn leader_follows_the_tagged_stake_weighted_draws() {
    let validators = [
        validator(1, 5),
        validator(2, 0),
        validator(3, 0),
        validator(4, 9),
    ];
    let root = neutrin0_primitives::validators_root(&validators[..]);
    for (chunk_id, round) in [(0, 0), (3, 1), (9, 2), (u64::MAX, u32::MAX)] {
        let expected = reference_leader(chunk_id, round, &validators);
        assert_eq!(bft_leader(7, chunk_id, round, &SEED, &validators), expected);
        assert_eq!(
            bft_leader_with_root(7, chunk_id, round, &SEED, &validators, root),
            expected
        );
    }
    assert_eq!(bft_leader(7, 0, 0, &SEED, &[validator(1, 0)]), None);
}

#[test]
fn the_incoming_seed_decides_leaders_a_set_encoding_cannot_pick() {
    // Whatever set a validator shapes, the seed it cannot choose still
    // moves round zero's leader.
    let validators: Vec<_> = (1..=8).map(|byte| validator(byte, 10)).collect();
    let leaders: alloc::collections::BTreeSet<_> = (0..=u8::MAX)
        .map(|byte| bft_leader(7, 11, 0, &[byte; 32], &validators).unwrap())
        .collect();
    assert_eq!(leaders.len(), validators.len());
}

#[test]
fn rounds_visit_every_eligible_validator_before_repeating() {
    let validators = [
        validator(1, 1),
        validator(2, 50),
        validator(3, 0),
        validator(4, 3),
    ];
    let leaders: Vec<_> = (0..6)
        .map(|round| bft_leader(7, 11, round, &SEED, &validators).unwrap())
        .collect();
    let mut first_cycle = leaders[..3].to_vec();
    first_cycle.sort_unstable();
    assert_eq!(first_cycle, [0, 1, 3]);
    assert_eq!(leaders[..3], leaders[3..]);
}

#[test]
fn round_zero_leadership_follows_stake_not_seat_count() {
    // One seat of stake 30 against thirty seats of stake 1: the large
    // seat leads round zero about half the time, not once in 31.
    let mut validators = alloc::vec![validator(0, 30)];
    validators.extend((1..=30).map(|byte| validator(byte, 1)));
    let led = (0..400)
        .filter(|chunk_id| bft_leader(7, *chunk_id, 0, &SEED, &validators) == Some(0))
        .count();
    assert!((150..=250).contains(&led), "large seat led {led} of 400");
}
