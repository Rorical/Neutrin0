use super::*;
use neutrin0_primitives::{BlsPublicKey, ZERO_HASH};

fn validator(byte: u8, stake: u128) -> Validator {
    Validator {
        pubkey: [byte; 48],
        withdrawal_credentials: neutrin0_primitives::runtime_account([byte; 20]),
        effective_stake: stake,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }
}

#[test]
fn empty_set_root_is_deterministic_and_nonzero() {
    let r = validator_set_root(&[]);
    assert_ne!(r, ZERO_HASH);
    assert_eq!(r, validator_set_root(&[]));
}

#[test]
fn distinct_sets_produce_distinct_roots() {
    let a = vec![validator(1, 1_000_000)];
    let b = vec![validator(1, 1_000_001)];
    let c = vec![validator(2, 1_000_000)];
    let ra = validator_set_root(&a);
    let rb = validator_set_root(&b);
    let rc = validator_set_root(&c);
    assert_ne!(ra, rb);
    assert_ne!(ra, rc);
    assert_ne!(rb, rc);
}

#[test]
fn root_is_order_sensitive() {
    let v1 = validator(1, 1_000_000);
    let v2 = validator(2, 1_000_000);
    let ab = validator_set_root(&[v1.clone(), v2.clone()]);
    let ba = validator_set_root(&[v2, v1]);
    assert_ne!(ab, ba);
}

#[test]
fn root_commits_to_the_tagged_borsh_vector_encoding() {
    let set = vec![validator(1, 1_000_000), validator(2, 2)];
    assert_eq!(
        validator_set_root(&set),
        neutrin0_primitives::validators_root(&set)
    );
}

#[test]
fn root_is_deterministic_across_runs() {
    let pubkey: BlsPublicKey = [7; 48];
    let v = Validator {
        pubkey,
        withdrawal_credentials: neutrin0_primitives::runtime_account([9; 20]),
        effective_stake: 32_000_000_000_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    };
    let r1 = validator_set_root(std::slice::from_ref(&v));
    let r2 = validator_set_root(std::slice::from_ref(&v));
    assert_eq!(r1, r2);
}
