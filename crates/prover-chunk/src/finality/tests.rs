use super::*;
use alloc::vec;
use neutrin0_primitives::BitVec;

const fn validator(byte: u8, effective_stake: u128) -> Validator {
    Validator {
        pubkey: [byte; 48],
        withdrawal_credentials: neutrin0_primitives::runtime_account([byte; 20]),
        effective_stake,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }
}

fn bits(values: &[bool]) -> BitVec {
    let mut bits = BitVec::default();
    for value in values {
        bits.push(*value);
    }
    bits
}

#[test]
fn stake_helpers_match_checked_u128_accumulation() {
    let overflowing = [validator(1, u128::MAX), validator(2, 1)];
    assert_eq!(active_stake_total(&overflowing), None);
    assert!(signers(&overflowing, &bits(&[true, true])).is_none());
    let (keys, stake) = signers(&overflowing, &bits(&[true, false])).unwrap();
    assert_eq!(keys, [[1; 48]]);
    assert_eq!(stake, u128::MAX);
    assert_eq!(active_stake_total(&[validator(1, 0)]), None);
    let zero = [validator(1, 5), validator(2, 0)];
    assert!(signers(&zero, &bits(&[true, true])).is_none());
    assert_eq!(
        signers(&zero, &bits(&[true, false])),
        Some((vec![[1; 48]], 5))
    );
}
