use super::checks::{check_bondable, check_exit_handoff};
use crate::ReceiptStatus;
use crate::state::{Validator, store_validator};
use neutrin0_runtime_core::StateBackend;
use neutrin0_runtime_core::host::{LiveTrie, TracingState};

fn seat(byte: u8) -> neutrin0_primitives::Validator {
    neutrin0_primitives::Validator {
        pubkey: [byte; 48],
        withdrawal_credentials: [byte; 32],
        effective_stake: 100,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }
}

#[test]
fn sequential_exits_cannot_drain_the_last_funded_active_identity() {
    let live = LiveTrie::default();
    let mut state = TracingState::new(&live);
    store_validator(&mut state, &[1; 32], &Validator { stake: 100 });
    store_validator(&mut state, &[2; 32], &Validator { stake: 100 });
    let active = [seat(1), seat(2)];
    check_exit_handoff(&mut state, &[1; 32], 0, &active).unwrap();
    store_validator(&mut state, &[1; 32], &Validator { stake: 0 });
    assert_eq!(
        check_exit_handoff(&mut state, &[2; 32], 0, &active).unwrap_err(),
        ReceiptStatus::Unauthorized
    );
    // A funded registration without a current authenticated seat is not a handoff.
    store_validator(&mut state, &[3; 32], &Validator { stake: 100 });
    assert!(check_exit_handoff(&mut state, &[2; 32], 0, &active).is_err());
    // Partial unbonding still leaves backing for the current identity.
    check_exit_handoff(&mut state, &[2; 32], 1, &active).unwrap();
}

#[test]
fn exiting_or_newly_sanctioned_seats_cannot_supply_replacement_backing() {
    let live = LiveTrie::default();
    let mut state = TracingState::new(&live);
    for address in [[1; 32], [2; 32]] {
        store_validator(&mut state, &address, &Validator { stake: 100 });
    }
    let mut active = [seat(1), seat(2)];
    active[1].exit_epoch = 2;
    assert!(check_exit_handoff(&mut state, &[1; 32], 0, &active).is_err());
    assert!(check_bondable(&mut state, &[2; 32], &active).is_err());
    active[1].exit_epoch = u64::MAX;
    state.write(
        &crate::accountability::slashed_key(&active[1].pubkey),
        alloc::vec![1],
    );
    assert!(check_exit_handoff(&mut state, &[1; 32], 0, &active).is_err());
}
