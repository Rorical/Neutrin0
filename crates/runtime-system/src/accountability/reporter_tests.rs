//! Reporter rewards exercise the same mandatory transition and witness replay.

extern crate std;

use super::execution::credit_reporter;
use super::*;
use crate::Account;
use crate::test_support::{evidence_input as input, run_block, seed_policy, seed_validator};
use alloc::vec;
use neutrin0_consensus_types::evidence::SanctionKind;
use neutrin0_runtime_abi::RuntimeTransaction;
use neutrin0_runtime_core::{
    WitnessState,
    host::{LiveTrie, TracingState},
};

const REPORTER: Address = [42; 32];

fn report(input: &mut RuntimeBlockInput, id: u8, kind: SanctionKind) -> RuntimeTransaction {
    let mut transaction = tests::admission(input, id, [id; 32], kind);
    let neutrin0_runtime_abi::RuntimeTransaction::SubmitEvidence(submission) = &mut transaction
    else {
        unreachable!()
    };
    submission.statement.reporter = Some(REPORTER);
    transaction
}

#[test]
fn empty_block_preserves_existing_totals_without_witnessing_them() {
    let input = input();
    let mut live = LiveTrie::default();
    let mut totals = settlement::SettlementTotals::default();
    totals.slash.deducted.value = 100;
    totals.slash.rewarded.value = 10;
    totals.slash.burned.value = 90;
    live.insert(
        settlement::SETTLEMENT_TOTALS_KEY,
        borsh::to_vec(&totals).unwrap(),
    );
    let mut state = TracingState::new(&live);
    let output = run_block(&mut state, &input, &[]);
    assert_eq!(output.post_state_root, live.state_root());
    assert_eq!(output.system.accountability.admitted, [] as [Sanction; 0]);
    assert_eq!(output.system.accountability.executed, [] as [Sanction; 0]);
    let (_, witness) = state.into_committed_and_witness().unwrap();
    assert!(
        !witness
            .witnessed_keys
            .iter()
            .any(|key| key == settlement::SETTLEMENT_TOTALS_KEY)
    );
    let mut guest = WitnessState::new(&witness).unwrap();
    let replayed = run_block(&mut guest, &input, &[]);
    assert_eq!(replayed.system.accountability, output.system.accountability);
    assert_eq!(guest.post_state_root(), output.post_state_root);
}

#[test]
fn shared_collateral_is_counted_only_when_each_fifo_deduction_executes() {
    let mut input = input();
    let first = report(&mut input, 1, SanctionKind::Slash);
    let mut second = report(&mut input, 2, SanctionKind::Slash);
    let neutrin0_runtime_abi::RuntimeTransaction::SubmitEvidence(submission) = &mut second else {
        unreachable!()
    };
    submission.statement.offender.withdrawal_credentials = [1; 32];
    input.transactions = vec![first, second];
    let mut live = LiveTrie::default();
    seed_validator(&mut live, &[1; 32], 73);
    let mut state = TracingState::new(&live);
    run_block(&mut state, &input, &[]);
    let snapshot = settlement::snapshot(&mut state);
    assert_eq!(snapshot.totals.slash.admitted.value, 2);
    assert_eq!(snapshot.totals.slash.executed.value, 2);
    assert_eq!(snapshot.totals.slash.zero_deductions.value, 1);
    assert_eq!(snapshot.totals.slash.deducted.value, 73);
    assert_eq!(snapshot.totals.slash.rewarded.value, 7);
    assert_eq!(snapshot.totals.slash.burned.value, 66);
    assert_eq!(crate::state::load_account(&mut state, &REPORTER).balance, 7);
}

#[test]
fn cumulative_metrics_overflow_never_blocks_mandatory_settlement() {
    let mut input = input();
    input.transactions = vec![report(&mut input, 1, SanctionKind::Slash)];
    let mut live = LiveTrie::default();
    seed_validator(&mut live, &[1; 32], 100);
    let mut totals = settlement::SettlementTotals::default();
    totals.slash.deducted.value = u128::MAX;
    live.insert(
        settlement::SETTLEMENT_TOTALS_KEY,
        borsh::to_vec(&totals).unwrap(),
    );
    let mut state = TracingState::new(&live);
    run_block(&mut state, &input, &[]);
    let totals = settlement::load_totals(&mut state);
    assert_eq!(totals.slash.deducted.value, u128::MAX);
    assert!(totals.slash.deducted.overflowed);
    assert_eq!(
        crate::state::load_account(&mut state, &REPORTER).balance,
        10
    );
    assert_eq!(load_queue(&mut state), [] as [PendingSanction; 0]);
}

#[test]
fn reward_uses_actual_stake_and_unbonding_deduction_and_replays_in_guest() {
    let mut input = input();
    input.transactions = vec![report(&mut input, 1, SanctionKind::Slash)];
    let mut live = LiveTrie::default();
    seed_validator(&mut live, &[1; 32], 37);
    live.insert(
        &crate::withdrawal_key(&[1; 32]),
        borsh::to_vec(&crate::WithdrawalQueue {
            entries: vec![crate::Withdrawal {
                amount: 64,
                mature_at_height: 100,
            }],
        })
        .unwrap(),
    );
    live.insert(
        &crate::account_key(&REPORTER),
        crate::encode_account(&Account { balance: 5 }),
    );
    let mut state = TracingState::new(&live);
    let output = run_block(&mut state, &input, &[]);
    assert_eq!(crate::state::load_validator(&mut state, &[1; 32]).stake, 0);
    assert_eq!(
        crate::state::load_withdrawal_queue(&mut state, &[1; 32]).total(),
        0
    );
    assert_eq!(
        crate::state::load_account(&mut state, &REPORTER),
        Account { balance: 15 }
    );
    let settled = settlement::snapshot(&mut state);
    assert_eq!(settled.totals.slash.admitted.value, 1);
    assert_eq!(settled.totals.slash.executed.value, 1);
    assert_eq!(settled.totals.slash.deducted.value, 101);
    assert_eq!(settled.totals.slash.rewarded.value, 10);
    assert_eq!(settled.totals.slash.burned.value, 91);
    assert_eq!(settled.pending_slash, 0);
    let (_, witness) = state.into_committed_and_witness().unwrap();
    let mut guest = WitnessState::new(&witness).unwrap();
    let replayed = run_block(&mut guest, &input, &[]);
    assert_eq!(replayed.system.accountability, output.system.accountability);
    assert_eq!(guest.post_state_root(), output.post_state_root);
}

#[test]
fn no_recipient_no_stake_and_inactivity_cannot_mint_rewards() {
    for (kind, balance, recipient) in [
        (SanctionKind::Slash, 100, None),
        (SanctionKind::Slash, 0, Some(REPORTER)),
        (SanctionKind::Inactivity, 100, Some(REPORTER)),
    ] {
        let mut input = input();
        let mut transaction = report(&mut input, 1, kind);
        let neutrin0_runtime_abi::RuntimeTransaction::SubmitEvidence(submission) = &mut transaction
        else {
            unreachable!()
        };
        submission.statement.reporter = recipient;
        input.transactions = vec![transaction];
        let mut live = LiveTrie::default();
        // Enable both sanction kinds so the admission is well-formed; the
        // point is that neither mints a reporter reward here.
        seed_policy(
            &mut live,
            &RuntimePolicy {
                inactivity_leak_amount: 50,
                ..RuntimePolicy::default()
            },
        );
        seed_validator(&mut live, &[1; 32], balance);
        let mut state = TracingState::new(&live);
        let output = run_block(&mut state, &input, &[]);
        assert_eq!(output.system.accountability.executed.len(), 1);
        assert_eq!(state.read(&crate::account_key(&REPORTER)), None);
    }
}

#[test]
fn pending_reward_terms_survive_policy_changes_and_fifo_delay() {
    let mut input = input();
    input.transactions = vec![
        report(&mut input, 1, SanctionKind::Slash),
        report(&mut input, 2, SanctionKind::Slash),
    ];
    let mut live = LiveTrie::default();
    let mut policy = RuntimePolicy {
        evidence_executions_per_block: 1,
        ..RuntimePolicy::default()
    };
    seed_policy(&mut live, &policy);
    seed_validator(&mut live, &[1; 32], 0);
    seed_validator(&mut live, &[2; 32], 37);
    let mut state = TracingState::new(&live);
    run_block(&mut state, &input, &[]);
    let queued = load_queue(&mut state);
    assert_eq!(queued.len(), 1);
    // A safety offence takes the whole slashable balance.
    assert_eq!(queued[0].amount, u128::MAX);
    assert_eq!(queued[0].reporter, Some(REPORTER));
    assert_eq!(queued[0].reporter_reward_bps, 1_000);
    let snapshot = settlement::snapshot(&mut state);
    assert_eq!(snapshot.pending_slash, 1);
    assert_eq!(snapshot.totals.slash.admitted.value, 2);
    assert_eq!(snapshot.totals.slash.executed.value, 1);
    assert_eq!(snapshot.totals.slash.zero_deductions.value, 1);
    assert_eq!(crate::state::load_account(&mut state, &REPORTER).balance, 0);
    let (post, _) = state.into_committed_and_witness().unwrap();
    let mut live = LiveTrie::from_trie(post);
    policy.reporter_reward_bps = 10_000;
    seed_policy(&mut live, &policy);
    input.block_height += 1;
    input.transactions.clear();
    let mut state = TracingState::new(&live);
    let output = run_block(&mut state, &input, &[]);
    assert_eq!(
        output.system.accountability.executed[0].offender.pubkey,
        [2; 48]
    );
    assert_eq!(crate::state::load_account(&mut state, &REPORTER).balance, 3);
    let totals = settlement::load_totals(&mut state);
    assert_eq!(totals.slash.executed.value, 2);
    assert_eq!(totals.slash.deducted.value, 37);
    assert_eq!(totals.slash.rewarded.value, 3);
    assert_eq!(totals.slash.burned.value, 34);
    assert_eq!(load_queue(&mut state), [] as [PendingSanction; 0]);
    let (_, witness) = state.into_committed_and_witness().unwrap();
    let mut guest = WitnessState::new(&witness).unwrap();
    let replayed = run_block(&mut guest, &input, &[]);
    assert_eq!(replayed.system.accountability, output.system.accountability);
    assert_eq!(guest.post_state_root(), output.post_state_root);
}

#[test]
fn changing_recipient_or_offence_cannot_reward_a_slashed_identity_twice() {
    let mut input = input();
    input.transactions = vec![report(&mut input, 1, SanctionKind::Slash)];
    let mut live = LiveTrie::default();
    seed_validator(&mut live, &[1; 32], 100);
    let mut state = TracingState::new(&live);
    run_block(&mut state, &input, &[]);
    assert_eq!(
        crate::state::load_account(&mut state, &REPORTER).balance,
        10
    );
    let neutrin0_runtime_abi::RuntimeTransaction::SubmitEvidence(submission) =
        &mut input.transactions[0]
    else {
        unreachable!()
    };
    submission.statement.reporter = Some([99; 32]);
    submission.statement.offence_id = [99; 32];
    let root = state.post_state_root();
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_block(&mut state, &input, &[])
    }));
    assert!(rejected.is_err());
    assert_eq!(state.post_state_root(), root);
    assert_eq!(state.read(&crate::account_key(&[99; 32])), None);
}

#[test]
fn maximum_deduction_and_full_account_do_not_overflow_or_block_fifo() {
    let mut input = input();
    input.transactions = vec![report(&mut input, 1, SanctionKind::Slash)];
    let mut live = LiveTrie::default();
    seed_validator(&mut live, &[1; 32], u128::MAX);
    live.insert(
        &crate::account_key(&REPORTER),
        crate::encode_account(&Account {
            balance: u128::MAX - 1,
        }),
    );
    let mut state = TracingState::new(&live);
    let output = run_block(&mut state, &input, &[]);
    assert_eq!(output.system.accountability.executed.len(), 1);
    assert_eq!(crate::state::load_validator(&mut state, &[1; 32]).stake, 0);
    assert_eq!(
        crate::state::load_account(&mut state, &REPORTER).balance,
        u128::MAX
    );
    let totals = settlement::load_totals(&mut state);
    assert_eq!(totals.slash.deducted.value, u128::MAX);
    assert_eq!(totals.slash.rewarded.value, 1);
    assert_eq!(totals.slash.burned.value, u128::MAX - 1);
    assert_eq!(load_queue(&mut state), [] as [PendingSanction; 0]);
    let (_, witness) = state.into_committed_and_witness().unwrap();
    let mut guest = WitnessState::new(&witness).unwrap();
    let replayed = run_block(&mut guest, &input, &[]);
    assert_eq!(replayed.system.accountability, output.system.accountability);
    assert_eq!(guest.post_state_root(), output.post_state_root);
}

#[test]
fn basis_points_round_down_without_multiplication_overflow() {
    let live = LiveTrie::default();
    let mut state = TracingState::new(&live);
    credit_reporter(&mut state, &REPORTER, u128::MAX, 1_000);
    assert_eq!(
        crate::state::load_account(&mut state, &REPORTER).balance,
        u128::MAX / 10
    );
    credit_reporter(&mut state, &REPORTER, 9, 1_000);
    assert_eq!(
        crate::state::load_account(&mut state, &REPORTER).balance,
        u128::MAX / 10
    );
    credit_reporter(&mut state, &REPORTER, u128::MAX, 0);
    assert_eq!(
        crate::state::load_account(&mut state, &REPORTER).balance,
        u128::MAX / 10
    );
}
