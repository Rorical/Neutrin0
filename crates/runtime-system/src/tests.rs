//! Staking, slashing, withdrawal and registration semantics driven through
//! the engine-authenticated system interface.

use super::*;

extern crate std;
use alloc::vec::Vec;
use neutrin0_consensus_types::{
    evidence::SanctionKind,
    participation::{NO_PARTICIPATION, ParticipationReport},
    runtime::{BlsIdentity, ConsensusCandidate, ConsensusCandidates},
};
use neutrin0_primitives::{DEFAULT_UNBONDING_DELAY_BLOCKS, StateRoot};
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_core::{
    StateBackend,
    host::{LiveTrie, TracingState},
};

use crate::system::{SystemAction, dispatch_with_policy};
use crate::test_support::{
    CHAIN_ID, TEST_BLOCK_HEIGHT, address, apply_against, block_input, fund, replay, seed_policy,
    seed_staked, seed_validator,
};

/// Funds that cover any test action's amount.
const FUNDS: u128 = 1_000_000;

/// The canonical policy with a minimum stake small enough for the
/// unit-sized stakes these tests use; the minimum is governable.
fn test_policy() -> RuntimePolicy {
    RuntimePolicy {
        min_validator_stake: 1,
        ..RuntimePolicy::default()
    }
}

fn live_with_account(addr: Address, balance: u128) -> LiveTrie {
    let mut live = LiveTrie::default();
    seed_policy(&mut live, &test_policy());
    fund(&mut live, &addr, balance);
    live
}

fn committee_seat(address: Address, tag: u8) -> neutrin0_primitives::Validator {
    let key = neutrin0_crypto::bls::SecretKey::key_gen(&[tag; 32], &[]).unwrap();
    neutrin0_primitives::Validator {
        pubkey: key.public_key().to_bytes(),
        withdrawal_credentials: address,
        effective_stake: 100,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }
}

fn with_committee(
    mut input: RuntimeBlockInput,
    validators: Vec<neutrin0_primitives::Validator>,
) -> RuntimeBlockInput {
    input.context.finalized.validators_root =
        neutrin0_consensus_types::evidence::commitment(&validators);
    input.active_validators = validators;
    input
}

fn read_account(live: &LiveTrie, addr: &Address) -> Account {
    live.get(&account_key(addr))
        .unwrap()
        .and_then(|b| decode_account(&b))
        .unwrap_or_default()
}

/// Root of the consensus-facing candidate record for `entries`, none of
/// which carries a BLS identity.
fn candidates_root(entries: &[(Address, u128)]) -> StateRoot {
    let mut candidates = ConsensusCandidates::default();
    for (address, stake) in entries {
        candidates.upsert(ConsensusCandidate {
            address: *address,
            stake: *stake,
            identity: None,
        });
    }
    candidates.root()
}

fn read_validator(live: &LiveTrie, addr: &Address) -> Validator {
    live.get(&validator_key(addr))
        .unwrap()
        .and_then(|b| borsh::from_slice(&b).ok())
        .unwrap_or_default()
}

fn read_withdrawal_queue(live: &LiveTrie, addr: &Address) -> WithdrawalQueue {
    live.get(&withdrawal_key(addr))
        .unwrap()
        .and_then(|b| borsh::from_slice(&b).ok())
        .unwrap_or_default()
}

/// A BLS identity bound to `address` by a valid proof of possession.
fn bls_identity(address: &Address) -> BlsIdentity {
    let key = neutrin0_crypto::bls::SecretKey::key_gen(address, &[]).unwrap();
    BlsIdentity {
        pubkey: key.public_key().to_bytes(),
        pop_signature: key.prove_registration(address).to_bytes(),
    }
}

fn register(address: Address, amount: u128) -> (Address, SystemAction) {
    let identity = bls_identity(&address);
    (
        address,
        SystemAction::Register {
            pubkey: identity.pubkey,
            pop: identity.pop_signature,
            amount,
        },
    )
}

// Pure system tests exercise deductions with a bound, already-authenticated
// statement. Actual proof bytes are verified separately by host/Guest tests.
fn proven_sanction_input(
    mut input: RuntimeBlockInput,
    live: &mut LiveTrie,
    address: Address,
    amount: u128,
    kind: SanctionKind,
) -> RuntimeBlockInput {
    // Only liveness classes take a governed amount; a safety offence
    // always deducts the whole slashable balance.
    let policy = RuntimePolicy {
        inactivity_leak_amount: amount,
        abandonment_penalty_amount: amount,
        ..RuntimePolicy::default()
    };
    seed_policy(live, &policy);
    input.transactions = alloc::vec![accountability::tests::admission(
        &mut input, 1, address, kind
    )];
    input
}

fn staked_live(addr: Address, stake: u128) -> LiveTrie {
    let mut live = LiveTrie::default();
    seed_staked(&mut live, &[(addr, stake)]);
    live
}

// -----------------------------------------------------------------
// Block sequence
// -----------------------------------------------------------------

#[test]
fn empty_block_is_a_noop() {
    let live = LiveTrie::default();
    let (run, _) = replay(&live, &block_input(TEST_BLOCK_HEIGHT), &[]);
    assert_eq!(run.results, [] as [Result<(), crate::ReceiptStatus>; 0]);
    assert_eq!(run.system.receipts, [] as [crate::Receipt; 0]);
    assert_eq!(run.system.gas, 0);
    assert_eq!(run.post_state_root, live.state_root());
}

#[test]
fn an_unauthenticated_backend_executes_no_action() {
    let addr = address(1);
    let mut live = live_with_account(addr, FUNDS);
    seed_validator(&mut live, &addr, 0);
    let input = block_input(TEST_BLOCK_HEIGHT);
    let mut state = TracingState::new(&live);
    let policy = load_runtime_policy(&mut state);
    for action in [
        SystemAction::Stake(10),
        SystemAction::Unstake(1),
        SystemAction::Exit,
        SystemAction::Withdraw,
        SystemAction::Vote([0; 32]),
        SystemAction::Policy(test_policy()),
    ] {
        assert_eq!(
            dispatch_with_policy(&mut state, &input, &action, &policy),
            Err(ReceiptStatus::Unauthorized)
        );
    }
    assert_eq!(state.post_state_root(), live.state_root());
}

#[test]
fn participation_reports_are_committed_and_recorded_once_per_chunk() {
    let live = LiveTrie::default();
    let report = |chunk_id, present: &[u8]| ParticipationReport {
        absent_identities: alloc::vec![[9; 48]],

        chunk_id,
        present: present.iter().map(|tag| [*tag; 32]).collect(),
        absent: alloc::vec![[9; 32]],
    };
    let input = |participation| RuntimeBlockInput {
        participation,
        ..block_input(TEST_BLOCK_HEIGHT)
    };
    // No report commits the zero hash and writes nothing.
    let (run, post) = apply_against(&live, &input(None), &[]);
    assert_eq!(run.system.participation, NO_PARTICIPATION);
    assert!(post.get(PARTICIPATION_KEY).unwrap().is_none());
    // A report is committed exactly and recorded for the runtime.
    let first = report(3, &[1, 2]);
    let (run, post) = apply_against(&live, &input(Some(first.clone())), &[]);
    assert_eq!(run.system.participation, first.commitment());
    assert_eq!(
        post.get(PARTICIPATION_KEY)
            .unwrap()
            .and_then(|bytes| borsh::from_slice::<ParticipationReport>(&bytes).ok()),
        Some(first.clone())
    );
    // Later blocks of the same chunk repeat the report without rewriting;
    // a newer chunk's report replaces it, an older one never does.
    let (run, same) = apply_against(&post, &input(Some(first.clone())), &[]);
    assert_eq!(run.system.participation, first.commitment());
    assert_eq!(same.state_root(), post.state_root());
    let newer = report(4, &[2]);
    let (_, advanced) = apply_against(&post, &input(Some(newer.clone())), &[]);
    assert_eq!(
        advanced
            .get(PARTICIPATION_KEY)
            .unwrap()
            .and_then(|bytes| borsh::from_slice::<ParticipationReport>(&bytes).ok()),
        Some(newer)
    );
    let stale = report(2, &[1]);
    let (_, kept) = apply_against(&post, &input(Some(stale)), &[]);
    assert_eq!(kept.state_root(), post.state_root());
}

// -----------------------------------------------------------------
// Staking, slashing, inactivity leak
// -----------------------------------------------------------------

#[test]
fn stake_moves_balance_to_stake_and_updates_set_root() {
    let addr = address(10);
    let mut live = live_with_account(addr, 100);
    // Stake adds to an existing validator record.
    seed_validator(&mut live, &addr, 0);

    let pre_root = ConsensusCandidates::default().root();
    let (run, post) = replay(
        &live,
        &block_input(TEST_BLOCK_HEIGHT),
        &[(addr, SystemAction::Stake(60))],
    );
    assert_eq!(run.counts(), (1, 0));
    assert_eq!(read_account(&post, &addr).balance, 40);
    assert_eq!(read_validator(&post, &addr).stake, 60);
    // The candidate root must reflect the new entry.
    assert_eq!(
        run.consensus_candidates_root,
        candidates_root(&[(addr, 60)])
    );
    assert_ne!(run.consensus_candidates_root, pre_root);
}

#[test]
fn unstake_after_stake_queues_withdrawal_and_zeroes_candidate_stake() {
    // Unstake does not credit the balance immediately; it queues a
    // withdrawal. The validator set still empties at the moment of unstake
    // because the validator's stake drops to zero.
    let addr = address(11);
    let mut live = live_with_account(addr, 100);
    seed_validator(&mut live, &addr, 0);

    let (run, post) = replay(
        &live,
        &block_input(TEST_BLOCK_HEIGHT),
        &[
            (addr, SystemAction::Stake(40)),
            (addr, SystemAction::Unstake(40)),
        ],
    );
    assert_eq!(run.counts(), (2, 0));
    assert_eq!(read_account(&post, &addr).balance, 60);
    assert_eq!(read_withdrawal_queue(&post, &addr).total(), 40);
    // Stake drained: the runtime index drops the validator but the
    // consensus candidate record keeps an authenticated zero.
    assert_eq!(run.consensus_candidates_root, candidates_root(&[]));
}

#[test]
fn stake_without_funds_is_refused() {
    let addr = address(12);
    let mut live = live_with_account(addr, 5);
    seed_validator(&mut live, &addr, 0);
    let (run, post) = replay(
        &live,
        &block_input(TEST_BLOCK_HEIGHT),
        &[(addr, SystemAction::Stake(1_000))],
    );
    assert_eq!(run.results, [Err(ReceiptStatus::InsufficientBalance)]);
    assert_eq!(read_account(&post, &addr).balance, 5);
    // A bare validator record never reached the candidate projection.
    assert_eq!(
        run.consensus_candidates_root,
        ConsensusCandidates::default().root()
    );
}

#[test]
fn stake_cannot_mint_a_validator_record() {
    // Bonding a fresh address would mint a validator with neither a
    // consensus identity nor a registration age.
    let addr = address(13);
    let live = live_with_account(addr, FUNDS);
    let (run, post) = replay(
        &live,
        &block_input(TEST_BLOCK_HEIGHT),
        &[(addr, SystemAction::Stake(10))],
    );
    assert_eq!(run.results, [Err(ReceiptStatus::Unauthorized)]);
    assert_eq!(read_account(&post, &addr).balance, FUNDS);
    assert!(post.get(&validator_key(&addr)).unwrap().is_none());
}

#[test]
fn stake_room_counts_the_weight_a_seat_keeps_beyond_its_stake() {
    // A full exit keeps its last weight in consensus until its exit epoch,
    // and a partial unstake keeps the seat's weight until the next rotation.
    // Neither frees room for fresh stake: rotation would weigh both, and the
    // next set's total would leave `u128`.
    let exiting = address(30);
    let staker = address(31);
    let mut live = live_with_account(staker, u128::MAX);
    seed_staked(&mut live, &[(exiting, 0), (staker, 10)]);
    let mut exit_seat = committee_seat(exiting, 1);
    exit_seat.effective_stake = neutrin0_primitives::MAX_TOTAL_STAKE - 100;
    exit_seat.exit_epoch = 9;
    let mut staker_seat = committee_seat(staker, 2);
    staker_seat.effective_stake = 10;
    let input = with_committee(
        block_input(TEST_BLOCK_HEIGHT),
        alloc::vec![exit_seat, staker_seat],
    );
    let (run, _) = replay(
        &live,
        &input,
        &[
            (staker, SystemAction::Stake(91)),
            (staker, SystemAction::Unstake(5)),
            (staker, SystemAction::Stake(91)),
            (staker, SystemAction::Stake(90)),
        ],
    );
    assert_eq!(
        run.results
            .iter()
            .map(|result| result.err())
            .collect::<Vec<_>>(),
        [
            Some(ReceiptStatus::Overflow),
            None,
            Some(ReceiptStatus::Overflow),
            None
        ]
    );
}

#[test]
fn slash_takes_the_whole_stake_and_updates_set_root() {
    let addr = address(14);
    let mut live = staked_live(addr, 100);
    let input = proven_sanction_input(
        block_input(TEST_BLOCK_HEIGHT),
        &mut live,
        addr,
        30,
        SanctionKind::Slash,
    );
    let (run, _) = replay(&live, &input, &[]);
    assert_eq!(run.system.accountability.executed.len(), 1);
    assert_eq!(run.consensus_candidates_root, candidates_root(&[]));
}

#[test]
fn slash_to_zero_removes_validator_from_set() {
    let addr = address(15);
    let mut live = staked_live(addr, 100);
    // Burn more than the stake: clamped to the current stake.
    let input = proven_sanction_input(
        block_input(TEST_BLOCK_HEIGHT),
        &mut live,
        addr,
        999,
        SanctionKind::Slash,
    );
    let (run, _) = replay(&live, &input, &[]);
    assert_eq!(run.system.accountability.executed.len(), 1);
    assert_eq!(run.consensus_candidates_root, candidates_root(&[]));
}

#[test]
fn inactivity_leak_shares_slash_semantics() {
    let addr = address(16);
    let mut live = staked_live(addr, 50);
    let input = proven_sanction_input(
        block_input(TEST_BLOCK_HEIGHT),
        &mut live,
        addr,
        20,
        SanctionKind::Inactivity,
    );
    let (run, _) = replay(&live, &input, &[]);
    assert_eq!(run.system.accountability.executed.len(), 1);
    assert_eq!(
        run.consensus_candidates_root,
        candidates_root(&[(addr, 30)])
    );
}

#[test]
fn an_abandonment_deducts_its_governed_amount_and_keeps_the_seat() {
    let addr = address(16);
    let mut live = staked_live(addr, 50);
    let input = proven_sanction_input(
        block_input(TEST_BLOCK_HEIGHT),
        &mut live,
        addr,
        20,
        SanctionKind::Abandonment,
    );
    let (run, _) = replay(&live, &input, &[]);
    assert_eq!(run.system.accountability.executed.len(), 1);
    assert_eq!(
        run.consensus_candidates_root,
        candidates_root(&[(addr, 30)])
    );
}

#[test]
fn slashing_an_unknown_validator_is_a_no_op() {
    // A safety claim is admissible once per identity at any age. The
    // mandatory deduction takes whatever slashable balance remains, here
    // nothing, and consensus ejects the identity regardless.
    let mut live = LiveTrie::default();
    let input = proven_sanction_input(
        block_input(TEST_BLOCK_HEIGHT),
        &mut live,
        [0xFF; 32],
        10,
        SanctionKind::Slash,
    );
    let (run, _) = replay(&live, &input, &[]);
    assert_eq!(run.system.accountability.executed.len(), 1);
    assert_eq!(
        run.consensus_candidates_root,
        ConsensusCandidates::default().root()
    );
}

#[test]
fn deduction_does_not_touch_queue_when_stake_covers_it() {
    // Validator with 100 active stake + 50 queued; a leak of 30 burns 30
    // from stake (=> 70) and leaves the queue untouched, so the
    // queue-touching path stays out of the witness for the common case.
    let addr = address(70);
    let mut live = staked_live(addr, 100);
    let queue = WithdrawalQueue {
        entries: alloc::vec![
            Withdrawal {
                amount: 30,
                mature_at_height: TEST_BLOCK_HEIGHT + DEFAULT_UNBONDING_DELAY_BLOCKS,
            },
            Withdrawal {
                amount: 20,
                mature_at_height: TEST_BLOCK_HEIGHT + DEFAULT_UNBONDING_DELAY_BLOCKS,
            },
        ],
    };
    live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());
    let input = proven_sanction_input(
        block_input(TEST_BLOCK_HEIGHT),
        &mut live,
        addr,
        30,
        SanctionKind::Inactivity,
    );
    let (run, post) = replay(&live, &input, &[]);
    assert_eq!(run.system.accountability.executed.len(), 1);
    let validator_after = read_validator(&post, &addr);
    assert_eq!(validator_after.stake, 70);
    assert!(validator_after.stake > 0);
    let queue_after = read_withdrawal_queue(&post, &addr);
    assert_eq!(queue_after.entries.len(), 2);
    assert_eq!(queue_after.total(), 50);
}

#[test]
fn deduction_drains_queued_unbonding_after_stake_exhausted() {
    // Validator with 50 active stake + 50 queued (split 30/20); a leak of 80
    // burns 50 from stake (=> 0), then 30 from the queue FIFO (drops the
    // first entry entirely), leaving the queue at [20]. The validator
    // becomes inactive and is removed from the set.
    let addr = address(71);
    let mut live = staked_live(addr, 50);
    let queue = WithdrawalQueue {
        entries: alloc::vec![
            Withdrawal {
                amount: 30,
                mature_at_height: TEST_BLOCK_HEIGHT + DEFAULT_UNBONDING_DELAY_BLOCKS,
            },
            Withdrawal {
                amount: 20,
                mature_at_height: TEST_BLOCK_HEIGHT + DEFAULT_UNBONDING_DELAY_BLOCKS + 1,
            },
        ],
    };
    live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());
    let input = proven_sanction_input(
        block_input(TEST_BLOCK_HEIGHT),
        &mut live,
        addr,
        80,
        SanctionKind::Inactivity,
    );
    let (run, post) = replay(&live, &input, &[]);
    assert_eq!(run.consensus_candidates_root, candidates_root(&[]));
    let validator_after = read_validator(&post, &addr);
    assert_eq!(validator_after.stake, 0);
    assert_eq!(validator_after.stake, 0);
    let queue_after = read_withdrawal_queue(&post, &addr);
    assert_eq!(queue_after.entries.len(), 1);
    assert_eq!(queue_after.entries[0].amount, 20);
    // The surviving entry keeps its original maturity: partial-burn
    // preservation is the anti-front-running property.
    assert_eq!(
        queue_after.entries[0].mature_at_height,
        TEST_BLOCK_HEIGHT + DEFAULT_UNBONDING_DELAY_BLOCKS + 1,
    );
}

#[test]
fn deduction_consumes_partial_entry_and_preserves_residue_maturity() {
    // The leak lands mid-entry: 0 stake + a single 50-entry queue; a leak
    // of 30 burns 30 from the entry, leaving 20 with the same maturity.
    let addr = address(72);
    let mut live = LiveTrie::default();
    seed_validator(&mut live, &addr, 0);
    let queue = WithdrawalQueue {
        entries: alloc::vec![Withdrawal {
            amount: 50,
            mature_at_height: TEST_BLOCK_HEIGHT + DEFAULT_UNBONDING_DELAY_BLOCKS,
        }],
    };
    live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());
    let input = proven_sanction_input(
        block_input(TEST_BLOCK_HEIGHT),
        &mut live,
        addr,
        30,
        SanctionKind::Inactivity,
    );
    let (run, post) = replay(&live, &input, &[]);
    assert_eq!(run.system.accountability.executed.len(), 1);
    let queue_after = read_withdrawal_queue(&post, &addr);
    assert_eq!(queue_after.entries.len(), 1);
    assert_eq!(queue_after.entries[0].amount, 20);
    assert_eq!(
        queue_after.entries[0].mature_at_height,
        TEST_BLOCK_HEIGHT + DEFAULT_UNBONDING_DELAY_BLOCKS,
    );
}

#[test]
fn slash_takes_the_total_slashable_balance() {
    // 10 stake + 5 queued: a safety offence burns all 15, stake and queue
    // are both zeroed and the queue key is deleted.
    let addr = address(73);
    let mut live = staked_live(addr, 10);
    let queue = WithdrawalQueue {
        entries: alloc::vec![Withdrawal {
            amount: 5,
            mature_at_height: TEST_BLOCK_HEIGHT + DEFAULT_UNBONDING_DELAY_BLOCKS,
        }],
    };
    live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());
    let input = proven_sanction_input(
        block_input(TEST_BLOCK_HEIGHT),
        &mut live,
        addr,
        1_000_000,
        SanctionKind::Slash,
    );
    let (run, post) = replay(&live, &input, &[]);
    assert_eq!(run.consensus_candidates_root, candidates_root(&[]));
    let validator_after = read_validator(&post, &addr);
    assert_eq!(validator_after.stake, 0);
    assert_eq!(validator_after.stake, 0);
    assert_eq!(
        read_withdrawal_queue(&post, &addr).entries,
        [] as [Withdrawal; 0]
    );
    assert!(post.get(&withdrawal_key(&addr)).unwrap().is_none());
}

// -----------------------------------------------------------------
// Unstake, exit, withdraw
// -----------------------------------------------------------------

#[test]
fn unstakes_maturing_together_share_one_queue_entry() {
    // Many unstakes in one block must not grow the queue by one entry each:
    // that would be a free way to inflate every later withdrawal, deduction and
    // reporter-status scan of the queue.
    let addr = address(44);
    let mut live = staked_live(addr, 50);
    seed_policy(&mut live, &test_policy());
    let (run, post) = replay(
        &live,
        &block_input(100),
        &[
            (addr, SystemAction::Unstake(10)),
            (addr, SystemAction::Unstake(15)),
            (addr, SystemAction::Unstake(5)),
        ],
    );
    assert_eq!(run.counts(), (3, 0));
    assert_eq!(read_validator(&post, &addr).stake, 20);
    assert_eq!(
        read_withdrawal_queue(&post, &addr).entries,
        alloc::vec![Withdrawal {
            amount: 30,
            mature_at_height: 100 + DEFAULT_UNBONDING_DELAY_BLOCKS,
        }]
    );
}

#[test]
fn unstake_queues_withdrawal_with_unbonding_delay() {
    let addr = address(43);
    let mut live = staked_live(addr, 50);
    seed_policy(&mut live, &test_policy());
    fund(&mut live, &addr, 7);
    let (run, post) = replay(
        &live,
        &block_input(100),
        &[(addr, SystemAction::Unstake(30))],
    );
    assert_eq!(run.counts(), (1, 0));
    // The balance is untouched: unstake does not credit immediately.
    assert_eq!(read_account(&post, &addr).balance, 7);
    assert_eq!(read_validator(&post, &addr).stake, 20);
    let queue = read_withdrawal_queue(&post, &addr);
    assert_eq!(queue.entries.len(), 1);
    assert_eq!(queue.entries[0].amount, 30);
    assert_eq!(
        queue.entries[0].mature_at_height,
        100 + DEFAULT_UNBONDING_DELAY_BLOCKS,
    );
}

#[test]
fn voluntary_exit_drains_stake_and_marks_inactive() {
    let addr = address(44);
    let successor = address(144);
    let mut live = staked_live(addr, 80);
    seed_policy(&mut live, &test_policy());
    seed_staked(&mut live, &[(successor, 100)]);

    let input = with_committee(
        block_input(50),
        alloc::vec![committee_seat(addr, 44), committee_seat(successor, 144)],
    );
    let (run, post) = replay(&live, &input, &[(addr, SystemAction::Exit)]);
    assert_eq!(run.counts(), (1, 0));
    let val = read_validator(&post, &addr);
    assert_eq!(val.stake, 0);
    let queue = read_withdrawal_queue(&post, &addr);
    assert_eq!(queue.entries.len(), 1);
    assert_eq!(queue.entries[0].amount, 80);
    // Left without stake, kept as an authenticated zero beside the bonded
    // successor that authorized the exit.
    assert_eq!(
        run.consensus_candidates_root,
        candidates_root(&[(addr, 0), (successor, 100)])
    );
}

#[test]
fn full_exit_uses_authenticated_seats_and_preserves_one_bonded_successor() {
    let alice = address(244);
    let bob = address(245);
    let mut live = LiveTrie::default();
    seed_policy(&mut live, &test_policy());
    seed_staked(&mut live, &[(alice, 100), (bob, 100)]);
    let alice_seat = committee_seat(alice, 244);
    let bob_seat = committee_seat(bob, 245);
    // A funded runtime candidate outside the authenticated seats cannot
    // authorize the final current seat to withdraw its collateral.
    let single = with_committee(
        block_input(TEST_BLOCK_HEIGHT),
        alloc::vec![alice_seat.clone()],
    );
    let (run, post) = replay(&live, &single, &[(alice, SystemAction::Exit)]);
    assert_eq!(run.results, [Err(ReceiptStatus::Unauthorized)]);
    assert_eq!(read_validator(&post, &alice).stake, 100);
    assert_eq!(read_withdrawal_queue(&post, &alice).entries, Vec::new());
    let (run, _) = replay(&live, &single, &[(alice, SystemAction::Unstake(100))]);
    assert_eq!(run.results, [Err(ReceiptStatus::Unauthorized)]);
    // Two seated validators can hand off, but the same evolving state stops
    // the second action from draining the remaining collateral.
    let both = with_committee(
        block_input(TEST_BLOCK_HEIGHT),
        alloc::vec![alice_seat, bob_seat],
    );
    let (run, post) = replay(
        &live,
        &both,
        &[(alice, SystemAction::Exit), (bob, SystemAction::Exit)],
    );
    assert_eq!(run.results, [Ok(()), Err(ReceiptStatus::Unauthorized)]);
    assert_eq!(read_validator(&post, &alice).stake, 0);
    assert_eq!(read_validator(&post, &bob).stake, 100);
    assert_eq!(read_withdrawal_queue(&post, &alice).entries[0].amount, 100);
    assert_eq!(read_withdrawal_queue(&post, &bob).entries, Vec::new());
    // A committee that differs from the authenticated validators root is
    // refused before any state access.
    let mut forged = both;
    forged.active_validators.pop();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| apply_against(
            &live,
            &forged,
            &[(alice, SystemAction::Exit)]
        )))
        .is_err()
    );
}

#[test]
fn voluntary_exit_with_zero_stake_is_refused() {
    let addr = address(45);
    let mut live = live_with_account(addr, 100);
    seed_validator(&mut live, &addr, 0);
    let (run, _) = replay(
        &live,
        &block_input(TEST_BLOCK_HEIGHT),
        &[(addr, SystemAction::Exit)],
    );
    assert_eq!(run.results, [Err(ReceiptStatus::InsufficientBalance)]);
}

#[test]
fn withdraw_credits_only_matured_entries() {
    let addr = address(46);
    let mut live = LiveTrie::default();
    seed_policy(&mut live, &test_policy());
    let queue = WithdrawalQueue {
        entries: alloc::vec![
            Withdrawal {
                amount: 25,
                mature_at_height: 30, // matured at h=100
            },
            Withdrawal {
                amount: 75,
                mature_at_height: 200, // still pending
            },
        ],
    };
    live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());
    let (run, post) = replay(&live, &block_input(100), &[(addr, SystemAction::Withdraw)]);
    assert_eq!(run.counts(), (1, 0));
    assert_eq!(read_account(&post, &addr).balance, 25);
    let remaining = read_withdrawal_queue(&post, &addr);
    assert_eq!(remaining.entries.len(), 1);
    assert_eq!(remaining.entries[0].amount, 75);
    assert_eq!(remaining.entries[0].mature_at_height, 200);
}

#[test]
fn withdraw_with_no_matured_entries_succeeds_but_credits_zero() {
    let addr = address(47);
    let mut live = live_with_account(addr, 10);
    let queue = WithdrawalQueue {
        entries: alloc::vec![Withdrawal {
            amount: 50,
            mature_at_height: 200,
        }],
    };
    live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());
    let (run, post) = replay(&live, &block_input(100), &[(addr, SystemAction::Withdraw)]);
    assert_eq!(run.counts(), (1, 0));
    assert_eq!(read_account(&post, &addr).balance, 10);
    assert_eq!(read_withdrawal_queue(&post, &addr).entries.len(), 1);
}

#[test]
fn withdraw_drains_empty_queue_removes_state_entry() {
    // The trie's `collect_path_nodes` harvests on-path sibling nodes, so the
    // SP1 guest's `Trie::remove` can collapse the parent branch and the
    // withdrawal may drop the queue key when empty.
    let addr = address(48);
    let mut live = LiveTrie::default();
    seed_policy(&mut live, &test_policy());
    let queue = WithdrawalQueue {
        entries: alloc::vec![Withdrawal {
            amount: 50,
            mature_at_height: 10,
        }],
    };
    live.insert(&withdrawal_key(&addr), borsh::to_vec(&queue).unwrap());
    let (run, post) = replay(&live, &block_input(100), &[(addr, SystemAction::Withdraw)]);
    assert_eq!(run.counts(), (1, 0));
    assert!(post.get(&withdrawal_key(&addr)).unwrap().is_none());
}

#[test]
fn full_unstake_withdraw_lifecycle_round_trips() {
    // Block 1: stake 40 from balance. Block 2: unstake 40 (queued, balance
    // unchanged). Block 2 + unbonding delay: withdraw drains it.
    let addr = address(49);
    let mut live = live_with_account(addr, 100);
    seed_validator(&mut live, &addr, 0);

    let (_, live1) = apply_against(&live, &block_input(1), &[(addr, SystemAction::Stake(40))]);
    let (_, live2) = apply_against(
        &live1,
        &block_input(2),
        &[(addr, SystemAction::Unstake(40))],
    );
    assert_eq!(read_account(&live2, &addr).balance, 60);
    assert_eq!(read_validator(&live2, &addr).stake, 0);
    assert_eq!(read_withdrawal_queue(&live2, &addr).total(), 40);

    // A withdrawal at block 5 (still pending) credits zero.
    let (run, live3) = apply_against(&live2, &block_input(5), &[(addr, SystemAction::Withdraw)]);
    assert_eq!(run.counts(), (1, 0));
    assert_eq!(read_account(&live3, &addr).balance, 60);
    assert_eq!(read_withdrawal_queue(&live3, &addr).total(), 40);

    // A withdrawal at the maturity height claims the 40 back.
    let claim_h = 2 + DEFAULT_UNBONDING_DELAY_BLOCKS;
    let (run, live4) = replay(
        &live3,
        &block_input(claim_h),
        &[(addr, SystemAction::Withdraw)],
    );
    assert_eq!(run.counts(), (1, 0));
    assert_eq!(read_account(&live4, &addr).balance, 100);
    assert_eq!(read_withdrawal_queue(&live4, &addr).total(), 0);
    // Nothing staked or queued remains, so the validator record is gone.
    assert!(live4.get(&validator_key(&addr)).unwrap().is_none());
    assert!(live4.get(&withdrawal_key(&addr)).unwrap().is_none());
}

#[test]
fn full_withdrawal_retires_registration_and_validator_records() {
    let addr = address(50);
    let mut live = LiveTrie::default();
    seed_policy(&mut live, &test_policy());
    let registration = ValidatorRegistration {
        address: addr,
        bls_pubkey: [1; 48],
        pop_signature: [2; 96],
        registered_at_height: 0,
    };
    live.insert(
        &registration_key(&addr),
        borsh::to_vec(&registration).unwrap(),
    );
    seed_validator(&mut live, &addr, 0);
    live.insert(
        &withdrawal_key(&addr),
        borsh::to_vec(&WithdrawalQueue {
            entries: alloc::vec![Withdrawal {
                amount: 40,
                mature_at_height: 10,
            }],
        })
        .unwrap(),
    );
    let (run, post) = replay(&live, &block_input(10), &[(addr, SystemAction::Withdraw)]);
    assert_eq!(run.counts(), (1, 0));
    assert_eq!(read_account(&post, &addr).balance, 40);
    assert!(post.get(&validator_key(&addr)).unwrap().is_none());
    assert!(post.get(&withdrawal_key(&addr)).unwrap().is_none());
    assert!(post.get(&registration_key(&addr)).unwrap().is_none());
    // A validator that still stakes keeps every record after a withdrawal.
    let mut staked = live.clone();
    seed_validator(&mut staked, &addr, 5);
    let (_, post) = apply_against(&staked, &block_input(10), &[(addr, SystemAction::Withdraw)]);
    assert_eq!(read_validator(&post, &addr).stake, 5);
    assert!(post.get(&registration_key(&addr)).unwrap().is_some());
}

// -----------------------------------------------------------------
// Receipts
// -----------------------------------------------------------------

#[test]
fn sanction_receipt_kind_is_distinct_from_evidence_admissions() {
    assert_eq!(accountability::EVIDENCE_RECEIPT_KIND, 7);
    assert_eq!(accountability::SANCTION_RECEIPT_KIND, 11);
    assert_ne!(
        accountability::EVIDENCE_RECEIPT_KIND,
        accountability::SANCTION_RECEIPT_KIND
    );
}

#[test]
fn mandatory_sanction_receipt_carries_the_sanction_kind() {
    let addr = [0x5A; 32];
    let mut live = staked_live(addr, 100);
    let input = proven_sanction_input(
        block_input(TEST_BLOCK_HEIGHT),
        &mut live,
        addr,
        30,
        SanctionKind::Slash,
    );
    let (run, _) = replay(&live, &input, &[]);
    assert_eq!(run.system.accountability.executed.len(), 1);
    // The execution's receipt precedes the receipt of the admitting
    // evidence, and the two kinds differ.
    assert_eq!(
        run.system.receipts,
        [
            Receipt {
                status_code: ReceiptStatus::Success.as_u32(),
                gas_used: GAS_SANCTION,
                kind: accountability::SANCTION_RECEIPT_KIND,
            },
            Receipt {
                status_code: ReceiptStatus::Success.as_u32(),
                gas_used: accountability::GAS_EVIDENCE_ADMISSION,
                kind: accountability::EVIDENCE_RECEIPT_KIND,
            },
        ]
    );
    assert_eq!(
        run.system.gas,
        GAS_SANCTION + accountability::GAS_EVIDENCE_ADMISSION
    );
}

// -----------------------------------------------------------------
// Registration and minimum stake
// -----------------------------------------------------------------

#[test]
fn zero_amount_staking_actions_are_refused() {
    // A zero-amount unstake would append an empty withdrawal entry, and a
    // zero stake or registration would mint a zero-stake validator and
    // consensus candidate. The shared check refuses all three before any
    // state is written.
    let addr = address(90);
    let fresh = address(91);
    let mut live = staked_live(addr, 50);
    seed_policy(&mut live, &test_policy());
    fund(&mut live, &addr, 100);
    fund(&mut live, &fresh, 100);
    seed_validator(&mut live, &[0xBB; 32], 1);
    let refused = [
        (addr, SystemAction::Unstake(0)),
        (addr, SystemAction::Stake(0)),
        register(fresh, 0),
    ];
    for action in refused {
        let (run, post) = replay(&live, &block_input(TEST_BLOCK_HEIGHT), &[action]);
        assert_eq!(run.results, [Err(ReceiptStatus::InsufficientBalance)]);
        assert_eq!(post.state_root(), live.state_root());
    }
    // The smallest non-zero unstake still queues its entry.
    let (run, post) = apply_against(
        &live,
        &block_input(TEST_BLOCK_HEIGHT),
        &[(addr, SystemAction::Unstake(1))],
    );
    assert_eq!(run.counts(), (1, 0));
    assert_eq!(read_withdrawal_queue(&post, &addr).entries.len(), 1);
}

#[test]
fn a_safety_hold_survives_retirement_and_covers_genesis_seats() {
    // A genesis seat holds no registration; its safety admission writes one
    // for the tombstoned key, so the address cannot register again.
    let genesis = address(51);
    let offender = committee_seat(genesis, 51);
    let funded = live_with_account(genesis, 100);
    let mut state = TracingState::new(&funded);
    state.write(
        &crate::accountability::slashed_key(&offender.pubkey),
        alloc::vec![1],
    );
    crate::staking::hold_offender(&mut state, &offender);
    let held = LiveTrie::from_trie(state.into_committed_and_witness().unwrap().0);
    let (run, _) = replay(
        &held,
        &block_input(TEST_BLOCK_HEIGHT),
        &[register(genesis, 40)],
    );
    assert_eq!(run.results, [Err(ReceiptStatus::Unauthorized)]);
    // A retiring validator whose registered key is tombstoned keeps the
    // registration that holds its address.
    let addr = address(52);
    let mut live = live_with_account(addr, 100);
    live.insert(
        &registration_key(&addr),
        borsh::to_vec(&ValidatorRegistration {
            address: addr,
            bls_pubkey: [1; 48],
            pop_signature: [2; 96],
            registered_at_height: 0,
        })
        .unwrap(),
    );
    live.insert(
        &crate::accountability::slashed_key(&[1; 48]),
        alloc::vec![1],
    );
    seed_validator(&mut live, &addr, 0);
    live.insert(
        &withdrawal_key(&addr),
        borsh::to_vec(&WithdrawalQueue {
            entries: alloc::vec![Withdrawal {
                amount: 40,
                mature_at_height: 10,
            }],
        })
        .unwrap(),
    );
    let (run, post) = replay(&live, &block_input(10), &[(addr, SystemAction::Withdraw)]);
    assert_eq!(run.counts(), (1, 0));
    assert!(post.get(&registration_key(&addr)).unwrap().is_some());
    let (run, _) = replay(&post, &block_input(11), &[register(addr, 40)]);
    assert_eq!(run.results, [Err(ReceiptStatus::Unauthorized)]);
}

#[test]
fn register_validator_mints_an_active_registered_candidate() {
    let validator = address(0xCC);
    let live = live_with_account(validator, 100);
    let identity = bls_identity(&validator);
    let (run, post) = replay(
        &live,
        &block_input(TEST_BLOCK_HEIGHT),
        &[register(validator, 40)],
    );
    assert_eq!(run.counts(), (1, 0));
    let mut candidates = ConsensusCandidates::default();
    candidates.upsert(ConsensusCandidate {
        address: validator,
        stake: 40,
        identity: Some(identity),
    });
    assert_eq!(run.consensus_candidates_root, candidates.root());
    assert_eq!(read_account(&post, &validator).balance, 60);
    assert_eq!(read_validator(&post, &validator), Validator { stake: 40 },);
    assert!(post.get(&registration_key(&validator)).unwrap().is_some());
    // A second registration of the same address is refused.
    let (run, _) = apply_against(
        &post,
        &block_input(TEST_BLOCK_HEIGHT),
        &[register(validator, 40)],
    );
    assert_eq!(run.results, [Err(ReceiptStatus::InsufficientBalance)]);
}

/// A key rotation replaces a staked validator's registered key with one
/// proven for its address, keeps the registration's age and stake, and waits
/// until consensus seated the previous rotation; keys already in use or
/// tombstoned are refused as registration refuses them.
#[test]
fn rotating_a_key_replaces_the_registration_with_a_fresh_proven_key() {
    let validator = address(0xCD);
    let other = address(0xCE);
    let mut live = live_with_account(validator, 100);
    fund(&mut live, &other, 100);
    let (_, registered) = replay(
        &live,
        &block_input(TEST_BLOCK_HEIGHT),
        &[register(validator, 40), register(other, 40)],
    );
    let key = |tag: u8| neutrin0_crypto::bls::SecretKey::key_gen(&[tag; 32], &[]).unwrap();
    let rotate = |key: &neutrin0_crypto::bls::SecretKey, at: &Address| {
        (
            validator,
            SystemAction::RotateKey {
                pubkey: key.public_key().to_bytes(),
                pop: key.prove_registration(at).to_bytes(),
            },
        )
    };
    let later = block_input(TEST_BLOCK_HEIGHT + 5);
    // A proof for another address, the other validator's key and an
    // account without stake are refused.
    let other_key = bls_identity(&other);
    let refused = [
        rotate(&key(0x61), &other),
        (
            validator,
            SystemAction::RotateKey {
                pubkey: other_key.pubkey,
                pop: other_key.pop_signature,
            },
        ),
        (address(0xCF), rotate(&key(0x61), &address(0xCF)).1),
    ];
    for action in refused {
        let (run, _) = apply_against(&registered, &later, &[action]);
        assert_eq!(run.results, [Err(ReceiptStatus::Unauthorized)]);
    }

    let (run, rotated) = apply_against(&registered, &later, &[rotate(&key(0x61), &validator)]);
    assert_eq!(run.results, [Ok(())]);
    let registration: crate::ValidatorRegistration =
        borsh::from_slice(&rotated.get(&registration_key(&validator)).unwrap().unwrap()).unwrap();
    assert_eq!(registration.bls_pubkey, key(0x61).public_key().to_bytes());
    assert_eq!(registration.registered_at_height, TEST_BLOCK_HEIGHT);
    assert_eq!(
        read_validator(&rotated, &validator),
        Validator { stake: 40 }
    );
    let mut candidates = ConsensusCandidates::default();
    for (address, identity) in [
        (
            validator,
            BlsIdentity {
                pubkey: key(0x61).public_key().to_bytes(),
                pop_signature: key(0x61).prove_registration(&validator).to_bytes(),
            },
        ),
        (other, other_key),
    ] {
        candidates.upsert(ConsensusCandidate {
            address,
            stake: 40,
            identity: Some(identity),
        });
    }
    assert_eq!(run.consensus_candidates_root, candidates.root());
    // While the seat still holds the key the registration replaced, a second
    // rotation waits for consensus to seat the first.
    let seated_old = with_committee(
        block_input(TEST_BLOCK_HEIGHT + 6),
        alloc::vec![neutrin0_primitives::Validator {
            pubkey: bls_identity(&validator).pubkey,
            withdrawal_credentials: validator,
            effective_stake: 40,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        }],
    );
    let (run, _) = apply_against(&rotated, &seated_old, &[rotate(&key(0x62), &validator)]);
    assert_eq!(run.results, [Err(ReceiptStatus::Unauthorized)]);
    // A seat in its exit handoff keeps the key it leaves under.
    let exiting = with_committee(
        block_input(TEST_BLOCK_HEIGHT + 6),
        alloc::vec![neutrin0_primitives::Validator {
            pubkey: key(0x61).public_key().to_bytes(),
            withdrawal_credentials: validator,
            effective_stake: 40,
            activation_epoch: 0,
            exit_epoch: 7,
        }],
    );
    let (run, _) = apply_against(&rotated, &exiting, &[rotate(&key(0x62), &validator)]);
    assert_eq!(run.results, [Err(ReceiptStatus::Unauthorized)]);
}

#[test]
fn minimum_stake_bounds_bonding_and_partial_unstakes() {
    // Every candidate entry must be backed by at least the governed minimum.
    // These unseated runtime candidates can exit to zero; seated exits also
    // require the authenticated handoff exercised above.
    const MIN: u128 = 100;
    let alice = address(95);
    let bob = address(96);
    let mut live = LiveTrie::default();
    seed_policy(
        &mut live,
        &RuntimePolicy {
            min_validator_stake: MIN,
            ..RuntimePolicy::default()
        },
    );
    fund(&mut live, &alice, FUNDS);
    fund(&mut live, &bob, FUNDS);
    // Stake adds to an existing validator record.
    seed_validator(&mut live, &alice, 0);
    // Each case: the action, and whether the minimum admits it.
    let cases = [
        ((alice, SystemAction::Stake(MIN - 1)), false),
        ((alice, SystemAction::Stake(MIN)), true),
        (register(bob, MIN - 1), false),
        (register(bob, MIN), true),
    ];
    for (action, admitted) in cases {
        let (run, _) = replay(&live, &block_input(TEST_BLOCK_HEIGHT), &[action]);
        assert_eq!(run.applied(), u32::from(admitted));
        if !admitted {
            assert_eq!(run.results, [Err(ReceiptStatus::InsufficientBalance)]);
        }
    }

    // An unseated stake record may unstake down to the minimum or fully exit,
    // but never leave dust behind.
    let mut staked = live.clone();
    seed_validator(&mut staked, &alice, 3 * MIN);
    for (amount, admitted) in [(2 * MIN + 1, false), (2 * MIN, true), (3 * MIN, true)] {
        let (run, _) = replay(
            &staked,
            &block_input(TEST_BLOCK_HEIGHT),
            &[(alice, SystemAction::Unstake(amount))],
        );
        assert_eq!(run.applied(), u32::from(admitted));
    }
}

#[test]
fn registration_with_an_invalid_possession_proof_is_refused() {
    // Consensus never seats a key whose POP fails. Accepting one would let an
    // unseatable registration hold a committee slot, reserve its BLS key and
    // carry runtime stake no consensus offence can reach.
    let alice = address(94);
    let live = live_with_account(alice, 100);
    let own = bls_identity(&alice);
    let other = neutrin0_crypto::bls::SecretKey::key_gen(&[0x5A; 32], &[]).unwrap();
    let other_key = other.public_key().to_bytes();
    for (pubkey, pop) in [
        // Proof copied from a registration of the same key at another address.
        (other_key, other.prove_registration(&[0xEE; 32]).to_bytes()),
        // Unrelated bytes.
        (own.pubkey, [0x22; 96]),
        // A key the proof does not belong to.
        (other_key, own.pop_signature),
    ] {
        let (run, post) = replay(
            &live,
            &block_input(TEST_BLOCK_HEIGHT),
            &[(
                alice,
                SystemAction::Register {
                    pubkey,
                    pop,
                    amount: 40,
                },
            )],
        );
        assert_eq!(run.results, [Err(ReceiptStatus::Unauthorized)]);
        assert!(post.get(&registration_key(&alice)).unwrap().is_none());
        assert_eq!(read_account(&post, &alice).balance, 100);
    }
}

#[test]
fn a_tombstoned_identity_leaves_the_candidates_and_is_never_projected_again() {
    let validator = address(0xCD);
    let identity = bls_identity(&validator);
    let candidates =
        |live: &LiveTrie| crate::load_consensus_candidates(&mut TracingState::new(live));
    let (_, registered) = apply_against(
        &live_with_account(validator, 100),
        &block_input(TEST_BLOCK_HEIGHT),
        &[register(validator, 40)],
    );
    assert!(candidates(&registered).contains(&validator));
    // The slash's execution writes the tombstone and drops the identity at
    // once, so no block reads a tombstone per candidate.
    let mut state = TracingState::new(&registered);
    state.write(
        &crate::accountability::slashed_key(&identity.pubkey),
        alloc::vec![1],
    );
    crate::staking::forget_tombstoned_identity(&mut state, &identity.pubkey);
    let slashed = LiveTrie::from_trie(state.into_committed_and_witness().unwrap().0);
    assert!(!candidates(&slashed).contains(&validator));
    // A later stake change of the account never projects it again.
    let (run, post) = apply_against(
        &slashed,
        &block_input(TEST_BLOCK_HEIGHT + 1),
        &[(validator, SystemAction::Unstake(10))],
    );
    assert_eq!(run.counts(), (1, 0));
    assert!(!candidates(&post).contains(&validator));
}

#[test]
fn only_withdrawals_and_policy_decisions_read_the_sanction_queue() {
    let addr = address(61);
    let mut live = LiveTrie::default();
    seed_policy(&mut live, &test_policy());
    fund(&mut live, &addr, 1_000);
    seed_validator(&mut live, &addr, 50);
    let input = block_input(TEST_BLOCK_HEIGHT);
    let reads_queue = |action: SystemAction| {
        let mut tracing = TracingState::new(&live);
        let _ = dispatch_with_policy(
            &mut crate::test_support::Caller {
                inner: &mut tracing,
                caller: addr,
            },
            &input,
            &action,
            &test_policy(),
        );
        tracing
            .into_witness()
            .unwrap()
            .witnessed_keys
            .contains(&crate::accountability::QUEUE_KEY.to_vec())
    };
    assert!(!reads_queue(SystemAction::Stake(10)));
    assert!(!reads_queue(SystemAction::Vote([0; 32])));
    assert!(reads_queue(SystemAction::Withdraw));
}

#[test]
fn registration_cannot_reuse_a_seated_or_registered_identity() {
    let alice = address(97);
    let bob = address(98);
    let mut live = LiveTrie::default();
    seed_policy(&mut live, &test_policy());
    fund(&mut live, &alice, 100);
    fund(&mut live, &bob, 100);
    let (run, post) = apply_against(
        &live,
        &block_input(TEST_BLOCK_HEIGHT),
        &[register(alice, 40)],
    );
    assert_eq!(run.counts(), (1, 0));
    // Bob cannot register under Alice's key, nor under a key the committee
    // already seats.
    let alice_identity = bls_identity(&alice);
    let seated = committee_seat([0xEE; 32], 0xEE);
    let input = with_committee(block_input(TEST_BLOCK_HEIGHT), alloc::vec![seated.clone()]);
    let (run, _) = replay(
        &post,
        &input,
        &[
            (
                bob,
                SystemAction::Register {
                    pubkey: alice_identity.pubkey,
                    pop: alice_identity.pop_signature,
                    amount: 40,
                },
            ),
            (
                bob,
                SystemAction::Register {
                    pubkey: seated.pubkey,
                    pop: [0; 96],
                    amount: 40,
                },
            ),
        ],
    );
    assert_eq!(
        run.results,
        [
            Err(ReceiptStatus::Unauthorized),
            Err(ReceiptStatus::Unauthorized)
        ]
    );
}

#[test]
fn a_full_candidate_record_yields_only_waiting_stake_and_never_to_a_tombstone() {
    let (carol, dave, erin) = (address(0xA3), address(0xA4), address(0xA5));
    let mut live = LiveTrie::default();
    seed_policy(&mut live, &test_policy());
    for who in [carol, dave, erin] {
        fund(&mut live, &who, 1_000);
    }
    // Every candidate record is taken; the first one holds a seat.
    let waiting: Vec<_> = (0..neutrin0_primitives::MAX_CONSENSUS_VALIDATORS)
        .map(|index| {
            let mut who = [0x30; 32];
            who[30..].copy_from_slice(&u16::try_from(index).unwrap().to_be_bytes());
            (who, 40 + u128::try_from(index).unwrap())
        })
        .collect();
    seed_staked(&mut live, &waiting);
    let seated = committee_seat(waiting[0].0, 0x31);
    let input = with_committee(block_input(TEST_BLOCK_HEIGHT), alloc::vec![seated]);
    // Equal stake displaces nothing. More stake displaces the lowest waiting
    // candidate, never the seated one even though its stake is lower: its
    // stake leaves as a voluntary exit would.
    let (run, post) = apply_against(&live, &input, &[register(carol, 41), register(dave, 42)]);
    assert_eq!(run.results, [Err(ReceiptStatus::Unauthorized), Ok(())]);
    assert_eq!(read_validator(&post, &waiting[0].0).stake, 40);
    assert_eq!(read_validator(&post, &waiting[1].0).stake, 0);
    assert_eq!(
        read_withdrawal_queue(&post, &waiting[1].0).entries[0].amount,
        41
    );
    assert_eq!(read_validator(&post, &dave).stake, 42);
    // A key with a safety tombstone cannot register, whatever its stake.
    let mut banned = LiveTrie::default();
    seed_policy(&mut banned, &test_policy());
    fund(&mut banned, &erin, 1_000);
    banned.insert(
        &crate::accountability::slashed_key(&bls_identity(&erin).pubkey),
        alloc::vec![1],
    );
    let (run, _) = apply_against(
        &banned,
        &block_input(TEST_BLOCK_HEIGHT),
        &[register(erin, 90)],
    );
    assert_eq!(run.results, [Err(ReceiptStatus::Unauthorized)]);
}

// -----------------------------------------------------------------
// Stake totals
// -----------------------------------------------------------------

#[test]
fn validator_set_total_stake_saturates_on_every_build() {
    // An unchecked sum panicked natively, where overflow checks are on, but
    // wrapped in the SP1 Guest, where they are off.
    let mut set = ValidatorSet::default();
    set.upsert([1; 32], u128::MAX);
    set.upsert([2; 32], 1);
    assert_eq!(set.total_stake(), u128::MAX);
    // Governance divides by this total; a voter holding the saturated stake
    // still reaches quorum.
    let proposal = UpgradeProposal {
        proposer: [1; 32],
        action: ProposalAction::Policy(RuntimePolicy::default()),
        proposed_at_chunk: 0,
        voters: alloc::vec![[1; 32]],
    };
    assert!(proposal.quorum_reached(&set));
}

#[test]
fn test_chain_identity_is_pinned() {
    assert_eq!(block_input(1).chain_id, CHAIN_ID);
}
