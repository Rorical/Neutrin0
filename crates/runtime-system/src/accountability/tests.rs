extern crate std;

use super::markers::expiry_key;
use super::*;
use crate::ReceiptStatus;
use crate::system::SystemAction;
use crate::test_support::run_block;
use alloc::vec;
use neutrin0_consensus_types::evidence::{
    EvidenceContext, EvidenceStatement, EvidenceSubmission, SanctionKind,
};
use neutrin0_consensus_types::history::{HistoryPath, history_root};
use neutrin0_primitives::Validator;
use neutrin0_runtime_abi::RuntimeTransaction;
use neutrin0_runtime_core::{
    WitnessState,
    host::{LiveTrie, TracingState},
};

use crate::test_support::{
    evidence_input as input, fund, seed_policy, seed_staked, seed_validator,
};

/// Pure-STF fixture: proof authenticity belongs to the execution shell.
/// Integration tests must supply independently verified proof attachments.
#[allow(clippy::redundant_pub_crate)] // Shared with sibling STF tests, never a public production API.
pub(crate) fn admission(
    input: &mut RuntimeBlockInput,
    id: u8,
    address: Address,
    kind: SanctionKind,
) -> RuntimeTransaction {
    let context = EvidenceContext {
        source_runtime_code_hash: [0; 32],
        source_block_guest_vk_digest: input.evidence_anchor.block_guest_vk_digest,
        chunk_id: 0,
        chunk_hash: [9; 32],
        end_height: input.block_height - 1,
        validators_root: [8; 32],
        seed: [0; 32],
        start_boundary: [0; 32],
    };
    let mut leaves = vec![commitment(&context)];
    if kind == SanctionKind::Inactivity {
        leaves.resize(3, [0; 32]);
    }
    input.evidence_anchor.chain_spec_hash = [7; 32];
    input.evidence_anchor.chunk_id = u64::try_from(leaves.len()).unwrap();
    input.context.finalized.next_chunk_id = input.evidence_anchor.chunk_id;
    input.evidence_anchor.history_root = history_root(&leaves);
    if kind == SanctionKind::Inactivity {
        // Blocks of chunk 1 carry chunk 0's certified report, which must
        // list a charged validator as absent.
        input
            .participation
            .get_or_insert_with(
                neutrin0_consensus_types::participation::ParticipationReport::default,
            )
            .absent
            .push(address);
        input
            .participation
            .as_mut()
            .unwrap()
            .absent_identities
            .push([id; 48]);
    }
    RuntimeTransaction::SubmitEvidence(alloc::boxed::Box::new(EvidenceSubmission {
        statement: EvidenceStatement {
            reporter: None,
            chain_id: input.chain_id,
            chain_spec_hash: input.evidence_anchor.chain_spec_hash,
            block_guest_vk_digest: input.evidence_anchor.block_guest_vk_digest,
            context,
            offender: Validator {
                pubkey: [id; 48],
                withdrawal_credentials: address,
                effective_stake: 100,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
            },
            kind,
            offence_id: [id; 32],
            facts_commitment: [id; 32],
        },
        history: HistoryPath::build(&leaves, 0).unwrap(),
    }))
}

/// The queue's verdict on withdrawals from `address`, as block execution
/// sees it after the mandatory phase.
fn withdrawal_held<B: StateBackend>(state: &mut B, address: &Address) -> bool {
    Backlog::of(&load_queue(state)).holds(address)
}

#[test]
fn invalid_historical_binding_is_rejected_before_state_access() {
    let mut input = input();
    input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Slash)];
    input.evidence_anchor.history_root[0] ^= 1;
    let live = LiveTrie::default();
    let mut state = TracingState::new(&live);
    let root = state.pre_state_root();
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_block(&mut state, &input, &[])
    }));
    assert!(rejected.is_err());
    assert_eq!(state.post_state_root(), root);
    let witness = state.into_witness().unwrap();
    assert_eq!(witness.witnessed_keys, [] as [Vec<u8>; 0]);
}

#[test]
fn fifo_holds_withdrawals_and_executes_without_new_transactions() {
    let mut input = input();
    input.transactions = vec![
        admission(&mut input, 1, [1; 32], SanctionKind::Slash),
        admission(&mut input, 2, [2; 32], SanctionKind::Slash),
    ];
    let mut live = LiveTrie::default();
    seed_policy(
        &mut live,
        &RuntimePolicy {
            evidence_executions_per_block: 1,
            ..RuntimePolicy::default()
        },
    );
    for id in [1, 2] {
        seed_validator(&mut live, &[id; 32], 100);
    }
    let mut state = TracingState::new(&live);
    let output = run_block(&mut state, &input, &[]);
    assert_eq!(output.system.accountability.admitted.len(), 2);
    assert_eq!(output.system.accountability.executed[0].offence_id, [1; 32]);
    assert!(!withdrawal_held(&mut state, &[1; 32]));
    assert!(withdrawal_held(&mut state, &[2; 32]));
    let (post, witness) = state.into_committed_and_witness().unwrap();
    let mut guest = WitnessState::new(&witness).unwrap();
    let replayed = run_block(&mut guest, &input, &[]);
    assert_eq!(replayed.system.accountability, output.system.accountability);
    assert_eq!(replayed.system.receipts, output.system.receipts);
    assert_eq!(guest.post_state_root(), output.post_state_root);
    let next_live = LiveTrie::from_trie(post);
    let mut next = TracingState::new(&next_live);
    input.transactions.clear();
    input.block_height += 1;
    let second = run_block(&mut next, &input, &[]);
    assert_eq!(second.system.accountability.executed[0].offence_id, [2; 32]);
    assert_eq!(load_queue(&mut next), [] as [PendingSanction; 0]);
    // A safety offence deducts the whole stake.
    assert_eq!(crate::state::load_validator(&mut next, &[2; 32]).stake, 0);
    assert_eq!(next.read(&slashed_key(&[2; 48])), Some(vec![1]));
    assert_eq!(next.read(&offence_key(&[2; 32])), None);
}

/// A safety admission holds the offender's address even after it rotated
/// to another key: the registration returns to the offending key and the
/// candidate leaves, so the address is never bonded or seated again.
#[test]
fn a_safety_admission_holds_an_address_whose_key_rotated() {
    let offender = [3; 32];
    let mut input = input();
    input.transactions = vec![admission(&mut input, 3, offender, SanctionKind::Slash)];
    let mut live = LiveTrie::default();
    seed_staked(&mut live, &[(offender, 100)]);
    let rotated = crate::ValidatorRegistration {
        address: offender,
        bls_pubkey: [9; 48],
        pop_signature: [0; 96],
        registered_at_height: 0,
    };
    live.insert(
        &crate::state::registration_key(&offender),
        borsh::to_vec(&rotated).unwrap(),
    );
    let mut state = TracingState::new(&live);
    run_block(&mut state, &input, &[]);
    let held = crate::state::load_validator_registration(&mut state, &offender).unwrap();
    assert_eq!(held.bls_pubkey, [3; 48]);
    assert_eq!(
        crate::state::load_consensus_candidates(&mut state).entries,
        []
    );
}

#[test]
fn liveness_claims_charge_only_certified_absences() {
    let mut input = input();
    input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Inactivity)];
    let mut live = LiveTrie::default();
    seed_policy(
        &mut live,
        &RuntimePolicy {
            inactivity_leak_amount: 1,
            ..RuntimePolicy::default()
        },
    );
    seed_validator(&mut live, &[1; 32], 100);
    // A valid certificate can omit any signer outside its quorum subset,
    // but the chunk's certified precommit counted this validator.
    let mut signed = input.clone();
    let report = signed.participation.as_mut().unwrap();
    report.present = core::mem::take(&mut report.absent);
    report.absent_identities.clear();
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_block(&mut TracingState::new(&live), &signed, &[])
    }));
    assert!(rejected.is_err());
    // The same claim against a certified absence is admitted, and the
    // absence stays readable for the whole liveness window.
    let mut state = TracingState::new(&live);
    let output = run_block(&mut state, &input, &[]);
    assert_eq!(output.system.accountability.admitted.len(), 1);
    assert_eq!(
        state.read(&crate::absent_key(0)),
        Some(borsh::to_vec(&vec![[1_u8; 32]]).unwrap())
    );
    let (post, _) = state.into_committed_and_witness().unwrap();
    let post = LiveTrie::from_trie(post);
    let mut later = crate::test_support::evidence_input();
    later.participation = Some(
        neutrin0_consensus_types::participation::ParticipationReport {
            chunk_id: neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS,
            ..neutrin0_consensus_types::participation::ParticipationReport::default()
        },
    );
    let mut state = TracingState::new(&post);
    run_block(&mut state, &later, &[]);
    assert_eq!(state.read(&crate::absent_key(0)), None);
}

#[test]
fn default_policy_rejects_certificate_omission_without_queueing_a_zero_penalty() {
    let mut input = input();
    input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Inactivity)];
    let live = LiveTrie::default();
    let mut state = TracingState::new(&live);
    let root = state.pre_state_root();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_block(
            &mut state,
            &input,
            &[]
        )))
        .is_err()
    );
    assert_eq!(state.post_state_root(), root);
    assert_eq!(state.read(QUEUE_KEY), None);
    assert_eq!(state.read(&offence_key(&[1; 32])), None);
}

#[test]
fn an_abandonment_is_admitted_once_enabled_and_refused_when_disabled() {
    let mut input = input();
    input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Abandonment)];
    let seeded = |amount| {
        let mut live = LiveTrie::default();
        seed_policy(
            &mut live,
            &RuntimePolicy {
                abandonment_penalty_amount: amount,
                ..RuntimePolicy::default()
            },
        );
        seed_validator(&mut live, &[1; 32], 100);
        live
    };
    let live = seeded(7);
    let mut state = TracingState::new(&live);
    let output = run_block(&mut state, &input, &[]);
    assert_eq!(output.system.accountability.admitted.len(), 1);
    assert!(state.read(&offence_key(&[1; 32])).is_some());
    let live = seeded(0);
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_block(&mut TracingState::new(&live), &input, &[])
    }));
    assert!(rejected.is_err());
}

#[test]
fn offence_marker_is_swept_after_the_unbonding_delay_not_the_window() {
    let mut input = input();
    // Retention follows the genesis-fixed unbonding delay, so a later
    // policy that widens the five-block window can never rebind an offence
    // whose marker was already swept.
    input.evidence_anchor.chunk_size = 1;
    input.evidence_anchor.unbonding_delay_blocks = 8;
    input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Inactivity)];
    let mut live = LiveTrie::default();
    seed_policy(
        &mut live,
        &RuntimePolicy {
            evidence_max_age_blocks: 5,
            inactivity_leak_amount: 1,
            ..RuntimePolicy::default()
        },
    );
    seed_validator(&mut live, &[1; 32], 100);
    let mut state = TracingState::new(&live);
    let output = run_block(&mut state, &input, &[]);
    assert_eq!(output.system.accountability.executed.len(), 1);
    assert_eq!(state.read(&offence_key(&[1; 32])), Some(vec![1]));
    let bucket: Vec<Vec<u8>> =
        borsh::from_slice(&state.read(&expiry_key(input.block_height)).unwrap()).unwrap();
    assert_eq!(bucket, vec![offence_key(&[1; 32])]);
    let admitted_at = input.block_height;
    let (post, _) = state.into_committed_and_witness().unwrap();
    // The window closes after five blocks but the marker stays for the
    // whole unbonding delay.
    let live = LiveTrie::from_trie(post);
    let mut state = TracingState::new(&live);
    input.transactions.clear();
    input.block_height = admitted_at + 8;
    run_block(&mut state, &input, &[]);
    assert!(state.read(&offence_key(&[1; 32])).is_some());
    assert!(state.read(&expiry_key(admitted_at)).is_some());
    let (post, _) = state.into_committed_and_witness().unwrap();
    // The first block past the unbonding delay sweeps the bucket and its
    // markers, and the Guest replays the same deletions from the witness.
    let live = LiveTrie::from_trie(post);
    let mut state = TracingState::new(&live);
    input.block_height = admitted_at + 9;
    let output = run_block(&mut state, &input, &[]);
    assert!(state.read(&offence_key(&[1; 32])).is_none());
    assert!(state.read(&expiry_key(admitted_at)).is_none());
    let (_, witness) = state.into_committed_and_witness().unwrap();
    let mut guest = WitnessState::new(&witness).unwrap();
    let replayed = run_block(&mut guest, &input, &[]);
    assert_eq!(replayed.system.accountability, output.system.accountability);
    assert_eq!(replayed.system.receipts, output.system.receipts);
    assert_eq!(guest.post_state_root(), output.post_state_root);
    assert_eq!(guest.post_state_root(), output.post_state_root);
}

#[test]
fn pending_obligation_blocks_mature_withdrawal_then_burns_before_release() {
    let address = [7; 32];
    let mut input = input();
    input.transactions = vec![
        admission(&mut input, 1, [1; 32], SanctionKind::Slash),
        admission(&mut input, 2, address, SanctionKind::Slash),
    ];
    let mut live = LiveTrie::default();
    seed_policy(
        &mut live,
        &RuntimePolicy {
            evidence_executions_per_block: 1,
            ..RuntimePolicy::default()
        },
    );
    seed_validator(&mut live, &[1; 32], 100);
    live.insert(
        &crate::withdrawal_key(&address),
        borsh::to_vec(&crate::WithdrawalQueue {
            entries: vec![crate::Withdrawal {
                amount: 100,
                mature_at_height: 1,
            }],
        })
        .unwrap(),
    );
    let funds = 1_000_000;
    fund(&mut live, &address, funds);
    let withdraw = [(address, SystemAction::Withdraw)];
    let mut state = TracingState::new(&live);
    let output = run_block(&mut state, &input, &withdraw);
    // The held withdrawal is refused and releases nothing.
    assert_eq!(output.results, [Err(ReceiptStatus::InsufficientBalance)]);
    assert_eq!(
        crate::state::load_account(&mut state, &address),
        crate::Account { balance: funds }
    );
    assert_eq!(
        crate::state::load_withdrawal_queue(&mut state, &address).total(),
        100
    );
    let (post, witness) = state.into_committed_and_witness().unwrap();
    let mut guest = WitnessState::new(&witness).unwrap();
    let replayed = run_block(&mut guest, &input, &withdraw);
    assert_eq!(replayed.results, output.results);
    assert_eq!(guest.post_state_root(), output.post_state_root);
    // Restored state carries the hold without relying on an in-memory pool.
    let restored = LiveTrie::from_trie(post);
    let mut state = TracingState::new(&restored);
    input.block_height += 1;
    input.transactions.clear();
    let output = run_block(&mut state, &input, &withdraw);
    // The whole unbonding balance was deducted, so the released
    // withdrawal credits nothing.
    assert_eq!(output.results, [Ok(())]);
    assert_eq!(
        crate::state::load_account(&mut state, &address).balance,
        funds
    );
    assert_eq!(load_queue(&mut state), [] as [PendingSanction; 0]);
    assert_eq!(
        crate::state::load_withdrawal_queue(&mut state, &address).entries,
        [] as [crate::Withdrawal; 0]
    );
}

#[test]
fn safety_tombstone_rejects_further_safety_claims_but_not_liveness_and_is_permanent() {
    let mut input = input();
    input.evidence_anchor.chunk_size = 1;
    input.evidence_anchor.unbonding_delay_blocks = 8;
    input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Slash)];
    let mut live = LiveTrie::default();
    seed_policy(
        &mut live,
        &RuntimePolicy {
            evidence_max_age_blocks: 5,
            inactivity_leak_amount: 1,
            ..RuntimePolicy::default()
        },
    );
    seed_validator(&mut live, &[1; 32], 100);
    let mut state = TracingState::new(&live);
    run_block(&mut state, &input, &[]);
    assert_eq!(state.read(&slashed_key(&[1; 48])), Some(vec![1]));
    let admitted_at = input.block_height;
    let (post, _) = state.into_committed_and_witness().unwrap();

    // A different offence by the same identity is rejected while the
    // tombstone stands: the first one already took the whole balance.
    let live = LiveTrie::from_trie(post);
    let mut second = input.clone();
    second.block_height += 1;
    second.transactions = vec![admission(&mut second, 1, [1; 32], SanctionKind::Slash)];
    if let RuntimeTransaction::SubmitEvidence(submission) = &mut second.transactions[0] {
        submission.statement.offence_id = [99; 32];
    }
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_block(&mut TracingState::new(&live), &second, &[])
    }));
    assert!(rejected.is_err());
    assert_eq!(
        crate::state::load_validator(&mut TracingState::new(&live), &[1; 32]).stake,
        0
    );

    // Liveness evidence against the same identity keys by offence and
    // is unaffected by the tombstone.
    let mut liveness = input.clone();
    liveness.block_height += 1;
    liveness.transactions = vec![admission(
        &mut liveness,
        1,
        [1; 32],
        SanctionKind::Inactivity,
    )];
    let mut state = TracingState::new(&live);
    let output = run_block(&mut state, &liveness, &[]);
    assert_eq!(output.system.accountability.admitted.len(), 1);
    assert_eq!(state.read(&offence_key(&[1; 32])), Some(vec![1]));

    // The unbonding delay sweeps the liveness marker but never the
    // tombstone: consensus never seats the identity again and a safety
    // claim has no age window, so the tombstone must outlive any balance
    // the identity could still hold.
    let (post, _) = state.into_committed_and_witness().unwrap();
    let live = LiveTrie::from_trie(post);
    let mut state = TracingState::new(&live);
    input.transactions.clear();
    input.block_height = admitted_at + 9;
    run_block(&mut state, &input, &[]);
    assert!(state.read(&slashed_key(&[1; 48])).is_some());
    assert!(state.read(&expiry_key(admitted_at)).is_none());
    input.block_height = admitted_at + 10;
    let (post, _) = state.into_committed_and_witness().unwrap();
    let live = LiveTrie::from_trie(post);
    let mut state = TracingState::new(&live);
    run_block(&mut state, &input, &[]);
    assert!(state.read(&slashed_key(&[1; 48])).is_some());
    assert!(state.read(&offence_key(&[1; 32])).is_none());
}

#[test]
fn safety_claim_against_an_identity_with_nothing_at_stake_still_tombstones_it() {
    // Nothing to deduct is an explicit outcome, not a reason to refuse the
    // claim: the tombstone still ejects the identity from consensus.
    let mut input = input();
    input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Slash)];
    let live = LiveTrie::default();
    let mut state = TracingState::new(&live);
    let output = run_block(&mut state, &input, &[]);
    assert_eq!(output.system.accountability.admitted.len(), 1);
    assert_eq!(output.system.accountability.executed.len(), 1);
    assert_eq!(state.read(&slashed_key(&[1; 48])), Some(vec![1]));
}

#[test]
fn safety_claim_binds_to_queued_unbonding_at_any_signature_age() {
    // The offence happened at block 1; the claim arrives a million blocks
    // later, long after any window, while the stake is still unbonding.
    let mut input = input();
    input.block_height = 2;
    input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Slash)];
    input.block_height = 1_000_000;
    let mut live = LiveTrie::default();
    live.insert(
        &crate::withdrawal_key(&[1; 32]),
        borsh::to_vec(&crate::WithdrawalQueue {
            entries: vec![crate::Withdrawal {
                amount: 100,
                mature_at_height: 1_000_050,
            }],
        })
        .unwrap(),
    );
    let mut state = TracingState::new(&live);
    let output = run_block(&mut state, &input, &[]);
    assert_eq!(output.system.accountability.executed.len(), 1);
    assert_eq!(
        crate::state::load_withdrawal_queue(&mut state, &[1; 32]).total(),
        0
    );
    assert_eq!(state.read(&slashed_key(&[1; 48])), Some(vec![1]));
    let (_, witness) = state.into_committed_and_witness().unwrap();
    let mut guest = WitnessState::new(&witness).unwrap();
    let replayed = run_block(&mut guest, &input, &[]);
    assert_eq!(replayed.system.accountability, output.system.accountability);
    assert_eq!(replayed.system.receipts, output.system.receipts);
    assert_eq!(guest.post_state_root(), output.post_state_root);
}

#[test]
#[should_panic(expected = "offence replay")]
fn replay_is_rejected_after_execution_even_with_different_statement_encoding() {
    let mut input = input();
    input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Slash)];
    let mut live = LiveTrie::default();
    seed_validator(&mut live, &[1; 32], 100);
    let mut state = TracingState::new(&live);
    run_block(&mut state, &input, &[]);
    if let RuntimeTransaction::SubmitEvidence(receipt) = &mut input.transactions[0] {
        receipt.statement.facts_commitment[0] ^= 1;
    }
    run_block(&mut state, &input, &[]);
}

#[test]
#[should_panic(expected = "mandatory sanction gas")]
fn admission_cannot_consume_id_while_starving_deduction() {
    let mut input = input();
    input.transactions = vec![admission(&mut input, 1, [1; 32], SanctionKind::Slash)];
    input.block_gas_limit = GAS_EVIDENCE_ADMISSION;
    let mut live = LiveTrie::default();
    seed_validator(&mut live, &[1; 32], 100);
    run_block(&mut TracingState::new(&live), &input, &[]);
}
