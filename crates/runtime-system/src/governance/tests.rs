use super::*;
use crate::ReceiptStatus;
use crate::system::{SystemAction, dispatch_with_policy};
use crate::test_support::{address, apply_against, run_block, seed_policy, seed_staked};
use crate::{Account, account_key, encode_account};
use alloc::vec;
use alloc::vec::Vec;
use neutrin0_consensus_types::history_proof::ExecutionPrograms;
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_core::host::{LiveTrie, TracingState};

const CHAIN_ID: u64 = 42;

/// Minimum activation lead of every test block's anchor.
fn lead() -> u64 {
    upgrade_min_lead_chunks(&neutrin0_consensus_types::evidence::EvidenceAnchor::default())
}

/// Activation chunk `chunk` of a chain whose minimum lead were one chunk,
/// shifted onto the real minimum lead.
fn at(chunk: u64) -> u64 {
    chunk + lead() - 1
}

fn programs(tag: u32) -> ProgramSet {
    ProgramSet {
        runtime_code_hash: [u8::try_from(tag).unwrap(); 32],
        execution: ExecutionPrograms {
            fact: [1; 8],
            evidence: [tag + 1; 8],
            block: [tag + 2; 8],
        },
    }
}

/// Validators with the given stakes, each with a funded account.
fn live(validators: &[(Address, u128)]) -> LiveTrie {
    let mut live = LiveTrie::default();
    for (addr, _) in validators {
        live.insert(
            &account_key(addr),
            encode_account(&Account { balance: 1_000_000 }),
        );
    }
    seed_staked(&mut live, validators);
    live
}

/// Content hashes naming every artifact `programs` changes against the
/// test blocks' zero program set.
fn artifacts(programs: &ProgramSet) -> ProgramArtifacts {
    // The Fact program never changes; its artifact is named for
    // distribution only.
    ProgramArtifacts {
        runtime: programs.runtime_code_hash,
        fact: [0xF0; 32],
        evidence: [0xE0; 32],
        block: [0xB0; 32],
    }
}

fn propose(addr: Address, programs: ProgramSet, activate: u64) -> (Address, SystemAction) {
    (
        addr,
        SystemAction::Propose {
            programs,
            artifacts: artifacts(&programs),
            activate_at_chunk: activate,
        },
    )
}

fn vote(addr: Address, proposal_id: [u8; 32]) -> (Address, SystemAction) {
    (addr, SystemAction::Vote(proposal_id))
}

fn propose_policy(addr: Address, policy: RuntimePolicy) -> (Address, SystemAction) {
    (addr, SystemAction::Policy(policy))
}

fn stake(addr: Address, amount: u128) -> (Address, SystemAction) {
    (addr, SystemAction::Stake(amount))
}

fn programs_action(programs: ProgramSet, activate_at_chunk: u64) -> ProposalAction {
    ProposalAction::Programs {
        programs,
        artifacts: artifacts(&programs),
        activate_at_chunk,
    }
}

fn proposed_programs(proposal: &UpgradeProposal) -> Option<ProgramSet> {
    match proposal.action {
        ProposalAction::Programs { programs, .. } => Some(programs),
        ProposalAction::Policy(_)
        | ProposalAction::Cancel { .. }
        | ProposalAction::Fork(_)
        | ProposalAction::CancelFork(_) => None,
    }
}

fn fork(count: u64) -> ScheduledFork {
    ScheduledFork {
        count,
        successor: [5; 32],
    }
}

/// One complete artifact of a single piece named `artifact`.
fn piece(artifact: [u8; 32]) -> neutrin0_consensus_types::ProgramPieceRef {
    neutrin0_consensus_types::ProgramPieceRef {
        artifact,
        index: 0,
        count: 1,
    }
}

/// Weighted consensus seats for every caller these tests use.
fn seats() -> Vec<neutrin0_primitives::Validator> {
    (1..=4).map(|seed| seat(address(seed))).collect()
}

fn seat(addr: Address) -> neutrin0_primitives::Validator {
    neutrin0_primitives::Validator {
        pubkey: [addr[31]; 48],
        withdrawal_credentials: addr,
        effective_stake: 1,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }
}

fn block(chunk: u64) -> RuntimeBlockInput {
    block_with_seats(chunk, seats())
}

fn block_with_seats(
    chunk: u64,
    active_validators: Vec<neutrin0_primitives::Validator>,
) -> RuntimeBlockInput {
    let mut context = neutrin0_consensus_types::runtime::ConsensusExecutionContext::default();
    context.finalized.validators_root =
        neutrin0_consensus_types::evidence::commitment(&active_validators);
    RuntimeBlockInput {
        active_validators,
        participation_acks: Vec::new(),
        program_pieces: Vec::new(),

        context,
        evidence_anchor: neutrin0_consensus_types::evidence::EvidenceAnchor {
            chunk_id: chunk,
            fact_guest_vk_digest: [1; 8],
            ..Default::default()
        },
        chain_id: CHAIN_ID,
        block_height: chunk * 4 + 1,
        block_gas_limit: 30_000_000,
        proposer_address: [0; 32],
        participation: None,
        proving: None,
        transactions: Vec::new(),
    }
}

fn run(
    live: &LiveTrie,
    input: &RuntimeBlockInput,
    actions: &[(Address, SystemAction)],
) -> (u32, u32, UpgradeStatus) {
    let mut tracer = TracingState::new(live);
    let run = run_block(&mut tracer, input, actions);
    let status = status(&mut tracer);
    (run.applied(), run.failed(), status)
}

#[test]
fn the_minimum_lead_lets_a_dissenting_staker_withdraw_before_the_switch() {
    for (unbonding_delay_blocks, chunk_size) in [
        (0, 1),
        (1, 1),
        (127, 128),
        (128, 128),
        (129, 128),
        (302_400, 128),
    ] {
        let anchor = EvidenceAnchor {
            unbonding_delay_blocks,
            chunk_size,
            ..EvidenceAnchor::default()
        };
        let lead = upgrade_min_lead_chunks(&anchor);
        assert!(lead >= 1);
        for enacted_chunk in [0, 7] {
            // Enactment in the chunk's last block, unbonding in the next
            // one and withdrawal at maturity still precede the first block
            // of the activation chunk, which runs the new programs.
            let enactment = (enacted_chunk + 1) * chunk_size;
            let withdrawal = enactment + 1 + unbonding_delay_blocks;
            let first_switched = (enacted_chunk + lead) * chunk_size + 1;
            assert!(withdrawal < first_switched);
        }
    }
    assert_eq!(
        upgrade_min_lead_chunks(&EvidenceAnchor::default()),
        (neutrin0_primitives::DEFAULT_UNBONDING_DELAY_BLOCKS + 1)
            .div_ceil(neutrin0_primitives::DEFAULT_CHUNK_SIZE)
            + 1
    );
}

#[test]
fn quorum_arithmetic_matches_two_thirds_without_overflow() {
    assert!(quorum_reached(2, 3, UPGRADE_QUORUM));
    assert!(!quorum_reached(1, 3, UPGRADE_QUORUM));
    assert!(quorum_reached(67, 100, UPGRADE_QUORUM));
    assert!(!quorum_reached(66, 100, UPGRADE_QUORUM));
    assert!(quorum_reached(u128::MAX, u128::MAX, UPGRADE_QUORUM));
    assert!(!quorum_reached(u128::MAX / 2, u128::MAX, UPGRADE_QUORUM));
}

#[test]
fn sole_validator_enacts_at_proposal_and_schedule_is_consumed_later() {
    let alice = address(1);
    let live = live(&[(alice, 100)]);
    let (applied, failed, status) = run(&live, &block(0), &[propose(alice, programs(7), at(1))]);
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(status.proposals, []);
    // Nothing was published yet, so the switch is not available.
    assert_eq!(
        status.scheduled,
        Some(ScheduledUpgrade {
            activate_at_chunk: at(1),
            programs: programs(7),
            artifacts: artifacts(&programs(7)),
            available: false,
        })
    );
    // Blocks of the activation chunk clear the consumed record.
    let (_, _, status) = run(&live, &block(at(1)), &[]);
    assert_eq!(status.scheduled, None);
}

#[test]
fn governance_cannot_propose_a_replacement_fact_program() {
    let alice = address(1);
    let live = live(&[(alice, 100)]);
    let mut replacement = programs(7);
    replacement.execution.fact = [2; 8];
    let (applied, failed, status) = run(&live, &block(0), &[propose(alice, replacement, at(1))]);
    assert_eq!((applied, failed), (0, 1));
    assert_eq!(status.proposals, []);
    assert_eq!(status.scheduled, None);
}

#[test]
fn vote_cannot_enact_a_stored_proposal_with_another_fact_identity() {
    let (alice, bob) = (address(1), address(2));
    let mut live = live(&[(alice, 60), (bob, 40)]);
    let mut replacement = programs(7);
    replacement.execution.fact = [2; 8];
    let proposal = UpgradeProposal {
        proposer: alice,
        action: programs_action(replacement, at(1)),
        proposed_at_chunk: 0,
        voters: vec![alice],
    };
    live.insert(
        UPGRADE_PROPOSALS_KEY,
        borsh::to_vec(&vec![&proposal]).unwrap(),
    );
    let (applied, failed, status) = run(&live, &block(0), &[vote(bob, proposal.id())]);
    assert_eq!((applied, failed), (0, 1));
    assert_eq!(status.proposals, [proposal]);
    assert_eq!(status.scheduled, None);
}

#[test]
fn policy_proposals_enact_through_the_same_quorum_and_apply_to_the_next_block() {
    let (a, b, c) = (address(1), address(2), address(3));
    let live = live(&[(a, 40), (b, 30), (c, 30)]);
    let anchor = neutrin0_consensus_types::evidence::EvidenceAnchor::default();
    let policy = RuntimePolicy {
        evidence_max_age_blocks: 777,
        reporter_reward_bps: 2_500,
        ..RuntimePolicy::default()
    };
    assert!(policy.is_valid_for(&anchor));

    // Policies the genesis facts or the structural bounds reject never
    // open a proposal, even from the largest validator.
    let too_old = RuntimePolicy {
        evidence_max_age_blocks: anchor.unbonding_delay_blocks,
        ..policy
    };
    let no_queue = RuntimePolicy {
        evidence_max_pending: 0,
        ..policy
    };
    let excessive_reward = RuntimePolicy {
        reporter_reward_bps: 10_001,
        ..policy
    };
    // The validator stake floor is a mandatory protection.
    let no_stake_floor = RuntimePolicy {
        min_validator_stake: 0,
        ..policy
    };
    let (applied, failed, pending) = run(
        &live,
        &block(0),
        &[
            propose_policy(a, too_old),
            propose_policy(a, no_queue),
            propose_policy(a, excessive_reward),
            propose_policy(a, no_stake_floor),
        ],
    );
    assert_eq!((applied, failed), (0, 4));
    assert_eq!(pending.policy_proposals, []);

    // A valid proposal waits for quorum like a program upgrade and does
    // not touch the policy in force.
    let (out, live) = apply_against(&live, &block(0), &[propose_policy(a, policy)]);
    assert_eq!(out.counts(), (1, 0));
    let mut view = TracingState::new(&live);
    let proposal = status(&mut view).policy_proposals.remove(0);
    assert_eq!(proposal.action, ProposalAction::Policy(policy));
    assert_eq!(
        proposal.id(),
        proposal_id(&a, &ProposalAction::Policy(policy))
    );
    assert_eq!(
        crate::load_runtime_policy(&mut view),
        RuntimePolicy::default()
    );

    // The vote that crosses two thirds enacts the policy; it changes
    // stake risk, so it waits until stake unbonded in the next block has
    // matured and been withdrawn.
    let (out, live) = apply_against(&live, &block(0), &[vote(b, proposal.id())]);
    assert_eq!(out.counts(), (1, 0));
    let mut view = TracingState::new(&live);
    let effective_height = block(0).block_height + 1 + anchor.unbonding_delay_blocks + 1;
    assert_eq!(
        status(&mut view),
        UpgradeStatus {
            pending_policy: Some(PendingPolicy {
                policy,
                effective_height,
            }),
            ..UpgradeStatus::default()
        }
    );
    assert_eq!(
        crate::load_runtime_policy(&mut view),
        RuntimePolicy::default()
    );

    // Blocks before the effective height keep the old policy and still
    // accept proposals; the effective block runs under the new one.
    let mut early = block(0);
    early.block_height = effective_height - 1;
    let (out, unchanged) = apply_against(
        &live,
        &early,
        &[propose_policy(c, RuntimePolicy::default())],
    );
    assert_eq!(out.counts(), (1, 0));
    assert_eq!(
        crate::load_runtime_policy(&mut TracingState::new(&unchanged)),
        RuntimePolicy::default()
    );
    let mut due = block(0);
    due.block_height = effective_height;
    let (_, applied) = apply_against(&live, &due, &[]);
    let mut view = TracingState::new(&applied);
    assert_eq!(crate::load_runtime_policy(&mut view), policy);
    assert_eq!(status(&mut view).pending_policy, None);
}

#[test]
fn policies_without_stake_risk_wait_sixty_four_chunks_and_never_reprice_the_past() {
    let (a, b) = (address(1), address(2));
    let live = live(&[(a, 70), (b, 30)]);
    let anchor = neutrin0_consensus_types::evidence::EvidenceAnchor::default();
    let cheaper = RuntimePolicy {
        chunk_prover_fee_bps: 9_000,
        ..RuntimePolicy::default()
    };
    let (out, live) = apply_against(&live, &block(0), &[propose_policy(a, cheaper)]);
    assert_eq!(out.counts(), (1, 0));
    let mut view = TracingState::new(&live);
    assert_eq!(
        status(&mut view).pending_policy,
        Some(PendingPolicy {
            policy: cheaper,
            effective_height: block(0).block_height
                + anchor.chunk_size * crate::POLICY_DELAY_CHUNKS,
        })
    );
}

#[test]
fn policies_cannot_shrink_the_queue_bound_below_the_live_backlog() {
    let (a, b, c) = (address(1), address(2), address(3));
    let live = live(&[(a, 40), (b, 30), (c, 30)]);
    let narrow = RuntimePolicy {
        evidence_max_pending: 1,
        evidence_admissions_per_block: 1,
        evidence_executions_per_block: 1,
        ..RuntimePolicy::default()
    };
    // Twenty queued sanctions outlast one block of mandatory executions.
    let backlog: Vec<crate::accountability::PendingSanction> = (0..20)
        .map(|tag| crate::accountability::PendingSanction {
            sanction: neutrin0_consensus_types::runtime::Sanction {
                offence_id: [tag; 32],
                offender: neutrin0_primitives::Validator {
                    pubkey: [tag; 48],
                    withdrawal_credentials: neutrin0_primitives::runtime_account([tag; 20]),
                    effective_stake: 1,
                    activation_epoch: 0,
                    exit_epoch: u64::MAX,
                },
                kind: neutrin0_consensus_types::evidence::SanctionKind::Slash,
            },
            amount: 1,
            reporter: None,
            reporter_reward_bps: 1_000,
        })
        .collect();
    let queue = borsh::to_vec(&backlog).unwrap();
    // The bound cannot be proposed into force over a longer backlog.
    let mut backlogged = live.clone();
    backlogged.insert(crate::accountability::QUEUE_KEY, queue.clone());
    let (applied, failed, pending) = run(&backlogged, &block(0), &[propose_policy(a, narrow)]);
    assert_eq!((applied, failed), (0, 1));
    assert_eq!(pending.policy_proposals, []);
    // Proposed while the queue was empty, it cannot be enacted by the vote
    // that reaches quorum once a backlog has built up; the proposal stays
    // open for a later vote.
    let (_, mut opened) = apply_against(&live, &block(0), &[propose_policy(b, narrow)]);
    opened.insert(crate::accountability::QUEUE_KEY, queue);
    let narrow_id = proposal_id(&b, &ProposalAction::Policy(narrow));
    // Stakes 30 + 40 of 100 reach quorum, so this vote would enact.
    let (applied, failed, pending) = run(&opened, &block(0), &[vote(a, narrow_id)]);
    assert_eq!((applied, failed), (0, 1));
    assert_eq!(pending.policy_proposals.len(), 1);
    let mut view = TracingState::new(&opened);
    assert_eq!(
        crate::load_runtime_policy(&mut view),
        RuntimePolicy::default()
    );
}

#[test]
fn votes_accumulate_by_stake_until_two_thirds() {
    let (a, b, c) = (address(1), address(2), address(3));
    let mut live = live(&[(a, 40), (b, 30), (c, 30)]);
    let proposal_id = proposal_id(&a, &programs_action(programs(9), at(5)));
    let (applied, _, status) = run(&live, &block(0), &[propose(a, programs(9), at(5))]);
    assert_eq!(applied, 1);
    let proposal = &status.proposals[0];
    assert_eq!(proposal.id(), proposal_id);
    assert_eq!(proposal.voters, vec![a]);
    assert_eq!(status.scheduled, None);
    live.insert(
        UPGRADE_PROPOSALS_KEY,
        borsh::to_vec(&status.proposals).unwrap(),
    );
    // Wrong id, double vote and a non-validator all fail; the second
    // valid vote crosses 70 >= 67.
    let outsider = address(4);
    let (applied, failed, status) = run(
        &live,
        &block(0),
        &[
            vote(b, [0; 32]),
            vote(a, proposal_id),
            vote(outsider, proposal_id),
            vote(b, proposal_id),
        ],
    );
    assert_eq!((applied, failed), (1, 3));
    assert_eq!(status.proposals, []);
    assert_eq!(
        status.scheduled.map(|s| (s.activate_at_chunk, s.programs)),
        Some((at(5), programs(9)))
    );
}

#[test]
fn proposals_need_complete_programs_lead_time_and_no_pending_switch() {
    let (a, b) = (address(1), address(2));
    let mut live = live(&[(a, 50), (b, 50)]);
    let mut incomplete = programs(3);
    incomplete.execution.block = [0; 8];
    let (applied, failed, _) = run(
        &live,
        &block(4),
        &[
            propose(a, incomplete, at(9)),
            propose(a, programs(3), at(4)),
            propose(a, programs(3), at(5)),
            propose(b, programs(4), at(6)),
        ],
    );
    // The last two are well formed, and each proposer holds its own.
    assert_eq!((applied, failed), (2, 2));
    // A dead proposal leaves the slot when the slot is next written.
    let stale = UpgradeProposal {
        proposer: a,
        action: programs_action(programs(3), at(2)),
        proposed_at_chunk: 0,
        voters: vec![a],
    };
    live.insert(UPGRADE_PROPOSALS_KEY, borsh::to_vec(&vec![stale]).unwrap());
    let (applied, _, status) = run(&live, &block(4), &[propose(b, programs(4), at(6))]);
    assert_eq!(applied, 1);
    assert_eq!(
        status
            .proposals
            .iter()
            .map(proposed_programs)
            .collect::<Vec<_>>(),
        [Some(programs(4))]
    );
    // A pending enacted switch blocks new proposals until consumed.
    live.insert(
        UPGRADE_KEY,
        borsh::to_vec(&ScheduledUpgrade {
            activate_at_chunk: at(8),
            programs: programs(5),
            artifacts: artifacts(&programs(5)),
            available: false,
        })
        .unwrap(),
    );
    let (applied, failed, _) = run(&live, &block(4), &[propose(a, programs(6), at(9))]);
    assert_eq!((applied, failed), (0, 1));
    // The policy slot stays open while the switch waits.
    let (applied, failed, status) = run(
        &live,
        &block(4),
        &[propose_policy(a, RuntimePolicy::default())],
    );
    assert_eq!((applied, failed), (1, 0));
    assert_eq!(status.policy_proposals.len(), 1);
}

#[test]
fn a_changed_program_must_name_its_artifact() {
    let alice = address(1);
    let live = live(&[(alice, 100)]);
    let mut unnamed = artifacts(&programs(7));
    unnamed.block = [0; 32];
    let (applied, failed, status) = run(
        &live,
        &block(0),
        &[(
            alice,
            SystemAction::Propose {
                programs: programs(7),
                artifacts: unnamed,
                activate_at_chunk: at(1),
            },
        )],
    );
    assert_eq!((applied, failed), (0, 1));
    assert_eq!(status.scheduled, None);
}

#[test]
fn a_switch_becomes_available_once_every_changed_program_artifact_is_published() {
    let (a, b) = (address(1), address(2));
    let live = live(&[(a, 60), (b, 40)]);
    let named = artifacts(&programs(7));
    let (_, live) = apply_against(&live, &block(0), &[propose(a, programs(7), at(3))]);
    // A piece published while the proposal is open already counts.
    let mut opened = block(1);
    opened.program_pieces = vec![piece(named.runtime)];
    let id = proposal_id(&a, &programs_action(programs(7), at(3)));
    let (out, live) = apply_against(&live, &opened, &[vote(b, id)]);
    assert_eq!(out.counts(), (1, 0));
    let mut view = TracingState::new(&live);
    assert!(!status(&mut view).scheduled.unwrap().available);
    // Pieces of unnamed artifacts change nothing; the last artifact of a
    // changed program makes the switch available, while the named but
    // unchanged Fact artifact is never required.
    let mut second = block(1);
    second.block_height += 1;
    second.program_pieces = vec![piece([0x77; 32]), piece(named.evidence)];
    let (_, live) = apply_against(&live, &second, &[]);
    assert!(
        !status(&mut TracingState::new(&live))
            .scheduled
            .unwrap()
            .available
    );
    let mut third = block(1);
    third.block_height += 2;
    third.program_pieces = vec![piece(named.block)];
    let (_, live) = apply_against(&live, &third, &[]);
    let mut view = TracingState::new(&live);
    assert!(status(&mut view).scheduled.unwrap().available);
    assert_eq!(load_pieces(&mut view), []);
}

#[test]
fn two_thirds_can_cancel_an_enacted_switch_before_it_activates() {
    let (a, b, c) = (address(1), address(2), address(3));
    let live = live(&[(a, 40), (b, 30), (c, 30)]);
    let (_, live) = apply_against(&live, &block(0), &[propose(a, programs(7), at(3))]);
    let (_, live) = apply_against(
        &live,
        &block(0),
        &[vote(
            b,
            proposal_id(&a, &programs_action(programs(7), at(3))),
        )],
    );
    assert!(status(&mut TracingState::new(&live)).scheduled.is_some());
    let cancel = |addr| {
        (
            addr,
            SystemAction::Cancel {
                programs: programs(7),
                activate_at_chunk: at(3),
            },
        )
    };
    // A cancellation naming another switch is refused.
    let (applied, failed, _) = run(
        &live,
        &block(1),
        &[(
            c,
            SystemAction::Cancel {
                programs: programs(8),
                activate_at_chunk: at(3),
            },
        )],
    );
    assert_eq!((applied, failed), (0, 1));
    let (out, live) = apply_against(&live, &block(1), &[cancel(c)]);
    assert_eq!(out.counts(), (1, 0));
    assert!(status(&mut TracingState::new(&live)).scheduled.is_some());
    let cancel_id = proposal_id(
        &c,
        &ProposalAction::Cancel {
            programs: programs(7),
            activate_at_chunk: at(3),
        },
    );
    let (out, live) = apply_against(&live, &block(1), &[vote(a, cancel_id)]);
    assert_eq!(out.counts(), (1, 0));
    let mut view = TracingState::new(&live);
    assert_eq!(status(&mut view), UpgradeStatus::default());
    // With the switch cancelled, a new program proposal is admissible.
    let (applied, failed, _) = run(&live, &block(1), &[propose(b, programs(8), at(4))]);
    assert_eq!((applied, failed), (1, 0));
}

#[test]
fn two_thirds_schedule_a_fork_in_its_own_slot_and_can_cancel_it() {
    let (a, b, c) = (address(1), address(2), address(3));
    let live = live(&[(a, 40), (b, 30), (c, 30)]);
    // A proposer holds one proposal in each slot.
    let (out, live) = apply_against(
        &live,
        &block(0),
        &[
            (a, SystemAction::ProposeFork(fork(at(3)))),
            propose(a, programs(7), at(3)),
        ],
    );
    assert_eq!(out.counts(), (2, 0));
    let fork_id = proposal_id(&a, &ProposalAction::Fork(fork(at(3))));
    let (out, live) = apply_against(&live, &block(0), &[vote(b, fork_id)]);
    assert_eq!(out.counts(), (1, 0));
    let scheduled = status(&mut TracingState::new(&live));
    assert_eq!(scheduled.scheduled_fork, Some(fork(at(3))));
    assert_eq!(scheduled.fork_proposals, []);
    // The program slot is untouched by the fork's decision.
    assert_eq!(scheduled.proposals.len(), 1);
    assert_eq!(scheduled.scheduled, None);
    // A scheduled fork admits only its own cancellation.
    let (applied, failed, _) = run(
        &live,
        &block(1),
        &[
            (c, SystemAction::ProposeFork(fork(at(4)))),
            (c, SystemAction::CancelFork(fork(at(4)))),
        ],
    );
    assert_eq!((applied, failed), (0, 2));
    let (out, live) = apply_against(
        &live,
        &block(1),
        &[(c, SystemAction::CancelFork(fork(at(3))))],
    );
    assert_eq!(out.counts(), (1, 0));
    let cancel_id = proposal_id(&c, &ProposalAction::CancelFork(fork(at(3))));
    let (out, live) = apply_against(&live, &block(1), &[vote(a, cancel_id)]);
    assert_eq!(out.counts(), (1, 0));
    let cancelled = status(&mut TracingState::new(&live));
    assert_eq!(cancelled.scheduled_fork, None);
    assert_eq!(cancelled.fork_proposals, []);
}

#[test]
fn a_fork_needs_the_switch_lead_and_a_successor() {
    let alice = address(1);
    let live = live(&[(alice, 100)]);
    let (applied, failed, status) = run(
        &live,
        &block(0),
        &[
            (alice, SystemAction::ProposeFork(fork(at(1) - 1))),
            (
                alice,
                SystemAction::ProposeFork(ScheduledFork {
                    count: at(1),
                    successor: [0; 32],
                }),
            ),
        ],
    );
    assert_eq!((applied, failed), (0, 2));
    assert_eq!(status, UpgradeStatus::default());
}

#[test]
fn the_successors_first_block_drops_the_fork_and_the_predecessors_schedule() {
    let alice = address(1);
    let live = live(&[(alice, 100)]);
    // A switch scheduled past the fork never runs on this chain.
    let (out, live) = apply_against(
        &live,
        &block(0),
        &[
            (alice, SystemAction::ProposeFork(fork(at(3)))),
            propose(alice, programs(7), at(5)),
        ],
    );
    assert_eq!(out.counts(), (2, 0));
    // The last chunk before the count still holds the fork, which the
    // boundary entering the count carries.
    let (_, before) = apply_against(&live, &block(at(3) - 1), &[]);
    let held = status(&mut TracingState::new(&before));
    assert_eq!(held.scheduled_fork, Some(fork(at(3))));
    assert!(held.scheduled.is_some());
    let (_, after) = apply_against(&before, &block(at(3)), &[]);
    let dropped = status(&mut TracingState::new(&after));
    assert_eq!(dropped.scheduled_fork, None);
    assert_eq!(dropped.scheduled, None);
}

#[test]
fn the_largest_validator_cannot_hold_a_slot_against_more_support() {
    let (whale, b, c) = (address(1), address(2), address(3));
    let live = live(&[(whale, 30), (b, 40), (c, 30)]);
    // The whale's junk proposal neither blocks a competing one nor can
    // displace it; support enacts the competitor and closes the slot.
    let (applied, failed, status) = run(
        &live,
        &block(0),
        &[
            propose(whale, programs(3), at(5)),
            propose(b, programs(4), at(6)),
            propose(whale, programs(3), at(5)),
            vote(c, proposal_id(&b, &programs_action(programs(4), at(6)))),
        ],
    );
    assert_eq!((applied, failed), (3, 1));
    assert_eq!(status.proposals, []);
    assert_eq!(status.scheduled.map(|s| s.programs), Some(programs(4)));
}

#[test]
fn a_vote_or_a_new_proposal_moves_support_within_its_slot() {
    let (a, b, c, d) = (address(1), address(2), address(3), address(4));
    let live = live(&[(a, 20), (b, 20), (c, 20), (d, 40)]);
    let first = proposal_id(&a, &programs_action(programs(3), at(5)));
    let second = proposal_id(&b, &programs_action(programs(4), at(6)));
    let (out, live) = apply_against(
        &live,
        &block(0),
        &[
            propose(a, programs(3), at(5)),
            propose(b, programs(4), at(6)),
            vote(c, first),
            vote(c, second),
            // A policy vote is in another slot and moves nothing here.
            propose_policy(c, RuntimePolicy::default()),
        ],
    );
    assert_eq!(out.counts(), (5, 0));
    let open = status(&mut TracingState::new(&live)).proposals;
    let voters = |id| {
        open.iter()
            .find(|proposal| proposal.id() == id)
            .map(|proposal| proposal.voters.clone())
    };
    assert_eq!(voters(first), Some(vec![a]));
    assert_eq!(voters(second), Some(vec![b, c]));
    // A proposer re-proposing replaces its own proposal and takes its
    // support along; 40 + 20 cannot enact, 40 + 40 can.
    let replacement = proposal_id(&a, &programs_action(programs(5), at(7)));
    let (applied, failed, status) = run(
        &live,
        &block(0),
        &[
            propose(a, programs(3), at(5)),
            propose(a, programs(5), at(7)),
            vote(d, replacement),
            vote(c, replacement),
        ],
    );
    assert_eq!((applied, failed), (3, 1));
    assert_eq!(status.scheduled.map(|s| s.programs), Some(programs(5)));
    assert_eq!(status.proposals, []);
}

#[test]
fn a_full_slot_yields_its_least_supported_proposal_to_more_support() {
    let (a, b) = (address(1), address(2));
    let mut live = live(&[(a, 10), (b, 90)]);
    // Proposals of departed proposers, supported by nobody counted.
    let departed: Vec<_> = (0..MAX_SLOT_PROPOSALS)
        .map(|index| UpgradeProposal {
            proposer: [u8::try_from(index % 200).unwrap() + 50; 32],
            action: programs_action(programs(u32::try_from(index % 100).unwrap() + 10), at(5)),
            proposed_at_chunk: 0,
            voters: Vec::new(),
        })
        .collect();
    live.insert(UPGRADE_PROPOSALS_KEY, borsh::to_vec(&departed).unwrap());
    let (applied, _, status) = run(&live, &block(0), &[propose(a, programs(3), at(6))]);
    assert_eq!(applied, 1);
    assert_eq!(status.proposals.len(), MAX_SLOT_PROPOSALS);
    assert!(
        status
            .proposals
            .iter()
            .any(|proposal| proposal.proposer == a)
    );
    // When every stored proposal has at least as much support, it is refused.
    let backed: Vec<_> = departed
        .into_iter()
        .map(|proposal| UpgradeProposal {
            voters: vec![b],
            ..proposal
        })
        .collect();
    live.insert(UPGRADE_PROPOSALS_KEY, borsh::to_vec(&backed).unwrap());
    let (applied, failed, _) = run(&live, &block(0), &[propose(a, programs(3), at(6))]);
    assert_eq!((applied, failed), (0, 1));
}

#[test]
fn nodes_prepare_the_best_supported_switch_still_live() {
    use neutrin0_runtime_abi::operational::{ProgramDistribution, QUERY_PROGRAMS};
    let (a, c) = (address(1), address(3));
    let mut live = live(&[(a, 50), (address(2), 30), (c, 20)]);
    let early = UpgradeProposal {
        proposer: a,
        action: programs_action(programs(3), at(2)),
        proposed_at_chunk: 0,
        voters: vec![a],
    };
    let late = UpgradeProposal {
        proposer: c,
        action: programs_action(programs(4), at(80)),
        proposed_at_chunk: 70,
        voters: vec![c],
    };
    live.insert(
        UPGRADE_PROPOSALS_KEY,
        borsh::to_vec(&vec![&early, &late]).unwrap(),
    );
    let prepared = |chunk: u64| {
        let response = crate::query::query(
            &neutrin0_runtime_abi::QueryRequest {
                method: QUERY_PROGRAMS.into(),
                args: borsh::to_vec(&EvidenceAnchor {
                    chunk_id: chunk,
                    ..EvidenceAnchor::default()
                })
                .unwrap(),
            },
            &mut TracingState::new(&live),
        );
        borsh::from_slice::<Vec<ProgramDistribution>>(&response.payload)
            .unwrap()
            .into_iter()
            .map(|distribution| distribution.programs)
            .collect::<Vec<_>>()
    };
    // Both live: the better supported switch. Once the early one has
    // expired, though still stored, the late one.
    assert_eq!(prepared(0), [programs(3)]);
    assert_eq!(prepared(70), [programs(4)]);
    let unnamed = crate::query::query(
        &neutrin0_runtime_abi::QueryRequest {
            method: QUERY_PROGRAMS.into(),
            args: Vec::new(),
        },
        &mut TracingState::new(&live),
    );
    assert!(!unnamed.is_ok());
}

#[test]
fn a_vote_after_the_lead_ran_out_cannot_enact() {
    let (a, b) = (address(1), address(2));
    let mut live = live(&[(a, 50), (b, 50)]);
    // Activation exactly the minimum lead after the proposal's chunk.
    let (applied, _, status) = run(&live, &block(10), &[propose(a, programs(3), at(11))]);
    assert_eq!(applied, 1);
    let open = status.proposals[0].clone();
    live.insert(
        UPGRADE_PROPOSALS_KEY,
        borsh::to_vec(&status.proposals).unwrap(),
    );
    // One chunk later the lead no longer fits: the proposal is not live and
    // the vote that would reach quorum enacts nothing.
    let (applied, failed, status) = run(&live, &block(11), &[vote(b, open.id())]);
    assert_eq!((applied, failed), (0, 1));
    assert!(status.scheduled.is_none());
}

#[test]
fn far_activations_are_rejected_and_unsupported_proposals_expire() {
    let (a, b) = (address(1), address(2));
    let mut live = live(&[(a, 50), (b, 50)]);
    // Beyond the maximum lead the slot could be held indefinitely.
    let (applied, failed, _) = run(
        &live,
        &block(10),
        &[
            propose(
                a,
                programs(3),
                at(10 + UPGRADE_ACTIVATION_WINDOW_CHUNKS + 1),
            ),
            propose(a, programs(3), u64::MAX),
        ],
    );
    assert_eq!((applied, failed), (0, 2));
    let (applied, _, status) = run(
        &live,
        &block(10),
        &[propose(
            a,
            programs(3),
            at(10 + UPGRADE_ACTIVATION_WINDOW_CHUNKS),
        )],
    );
    assert_eq!(applied, 1);
    let open = status.proposals[0].clone();
    live.insert(
        UPGRADE_PROPOSALS_KEY,
        borsh::to_vec(&status.proposals).unwrap(),
    );
    // Votes still count at the deadline; right after it the proposal takes
    // none and leaves its slot on the next write.
    let deadline = 10 + UPGRADE_VOTING_PERIOD_CHUNKS;
    let (applied, _, status) = run(&live, &block(deadline), &[vote(b, open.id())]);
    assert_eq!(applied, 1);
    assert!(status.scheduled.is_some());
    let (applied, failed, status) = run(
        &live,
        &block(deadline + 1),
        &[
            vote(b, open.id()),
            propose(b, programs(4), at(deadline + 3)),
        ],
    );
    assert_eq!((applied, failed), (1, 1));
    assert_eq!(
        status
            .proposals
            .iter()
            .map(proposed_programs)
            .collect::<Vec<_>>(),
        [Some(programs(4))]
    );
}

#[test]
fn young_registrations_neither_vote_nor_count_until_they_age() {
    use crate::{ValidatorRegistration, registration_key};

    let (old, young) = (address(1), address(2));
    // Equal stake: alone, `old` holds 100% of the eligible set.
    let mut live = live(&[(old, 50), (young, 50)]);
    let registration = ValidatorRegistration {
        address: young,
        bls_pubkey: [1; 48],
        pop_signature: [2; 96],
        registered_at_height: 0,
    };
    live.insert(
        &registration_key(&registration.address),
        borsh::to_vec(&registration).unwrap(),
    );
    // Before the registration ages the young validator cannot propose,
    // and the old one enacts alone because the denominator excludes it.
    let mut input = block(0);
    input.block_height = UPGRADE_VOTER_MIN_AGE_BLOCKS - 1;
    let (applied, failed, _) = run(&live, &input, &[propose(young, programs(2), at(3))]);
    assert_eq!((applied, failed), (0, 1));
    let (applied, _, status) = run(&live, &input, &[propose(old, programs(2), at(3))]);
    assert_eq!(applied, 1);
    assert!(status.scheduled.is_some());
    // Once aged, both count: the old validator alone holds only half.
    input.block_height = UPGRADE_VOTER_MIN_AGE_BLOCKS;
    let (applied, _, status) = run(&live, &input, &[propose(old, programs(2), at(3))]);
    assert_eq!(applied, 1);
    assert!(status.scheduled.is_none());
    assert_eq!(status.proposals.len(), 1);
}

fn low_stake_floor(live: &mut LiveTrie) {
    seed_policy(
        live,
        &RuntimePolicy {
            min_validator_stake: 1,
            ..RuntimePolicy::default()
        },
    );
}

#[test]
fn stake_cannot_mint_a_validator_that_governance_would_count() {
    let (honest, whale) = (address(1), address(2));
    let mut live = live(&[(honest, 100)]);
    low_stake_floor(&mut live);
    // Liquid balance only: no validator record and no registration.
    live.insert(
        &account_key(&whale),
        encode_account(&Account { balance: 1_000_000 }),
    );
    let (applied, failed, status) = run(
        &live,
        &block(0),
        &[stake(whale, 500_000), propose(whale, programs(2), at(1))],
    );
    assert_eq!((applied, failed), (0, 2));
    assert_eq!(status, UpgradeStatus::default());
}

#[test]
fn stake_added_to_a_validator_counts_in_governance_once_aged() {
    let (honest, whale) = (address(1), address(2));
    // Genesis validators; the whale holds a third of the stake.
    let mut live = live(&[(honest, 200), (whale, 100)]);
    low_stake_floor(&mut live);
    let mut bonding = block(0);
    bonding.block_height = 10;
    let (out, live) = apply_against(&live, &bonding, &[stake(whale, 500_000)]);
    assert_eq!(out.counts(), (1, 0));

    // Until the addition ages, the whale weighs only its genesis third.
    let mut young = block(0);
    young.block_height = 10 + UPGRADE_VOTER_MIN_AGE_BLOCKS - 1;
    let (applied, _, status) = run(&live, &young, &[propose(whale, programs(2), at(1))]);
    assert_eq!(applied, 1);
    assert!(status.scheduled.is_none());
    assert_eq!(status.proposals.len(), 1);

    let mut aged = young;
    aged.block_height += 1;
    let (applied, _, status) = run(&live, &aged, &[propose(whale, programs(2), at(1))]);
    assert_eq!(applied, 1);
    assert!(status.scheduled.is_some());
}

#[test]
fn an_unauthenticated_backend_cannot_propose_or_vote() {
    let a = address(1);
    let live = live(&[(a, 100)]);
    let input = block(0);
    let mut state = TracingState::new(&live);
    let policy = crate::load_runtime_policy(&mut state);
    for (_, action) in [
        propose(a, programs(2), at(1)),
        vote(a, [0; 32]),
        propose_policy(a, RuntimePolicy::default()),
    ] {
        assert_eq!(
            dispatch_with_policy(&mut state, &input, &action, &policy),
            Err(ReceiptStatus::Unauthorized)
        );
    }
    assert_eq!(status(&mut state), UpgradeStatus::default());
    assert_eq!(state.post_state_root(), live.state_root());
}

#[test]
fn only_weighted_unslashed_consensus_seats_govern() {
    // Runtime stake consensus has not seated answers to no consensus
    // offence, so it neither votes nor counts toward the denominator.
    let (alice, bob, mallory) = (address(1), address(2), address(5));
    let live = live(&[(alice, 40), (bob, 30), (mallory, 1_000)]);
    let (applied, failed, status) = run(&live, &block(0), &[propose(mallory, programs(7), at(1))]);
    assert_eq!((applied, failed), (0, 1));
    assert_eq!(status, UpgradeStatus::default());

    // Alice alone holds 40 of the 70 seated stake: no quorum yet.
    let (applied, _, status) = run(&live, &block(0), &[propose(alice, programs(7), at(1))]);
    assert_eq!(applied, 1);
    assert!(status.scheduled.is_none());

    // A slashed or zero-weight seat no longer counts: Bob's seat is
    // slashed, so Alice now holds every counted stake and enacts alone.
    let mut slashed = seat(bob);
    slashed.effective_stake = 0;
    let mut pending = seat(address(3));
    pending.effective_stake = 0;
    let input = block_with_seats(0, vec![seat(alice), slashed, pending]);
    let (applied, _, status) = run(&live, &input, &[propose(alice, programs(7), at(1))]);
    assert_eq!(applied, 1);
    assert!(status.scheduled.is_some());
}
