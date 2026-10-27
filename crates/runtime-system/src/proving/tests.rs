use super::*;
use crate::state::PARTICIPATION_KEY;
use neutrin0_consensus_types::participation::ParticipationReport;
use neutrin0_consensus_types::proving::ProvingEntry;
use neutrin0_consensus_types::runtime::{
    CONSENSUS_CANDIDATES_KEY, ConsensusCandidate, ConsensusCandidates, ConsensusExecutionContext,
};
use neutrin0_runtime_core::host::{LiveTrie, TracingState};

fn policy() -> RuntimePolicy {
    RuntimePolicy {
        chunk_prover_fee_bps: 1_000,
        annual_issuance_bps: 0,
        ..RuntimePolicy::default()
    }
}

fn at(slot: u64, timestamp: u64) -> ConsensusExecutionContext {
    ConsensusExecutionContext {
        slot,
        timestamp,
        ..ConsensusExecutionContext::default()
    }
}

fn participation(chunk_id: u64, present: &[Hash]) -> ParticipationReport {
    ParticipationReport {
        chunk_id,
        present: present.to_vec(),
        ..ParticipationReport::default()
    }
}

#[test]
fn base_fees_go_to_participants_and_the_chunk_prover_never_the_proposer() {
    let live = LiveTrie::default();
    let mut state = TracingState::new(&live);
    let (prover, a, b, absent) = ([2; 32], [3; 32], [4; 32], [5; 32]);
    let candidates = crate::load_consensus_candidates(&mut state);
    record_block_fees(&mut state, 5, &at(25, 100), 2_000, &policy(), &candidates);
    assert_eq!(
        read_record::<FeeEscrow, _>(&mut state, &escrow_fees_key(5)),
        Some(FeeEscrow {
            committee: 1_800,
            chunk_prover: 200,
            block_prover: 0,
        })
    );
    write_record(&mut state, PARTICIPATION_KEY, &participation(0, &[a, b]));
    let report = ProvingReport {
        chunk_id: 0,
        entries: alloc::vec![ProvingEntry { height: 5, prover }],
        committee: alloc::vec![(a, 1), (b, 3), (absent, 4)],
        chunk_provers: alloc::vec![],
    };
    let (commitment, gas) = apply_proving(&mut state, Some(&report));
    assert_eq!(commitment, report.commitment());
    // One prover payment, two participants and the chunk escrow write.
    assert_eq!(gas, 4 * GAS_SETTLEMENT_PAYMENT);
    // The absent member's stake does not dilute the participants.
    assert_eq!(load_account(&mut state, &a).balance, 450);
    assert_eq!(load_account(&mut state, &b).balance, 1_350);
    assert_eq!(load_account(&mut state, &absent).balance, 0);
    assert_eq!(load_account(&mut state, &prover).balance, 0);
    assert_eq!(
        read_record::<u128, _>(&mut state, &escrow_chunk_key(0)),
        Some(200)
    );
    assert!(read_record::<FeeEscrow, _>(&mut state, &escrow_fees_key(5)).is_none());

    // The same report repeats in every block of the consuming chunk and
    // settles once.
    let (again, gas) = apply_proving(&mut state, Some(&report));
    assert_eq!(again, report.commitment());
    assert_eq!(gas, 0);
    assert_eq!(load_account(&mut state, &b).balance, 1_350);
    // A later block before the next carrier commits the settled report.
    assert_eq!(apply_proving(&mut state, None), (report.commitment(), 0));
}

#[test]
fn wei_stakes_share_committee_fees_exactly() {
    let live = LiveTrie::default();
    let mut state = TracingState::new(&live);
    let (prover, a, b) = ([2; 32], [3; 32], [4; 32]);
    let fees = 1_000 * neutrin0_primitives::WEI_PER_TOKEN;
    let candidates = crate::load_consensus_candidates(&mut state);
    record_block_fees(&mut state, 5, &at(25, 100), fees, &policy(), &candidates);
    write_record(&mut state, PARTICIPATION_KEY, &participation(0, &[a, b]));
    // Fees times stake exceed `u128`; the shares are still exact.
    let bonded = 32 * neutrin0_primitives::WEI_PER_TOKEN;
    let report = ProvingReport {
        chunk_id: 0,
        entries: alloc::vec![ProvingEntry { height: 5, prover }],
        committee: alloc::vec![(a, bonded), (b, 3 * bonded)],
        chunk_provers: alloc::vec![],
    };
    apply_proving(&mut state, Some(&report));
    let committee = fees - share(fees, policy().chunk_prover_fee_bps);
    assert_eq!(load_account(&mut state, &a).balance, committee / 4);
    assert_eq!(load_account(&mut state, &b).balance, committee / 4 * 3);
}

#[test]
fn issuance_accrues_by_time_on_total_stake_and_splits_between_provers() {
    let live = LiveTrie::default();
    let mut state = TracingState::new(&live);
    let mut candidates = ConsensusCandidates::default();
    let bonded = 32 * neutrin0_primitives::WEI_PER_TOKEN;
    candidates.upsert(ConsensusCandidate {
        address: [9; 32],
        stake: bonded,
        identity: None,
    });
    write_record(&mut state, CONSENSUS_CANDIDATES_KEY, &candidates);
    let policy = RuntimePolicy {
        annual_issuance_bps: 200,
        chunk_prover_fee_bps: 0,
        ..RuntimePolicy::default()
    };
    // The first block only starts the clock.
    let candidates = crate::load_consensus_candidates(&mut state);
    record_block_fees(&mut state, 1, &at(1, 1_000), 0, &policy, &candidates);
    assert_eq!(
        read_record::<FeeEscrow, _>(&mut state, &escrow_fees_key(1)),
        Some(FeeEscrow::default())
    );
    // A whole year later two percent of the stake accrues, half each.
    let candidates = crate::load_consensus_candidates(&mut state);
    record_block_fees(
        &mut state,
        2,
        &at(2, 1_000 + SECONDS_PER_YEAR),
        0,
        &policy,
        &candidates,
    );
    assert_eq!(
        read_record::<FeeEscrow, _>(&mut state, &escrow_fees_key(2)),
        Some(FeeEscrow {
            committee: 0,
            chunk_prover: 320_000_000_000_000_000,
            block_prover: 320_000_000_000_000_000,
        })
    );
    assert_eq!(issuance_for(&policy, bonded, 4), 81_121_504_803);
    assert_eq!(
        issuance_for(&policy, bonded, 10 * SECONDS_PER_YEAR),
        640_000_000_000_000_000
    );
}

#[test]
fn a_block_after_a_long_gap_accrues_only_the_capped_slots() {
    let live = LiveTrie::default();
    let mut state = TracingState::new(&live);
    let mut candidates = ConsensusCandidates::default();
    let bonded = 32 * neutrin0_primitives::WEI_PER_TOKEN;
    candidates.upsert(ConsensusCandidate {
        address: [9; 32],
        stake: bonded,
        identity: None,
    });
    let policy = RuntimePolicy {
        annual_issuance_bps: 200,
        chunk_prover_fee_bps: 0,
        ..RuntimePolicy::default()
    };
    let issued = |state: &mut TracingState<'_>, height| {
        read_record::<FeeEscrow, _>(state, &escrow_fees_key(height))
            .map(|escrow| escrow.block_prover + escrow.chunk_prover)
    };
    record_block_fees(&mut state, 1, &at(10, 40), 0, &policy, &candidates);
    // Within the cap a gap accrues every second it spans.
    record_block_fees(&mut state, 2, &at(18, 72), 0, &policy, &candidates);
    assert_eq!(
        issued(&mut state, 2),
        Some(issuance_for(&policy, bonded, 32))
    );
    // A replacement 40 slots on accrues the capped eight.
    record_block_fees(&mut state, 3, &at(58, 232), 0, &policy, &candidates);
    assert_eq!(
        issued(&mut state, 3),
        Some(issuance_for(&policy, bonded, 32))
    );
}

#[test]
fn chunk_prover_share_is_escrowed_per_chunk_and_paid_on_ratification() {
    let live = LiveTrie::default();
    let mut state = TracingState::new(&live);
    let (prover, a, c, d) = ([2; 32], [3; 32], [5; 32], [6; 32]);
    // Chunk 2's settlement left its chunk prover share in escrow.
    write_record(&mut state, &escrow_chunk_key(2), &40_u128);
    write_record(
        &mut state,
        &escrow_fees_key(10),
        &FeeEscrow {
            committee: 0,
            chunk_prover: 200,
            block_prover: 7,
        },
    );
    write_record(&mut state, PARTICIPATION_KEY, &participation(3, &[a]));
    let report = ProvingReport {
        chunk_id: 3,
        entries: alloc::vec![ProvingEntry { height: 10, prover }],
        committee: alloc::vec![(a, 1), (prover, 1)],
        chunk_provers: alloc::vec![(2, c)],
    };
    let (_, gas) = apply_proving(&mut state, Some(&report));
    // One block prover payment, one participant, one chunk prover and
    // the new chunk escrow.
    assert_eq!(gas, 4 * GAS_SETTLEMENT_PAYMENT);
    assert_eq!(load_account(&mut state, &prover).balance, 7);
    assert_eq!(
        read_record::<u128, _>(&mut state, &escrow_chunk_key(3)),
        Some(200)
    );
    // Chunk 2's ratified prover takes its escrow.
    assert_eq!(load_account(&mut state, &c).balance, 40);
    assert_eq!(
        read_record::<u128, _>(&mut state, &escrow_chunk_key(2)),
        None
    );

    // The next report ratifies chunk 3; a chunk without fees escrows
    // nothing for its own prover.
    write_record(&mut state, &escrow_fees_key(20), &FeeEscrow::default());
    write_record(&mut state, PARTICIPATION_KEY, &participation(4, &[a]));
    let next = ProvingReport {
        chunk_id: 4,
        entries: alloc::vec![ProvingEntry { height: 20, prover }],
        committee: alloc::vec![(a, 1), (prover, 1)],
        chunk_provers: alloc::vec![(3, d)],
    };
    let (_, gas) = apply_proving(&mut state, Some(&next));
    assert_eq!(gas, 3 * GAS_SETTLEMENT_PAYMENT);
    assert_eq!(load_account(&mut state, &d).balance, 200);
    assert_eq!(
        read_record::<u128, _>(&mut state, &escrow_chunk_key(3)),
        None
    );
    assert_eq!(
        read_record::<u128, _>(&mut state, &escrow_chunk_key(4)),
        None
    );
}

#[test]
fn a_certificate_without_participants_issues_no_committee_share() {
    let live = LiveTrie::default();
    let mut state = TracingState::new(&live);
    let (prover, a) = ([2; 32], [3; 32]);
    let candidates = crate::load_consensus_candidates(&mut state);
    record_block_fees(&mut state, 1, &at(0, 0), 1_000, &policy(), &candidates);
    let report = ProvingReport {
        chunk_id: 0,
        entries: alloc::vec![ProvingEntry { height: 1, prover }],
        committee: alloc::vec![(a, 10)],
        chunk_provers: alloc::vec![],
    };
    apply_proving(&mut state, Some(&report));
    assert_eq!(load_account(&mut state, &a).balance, 0);
    assert_eq!(load_account(&mut state, &prover).balance, 0);
}

#[test]
fn shares_are_floor_basis_points() {
    assert_eq!(share(2_500, 1_000), 250);
    assert_eq!(share(9, 5_000), 4);
    assert_eq!(share(u128::MAX, 10_000), u128::MAX);
}
