//! Reservation rule coverage over an in-memory journal.

use super::*;
use neutrin0_consensus_types::{
    AggregatedVote, NilVoteAttestation, NilVoteData, QuorumCertificate, RoundChange,
    VoteAttestation,
};
use neutrin0_storage::MemoryDatabase;

const ME: BlsPublicKey = [1; 48];

fn data(chunk_id: u64, round: u32, value: u8, phase: FinalityVotePhase) -> FinalityVoteData {
    FinalityVoteData {
        chunk_id,
        round,
        chunk_hash: [value; 32],
        selection: [0; 32],
        phase,
    }
}

fn quorum(round: u32, value: u8) -> QuorumCertificate {
    QuorumCertificate {
        data: data(0, round, value, FinalityVotePhase::Prevote),
        aggregate: AggregatedVote {
            aggregation_bits: neutrin0_primitives::BitVec::default(),
            signature: [0; 96],
        },
    }
}

fn vote(
    round: u32,
    value: u8,
    phase: FinalityVotePhase,
    unlock: Option<QuorumCertificate>,
) -> SignRequest {
    SignRequest::Vote(VoteAttestation {
        validator_index: 0,
        vote_signature: [0; 96],
        vote: data(0, round, value, phase),
        proof_acceptance: None,
        unlock_quorum: unlock,
        signature: [0; 96],
    })
}

fn nil(chunk_id: u64, round: u32) -> SignRequest {
    SignRequest::NilVote(NilVoteAttestation {
        validator_index: 0,
        vote: NilVoteData {
            chunk_id,
            round,
            phase: FinalityVotePhase::Prevote,
        },
        vote_signature: [0; 96],
        signature: [0; 96],
    })
}

fn round_change(chunk_id: u64, round: u32, validator_index: u32) -> SignRequest {
    SignRequest::RoundChange(RoundChange {
        chunk_id,
        round,
        validator_index,
        highest_quorum: None,
        signature: [0; 96],
    })
}

#[test]
fn one_message_per_position_and_never_an_earlier_round() {
    let mut journal = Journal::new(MemoryDatabase::new());
    let prevote = vote(2, 7, FinalityVotePhase::Prevote, None);
    assert_eq!(journal.reserve(&ME, &prevote), Ok(()));
    // The same request is signed again; another at its position is not,
    // nil or value alike.
    assert_eq!(journal.reserve(&ME, &prevote), Ok(()));
    assert_eq!(
        journal.reserve(&ME, &vote(2, 8, FinalityVotePhase::Prevote, None)),
        Err(Refusal::Conflict)
    );
    assert_eq!(journal.reserve(&ME, &nil(0, 2)), Err(Refusal::Conflict));
    assert_eq!(journal.reserve(&ME, &nil(0, 1)), Err(Refusal::Regression));
    assert_eq!(journal.reserve(&ME, &round_change(0, 3, 0)), Ok(()));
    assert_eq!(
        journal.reserve(&ME, &round_change(0, 3, 1)),
        Err(Refusal::Conflict)
    );
    // Another identity has its own positions.
    assert_eq!(
        journal.reserve(&[2; 48], &vote(2, 8, FinalityVotePhase::Prevote, None)),
        Ok(())
    );
}

#[test]
fn a_lock_yields_only_to_a_later_quorum_for_the_new_value() {
    let mut journal = Journal::new(MemoryDatabase::new());
    assert_eq!(
        journal.reserve(&ME, &vote(1, 7, FinalityVotePhase::Precommit, None)),
        Err(Refusal::Conflict)
    );
    assert_eq!(
        journal.reserve(
            &ME,
            &vote(1, 7, FinalityVotePhase::Precommit, Some(quorum(1, 7)))
        ),
        Ok(())
    );
    assert_eq!(
        journal.reserve(&ME, &vote(4, 8, FinalityVotePhase::Prevote, None)),
        Err(Refusal::Conflict)
    );
    // A quorum at the lock's round or for another value does not unlock.
    for unlock in [quorum(1, 8), quorum(3, 9)] {
        assert_eq!(
            journal.reserve(&ME, &vote(4, 8, FinalityVotePhase::Prevote, Some(unlock))),
            Err(Refusal::Conflict)
        );
    }
    assert_eq!(
        journal.reserve(&ME, &vote(4, 7, FinalityVotePhase::Prevote, None)),
        Ok(())
    );
    assert_eq!(
        journal.reserve(
            &ME,
            &vote(5, 8, FinalityVotePhase::Prevote, Some(quorum(3, 8)))
        ),
        Ok(())
    );
}

#[test]
fn headers_move_forward_and_old_chunks_leave_the_window() {
    let mut journal = Journal::new(MemoryDatabase::new());
    let header = |slot, parent| {
        SignRequest::Header(neutrin0_consensus_types::Header {
            height: slot,
            slot,
            parent_hash: [parent; 32],
            proposer_index: 0,
            vrf_proof: [0; 96],
            state_root: [0; 32],
            transactions_root: [0; 32],
            votes_root: [0; 32],
            da_root: [0; 32],
            runtime_extra: [0; 32],
            inputs_root: [0; 32],
            receipts_root: [0; 32],
            gas_used: 0,
            gas_limit: 0,
            timestamp: 0,
            signature: [0; 96],
        })
    };
    assert_eq!(journal.reserve(&ME, &header(5, 1)), Ok(()));
    assert_eq!(journal.reserve(&ME, &header(5, 1)), Ok(()));
    assert_eq!(journal.reserve(&ME, &header(5, 2)), Err(Refusal::Conflict));
    assert_eq!(
        journal.reserve(&ME, &header(4, 1)),
        Err(Refusal::Regression)
    );
    assert_eq!(journal.reserve(&ME, &header(6, 2)), Ok(()));

    assert_eq!(journal.reserve_at(&ME, &nil(3, 0), 1_000), Ok(()));
    assert_eq!(
        journal.reserve_at(&ME, &nil(3 + WINDOW + 1, 0), 1_001),
        Ok(())
    );
    assert_eq!(journal.reserve(&ME, &nil(3, 0)), Err(Refusal::Expired));
    assert!(
        journal
            .db
            .keys_from(Column::SigningJournal, &chunk_key(VOTE, &ME, 0), 8)
            .unwrap()
            .first()
            .is_some_and(|key| *key >= chunk_key(VOTE, &ME, 4))
    );
}

#[test]
fn a_far_future_request_cannot_move_the_window() {
    let mut journal = Journal::new(MemoryDatabase::new());
    assert_eq!(journal.reserve_at(&ME, &nil(10, 0), 1_000), Ok(()));
    assert_eq!(
        journal.reserve_at(&ME, &nil(u64::MAX, 0), 1_001),
        Err(Refusal::TooFarAhead)
    );
    assert_eq!(
        journal.reserve_at(&ME, &nil(10 + WINDOW + 100, 0), 1_010),
        Err(Refusal::TooFarAhead)
    );
    assert_eq!(journal.reserve_at(&ME, &nil(11, 0), 1_002), Ok(()));
    // A validator back from an outage is as far ahead as time allows.
    assert_eq!(journal.reserve_at(&ME, &nil(5_000, 0), 6_002), Ok(()));
}
