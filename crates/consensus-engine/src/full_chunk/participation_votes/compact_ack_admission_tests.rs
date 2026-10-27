use super::*;
use neutrin0_consensus_types::{
    Body, FinalityVoteData, FinalityVotePhase,
    participation::{
        MAX_PARTICIPATION_ACKS, MAX_PARTICIPATION_VOTE_BYTES, ParticipationVote, vote_lane_bytes,
    },
};

fn compact(index: u32) -> ParticipationVote {
    ParticipationVote {
        data: FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: [1; 32],
            selection: crate::bft_loop::fixture_selection(),
            phase: FinalityVotePhase::Precommit,
        },
        validator_index: index,
        vote_signature: [2; 96],
    }
}

#[test]
fn compact_admission_reserves_inherited_bytes_and_preserves_each_signature() {
    let mut body = Body::default();
    let first = compact(0);
    let second = compact(1);
    let one = borsh::object_length(&first).unwrap();
    let inherited = MAX_PARTICIPATION_VOTE_BYTES - vote_lane_bytes(&[]).unwrap() - one;
    admit_participation_votes(
        &mut body,
        alloc::vec![first.clone(), second.clone()],
        inherited,
    )
    .unwrap();
    assert_eq!(body.participation_acks, alloc::vec![first]);
    assert_eq!(
        vote_lane_bytes(&body.participation_acks).unwrap() + inherited,
        MAX_PARTICIPATION_VOTE_BYTES
    );
    let prior = body.clone();
    admit_participation_votes(&mut body, alloc::vec![second], inherited).unwrap();
    assert_eq!(body, prior);
}

#[test]
fn compact_admission_obeys_count_and_fails_atomically_on_existing_overflow() {
    let mut body = Body {
        participation_acks: alloc::vec![compact(0); MAX_PARTICIPATION_ACKS],
        ..Default::default()
    };
    let prior = body.clone();
    admit_participation_votes(&mut body, alloc::vec![compact(1)], 0).unwrap();
    assert_eq!(body, prior);
    assert!(
        admit_participation_votes(
            &mut body,
            alloc::vec![compact(1)],
            MAX_PARTICIPATION_VOTE_BYTES
        )
        .is_err()
    );
    assert_eq!(body, prior);
    body.participation_acks.push(compact(1));
    let oversized = body.clone();
    assert!(admit_participation_votes(&mut body, Vec::new(), 0).is_err());
    assert_eq!(body, oversized);
}
