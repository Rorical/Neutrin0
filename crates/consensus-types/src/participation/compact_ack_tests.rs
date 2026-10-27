use super::*;

fn vote(index: u32) -> ParticipationVote {
    ParticipationVote {
        data: crate::FinalityVoteData {
            chunk_id: 7,
            round: 3,
            chunk_hash: [9; 32],
            selection: [0; 32],
            phase: crate::FinalityVotePhase::Precommit,
        },
        validator_index: index,
        vote_signature: [u8::try_from(index).unwrap(); 96],
    }
}

#[test]
fn compact_wire_is_bounded_and_rejects_non_precommits() {
    let oversized = u32::try_from(MAX_PARTICIPATION_ACKS + 1)
        .unwrap()
        .to_le_bytes();
    assert_eq!(
        read_participation_votes(&mut oversized.as_slice())
            .unwrap_err()
            .kind(),
        borsh::io::ErrorKind::InvalidData
    );
    let votes = alloc::vec![vote(1), vote(2)];
    let bytes = borsh::to_vec(&votes).unwrap();
    assert_eq!(
        read_participation_votes(&mut bytes.as_slice()).unwrap(),
        votes
    );
    let mut wrong_phase = vote(1);
    wrong_phase.data.phase = crate::FinalityVotePhase::Prevote;
    let bytes = borsh::to_vec(&alloc::vec![wrong_phase]).unwrap();
    assert_eq!(
        read_participation_votes(&mut bytes.as_slice())
            .unwrap_err()
            .kind(),
        borsh::io::ErrorKind::InvalidData
    );
}

#[test]
fn tagged_vote_root_binds_the_compact_signed_payload_and_order() {
    let a = vote(1);
    let b = vote(2);
    let root = vote_lane_root(&[a.clone(), b.clone()]);
    let expected = neutrin0_primitives::merkle_root_from_hashes(alloc::vec![
        crate::evidence::commitment(&a),
        crate::evidence::commitment(&b),
    ]);
    assert_eq!(root, expected);
    assert_eq!(vote_lane_count(&[a.clone(), b.clone()]), 2);
    assert_ne!(root, vote_lane_root(&[b, a.clone()]));
    let mut changed = a.clone();
    changed.vote_signature[0] ^= 1;
    assert_ne!(vote_lane_root(&[a]), vote_lane_root(&[changed]));
    assert!(!vote_lane_is_bounded(&alloc::vec![
        vote(1);
        MAX_PARTICIPATION_ACKS + 1
    ]));
    assert!(vote_lane_is_bounded(&alloc::vec![
        vote(1);
        MAX_PARTICIPATION_ACKS
    ]));
    assert_eq!(vote_lane_bytes(&[]).unwrap(), 4);
}

#[test]
fn source_record_resolution_preserves_identity_scope_and_grace() {
    let signed = vote(0);
    let validator = Validator {
        pubkey: [3; 48],
        withdrawal_credentials: neutrin0_primitives::runtime_account([4; 20]),
        effective_stake: 1,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    };
    let resolved = acknowledgement_from_participation_vote(
        9,
        [9; 32],
        core::slice::from_ref(&validator),
        &signed,
    )
    .unwrap();
    assert_eq!(resolved.identity, validator.pubkey);
    assert_eq!(resolved.address, validator.withdrawal_credentials);
    assert_eq!(resolved.chunk_id, 7);
    for incoming in [7, 10] {
        assert!(
            acknowledgement_from_participation_vote(
                incoming,
                [9; 32],
                core::slice::from_ref(&validator),
                &signed
            )
            .is_none()
        );
    }
    assert!(
        acknowledgement_from_participation_vote(
            8,
            [8; 32],
            core::slice::from_ref(&validator),
            &signed
        )
        .is_none()
    );
    let mut slashed = validator;
    slashed.effective_stake = 0;
    assert!(acknowledgement_from_participation_vote(8, [9; 32], &[slashed], &signed).is_none());
    assert!(acknowledgement_from_participation_vote(8, [9; 32], &[], &signed).is_none());
}
