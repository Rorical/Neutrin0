use super::*;
use neutrin0_consensus_types::participation::{
    ParticipationAcknowledgement, ParticipationReport, acknowledgement_commitment,
};
use neutrin0_runtime_core::host::{LiveTrie, TracingState};

#[test]
fn batched_source_acknowledgements_match_individual_state_and_gas() {
    let live = LiveTrie::default();
    let mut input = crate::test_support::evidence_input();
    input.participation_acks = alloc::vec![
        ParticipationAcknowledgement {
            chunk_id: 0,
            identity: [3; 48],
            address: [1; 32]
        },
        ParticipationAcknowledgement {
            chunk_id: 0,
            identity: [4; 48],
            address: [2; 32]
        },
        ParticipationAcknowledgement {
            chunk_id: 1,
            identity: [3; 48],
            address: [1; 32]
        },
    ];
    let mut batched = TracingState::new(&live);
    let gas = apply_participation_acks(&mut batched, &input);
    let mut individual = TracingState::new(&live);
    let mut individual_gas = 0;
    for ack in &input.participation_acks {
        let mut one = input.clone();
        one.participation_acks = alloc::vec![ack.clone()];
        individual_gas += apply_participation_acks(&mut individual, &one);
    }
    assert_eq!(gas, individual_gas);
    assert_eq!(gas, 3 * GAS_PARTICIPATION_ACK);
    assert_eq!(batched.post_state_root(), individual.post_state_root());
    assert!(participation_acknowledged(&mut batched, 0, &[4; 48]));
    assert!(!participation_acknowledged(&mut batched, 1, &[4; 48]));
    let root = batched.post_state_root();
    // Replay still charges each authenticated input, with no second state effect.
    assert_eq!(apply_participation_acks(&mut batched, &input), gas);
    assert_eq!(batched.post_state_root(), root);
}

#[test]
fn positive_participation_survives_replay_and_only_protects_the_source_identity() {
    let mut input = crate::test_support::evidence_input();
    input.context.finalized.next_chunk_id = 1;
    input.evidence_anchor.chunk_id = 1;
    let address = [9; 32];
    input.participation = Some(ParticipationReport {
        chunk_id: 0,
        present: alloc::vec![address],
        absent: alloc::vec![address, address],
        absent_identities: alloc::vec![[3; 48], [4; 48]],
    });
    let live = LiveTrie::default();
    let mut trace = TracingState::new(&live);
    crate::test_support::run_block(&mut trace, &input, &[]);
    assert!(!liveness_eligible(&mut trace, 2, 0, &[4; 48], &address));
    let (post, _) = trace.into_committed_and_witness().unwrap();
    let post = LiveTrie::from_trie(post);
    input.context.finalized.next_chunk_id = 2;
    input.evidence_anchor.chunk_id = 2;
    input.participation = Some(ParticipationReport {
        chunk_id: 1,
        ..Default::default()
    });
    input.participation_acks = alloc::vec![ParticipationAcknowledgement {
        chunk_id: 0,
        identity: [4; 48],
        address
    }];
    let mut trace = TracingState::new(&post);
    let output = crate::test_support::run_block(&mut trace, &input, &[]);
    assert_ne!(
        acknowledgement_commitment(&input.participation_acks),
        acknowledgement_commitment(&[])
    );
    assert_eq!(output.system.gas, GAS_PARTICIPATION_ACK);
    assert!(!liveness_eligible(&mut trace, 3, 0, &[4; 48], &address));
    assert!(liveness_eligible(&mut trace, 3, 0, &[3; 48], &address));
    let (_, witness) = trace.into_committed_and_witness().unwrap();
    let mut guest = neutrin0_runtime_core::WitnessState::new(&witness).unwrap();
    let replayed = crate::test_support::run_block(&mut guest, &input, &[]);
    assert_eq!(replayed.system.gas, output.system.gas);
    assert_eq!(guest.post_state_root(), output.post_state_root);
}

#[test]
fn governance_cannot_erase_the_challenge_time_or_mandatory_gas_reserve() {
    let mut anchor = neutrin0_consensus_types::evidence::EvidenceAnchor {
        chunk_size: 1,
        ..Default::default()
    };
    let mut policy = RuntimePolicy {
        inactivity_leak_amount: 1,
        evidence_max_age_blocks: 2,
        ..Default::default()
    };
    assert!(!policy.is_valid_for(&anchor));
    policy.evidence_max_age_blocks = 3;
    assert!(policy.is_valid_for(&anchor));
    // The reserve includes one chunk's settlement payments and its chunk
    // prover escrow write (design 08).
    anchor.block_gas_limit = 777_899;
    assert!(!policy.is_valid_for(&anchor));
    anchor.block_gas_limit = 777_900;
    assert!(policy.is_valid_for(&anchor));
}
