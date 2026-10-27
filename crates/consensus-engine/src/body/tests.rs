use super::*;
use crate::merkle::EMPTY_MERKLE_ROOT;
use neutrin0_consensus_types::{Body, FinalityVoteData, FinalityVotePhase};

#[test]
fn empty_body_roots_are_the_empty_lane_roots() {
    let body = Body::default();
    let roots = compute_body_roots(&body);
    // The transaction root counts its leaves, so even an empty list
    // commits its count.
    assert_eq!(
        roots.transactions_root,
        neutrin0_primitives::transactions_root(Vec::new())
    );
    assert_eq!(roots.votes_root, EMPTY_MERKLE_ROOT);
    assert_ne!(roots.da_root, EMPTY_MERKLE_ROOT);
}

#[test]
fn transactions_root_is_order_sensitive() {
    let body_a = Body {
        transactions: vec![vec![1, 2], vec![3, 4]],
        ..Body::default()
    };
    let body_b = Body {
        transactions: vec![vec![3, 4], vec![1, 2]],
        ..Body::default()
    };
    let roots_a = compute_body_roots(&body_a);
    let roots_b = compute_body_roots(&body_b);
    assert_ne!(roots_a.transactions_root, roots_b.transactions_root);
}

#[test]
fn counted_da_matches_guest_and_binds_lane_count_and_identity() {
    for transactions in [vec![], vec![vec![1]], vec![vec![1], vec![2; 129], vec![3]]] {
        let body = Body {
            transactions,
            ..Body::default()
        };
        assert_eq!(
            compute_body_roots(&body).da_root,
            neutrin0_prover_chunk::consensus::body_da_root(&body)
        );
    }
    let lanes = [(3, [7; 32]), (2, [8; 32]), (1, [9; 32]), (0, [0; 32])];
    let root = da_root_from_lane_roots(lanes);
    let mut wrong_count = lanes;
    wrong_count[0].0 += 1;
    assert_ne!(root, da_root_from_lane_roots(wrong_count));
    let mut swapped = lanes;
    swapped.swap(0, 1);
    assert_ne!(root, da_root_from_lane_roots(swapped));
}

#[test]
fn da_root_commits_to_the_vote_lane() {
    let body_a = Body {
        transactions: vec![vec![1, 2, 3]],
        ..Body::default()
    };
    let body_b = Body {
        participation_acks: vec![neutrin0_consensus_types::participation::ParticipationVote {
            data: FinalityVoteData {
                chunk_id: 1,
                round: 0,
                chunk_hash: [7; 32],
                selection: crate::bft_loop::fixture_selection(),
                phase: FinalityVotePhase::Precommit,
            },
            validator_index: 0,
            vote_signature: [9; 96],
        }],
        ..body_a.clone()
    };

    let roots_a = compute_body_roots(&body_a);
    let roots_b = compute_body_roots(&body_b);
    assert_ne!(roots_a.da_root, roots_b.da_root);
}
