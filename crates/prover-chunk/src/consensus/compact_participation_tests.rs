use super::*;
use crate::bls::{BatchVerifier, DirectVerifier};
use bls12_381::{G1Affine, G2Affine};
use neutrin0_consensus_types::{
    FinalityVoteData, FinalityVotePhase, participation::ParticipationVote,
};
use neutrin0_crypto::bls::SecretKey;
use neutrin0_primitives::ConsensusDomain;
use neutrin0_primitives::Validator;

fn source() -> Chunk {
    Chunk {
        chunk_id: 0,
        start_height: 1,
        end_height: 1,
        start_state_root: [1; 32],
        end_state_root: [2; 32],
        start_block_hash: [3; 32],
        end_block_hash: [3; 32],
        block_hash_root: [4; 32],
        block_proof_root: [5; 32],
        vrf_proof_root: [6; 32],
        active_validator_set_root: [7; 32],
        next_validator_set_root: [8; 32],
        next_identity_sanctions_root: [0; 32],
        da_root: [9; 32],
    }
}

fn member(pubkey: [u8; 48], account: u8) -> Validator {
    Validator {
        pubkey,
        withdrawal_credentials: neutrin0_primitives::runtime_account([account; 20]),
        effective_stake: 1,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }
}

fn signed() -> (ConsensusDomain, Chunk, Vec<Validator>, ParticipationVote) {
    let domain = ConsensusDomain::new(1, [10; 32]);
    let chunk = source();
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let data = FinalityVoteData {
        chunk_id: 0,
        round: 2,
        chunk_hash: chunk.hash(),
        selection: [0; 32],
        phase: FinalityVotePhase::Precommit,
    };
    let signature = key.sign(&data.signing_message(domain)).to_bytes();
    let validators = alloc::vec![member(key.public_key().to_bytes(), 1)];
    (
        domain,
        chunk,
        validators,
        ParticipationVote {
            data,
            validator_index: 0,
            vote_signature: signature,
        },
    )
}

#[test]
fn inverse_public_keys_keep_both_individually_valid_economic_claims() {
    let (domain, mut chunk, mut validators, first) = signed();
    let inverse = (-G1Affine::from_compressed(&validators[0].pubkey).unwrap()).to_compressed();
    validators.push(member(inverse, 2));
    chunk.active_validator_set_root = commitment(&validators);
    // Re-sign after binding the exact authenticated source committee.
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let data = FinalityVoteData {
        chunk_hash: chunk.hash(),
        selection: [0; 32],
        ..first.data
    };
    let signature = key.sign(&data.signing_message(domain)).to_bytes();
    let positive = ParticipationVote {
        data: data.clone(),
        validator_index: 0,
        vote_signature: signature,
    };
    let negative = ParticipationVote {
        data,
        validator_index: 1,
        vote_signature: (-G2Affine::from_compressed(&signature).unwrap()).to_compressed(),
    };
    let mut direct = DirectVerifier::default();
    let a = verify_participation_vote_using(domain, 2, &chunk, &validators, &positive, &mut direct)
        .unwrap();
    let b = verify_participation_vote_using(domain, 2, &chunk, &validators, &negative, &mut direct)
        .unwrap();
    assert_ne!(a.identity, b.identity);
    assert_ne!(a.address, b.address);
    let mut batch = BatchVerifier::default();
    assert!(
        verify_participation_vote_using(domain, 2, &chunk, &validators, &positive, &mut batch)
            .is_ok()
    );
    assert!(
        verify_participation_vote_using(domain, 2, &chunk, &validators, &negative, &mut batch)
            .is_ok()
    );
    assert!(batch.finish());
    let mut substituted = negative;
    substituted.vote_signature = positive.vote_signature;
    assert!(
        verify_participation_vote_using(domain, 2, &chunk, &validators, &substituted, &mut direct)
            .is_err()
    );
}

#[test]
fn bare_precommit_cannot_claim_another_source_domain_or_late_credit() {
    let (domain, chunk, validators, vote) = signed();
    let mut verifier = DirectVerifier::default();
    assert!(
        verify_participation_vote_using(domain, 1, &chunk, &validators, &vote, &mut verifier)
            .is_ok()
    );
    assert!(
        verify_participation_vote_using(domain, 3, &chunk, &validators, &vote, &mut verifier)
            .is_err()
    );
    let other_domain = ConsensusDomain {
        chain_spec_hash: [11; 32],
        ..domain
    };
    assert!(
        verify_participation_vote_using(other_domain, 1, &chunk, &validators, &vote, &mut verifier)
            .is_err()
    );
    let mut wrong = vote.clone();
    wrong.validator_index = 1;
    assert!(
        verify_participation_vote_using(domain, 1, &chunk, &validators, &wrong, &mut verifier)
            .is_err()
    );
    wrong = vote.clone();
    wrong.data.chunk_id = 1;
    assert!(
        verify_participation_vote_using(domain, 2, &chunk, &validators, &wrong, &mut verifier)
            .is_err()
    );
    wrong = vote.clone();
    wrong.data.phase = FinalityVotePhase::Prevote;
    assert!(
        verify_participation_vote_using(domain, 1, &chunk, &validators, &wrong, &mut verifier)
            .is_err()
    );
    wrong = vote;
    wrong.vote_signature = [0; 96];
    assert!(
        verify_participation_vote_using(domain, 1, &chunk, &validators, &wrong, &mut verifier)
            .is_err()
    );
}
