use super::*;
use neutrin0_consensus_types::FinalityVotePhase;
use neutrin0_crypto::bls::PublicKey;
use neutrin0_primitives::DOMAIN_PREVOTE;

const fn test_domain(chain_id: u64) -> ConsensusDomain {
    ConsensusDomain::new(chain_id, [9; 32])
}

#[test]
fn from_ikm_is_deterministic_for_same_input() {
    let ikm = [0x42_u8; 32];
    let p1 = ProposerKey::from_ikm(&ikm, 0).expect("derive");
    let p2 = ProposerKey::from_ikm(&ikm, 0).expect("derive");
    assert_eq!(p1.public_key_bytes(), p2.public_key_bytes());
    assert_eq!(p1.validator_index(), p2.validator_index());
}

#[test]
fn from_ikm_rejects_short_input() {
    // BLS KeyGen requires IKM >= 32 bytes.
    let err = ProposerKey::from_ikm(&[0; 16], 0).expect_err("short IKM");
    assert_eq!(err, ProposerKeyError::InvalidKeyMaterial);
}

#[test]
fn signature_is_deterministic_and_verifies() {
    let proposer = ProposerKey::from_ikm(&[0x77; 32], 3).expect("derive");
    let header_hash: Hash = [0xAB; 32];
    let sig1 = proposer.sign_proposer_message(test_domain(7), &header_hash);
    let sig2 = proposer.sign_proposer_message(test_domain(7), &header_hash);
    assert_eq!(sig1, sig2);

    let mut message = Vec::with_capacity(56);
    message.extend_from_slice(&DOMAIN_PROPOSER_SIG);
    message.extend_from_slice(&7_u64.to_le_bytes());
    message.extend_from_slice(&test_domain(7).chain_spec_hash);
    message.extend_from_slice(&header_hash);

    let pk = PublicKey::from_bytes(proposer.public_key_bytes()).expect("decode pk");
    let parsed = neutrin0_crypto::bls::Signature::from_bytes(&sig1).expect("decode sig");
    pk.verify(&message, &parsed).expect("verify");
}

#[test]
fn signature_binds_chain_id() {
    let proposer = ProposerKey::from_ikm(&[0x11; 32], 0).expect("derive");
    let header_hash: Hash = [0xCD; 32];
    let s1 = proposer.sign_proposer_message(test_domain(1), &header_hash);
    let s2 = proposer.sign_proposer_message(test_domain(2), &header_hash);
    assert_ne!(s1, s2);
}

#[test]
fn signature_binds_header_hash() {
    let proposer = ProposerKey::from_ikm(&[0x22; 32], 0).expect("derive");
    let s1 = proposer.sign_proposer_message(test_domain(1), &[0xCD; 32]);
    let s2 = proposer.sign_proposer_message(test_domain(1), &[0xCE; 32]);
    assert_ne!(s1, s2);
}

#[test]
fn finality_vote_signature_verifies_against_public_key() {
    let proposer = ProposerKey::from_ikm(&[0x33; 32], 0).expect("derive");
    let prevote_data = FinalityVoteData {
        chunk_id: 7,
        round: 0,
        chunk_hash: [0xAB; 32],
        selection: crate::bft_loop::fixture_selection(),
        phase: FinalityVotePhase::Prevote,
    };
    let sig_bytes = proposer.sign_finality_vote(test_domain(1), &prevote_data);

    let mut message = Vec::with_capacity(56);
    message.extend_from_slice(&DOMAIN_PREVOTE);
    message.extend_from_slice(&1_u64.to_le_bytes());
    message.extend_from_slice(&test_domain(1).chain_spec_hash);
    message.extend_from_slice(&borsh::to_vec(&prevote_data).expect("borsh encode is infallible"));

    let pk = PublicKey::from_bytes(proposer.public_key_bytes()).expect("decode pk");
    let parsed = Signature::from_bytes(&sig_bytes).expect("decode sig");
    pk.verify(&message, &parsed).expect("verify");
}

#[test]
fn finality_vote_signature_differs_by_phase() {
    let proposer = ProposerKey::from_ikm(&[0x44; 32], 0).expect("derive");
    let base = FinalityVoteData {
        chunk_id: 1,
        round: 0,
        chunk_hash: [0x99; 32],
        selection: crate::bft_loop::fixture_selection(),
        phase: FinalityVotePhase::Prevote,
    };
    let prevote_sig = proposer.sign_finality_vote(test_domain(1), &base);
    let precommit_sig = proposer.sign_finality_vote(
        test_domain(1),
        &FinalityVoteData {
            phase: FinalityVotePhase::Precommit,
            ..base
        },
    );
    assert_ne!(prevote_sig, precommit_sig);
}

#[test]
fn finality_vote_signature_binds_chunk_round_and_hash() {
    let proposer = ProposerKey::from_ikm(&[0x55; 32], 0).expect("derive");
    let base = FinalityVoteData {
        chunk_id: 1,
        round: 0,
        chunk_hash: [0x99; 32],
        selection: crate::bft_loop::fixture_selection(),
        phase: FinalityVotePhase::Prevote,
    };
    let s1 = proposer.sign_finality_vote(test_domain(1), &base);
    let s_chunk = proposer.sign_finality_vote(
        test_domain(1),
        &FinalityVoteData {
            chunk_id: 2,
            ..base
        },
    );
    let s_round =
        proposer.sign_finality_vote(test_domain(1), &FinalityVoteData { round: 1, ..base });
    let s_hash = proposer.sign_finality_vote(
        test_domain(1),
        &FinalityVoteData {
            chunk_hash: [0x77; 32],
            ..base
        },
    );
    assert_ne!(s1, s_chunk);
    assert_ne!(s1, s_round);
    assert_ne!(s1, s_hash);
}
