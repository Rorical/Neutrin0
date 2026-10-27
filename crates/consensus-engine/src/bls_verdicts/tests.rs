use super::*;
use neutrin0_consensus_types::{
    AggregatedVote, FinalityVote, FinalityVoteData, FinalityVotePhase, QuorumCertificate,
};
use neutrin0_crypto::bls::{SecretKey, aggregate_signatures};
use neutrin0_primitives::{BitVec, ConsensusDomain, ConsensusParams, Validator};

const DOMAIN: ConsensusDomain = ConsensusDomain::new(7, [9; 32]);

fn secret(index: u8) -> SecretKey {
    SecretKey::key_gen(&[42 + index; 32], &[]).unwrap()
}

/// Seats weigh 2:2:1, so the signers `{0, 1}` (4/5) hold strictly more than
/// two thirds.
fn validators() -> Vec<Validator> {
    (0..3)
        .map(|index| Validator {
            pubkey: secret(index).public_key().to_bytes(),
            withdrawal_credentials: [0; 32],
            effective_stake: if index == 2 { 1 } else { 2 },
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect()
}

fn vote() -> FinalityVote {
    let data = FinalityVoteData {
        chunk_id: 0,
        chunk_hash: [7; 32],
        selection: crate::bft_loop::fixture_selection(),
        round: 1,
        phase: FinalityVotePhase::Prevote,
    };
    let signatures: Vec<_> = (0..2)
        .map(|index| {
            secret(index).sign(&crate::slashing::finality_vote_signed_message(
                DOMAIN, &data,
            ))
        })
        .collect();
    FinalityVote {
        proof_manifests: Vec::new(),
        attestations: (0..2)
            .map(|index| {
                crate::ProposerKey::from_ikm(&[42 + index; 32], u32::from(index))
                    .unwrap()
                    .attest_vote(DOMAIN, data.clone(), Vec::new(), None)
            })
            .collect(),
        data,
        aggregation_bits: BitVec::from_bytes(3, vec![3]).unwrap(),
        signature: aggregate_signatures(&signatures.iter().collect::<Vec<_>>())
            .unwrap()
            .to_bytes(),
    }
}

#[test]
fn exact_equations_bind_keys_messages_signatures_operations_and_cipher_suites() {
    let key = secret(0).public_key().to_bytes();
    let other = secret(1).public_key().to_bytes();
    let signature = secret(0).sign(b"first").to_bytes();
    let mut verifier = NativeBlsVerifier::default();
    assert!(verifier.verify(&key, b"first", &signature));
    assert!(verifier.verify(&key, b"first", &signature));
    assert_eq!(verifier.checks, 1);
    assert!(!verifier.verify(&other, b"first", &signature));
    assert!(!verifier.verify(&key, b"second", &signature));
    assert!(!verifier.verify(&key, b"first", &secret(1).sign(b"first").to_bytes()));
    assert_eq!(verifier.checks, 4);
    assert!(verifier.aggregate(&[key], b"first", &signature));
    assert_eq!(
        verifier.checks, 5,
        "single and aggregate operations are distinct"
    );

    let signatures = [secret(0).sign(b"both"), secret(1).sign(b"both")];
    let aggregate = aggregate_signatures(&signatures.iter().collect::<Vec<_>>())
        .unwrap()
        .to_bytes();
    assert!(verifier.aggregate(&[key, other], b"both", &aggregate));
    assert!(verifier.aggregate(&[key, other], b"both", &aggregate));
    assert_eq!(verifier.checks, 6);
    assert!(verifier.aggregate(&[other, key], b"both", &aggregate));
    assert_eq!(
        verifier.checks, 7,
        "ordered lists have distinct cache identities"
    );
    assert!(!verifier.aggregate(&[key], b"both", &aggregate));
    assert!(!verifier.aggregate(&[key, key], b"both", &aggregate));
    assert!(!verifier.aggregate(&[], b"both", &aggregate));

    let pop = secret(0).prove_possession().to_bytes();
    assert!(verifier.pop(&key, &pop));
    assert!(!verifier.verify(&key, &key, &pop));
    assert!(!verifier.pop(&key, &secret(0).sign(&key).to_bytes()));
    let before_retry = verifier.checks;
    assert!(!verifier.verify(&key, &key, &pop));
    assert_eq!(
        verifier.checks, before_retry,
        "an exact negative equation is reusable"
    );
    let mut identity_key = [0; 48];
    identity_key[0] = 0xc0;
    let mut identity_signature = [0; 96];
    identity_signature[0] = 0xc0;
    assert!(!verifier.verify(&identity_key, b"first", &signature));
    assert!(!verifier.verify(&key, b"first", &identity_signature));
}

#[test]
fn native_verdicts_match_portable_checked_verification_for_adversarial_points() {
    let key = secret(0).public_key().to_bytes();
    let signature = secret(0).sign(b"message").to_bytes();
    let mut identity_key = [0; 48];
    identity_key[0] = 0xc0;
    let mut identity_signature = [0; 96];
    identity_signature[0] = 0xc0;
    // Compressed x=0 on G1 is a curve point of order three, outside its subgroup.
    let mut torsion_key = [0; 48];
    torsion_key[0] = 0x80;
    let mut negated_key = key;
    negated_key[0] ^= 0x20;
    let mut negated_signature = signature;
    negated_signature[0] ^= 0x20;
    let mut native = NativeBlsVerifier::default();
    let mut portable = neutrin0_prover_chunk::bls::DirectVerifier::default();
    for (key, message, signature) in [
        (key, b"message".as_slice(), signature),
        (key, b"wrong".as_slice(), signature),
        (identity_key, b"message".as_slice(), signature),
        (torsion_key, b"message".as_slice(), signature),
        ([0; 48], b"message".as_slice(), signature),
        (key, b"message".as_slice(), identity_signature),
        (key, b"message".as_slice(), [0; 96]),
    ] {
        assert_eq!(
            native.verify(&key, message, &signature),
            portable.verify(&key, message, &signature),
        );
    }
    let cancelled = aggregate_signatures(&[
        &Signature::from_bytes(&signature).unwrap(),
        &Signature::from_bytes(&negated_signature).unwrap(),
    ])
    .unwrap()
    .to_bytes();
    for keys in [
        vec![key],
        vec![],
        vec![key, negated_key],
        vec![key, torsion_key],
    ] {
        for signature in [signature, cancelled] {
            assert_eq!(
                native.aggregate(&keys, b"message", &signature),
                portable.aggregate(&keys, b"message", &signature),
            );
        }
    }
    let pop = secret(0).prove_possession().to_bytes();
    for (key, pop) in [
        (key, pop),
        (key, signature),
        (identity_key, pop),
        (torsion_key, pop),
    ] {
        assert_eq!(native.pop(&key, &pop), portable.pop(&key, &pop));
    }
}

#[test]
fn cached_signatures_recheck_coverage_active_membership_and_all_signed_fields() {
    let validators = validators();
    let vote = vote();
    let params = ConsensusParams::default();
    let mut verifier = NativeBlsVerifier::default();
    let check =
        |validators: &[Validator], vote: &FinalityVote, verifier: &mut NativeBlsVerifier| {
            neutrin0_prover_chunk::finality::verify_vote_signatures_using(
                DOMAIN, validators, vote, &params, verifier,
            )
        };
    check(&validators, &vote, &mut verifier).unwrap();
    let first_checks = verifier.checks;
    check(&validators, &vote, &mut verifier).unwrap();
    assert_eq!(verifier.checks, first_checks);
    {
        let mut inactive = validators.clone();
        inactive[0].effective_stake = 0;
        assert!(check(&inactive, &vote, &mut verifier).is_err());
    }
    let mut missing = vote.clone();
    missing.attestations.pop();
    assert!(check(&validators, &missing, &mut verifier).is_err());
    let mut duplicate = vote.clone();
    duplicate.attestations[1] = duplicate.attestations[0].clone();
    assert!(check(&validators, &duplicate, &mut verifier).is_err());
    let mut altered = vote.clone();
    altered.data.chunk_hash[0] ^= 1;
    for claim in &mut altered.attestations {
        claim.vote.clone_from(&altered.data);
    }
    assert!(check(&validators, &altered, &mut verifier).is_err());
    assert!(
        neutrin0_prover_chunk::finality::verify_vote_signatures_using(
            ConsensusDomain {
                chain_id: 8,
                ..DOMAIN
            },
            &validators,
            &vote,
            &params,
            &mut verifier,
        )
        .is_err()
    );
    let mut claim = vote.clone();
    claim.attestations[0].unlock_quorum = Some(QuorumCertificate {
        data: vote.data.clone(),
        aggregate: AggregatedVote {
            aggregation_bits: vote.aggregation_bits.clone(),
            signature: vote.signature,
        },
    });
    assert!(check(&validators, &claim, &mut verifier).is_err());
}

#[test]
fn cached_quorums_recheck_stake_threshold_and_strict_unlock_target_and_round() {
    use neutrin0_prover_chunk::slashing::{verify_quorum_using, verify_unlock_using};
    let validators = validators();
    let vote = vote();
    let quorum = QuorumCertificate {
        data: vote.data.clone(),
        aggregate: AggregatedVote {
            aggregation_bits: vote.aggregation_bits,
            signature: vote.signature,
        },
    };
    let mut verifier = NativeBlsVerifier::default();
    verify_quorum_using(DOMAIN, &validators, &quorum, (2, 3), &mut verifier).unwrap();
    let mut target = quorum.data.clone();
    target.round += 1;
    verify_unlock_using(DOMAIN, &validators, &target, &quorum, (2, 3), &mut verifier).unwrap();
    assert_eq!(verifier.checks, 1);
    assert!(verify_quorum_using(DOMAIN, &validators, &quorum, (1, 1), &mut verifier).is_err());
    let mut heavier = validators.clone();
    heavier[2].effective_stake = 10;
    assert!(verify_quorum_using(DOMAIN, &heavier, &quorum, (2, 3), &mut verifier).is_err());
    {
        let mut inactive = validators.clone();
        inactive[0].effective_stake = 0;
        assert!(verify_quorum_using(DOMAIN, &inactive, &quorum, (2, 3), &mut verifier).is_err());
    }
    target.round = quorum.data.round;
    assert!(
        verify_unlock_using(DOMAIN, &validators, &target, &quorum, (2, 3), &mut verifier).is_err()
    );
    target.round += 1;
    target.chunk_hash[0] ^= 1;
    assert!(
        verify_unlock_using(DOMAIN, &validators, &target, &quorum, (2, 3), &mut verifier).is_err()
    );
    target.chunk_hash = quorum.data.chunk_hash;
    target.chunk_id += 1;
    assert!(
        verify_unlock_using(DOMAIN, &validators, &target, &quorum, (2, 3), &mut verifier).is_err()
    );
    assert_eq!(
        verifier.checks, 1,
        "cached positive cannot bypass policy rejection"
    );
}

#[test]
fn verdict_retention_is_fifo_and_repeated_hits_do_not_pin_entries() {
    let key = secret(0).public_key().to_bytes();
    let signature = secret(0).sign(b"first").to_bytes();
    let mut verifier = NativeBlsVerifier::default();
    assert!(verifier.verify(&key, b"first", &signature));
    for index in 1..MAX_VERDICTS {
        verifier.remember(neutrin0_primitives::blake3_256(&index.to_le_bytes()), false);
    }
    assert!(verifier.verify(&key, b"first", &signature));
    assert_eq!(verifier.checks, 1);
    verifier.remember([0xff; 32], false);
    assert_eq!(verifier.verdicts.len(), MAX_VERDICTS);
    assert_eq!(verifier.order.len(), MAX_VERDICTS);
    assert!(verifier.verify(&key, b"first", &signature));
    assert_eq!(
        verifier.checks, 2,
        "evicted verdicts require native verification again"
    );
    assert_eq!(verifier.verdicts.len(), MAX_VERDICTS);
}
