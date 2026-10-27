use super::*;
use alloc::vec;
use alloc::vec::Vec;
use neutrin0_consensus_types::AggregatedVote;
use neutrin0_consensus_types::{LockEvidence, QuorumCertificate};
use neutrin0_primitives::ConsensusParams;
use neutrin0_primitives::{BitVec, BlsPublicKey, BlsSignature, ConsensusDomain};

const DOMAIN: ConsensusDomain = ConsensusDomain::new(1, [4; 32]);

fn signing_context() -> (Vec<neutrin0_crypto::bls::SecretKey>, Vec<Validator>) {
    let keys: Vec<_> = (1..=3)
        .map(|byte| neutrin0_crypto::bls::SecretKey::key_gen(&[byte; 32], &[]).unwrap())
        .collect();
    let validators = keys
        .iter()
        .zip([2, 1, 1])
        .map(|(key, stake)| Validator {
            pubkey: key.public_key().to_bytes(),
            withdrawal_credentials: [0; 32],
            effective_stake: stake,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect();
    (keys, validators)
}

fn signed_quorum(
    keys: &[neutrin0_crypto::bls::SecretKey],
    positions: &[usize],
    data: FinalityVoteData,
) -> QuorumCertificate {
    let message = data.signing_message(DOMAIN);
    let signatures: Vec<_> = positions
        .iter()
        .map(|index| keys[*index].sign(&message))
        .collect();
    let mut bits = BitVec::default();
    for index in 0..keys.len() {
        bits.push(positions.contains(&index));
    }
    QuorumCertificate {
        data,
        aggregate: AggregatedVote {
            aggregation_bits: bits,
            signature: neutrin0_crypto::bls::aggregate_signatures(
                &signatures.iter().collect::<Vec<_>>(),
            )
            .unwrap()
            .to_bytes(),
        },
    }
}

fn signed_claim(
    key: &neutrin0_crypto::bls::SecretKey,
    vote: FinalityVoteData,
    unlock: Option<QuorumCertificate>,
) -> VoteAttestation {
    let mut claim = VoteAttestation {
        vote_signature: key.sign(&vote.signing_message(DOMAIN)).to_bytes(),
        validator_index: 0,
        vote,
        proof_acceptance: None,
        unlock_quorum: unlock,
        signature: [0; 96],
    };
    claim.signature = key.sign(&claim.signing_message(DOMAIN)).to_bytes();
    claim
}

#[test]
fn compact_unlock_binding_preserves_distinct_valid_weighted_subsets() {
    let (keys, validators) = signing_context();
    let source = FinalityVoteData {
        chunk_id: 1,
        round: 1,
        chunk_hash: [2; 32],
        selection: [0; 32],
        phase: FinalityVotePhase::Prevote,
    };
    let first = signed_quorum(&keys, &[0, 1], source.clone());
    let alternate = signed_quorum(&keys, &[0, 2], source.clone());
    verify_quorum(DOMAIN, &validators, &first, (2, 3)).unwrap();
    verify_quorum(DOMAIN, &validators, &alternate, (2, 3)).unwrap();
    assert_ne!(first.commitment(), alternate.commitment());
    // Two signatures with only half of the stake cannot become a quorum.
    let insufficient = signed_quorum(&keys, &[1, 2], source.clone());
    assert_eq!(
        verify_quorum(DOMAIN, &validators, &insufficient, (2, 3)),
        Err(EvidenceError::Quorum)
    );
    let later = FinalityVoteData { round: 2, ..source };
    let claim = signed_claim(&keys[0], later.clone(), Some(first));
    verify_attestation(DOMAIN, &validators, 0, &later, &claim).unwrap();
    let mut substituted = claim;
    substituted.unlock_quorum = Some(alternate);
    assert_eq!(
        verify_attestation(DOMAIN, &validators, 0, &later, &substituted),
        Err(EvidenceError::Signature)
    );
    substituted.signature = keys[0]
        .sign(&substituted.signing_message(DOMAIN))
        .to_bytes();
    verify_attestation(DOMAIN, &validators, 0, &later, &substituted).unwrap();
    let encoded = borsh::to_vec(&neutrin0_consensus_types::FinalityVote {
        aggregation_bits: BitVec::from_bytes(3, vec![1]).unwrap(),
        data: later,
        signature: substituted.vote_signature,
        attestations: vec![substituted],
        proof_manifests: Vec::new(),
    })
    .unwrap();
    let decoded: neutrin0_consensus_types::FinalityVote = borsh::from_slice(&encoded).unwrap();
    crate::finality::verify_vote(
        DOMAIN,
        &validators,
        &decoded,
        &ConsensusParams {
            chunk_size: 1,
            ..ConsensusParams::default()
        },
    )
    .unwrap();
}

#[test]
fn compact_carriers_do_not_relax_strict_lock_unlock_rounds() {
    let (keys, validators) = signing_context();
    let locked_data = FinalityVoteData {
        chunk_id: 1,
        round: 1,
        chunk_hash: [2; 32],
        selection: [0; 32],
        phase: FinalityVotePhase::Prevote,
    };
    let locked = signed_quorum(&keys, &[0, 1], locked_data.clone());
    let first_data = FinalityVoteData {
        phase: FinalityVotePhase::Precommit,
        ..locked_data
    };
    let first = IndexedVote {
        signature: keys[0].sign(&first_data.signing_message(DOMAIN)).to_bytes(),
        data: first_data,
    };
    let later_data = FinalityVoteData {
        chunk_id: 1,
        round: 3,
        chunk_hash: [3; 32],
        selection: [0; 32],
        phase: FinalityVotePhase::Prevote,
    };
    let later = IndexedVote {
        signature: keys[0].sign(&later_data.signing_message(DOMAIN)).to_bytes(),
        data: later_data.clone(),
    };
    let earlier_unlock = signed_quorum(
        &keys,
        &[0, 2],
        FinalityVoteData {
            round: 2,
            ..later_data
        },
    );
    let honest = LockEvidence {
        locked_prevote_quorum: locked.clone(),
        attestation: signed_claim(&keys[0], later_data.clone(), Some(earlier_unlock)),
    };
    assert_eq!(
        verify_lock_violation(DOMAIN, &validators, 0, (&first, &later), &honest, (2, 3)),
        Err(EvidenceError::HonestUnlock)
    );
    let circular = signed_quorum(&keys, &[0, 2], later_data.clone());
    let violation = LockEvidence {
        locked_prevote_quorum: locked,
        attestation: signed_claim(&keys[0], later_data, Some(circular)),
    };
    let encoded = borsh::to_vec(&violation).unwrap();
    let decoded: LockEvidence = borsh::from_slice(&encoded).unwrap();
    verify_lock_violation(DOMAIN, &validators, 0, (&first, &later), &decoded, (2, 3)).unwrap();
}

#[derive(Default)]
struct Counting {
    aggregates: usize,
}

impl crate::bls::Verifier for Counting {
    fn verify(&mut self, _: &BlsPublicKey, _: &[u8], _: &BlsSignature) -> bool {
        true
    }
    fn aggregate(&mut self, _: &[BlsPublicKey], _: &[u8], _: &BlsSignature) -> bool {
        self.aggregates += 1;
        true
    }
    fn pop(&mut self, _: &BlsPublicKey, _: &BlsSignature) -> bool {
        true
    }
}

const fn validators() -> [Validator; 1] {
    [Validator {
        pubkey: [1; 48],
        withdrawal_credentials: neutrin0_primitives::runtime_account([1; 20]),
        effective_stake: 1,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }]
}

fn check<'a>(
    quorum: &'a QuorumCertificate,
    fraction: (u64, u64),
    verifier: &mut Counting,
    quorums: &mut VerifiedQuorums<'a>,
) -> Result<(), EvidenceError> {
    verify_quorum_with(DOMAIN, &validators(), quorum, fraction, verifier, quorums)
}

#[test]
fn verified_quorums_skip_only_exact_repeats_under_one_fraction() {
    let mut bits = BitVec::default();
    bits.push(true);
    let data = FinalityVoteData {
        chunk_id: 1,
        round: 0,
        chunk_hash: [2; 32],
        selection: [0; 32],
        phase: FinalityVotePhase::Prevote,
    };
    let quorum = QuorumCertificate {
        data: data.clone(),
        aggregate: AggregatedVote {
            aggregation_bits: bits,
            signature: [3; 96],
        },
    };
    let mut later = quorum.clone();
    later.data.round = 1;
    let mut verifier = Counting::default();
    let mut quorums = VerifiedQuorums::new((2, 3));
    for _ in 0..3 {
        check(&quorum, (2, 3), &mut verifier, &mut quorums).unwrap();
    }
    assert_eq!(verifier.aggregates, 1);
    check(&later, (2, 3), &mut verifier, &mut quorums).unwrap();
    assert_eq!(verifier.aggregates, 2);
    // Another fraction bypasses the cache instead of reusing its verdicts.
    check(&quorum, (3, 4), &mut verifier, &mut quorums).unwrap();
    assert_eq!(verifier.aggregates, 3);
    // A cached QC still fails its carrier's own unlock binding.
    assert_eq!(
        verify_unlock_with(
            DOMAIN,
            &validators(),
            &data,
            &quorum,
            (2, 3),
            &mut verifier,
            &mut quorums,
        ),
        Err(EvidenceError::Binding)
    );
}
