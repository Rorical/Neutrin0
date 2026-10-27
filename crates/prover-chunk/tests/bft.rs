//! Round leader, explicit nil and authenticated pacemaker adversarial checks.

#[allow(unreachable_pub)]
mod support;

use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::{
    BftProposal, FinalityVotePhase, NilVote, NilVoteAttestation, NilVoteData, RoundChange,
    RoundChangeCertificate, bft_leader,
};
use neutrin0_crypto::bls::{SecretKey, aggregate_signatures};
use neutrin0_primitives::{BitVec, Validator};
use neutrin0_prover_chunk::{bft, consensus::as_chunk, finality::FinalityError};

fn test_domain() -> neutrin0_primitives::ConsensusDomain {
    support::fixture([1; 8], [4; 32])
        .0
        .chain_spec
        .consensus_domain()
}

fn validators() -> (Vec<SecretKey>, Vec<Validator>) {
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let template = &input.context.active_validators[0];
    let keys: Vec<_> = (10..14)
        .map(|byte| SecretKey::key_gen(&[byte; 32], &[]).unwrap())
        .collect();
    let validators = keys
        .iter()
        .enumerate()
        .map(|(index, key)| Validator {
            pubkey: key.public_key().to_bytes(),
            withdrawal_credentials: neutrin0_primitives::runtime_account(
                [u8::try_from(index).unwrap(); 20],
            ),
            effective_stake: 100,
            ..template.clone()
        })
        .collect();
    (keys, validators)
}

fn proposal(round: u32) -> BftProposal {
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let (keys, validators) = validators();
    let mut chunk = as_chunk(
        &neutrin0_prover_chunk::consensus::validate_candidate(&input)
            .unwrap()
            .execution
            .chunk,
    );
    chunk.active_validator_set_root = commitment(&validators);
    let leader = bft_leader(7, chunk.chunk_id, round, &SEED, &validators).unwrap();
    let mut proposal = BftProposal {
        chunk,
        round,
        proposer_index: leader,
        valid_quorum: None,
        round_change_certificate: None,
        proposal_slot: input.blocks.last().map_or(0, |block| block.header.slot),
        receipts: input
            .blocks
            .iter()
            .map(|block| neutrin0_consensus_types::bft::ReceiptChoice {
                prover_address: block.prover_address,
                statement_key: commitment(&block.statement()),
            })
            .collect(),
        ratified_chunk_proofs: Vec::new(),
        signature: [0; 96],
    };
    if round > 0 {
        proposal.round_change_certificate = Some(RoundChangeCertificate {
            chunk_id: 0,
            round,
            reports: (0..3).map(|index| report(index, round)).collect(),
        });
    }
    proposal.signature = keys[leader as usize]
        .sign(&proposal.signing_message(test_domain()))
        .to_bytes();
    proposal
}

fn nil_vote(phase: FinalityVotePhase, positions: &[usize]) -> NilVote {
    let (keys, _) = validators();
    let data = NilVoteData {
        chunk_id: 0,
        round: 2,
        phase,
    };
    let signatures: Vec<_> = positions
        .iter()
        .map(|index| keys[*index].sign(&data.signing_message(test_domain())))
        .collect();
    let mut bits = BitVec::default();
    for index in 0..keys.len() {
        bits.push(positions.contains(&index));
    }
    let attestations = positions
        .iter()
        .map(|index| {
            let mut claim = NilVoteAttestation {
                validator_index: u32::try_from(*index).unwrap(),
                vote: data.clone(),
                vote_signature: keys[*index]
                    .sign(&data.signing_message(test_domain()))
                    .to_bytes(),
                signature: [0; 96],
            };
            claim.signature = keys[*index]
                .sign(&claim.signing_message(test_domain()))
                .to_bytes();
            claim
        })
        .collect();
    NilVote {
        data,
        aggregation_bits: bits,
        signature: aggregate_signatures(&signatures.iter().collect::<Vec<_>>())
            .unwrap()
            .to_bytes(),
        attestations,
    }
}

fn report(index: usize, round: u32) -> RoundChange {
    let (keys, _) = validators();
    let mut report = RoundChange {
        chunk_id: 0,
        round,
        validator_index: u32::try_from(index).unwrap(),
        highest_quorum: None,
        signature: [0; 96],
    };
    report.signature = keys[index]
        .sign(&report.signing_message(test_domain()))
        .to_bytes();
    report
}

fn prevote_quorum(
    chunk: &neutrin0_consensus_types::Chunk,
    round: u32,
) -> neutrin0_consensus_types::QuorumCertificate {
    let (keys, _) = validators();
    let data = neutrin0_consensus_types::FinalityVoteData {
        chunk_id: chunk.chunk_id,
        round,
        chunk_hash: chunk.hash(),
        // A justifying quorum signs the same payment selection the
        // re-proposal carries (design 08).
        selection: proposal(round).selection(),
        phase: FinalityVotePhase::Prevote,
    };
    let message = data.signing_message(test_domain());
    let signatures: Vec<_> = keys[..3].iter().map(|key| key.sign(&message)).collect();
    neutrin0_consensus_types::QuorumCertificate {
        data,
        aggregate: neutrin0_consensus_types::AggregatedVote {
            aggregation_bits: BitVec::from_bytes(4, vec![7]).unwrap(),
            signature: aggregate_signatures(&signatures.iter().collect::<Vec<_>>())
                .unwrap()
                .to_bytes(),
        },
    }
}

/// Incoming seed of the test chunk, which draws its leaders.
const SEED: neutrin0_primitives::Seed = [0x5e; 32];
#[test]
fn equal_chain_ids_do_not_replay_nil_round_proposal_or_value_signatures() {
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let mut other = input.chain_spec.clone();
    other.consensus.bft_round_timeout_base_secs += 1;
    other.validate().unwrap();
    let original = input.chain_spec.consensus_domain();
    let foreign = other.consensus_domain();
    assert_eq!(original.chain_id, foreign.chain_id);
    assert_ne!(original.chain_spec_hash, foreign.chain_spec_hash);
    let (_, validators) = validators();
    let proposal = proposal(0);
    let nil = nil_vote(FinalityVotePhase::Prevote, &[0, 1, 2]);
    let round = report(0, 2);
    let certificate = RoundChangeCertificate {
        chunk_id: 0,
        round: 2,
        reports: (0..3).map(|index| report(index, 2)).collect(),
    };
    let quorum = prevote_quorum(&proposal.chunk, 0);
    bft::verify_proposal(original, &validators, &SEED, &proposal, (2, 3)).unwrap();
    bft::verify_nil_vote(original, &validators, &nil).unwrap();
    bft::verify_round_change(original, &validators, &round, (2, 3)).unwrap();
    bft::verify_round_change_certificate(original, &validators, &certificate, (2, 3)).unwrap();
    neutrin0_prover_chunk::slashing::verify_quorum(original, &validators, &quorum, (2, 3)).unwrap();
    assert!(bft::verify_proposal(foreign, &validators, &SEED, &proposal, (2, 3)).is_err());
    assert!(bft::verify_nil_vote(foreign, &validators, &nil).is_err());
    assert!(bft::verify_round_change(foreign, &validators, &round, (2, 3)).is_err());
    assert!(
        bft::verify_round_change_certificate(foreign, &validators, &certificate, (2, 3)).is_err()
    );
    assert!(
        neutrin0_prover_chunk::slashing::verify_quorum(foreign, &validators, &quorum, (2, 3))
            .is_err()
    );
}

#[test]
fn nonzero_round_proposal_requires_certified_entry_and_cannot_ignore_its_highest_quorum() {
    let (keys, validators) = validators();
    let mut good = proposal(2);
    let quorum = prevote_quorum(&good.chunk, 1);
    good.valid_quorum = Some(quorum.clone());
    for report in &mut good.round_change_certificate.as_mut().unwrap().reports {
        report.highest_quorum = Some(quorum.clone());
        report.signature = keys[report.validator_index as usize]
            .sign(&report.signing_message(test_domain()))
            .to_bytes();
    }
    good.signature = keys[good.proposer_index as usize]
        .sign(&good.signing_message(test_domain()))
        .to_bytes();
    assert_eq!(
        bft::verify_proposal(test_domain(), &validators, &SEED, &good, (2, 3)),
        Ok(())
    );
    let mut missing = good.clone();
    missing.round_change_certificate = None;
    missing.signature = keys[missing.proposer_index as usize]
        .sign(&missing.signing_message(test_domain()))
        .to_bytes();
    assert_eq!(
        bft::verify_proposal(test_domain(), &validators, &SEED, &missing, (2, 3)),
        Err(FinalityError::Target)
    );
    let mut ignored = good.clone();
    ignored.valid_quorum = None;
    ignored.signature = keys[ignored.proposer_index as usize]
        .sign(&ignored.signing_message(test_domain()))
        .to_bytes();
    assert_eq!(
        bft::verify_proposal(test_domain(), &validators, &SEED, &ignored, (2, 3)),
        Err(FinalityError::Target)
    );
    let mut minority = good.clone();
    minority
        .round_change_certificate
        .as_mut()
        .unwrap()
        .reports
        .pop();
    minority.signature = keys[minority.proposer_index as usize]
        .sign(&minority.signing_message(test_domain()))
        .to_bytes();
    assert_eq!(
        bft::verify_proposal(test_domain(), &validators, &SEED, &minority, (2, 3)),
        Err(FinalityError::Quorum)
    );
    let mut downgraded = good;
    downgraded.valid_quorum = Some(prevote_quorum(&downgraded.chunk, 0));
    downgraded.signature = keys[downgraded.proposer_index as usize]
        .sign(&downgraded.signing_message(test_domain()))
        .to_bytes();
    assert_eq!(
        bft::verify_proposal(test_domain(), &validators, &SEED, &downgraded, (2, 3)),
        Err(FinalityError::Target)
    );
}

#[test]
fn leader_is_fair_and_excludes_inactive_stake_without_balance_monopoly() {
    let (_, mut validators) = validators();
    validators[0].effective_stake = u128::MAX / 4;
    validators[1].effective_stake = 0;
    validators[2].effective_stake = 0;
    let first = bft_leader(7, 0, 0, &SEED, &validators).unwrap();
    let second = bft_leader(7, 0, 1, &SEED, &validators).unwrap();
    assert_ne!(first, second);
    assert!([0, 3].contains(&first));
    assert!([0, 3].contains(&second));
    assert_eq!(bft_leader(7, 0, 2, &SEED, &validators), Some(first));
    for validator in &mut validators {
        validator.effective_stake = 0;
    }
    assert_eq!(bft_leader(7, 0, 0, &SEED, &validators), None);
}

#[test]
fn signed_proposal_rejects_foreign_leader_mutated_target_and_chain() {
    let (keys, validators) = validators();
    let good = proposal(0);
    assert_eq!(
        bft::verify_proposal(test_domain(), &validators, &SEED, &good, (2, 3)),
        Ok(())
    );
    let mut foreign = good.clone();
    foreign.proposer_index = (good.proposer_index + 1) % 4;
    foreign.signature = keys[foreign.proposer_index as usize]
        .sign(&foreign.signing_message(test_domain()))
        .to_bytes();
    assert_eq!(
        bft::verify_proposal(test_domain(), &validators, &SEED, &foreign, (2, 3)),
        Err(FinalityError::Target)
    );
    let mut mutated = good.clone();
    mutated.chunk.end_state_root[0] ^= 1;
    assert_eq!(
        bft::verify_proposal(test_domain(), &validators, &SEED, &mutated, (2, 3)),
        Err(FinalityError::Signature)
    );
    assert!(
        bft::verify_proposal(
            neutrin0_primitives::ConsensusDomain {
                chain_id: 8,
                ..test_domain()
            },
            &validators,
            &SEED,
            &good,
            (2, 3)
        )
        .is_err()
    );
}

#[test]
fn nil_requires_exact_individual_signers_and_separate_phase_domain() {
    let (_, validators) = validators();
    let good = nil_vote(FinalityVotePhase::Prevote, &[0, 1, 2]);
    assert_eq!(
        bft::verify_nil_vote(test_domain(), &validators, &good),
        Ok(())
    );
    let mut missing = good.clone();
    missing.attestations.pop();
    assert_eq!(
        bft::verify_nil_vote(test_domain(), &validators, &missing),
        Err(FinalityError::Membership)
    );
    let mut duplicate = good.clone();
    duplicate.attestations[1] = duplicate.attestations[0].clone();
    assert_eq!(
        bft::verify_nil_vote(test_domain(), &validators, &duplicate),
        Err(FinalityError::Membership)
    );
    let mut phase = good.clone();
    phase.data.phase = FinalityVotePhase::Precommit;
    assert!(bft::verify_nil_vote(test_domain(), &validators, &phase).is_err());
    assert_eq!(
        bft::verify_nil_vote(
            neutrin0_primitives::ConsensusDomain {
                chain_id: 8,
                ..test_domain()
            },
            &validators,
            &good
        ),
        Err(FinalityError::Signature)
    );
    let mut inactive = validators;
    inactive[1].effective_stake = 0;
    assert_eq!(
        bft::verify_nil_vote(test_domain(), &inactive, &good),
        Err(FinalityError::Membership)
    );
}

#[test]
fn round_change_quorum_rejects_one_third_duplicate_and_mutated_reports() {
    let (_, validators) = validators();
    let mut cert = RoundChangeCertificate {
        chunk_id: 0,
        round: 3,
        reports: vec![report(0, 3), report(1, 3), report(2, 3)],
    };
    assert_eq!(
        bft::verify_round_change_certificate(test_domain(), &validators, &cert, (2, 3)),
        Ok(())
    );
    cert.reports.pop();
    assert_eq!(
        bft::verify_round_change_certificate(test_domain(), &validators, &cert, (2, 3)),
        Err(FinalityError::Quorum)
    );
    cert.reports.push(cert.reports[0].clone());
    assert_eq!(
        bft::verify_round_change_certificate(test_domain(), &validators, &cert, (2, 3)),
        Err(FinalityError::Target)
    );
    cert.reports[2] = report(2, 3);
    cert.reports[0].signature[0] ^= 1;
    assert_eq!(
        bft::verify_round_change_certificate(test_domain(), &validators, &cert, (2, 3)),
        Err(FinalityError::Signature)
    );
}

#[test]
fn new_bft_wire_rejects_unbounded_inner_counts_before_payload() {
    let mut bytes = vec![1_u8]; // Explicit BftVote::Nil target.
    bytes.extend(
        borsh::to_vec(&NilVoteData {
            chunk_id: 0,
            round: 0,
            phase: FinalityVotePhase::Prevote,
        })
        .unwrap(),
    );
    bytes.extend(u32::MAX.to_le_bytes());
    bytes.extend(u32::MAX.to_le_bytes());
    assert_eq!(
        borsh::from_slice::<neutrin0_consensus_types::BftVote>(&bytes)
            .unwrap_err()
            .kind(),
        borsh::io::ErrorKind::InvalidData
    );
    let mut bytes = vec![3_u8]; // BftMessage::RoundChangeCertificate.
    bytes.extend(borsh::to_vec(&0_u64).unwrap());
    bytes.extend(1_u32.to_le_bytes());
    bytes.extend(u32::MAX.to_le_bytes());
    assert_eq!(
        borsh::from_slice::<neutrin0_consensus_types::BftMessage>(&bytes)
            .unwrap_err()
            .kind(),
        borsh::io::ErrorKind::InvalidData
    );
}
