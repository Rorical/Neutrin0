use super::*;
use neutrin0_consensus_types::{
    AggregatedVote, FinalityVote, FinalityVoteData, FinalityVotePhase, RoundChange,
};
use neutrin0_consensus_types::{QuorumCertificate, RoundChangeCertificate};
use neutrin0_primitives::{BitVec, Validator};

use crate::accumulator::{aggregate_vote_signatures, extend_vote_aggregate};
use crate::stake::nil_stake;
use crate::verify::{
    finality_vote_signed_message, verify_nil_native, verify_round_certificate_native,
    verify_round_change_native, verify_vote_signature,
};

const DOMAIN: ConsensusDomain = ConsensusDomain::new(7, [1; 32]);
/// Incoming seed of the test chunk.
const SEED: neutrin0_primitives::Seed = [0x5e; 32];

fn hash(byte: u8) -> Hash {
    [byte; 32]
}

fn validator(pubkey: [u8; 48], stake: u128) -> Validator {
    Validator {
        pubkey,
        withdrawal_credentials: hash(1),
        effective_stake: stake,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }
}

fn test_secret_key(position: usize) -> neutrin0_crypto::bls::SecretKey {
    let byte = u8::try_from(position + 1).expect("test position fits u8");
    neutrin0_crypto::bls::SecretKey::key_gen(&[byte; 32], &[]).expect("valid test key")
}

fn test_validator(position: usize, stake: u128) -> Validator {
    validator(test_secret_key(position).public_key().to_bytes(), stake)
}

/// Weighted so `{0, 1}` holds 4/5, strictly above two thirds, while any
/// single seat or `{0, 2}`/`{1, 2}` (3/5) does not.
fn validators() -> Vec<Validator> {
    alloc::vec![
        test_validator(0, 2),
        test_validator(1, 2),
        test_validator(2, 1)
    ]
}

fn chunk() -> Chunk {
    Chunk {
        next_identity_sanctions_root: [0; 32],

        chunk_id: 3,
        start_height: 1,
        end_height: 128,
        start_state_root: hash(2),
        end_state_root: hash(3),
        start_block_hash: hash(4),
        end_block_hash: hash(5),
        block_hash_root: hash(6),
        block_proof_root: hash(7),
        vrf_proof_root: hash(8),
        active_validator_set_root: hash(9),
        next_validator_set_root: hash(10),
        da_root: hash(11),
    }
}

fn bits(values: &[bool]) -> BitVec {
    let mut bits = BitVec::default();
    for &value in values {
        bits.push(value);
    }
    bits
}

fn vote_data(phase: FinalityVotePhase, round: u32) -> FinalityVoteData {
    let chunk = chunk();
    FinalityVoteData {
        chunk_id: chunk.chunk_id,
        round,
        chunk_hash: chunk.hash(),
        selection: neutrin0_consensus_types::bft::selection_commitment(0, &[], &[]),
        phase,
    }
}

fn signed_vote_for_positions(
    phase: FinalityVotePhase,
    round: u32,
    positions: &[usize],
) -> FinalityVote {
    signed_vote_for_count(phase, round, positions, validators().len())
}

fn signed_vote_for_count(
    phase: FinalityVotePhase,
    round: u32,
    positions: &[usize],
    count: usize,
) -> FinalityVote {
    signed_vote_with_data(vote_data(phase, round), positions, count)
}

fn signed_vote_with_data(
    data: FinalityVoteData,
    positions: &[usize],
    count: usize,
) -> FinalityVote {
    let phase = data.phase;
    let message = finality_vote_signed_message(DOMAIN, &data);
    let signatures: Vec<neutrin0_crypto::bls::Signature> = positions
        .iter()
        .map(|position| test_secret_key(*position).sign(&message))
        .collect();
    let signature_refs: Vec<&neutrin0_crypto::bls::Signature> = signatures.iter().collect();
    let signature = neutrin0_crypto::bls::aggregate_signatures(&signature_refs)
        .expect("aggregate test signatures")
        .to_bytes();
    let mut aggregation_bits = BitVec::default();
    for position in 0..count {
        aggregation_bits.push(positions.contains(&position));
    }
    let attestations = positions
        .iter()
        .map(|position| {
            let key = test_secret_key(*position);
            let mut claim = neutrin0_consensus_types::VoteAttestation {
                validator_index: u32::try_from(*position).unwrap(),
                vote: data.clone(),
                vote_signature: key.sign(&message).to_bytes(),
                proof_acceptance: (phase == FinalityVotePhase::Precommit).then(|| {
                    neutrin0_consensus_types::ProofManifest {
                        proof_hashes: vec![[1; 32]; 128],
                    }
                    .commitment()
                }),
                unlock_quorum: None,
                signature: [0; 96],
            };
            claim.signature = key.sign(&claim.signing_message(DOMAIN)).to_bytes();
            claim
        })
        .collect();
    FinalityVote {
        proof_manifests: if phase == FinalityVotePhase::Precommit {
            vec![neutrin0_consensus_types::ProofManifest {
                proof_hashes: vec![[1; 32]; 128],
            }]
        } else {
            Vec::new()
        },
        attestations,
        aggregation_bits,
        data,
        signature,
    }
}

fn unanimous_bft(count: usize) -> ChunkBft {
    let active: Vec<_> = (0..count)
        .map(|position| test_validator(position, 1))
        .collect();
    let index =
        neutrin0_consensus_types::bft_leader(DOMAIN.chain_id, chunk().chunk_id, 0, &SEED, &active)
            .unwrap();
    let mut proposal = BftProposal {
        chunk: chunk(),
        round: 0,
        proposer_index: index,
        valid_quorum: None,
        round_change_certificate: None,
        proposal_slot: 0,
        receipts: Vec::new(),
        ratified_chunk_proofs: Vec::new(),
        signature: [0; 96],
    };
    proposal.signature = test_secret_key(index as usize)
        .sign(&proposal.signing_message(DOMAIN))
        .to_bytes();
    let mut bft = ChunkBft::with_quorum(
        DOMAIN,
        chunk(),
        0,
        active,
        chunk().active_validator_set_root,
        SEED,
        (1, 1),
        (1, 1),
    )
    .unwrap();
    bft.set_proposal(proposal).unwrap();
    bft
}

fn signed_nil_for_positions(phase: FinalityVotePhase, positions: &[usize]) -> NilVote {
    let data = neutrin0_consensus_types::NilVoteData {
        chunk_id: chunk().chunk_id,
        round: 0,
        phase,
    };
    let mut aggregation_bits = BitVec::default();
    for position in 0..16 {
        aggregation_bits.push(positions.contains(&position));
    }
    let attestations: Vec<_> = positions
        .iter()
        .map(|position| {
            let key = test_secret_key(*position);
            let mut claim = neutrin0_consensus_types::NilVoteAttestation {
                validator_index: u32::try_from(*position).unwrap(),
                vote: data.clone(),
                vote_signature: key.sign(&data.signing_message(DOMAIN)).to_bytes(),
                signature: [0; 96],
            };
            claim.signature = key.sign(&claim.signing_message(DOMAIN)).to_bytes();
            claim
        })
        .collect();
    let signature = aggregate_vote_signatures(
        &attestations
            .iter()
            .map(|claim| claim.vote_signature)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    NilVote {
        data,
        aggregation_bits,
        signature,
        attestations,
    }
}

#[test]
fn replayed_votes_are_accepted_without_changing_or_reverifying_the_aggregate() {
    let mut bft = unanimous_bft(16);
    let positions: Vec<_> = (0..8).collect();
    for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
        let vote = signed_vote_for_count(phase, 0, &positions, 16);
        bft.add_vote(vote.clone(), phase).unwrap();
        let before = bft.clone();
        // Exact replay and a replay with a corrupted aggregate over the same
        // retained claims both change nothing and skip verification.
        bft.add_vote(vote.clone(), phase).unwrap();
        let mut corrupted = vote.clone();
        corrupted.signature[0] ^= 1;
        bft.add_vote(corrupted, phase).unwrap();
        assert_eq!(bft, before);
        // A signer not yet retained still needs verification.
        let mut forged = signed_vote_for_count(phase, 0, &[15], 16);
        forged.attestations[0].vote_signature[0] ^= 1;
        assert!(bft.add_vote(forged, phase).is_err());
        assert_eq!(bft, before);
    }
    let nil = signed_nil_for_positions(FinalityVotePhase::Prevote, &[0, 1]);
    bft.add_nil_vote(nil.clone()).unwrap();
    let before = bft.clone();
    bft.add_nil_vote(nil.clone()).unwrap();
    let mut corrupted = nil;
    corrupted.signature[0] ^= 1;
    bft.add_nil_vote(corrupted).unwrap();
    assert_eq!(bft, before);
}

#[test]
fn overlapping_value_aggregates_keep_fifteen_signers_and_add_the_missing_sixteenth() {
    let mut bft = unanimous_bft(16);
    let first: Vec<_> = (0..8).collect();
    let second: Vec<_> = (7..15).collect();
    for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
        for positions in [&first[..], &second[..]] {
            bft.add_vote(signed_vote_for_count(phase, 0, positions, 16), phase)
                .unwrap();
        }
        assert_eq!(bft.aggregate_stake(phase), 15);
        assert_eq!(bft.current_attestations(phase).len(), 15);
    }
    assert_eq!(
        bft.finalization_status(chunk().active_validator_set_root),
        Ok(FinalizationStatus::Pending)
    );
    for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
        let retained = bft
            .current_attestations(phase)
            .into_iter()
            .find(|claim| claim.validator_index == 7)
            .unwrap();
        let mut last = signed_vote_for_count(phase, 0, &[7, 15], 16);
        if phase == FinalityVotePhase::Precommit {
            let manifest = neutrin0_consensus_types::ProofManifest {
                proof_hashes: vec![[9; 32]; 128],
            };
            last.attestations[0].proof_acceptance = Some(manifest.commitment());
            last.proof_manifests.push(manifest);
            last.proof_manifests
                .sort_by_key(neutrin0_consensus_types::ProofManifest::commitment);
            last.attestations[0].signature = test_secret_key(7)
                .sign(&last.attestations[0].signing_message(DOMAIN))
                .to_bytes();
        }
        bft.add_vote(last.clone(), phase).unwrap();
        bft.add_vote(last, phase).unwrap();
        assert_eq!(bft.aggregate_stake(phase), 16);
        assert_eq!(bft.current_attestations(phase).len(), 16);
        assert_eq!(
            bft.current_attestations(phase)
                .into_iter()
                .find(|claim| claim.validator_index == 7),
            Some(retained)
        );
        let aggregate = bft.current_aggregate(phase).unwrap();
        let vote = FinalityVote {
            proof_manifests: bft.current_proof_manifests(phase),
            data: vote_data(phase, 0),
            aggregation_bits: aggregate.aggregation_bits,
            signature: aggregate.signature,
            attestations: bft.current_attestations(phase),
        };
        verify_vote_signature(DOMAIN, &bft.active_set, &vote).unwrap();
        assert!(neutrin0_consensus_types::attestation_coverage_valid(
            &vote.data,
            &vote.aggregation_bits,
            &vote.attestations,
            128
        ));
    }
    assert!(
        bft.try_finalize(chunk().active_validator_set_root)
            .unwrap()
            .is_some()
    );
}

#[test]
fn overlapping_nil_aggregates_union_signers_without_creating_value_finality() {
    let mut bft = unanimous_bft(16);
    let first: Vec<_> = (0..8).collect();
    let second: Vec<_> = (7..15).collect();
    for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
        for positions in [&first[..], &second[..]] {
            bft.add_nil_vote(signed_nil_for_positions(phase, positions))
                .unwrap();
        }
        assert!(!bft.nil_quorum_reached(phase));
        let last = signed_nil_for_positions(phase, &[7, 15]);
        bft.add_nil_vote(last.clone()).unwrap();
        bft.add_nil_vote(last).unwrap();
        let aggregate = bft.current_nil_aggregate(phase).unwrap();
        assert_eq!(aggregate.attestations.len(), 16);
        assert_eq!(nil_stake(&bft.active_set, &aggregate), Ok(16));
        verify_nil_native(DOMAIN, &bft.active_set, &aggregate).unwrap();
        assert!(bft.nil_quorum_reached(phase));
    }
    assert_eq!(
        bft.finalization_status(chunk().active_validator_set_root),
        Ok(FinalizationStatus::Pending)
    );
}

fn signed_vote_with_bits(
    phase: FinalityVotePhase,
    round: u32,
    aggregation_bits: BitVec,
    positions: &[usize],
) -> FinalityVote {
    let mut vote = signed_vote_for_positions(phase, round, positions);
    vote.aggregation_bits = aggregation_bits;
    vote
}

fn make_bft() -> ChunkBft {
    let chunk = chunk();
    let mut bft = ChunkBft::new(
        DOMAIN,
        chunk.clone(),
        0,
        validators(),
        chunk.active_validator_set_root,
        SEED,
    )
    .expect("create bft");
    bft.set_proposal(signed_proposal(0)).unwrap();
    bft
}

fn signed_proposal(round: u32) -> BftProposal {
    signed_proposal_for(round, &validators())
}

fn signed_proposal_for(round: u32, active: &[Validator]) -> BftProposal {
    let index = neutrin0_consensus_types::bft_leader(
        DOMAIN.chain_id,
        chunk().chunk_id,
        round,
        &SEED,
        active,
    )
    .unwrap();
    let mut proposal = BftProposal {
        chunk: chunk(),
        round,
        proposer_index: index,
        valid_quorum: None,
        round_change_certificate: None,
        proposal_slot: 0,
        receipts: Vec::new(),
        ratified_chunk_proofs: Vec::new(),
        signature: [0; 96],
    };
    proposal.signature = test_secret_key(index as usize)
        .sign(&proposal.signing_message(DOMAIN))
        .to_bytes();
    proposal
}

#[test]
fn votes_for_another_selection_of_the_chunk_are_another_value() {
    let other = |selection: u8, positions: &[usize]| {
        let mut data = vote_data(FinalityVotePhase::Prevote, 0);
        data.selection = [selection; 32];
        signed_vote_with_data(data, positions, validators().len())
    };
    let mut bft = make_bft();
    assert_eq!(
        bft.add_prevote(other(1, &[0, 1])),
        Err(BftError::WrongVoteTarget)
    );
    // Before the round's proposal, votes are held per selection and count
    // for nothing; the proposal keeps only its own selection's votes.
    let mut fresh = ChunkBft::new(DOMAIN, chunk(), 0, validators(), hash(9), SEED).unwrap();
    fresh
        .add_prevote(signed_vote_for_positions(
            FinalityVotePhase::Prevote,
            0,
            &[0],
        ))
        .unwrap();
    fresh.add_prevote(other(1, &[1, 2])).unwrap();
    assert!(!fresh.prevote_quorum_reached());
    assert_eq!(fresh.pending_votes().len(), 2);
    // Held selections are bounded: one more with no more stake than the
    // weakest held is refused.
    for selection in 2..u8::try_from(MAX_PENDING_SELECTIONS).unwrap() {
        fresh.add_prevote(other(selection, &[2])).unwrap();
    }
    assert_eq!(
        fresh.add_prevote(other(0xee, &[2])),
        Err(BftError::PendingSelectionsFull)
    );
    fresh.set_proposal(signed_proposal(0)).unwrap();
    assert_eq!(fresh.pending_votes(), Vec::<FinalityVote>::new());
    assert_eq!(fresh.aggregate_stake(FinalityVotePhase::Prevote), {
        let mut alone = make_bft();
        alone
            .add_prevote(signed_vote_for_positions(
                FinalityVotePhase::Prevote,
                0,
                &[0],
            ))
            .unwrap();
        alone.aggregate_stake(FinalityVotePhase::Prevote)
    });
    fresh
        .add_prevote(signed_vote_for_positions(
            FinalityVotePhase::Prevote,
            0,
            &[1],
        ))
        .unwrap();
    assert!(fresh.prevote_quorum_reached());
    assert_eq!(
        fresh.add_prevote(other(1, &[3])),
        Err(BftError::WrongVoteTarget)
    );
}

#[test]
fn a_full_pending_set_yields_its_weakest_selection_to_more_stake() {
    let validators: Vec<_> = (0..6)
        .map(|position| test_validator(position, if position == 5 { 5 } else { 1 }))
        .collect();
    let mut bft = ChunkBft::new(DOMAIN, chunk(), 0, validators.clone(), hash(9), SEED).unwrap();
    let vote = |selection: u8, positions: &[usize]| {
        let mut data = vote_data(FinalityVotePhase::Prevote, 0);
        data.selection = [selection; 32];
        signed_vote_with_data(data, positions, validators.len())
    };
    // Four signers fill the held selections, one each.
    for (selection, signer) in (1..=4).zip(0..4) {
        bft.add_prevote(vote(selection, &[signer])).unwrap();
    }
    // Another selection with no more stake than the weakest is refused,
    // and one that outweighs it takes its place.
    assert_eq!(
        bft.add_prevote(vote(7, &[4])),
        Err(BftError::PendingSelectionsFull)
    );
    bft.add_prevote(vote(8, &[5])).unwrap();
    let held: Vec<_> = bft
        .pending_votes()
        .iter()
        .map(|vote| vote.data.selection[0])
        .collect();
    assert_eq!(held.len(), MAX_PENDING_SELECTIONS);
    assert!(held.contains(&8) && !held.contains(&1));
}

#[test]
fn finalizes_with_valid_proof_and_two_quorums() {
    let mut bft = make_bft();
    bft.add_prevote(signed_vote_for_positions(
        FinalityVotePhase::Prevote,
        0,
        &[0, 1],
    ))
    .expect("prevote");
    bft.add_precommit(signed_vote_for_positions(
        FinalityVotePhase::Precommit,
        0,
        &[0, 1, 2],
    ))
    .expect("precommit");

    let cert = bft
        .try_finalize(chunk().active_validator_set_root)
        .expect("try finalize")
        .expect("finalized");

    assert_eq!(cert.chunk_id, chunk().chunk_id);
    assert_eq!(cert.round, 0);
    assert_eq!(cert.chunk_hash, chunk().hash());
}

#[cfg(feature = "std")]
#[test]
fn combines_disjoint_partial_votes_to_reach_quorum() {
    let mut bft = make_bft();
    bft.add_prevote(signed_vote_for_positions(
        FinalityVotePhase::Prevote,
        0,
        &[0],
    ))
    .expect("first prevote");
    bft.add_precommit(signed_vote_for_positions(
        FinalityVotePhase::Precommit,
        0,
        &[0],
    ))
    .expect("first precommit");
    assert_eq!(
        bft.finalization_status(chunk().active_validator_set_root),
        Ok(FinalizationStatus::Pending),
    );

    bft.add_prevote(signed_vote_for_positions(
        FinalityVotePhase::Prevote,
        0,
        &[1],
    ))
    .expect("second prevote");
    bft.add_precommit(signed_vote_for_positions(
        FinalityVotePhase::Precommit,
        0,
        &[1],
    ))
    .expect("second precommit");

    let cert = bft
        .try_finalize(chunk().active_validator_set_root)
        .expect("try finalize")
        .expect("finalized");

    assert_eq!(cert.prevote.aggregation_bits.bit_len(), 3);
    assert_eq!(cert.prevote.aggregation_bits.get(0), Some(true));
    assert_eq!(cert.prevote.aggregation_bits.get(1), Some(true));
    assert_eq!(cert.prevote.aggregation_bits.get(2), Some(false));

    let sig = neutrin0_crypto::bls::Signature::from_bytes(&cert.prevote.signature)
        .expect("combined signature decodes");
    let key_1 = test_secret_key(0);
    let key_2 = test_secret_key(1);
    let pk_1 = key_1.public_key();
    let pk_2 = key_2.public_key();
    let message = finality_vote_signed_message(DOMAIN, &vote_data(FinalityVotePhase::Prevote, 0));
    neutrin0_crypto::bls::fast_aggregate_verify(&[&pk_1, &pk_2], &message, &sig)
        .expect("combined signature verifies");
}

#[test]
fn refuses_each_missing_finality_precondition() {
    let mut bft = make_bft();
    bft.add_prevote(signed_vote_for_positions(
        FinalityVotePhase::Prevote,
        0,
        &[0, 1],
    ))
    .expect("prevote");
    bft.add_precommit(signed_vote_for_positions(
        FinalityVotePhase::Precommit,
        0,
        &[0, 1],
    ))
    .expect("precommit");

    let mut no_precommit = make_bft();
    no_precommit
        .add_prevote(signed_vote_for_positions(
            FinalityVotePhase::Prevote,
            0,
            &[0, 1],
        ))
        .expect("prevote");
    assert_eq!(
        no_precommit.finalization_status(chunk().active_validator_set_root),
        Ok(FinalizationStatus::Pending)
    );

    let mut no_prevote = make_bft();
    no_prevote
        .add_precommit(signed_vote_for_positions(
            FinalityVotePhase::Precommit,
            0,
            &[0, 1],
        ))
        .expect("precommit");
    assert_eq!(
        no_prevote.finalization_status(chunk().active_validator_set_root),
        Ok(FinalizationStatus::Pending)
    );

    assert_eq!(
        bft.finalization_status(hash(99)),
        Err(BftError::ValidatorSetRootMismatch)
    );
}

#[test]
fn rejects_wrong_phase_target_and_bit_length() {
    let mut bft = make_bft();
    assert_eq!(
        bft.add_prevote(signed_vote_for_positions(
            FinalityVotePhase::Precommit,
            0,
            &[0, 1],
        )),
        Err(BftError::WrongPhase)
    );
    assert_eq!(
        bft.add_prevote(signed_vote_for_positions(
            FinalityVotePhase::Prevote,
            1,
            &[0, 1],
        )),
        Err(BftError::WrongVoteTarget)
    );
    assert_eq!(
        bft.add_prevote(signed_vote_with_bits(
            FinalityVotePhase::Prevote,
            0,
            bits(&[true, true]),
            &[0, 1]
        )),
        Err(BftError::InvalidAggregationBits)
    );
}

#[test]
fn rejects_vote_with_invalid_aggregate_signature() {
    let mut bft = make_bft();
    let mut vote = signed_vote_for_positions(FinalityVotePhase::Prevote, 0, &[0, 1]);
    vote.signature = signed_vote_for_positions(FinalityVotePhase::Precommit, 0, &[0, 1]).signature;
    assert_eq!(
        bft.add_prevote(vote),
        Err(BftError::InvalidAggregateSignature)
    );
    assert!(!bft.prevote_quorum_reached());
}

#[test]
fn quorum_requires_two_thirds_stake() {
    let mut bft = make_bft();
    bft.add_prevote(signed_vote_for_positions(
        FinalityVotePhase::Prevote,
        0,
        &[0],
    ))
    .expect("one stake prevote");
    bft.add_precommit(signed_vote_for_positions(
        FinalityVotePhase::Precommit,
        0,
        &[0, 1],
    ))
    .expect("two stake precommit");

    assert_eq!(
        bft.finalization_status(chunk().active_validator_set_root),
        Ok(FinalizationStatus::Pending)
    );
}

#[test]
fn authenticated_round_advance_clears_votes_and_requires_a_fresh_proposal() {
    let mut bft = make_bft();
    bft.add_prevote(signed_vote_for_positions(
        FinalityVotePhase::Prevote,
        0,
        &[0, 1],
    ))
    .expect("prevote");
    let mut bft = bft.advance_to_round(1).unwrap();

    assert_eq!(bft.round(), 1);
    assert_eq!(
        bft.finalization_status(chunk().active_validator_set_root),
        Ok(FinalizationStatus::Pending)
    );
    assert_eq!(
        bft.add_prevote(signed_vote_for_positions(
            FinalityVotePhase::Prevote,
            0,
            &[0, 1],
        )),
        Err(BftError::WrongVoteTarget)
    );
}

#[test]
fn constructor_rejects_invalid_stake_and_quorum() {
    let chunk = chunk();
    assert_eq!(
        ChunkBft::new(
            DOMAIN,
            chunk.clone(),
            0,
            alloc::vec![test_validator(0, 0)],
            chunk.active_validator_set_root,
            SEED,
        ),
        Err(BftError::ZeroTotalStake)
    );
    assert_eq!(
        ChunkBft::with_quorum(
            DOMAIN,
            chunk.clone(),
            0,
            validators(),
            chunk.active_validator_set_root,
            SEED,
            (0, 3),
            (2, 3),
        ),
        Err(BftError::InvalidQuorum)
    );
}
#[test]
fn precommit_requires_every_signer_and_complete_proof_list() {
    type Mutation = fn(&mut FinalityVote);
    let good = signed_vote_for_positions(FinalityVotePhase::Precommit, 0, &[0, 1]);
    let mutations: &[Mutation] = &[
        |v| v.attestations.clear(),
        |v| {
            v.attestations.pop();
        },
        |v| v.attestations.push(v.attestations[0].clone()),
        |v| v.attestations[0].validator_index = 2,
        |v| v.proof_manifests.clear(),
        |v| v.proof_manifests.push(v.proof_manifests[0].clone()),
        |v| v.proof_manifests[0].proof_hashes[0][0] ^= 1,
        |v| {
            v.proof_manifests
                .push(neutrin0_consensus_types::ProofManifest {
                    proof_hashes: alloc::vec![[9; 32]; 128],
                });
            v.proof_manifests
                .sort_by_key(neutrin0_consensus_types::ProofManifest::commitment);
        },
        |v| v.attestations[0].proof_acceptance = None,
        |v| {
            v.attestations[0].proof_acceptance.as_mut().unwrap().count -= 1;
        },
        |v| v.attestations[0].vote.chunk_hash[0] ^= 1,
        |v| v.attestations[0].signature[0] ^= 1,
        |v| {
            v.attestations[0].vote_signature[0] ^= 1;
            v.attestations[0].signature = test_secret_key(0)
                .sign(&v.attestations[0].signing_message(DOMAIN))
                .to_bytes();
        },
    ];
    for mutate in mutations {
        let mut bft = ChunkBft::new(DOMAIN, chunk(), 0, validators(), hash(9), SEED).unwrap();
        bft.set_proposal(signed_proposal(0)).unwrap();
        let mut invalid = good.clone();
        mutate(&mut invalid);
        assert!(bft.add_precommit(invalid).is_err());
        assert_eq!(bft.aggregate_stake(FinalityVotePhase::Precommit), 0);
        bft.add_precommit(good.clone()).unwrap();
        assert!(bft.precommit_quorum_reached());
    }
}

#[test]
fn heterogeneous_exact_receipt_manifests_survive_aggregation_and_finalization() {
    let mut bft = make_bft();
    bft.add_prevote(signed_vote_for_positions(
        FinalityVotePhase::Prevote,
        0,
        &[0, 1],
    ))
    .unwrap();
    bft.add_precommit(signed_vote_for_positions(
        FinalityVotePhase::Precommit,
        0,
        &[0],
    ))
    .unwrap();
    let mut alternate = signed_vote_for_positions(FinalityVotePhase::Precommit, 0, &[1]);
    alternate.proof_manifests[0].proof_hashes[7][0] ^= 1;
    alternate.attestations[0].proof_acceptance = Some(alternate.proof_manifests[0].commitment());
    alternate.attestations[0].signature = test_secret_key(1)
        .sign(&alternate.attestations[0].signing_message(DOMAIN))
        .to_bytes();
    bft.add_precommit(alternate.clone()).unwrap();
    let certificate = bft.try_finalize(hash(9)).unwrap().unwrap();
    assert_eq!(certificate.proof_manifests.len(), 2);
    assert!(neutrin0_consensus_types::proof_manifests_valid(
        &certificate.precommit_attestations,
        &certificate.proof_manifests
    ));
    assert_eq!(
        certificate.precommit_vote().proof_manifests,
        certificate.proof_manifests
    );
    assert_eq!(certificate.prevote_vote().proof_manifests, Vec::new());
    let index =
        neutrin0_consensus_types::ProofManifestIndex::new(&certificate.proof_manifests).unwrap();
    let signed = certificate
        .precommit_attestations
        .iter()
        .find(|claim| claim.validator_index == 1)
        .unwrap();
    assert_eq!(
        index.get(&signed.proof_acceptance.unwrap()),
        Some(&alternate.proof_manifests[0])
    );
}

#[test]
fn finality_certificate_preserves_exact_aggregate_signer_coverage() {
    let mut bft = make_bft();
    bft.add_prevote(signed_vote_for_positions(
        FinalityVotePhase::Prevote,
        0,
        &[0, 1],
    ))
    .unwrap();
    for positions in [&[0][..], &[1][..], &[0, 1][..]] {
        bft.add_precommit(signed_vote_for_positions(
            FinalityVotePhase::Precommit,
            0,
            positions,
        ))
        .unwrap();
    }
    let certificate = bft.try_finalize(hash(9)).unwrap().unwrap();
    let vote = certificate.precommit_vote();
    assert_eq!(certificate.precommit_attestations.len(), 2);
    assert!(neutrin0_consensus_types::attestation_coverage_valid(
        &vote.data,
        &vote.aggregation_bits,
        &vote.attestations,
        128
    ));
}

#[test]
fn inactive_signers_are_rejected_in_votes_and_carried_quorums() {
    {
        let mut active = validators();
        active[2].effective_stake = 0;
        let mut bft = ChunkBft::new(DOMAIN, chunk(), 0, active.clone(), hash(9), SEED).unwrap();
        bft.set_proposal(signed_proposal_for(0, &active)).unwrap();
        let prevote = signed_vote_for_positions(FinalityVotePhase::Prevote, 0, &[0, 1, 2]);
        assert_eq!(
            bft.add_prevote(prevote.clone()),
            Err(BftError::InvalidAggregationBits)
        );
        let quorum = neutrin0_consensus_types::QuorumCertificate {
            data: prevote.data,
            aggregate: AggregatedVote {
                aggregation_bits: prevote.aggregation_bits,
                signature: prevote.signature,
            },
        };
        let mut precommit = signed_vote_for_positions(FinalityVotePhase::Precommit, 0, &[0]);
        let claim = &mut precommit.attestations[0];
        claim.unlock_quorum = Some(quorum);
        claim.signature = test_secret_key(0)
            .sign(&claim.signing_message(DOMAIN))
            .to_bytes();
        assert_eq!(
            bft.add_precommit(precommit),
            Err(BftError::InvalidAggregationBits)
        );
        assert_eq!(bft.aggregate_stake(FinalityVotePhase::Precommit), 0);
    }
}

#[test]
fn extended_aggregates_equal_full_reaggregation_even_after_cancellation() {
    let message = finality_vote_signed_message(DOMAIN, &vote_data(FinalityVotePhase::Prevote, 0));
    // The scalars 1 and r - 1 are opposite, so their signatures sum to the identity.
    let minus_one: [u8; 32] = [
        0x73ed_a753_299d_7d48_u64,
        0x3339_d808_09a1_d805,
        0x53bd_a402_fffe_5bfe,
        0xffff_ffff_0000_0000,
    ]
    .map(u64::to_be_bytes)
    .concat()
    .try_into()
    .unwrap();
    let mut one = [0_u8; 32];
    one[31] = 1;
    let mut keys: Vec<_> = [one, minus_one]
        .iter()
        .map(|scalar| neutrin0_crypto::bls::SecretKey::from_bytes(scalar).unwrap())
        .collect();
    keys.extend((0..4).map(test_secret_key));
    let signatures: Vec<_> = keys
        .iter()
        .map(|key| key.sign(&message).to_bytes())
        .collect();
    let cancelled = aggregate_vote_signatures(&signatures[..2]).unwrap();
    assert!(neutrin0_crypto::bls::Signature::from_bytes(&cancelled).is_err());
    for end in 2..=signatures.len() {
        let claims = &signatures[..end];
        let expected = aggregate_vote_signatures(claims).unwrap();
        for retained in 1..end {
            let existing = aggregate_vote_signatures(&claims[..retained]).unwrap();
            assert_eq!(
                extend_vote_aggregate(&existing, claims, retained, |signature| *signature),
                Ok(expected),
                "retained {retained} of {end}"
            );
        }
    }
}

fn signed_round_change(index: usize, highest_quorum: Option<&QuorumCertificate>) -> RoundChange {
    let mut report = RoundChange {
        chunk_id: chunk().chunk_id,
        round: 1,
        validator_index: u32::try_from(index).unwrap(),
        highest_quorum: highest_quorum.cloned(),
        signature: [0; 96],
    };
    let key = test_secret_key(index);
    report.signature = key.sign(&report.signing_message(DOMAIN)).to_bytes();
    report
}

fn verify_each_report(validators: &[Validator], reports: &[RoundChange]) -> Result<(), BftError> {
    for report in reports {
        let mut fresh = Vec::new();
        verify_round_change_native(DOMAIN, validators, None, report, (2, 3), &mut fresh)?;
    }
    Ok(())
}

#[test]
fn round_certificates_verify_each_distinct_carried_quorum_once() {
    let validators = validators();
    let prevote = signed_vote_for_positions(FinalityVotePhase::Prevote, 0, &[0, 1]);
    let precommit = signed_vote_for_positions(FinalityVotePhase::Precommit, 0, &[0, 1]);
    let quorum = QuorumCertificate {
        data: prevote.data,
        aggregate: AggregatedVote {
            aggregation_bits: prevote.aggregation_bits,
            signature: prevote.signature,
        },
    };
    let mut tampered = quorum.clone();
    tampered.aggregate.signature = precommit.signature;
    let (valid, forged) = (Some(&quorum), Some(&tampered));
    for carried in [
        [valid, valid, valid],
        [valid, None, valid],
        [None, valid, forged],
        [forged, valid, valid],
    ] {
        let certificate = RoundChangeCertificate {
            chunk_id: chunk().chunk_id,
            round: 1,
            reports: (0..3)
                .zip(carried)
                .map(|(index, quorum)| signed_round_change(index, quorum))
                .collect(),
        };
        let result = verify_round_certificate_native(DOMAIN, &validators, 3, &certificate, (2, 3));
        let expected = verify_each_report(&validators, &certificate.reports);
        assert_eq!(result, expected);
        assert_eq!(result.is_ok(), !carried.contains(&forged));
    }
}

#[test]
fn shared_round_certificate_wire_preserves_exact_signed_quorum_subsets() {
    let validators = validators();
    let make_quorum = |positions: &[usize]| {
        let vote = signed_vote_for_positions(FinalityVotePhase::Prevote, 0, positions);
        QuorumCertificate {
            data: vote.data,
            aggregate: AggregatedVote {
                aggregation_bits: vote.aggregation_bits,
                signature: vote.signature,
            },
        }
    };
    let first = make_quorum(&[0, 1]);
    let alternate = make_quorum(&[0, 1, 2]);
    let certificate = RoundChangeCertificate {
        chunk_id: chunk().chunk_id,
        round: 1,
        reports: vec![
            signed_round_change(0, Some(&first)),
            signed_round_change(1, Some(&alternate)),
            signed_round_change(2, Some(&first)),
        ],
    };
    let encoded = borsh::to_vec(&certificate).unwrap();
    assert_eq!(u32::from_le_bytes(encoded[..4].try_into().unwrap()), 2);
    let mut decoded: RoundChangeCertificate = borsh::from_slice(&encoded).unwrap();
    assert_eq!(decoded, certificate);
    verify_round_certificate_native(DOMAIN, &validators, 3, &decoded, (2, 3)).unwrap();
    decoded.reports[0].highest_quorum = Some(alternate);
    assert!(verify_round_certificate_native(DOMAIN, &validators, 3, &decoded, (2, 3)).is_err());
    decoded.reports[0].signature = test_secret_key(0)
        .sign(&decoded.reports[0].signing_message(DOMAIN))
        .to_bytes();
    verify_round_certificate_native(DOMAIN, &validators, 3, &decoded, (2, 3)).unwrap();
    decoded.reports[0].highest_quorum = None;
    assert!(verify_round_certificate_native(DOMAIN, &validators, 3, &decoded, (2, 3)).is_err());
}
