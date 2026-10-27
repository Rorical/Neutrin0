use super::*;
use crate::{AggregatedVote, FinalityVotePhase, ProofManifest};
use crate::{Chunk, RoundChange, VoteAttestation};
use alloc::vec;
use alloc::vec::Vec;
use neutrin0_primitives::{BitVec, ConsensusDomain};

const DOMAIN: ConsensusDomain = ConsensusDomain::new(7, [8; 32]);

fn quorum(mask: u8) -> QuorumCertificate {
    QuorumCertificate {
        data: FinalityVoteData {
            chunk_id: 0,
            round: 1,
            chunk_hash: [9; 32],
            selection: [0; 32],
            phase: FinalityVotePhase::Prevote,
        },
        aggregate: AggregatedVote {
            aggregation_bits: BitVec::from_bytes(3, vec![mask]).unwrap(),
            signature: [mask; 96],
        },
    }
}

fn claim(index: u32, quorum: Option<QuorumCertificate>) -> VoteAttestation {
    VoteAttestation {
        vote_signature: [2; 96],
        validator_index: index,
        vote: FinalityVoteData {
            chunk_id: 0,
            round: 2,
            chunk_hash: [9; 32],
            selection: [0; 32],
            phase: FinalityVotePhase::Prevote,
        },
        proof_acceptance: None,
        unlock_quorum: quorum,
        signature: [3; 96],
    }
}

fn vote() -> FinalityVote {
    FinalityVote {
        aggregation_bits: BitVec::from_bytes(3, vec![7]).unwrap(),
        data: claim(0, None).vote,
        signature: [4; 96],
        attestations: (0..3).map(|index| claim(index, Some(quorum(7)))).collect(),
        proof_manifests: Vec::new(),
    }
}

fn chunk() -> Chunk {
    Chunk {
        chunk_id: 0,
        start_height: 1,
        end_height: 1,
        start_state_root: [1; 32],
        end_state_root: [2; 32],
        start_block_hash: [3; 32],
        end_block_hash: [4; 32],
        block_hash_root: [5; 32],
        block_proof_root: [6; 32],
        vrf_proof_root: [7; 32],
        active_validator_set_root: [8; 32],
        next_validator_set_root: [8; 32],
        next_identity_sanctions_root: [0; 32],
        da_root: [9; 32],
    }
}

fn reports() -> RoundChangeCertificate {
    RoundChangeCertificate {
        chunk_id: 0,
        round: 2,
        reports: (0..3)
            .map(|index| RoundChange {
                chunk_id: 0,
                round: 2,
                validator_index: index,
                highest_quorum: Some(quorum(7)),
                signature: [4; 96],
            })
            .collect(),
    }
}

fn proposal() -> BftProposal {
    BftProposal {
        chunk: chunk(),
        round: 2,
        proposer_index: 0,
        valid_quorum: Some(quorum(7)),
        round_change_certificate: Some(reports()),
        proposal_slot: 9,
        receipts: vec![bft::ReceiptChoice {
            prover_address: [4; 32],
            statement_key: [3; 32],
        }],
        ratified_chunk_proofs: vec![bft::ChunkRatification {
            chunk_id: 1,
            prover_address: [6; 32],
            finality_cert_hash: [7; 32],
            statement_key: [8; 32],
        }],
        signature: [5; 96],
    }
}

fn dictionary_count(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().unwrap())
}

#[test]
fn repeated_quorums_encode_once_and_restore_original_claims() {
    let vote = vote();
    let encoded = borsh::to_vec(&vote).unwrap();
    assert_eq!(dictionary_count(&encoded), 1);
    assert_eq!(borsh::from_slice::<FinalityVote>(&encoded).unwrap(), vote);
    // Compare to repeated full semantic carriers, rather than accepting an
    // empty/unsigned surrogate for the original declarations.
    let repeated = borsh::to_vec(&(
        &vote.aggregation_bits,
        &vote.data,
        &vote.signature,
        &vote.attestations,
        &vote.proof_manifests,
    ))
    .unwrap();
    assert!(encoded.len() < repeated.len());
    let report = reports();
    let encoded = borsh::to_vec(&report).unwrap();
    assert_eq!(dictionary_count(&encoded), 1);
    assert_eq!(
        borsh::from_slice::<RoundChangeCertificate>(&encoded).unwrap(),
        report
    );
    let proposal = proposal();
    let encoded = borsh::to_vec(&proposal).unwrap();
    assert_eq!(dictionary_count(&encoded), 1);
    assert_eq!(
        borsh::from_slice::<BftProposal>(&encoded).unwrap(),
        proposal
    );
}

#[test]
fn finality_shares_one_dictionary_across_proposal_reports_and_both_phases() {
    let prevote = vote();
    let manifest = ProofManifest {
        proof_hashes: vec![[1; 32]],
    };
    let mut precommits = prevote.attestations.clone();
    for claim in &mut precommits {
        claim.vote.phase = FinalityVotePhase::Precommit;
        claim.proof_acceptance = Some(manifest.commitment());
    }
    let certificate = FinalityCert {
        proposal: proposal(),
        prevote_attestations: prevote.attestations,
        precommit_attestations: precommits,
        proof_manifests: vec![manifest],
        chunk_id: 0,
        round: 2,
        chunk_hash: chunk().hash(),
        active_validator_set_root: [8; 32],
        prevote: AggregatedVote {
            aggregation_bits: prevote.aggregation_bits.clone(),
            signature: [2; 96],
        },
        precommit: AggregatedVote {
            aggregation_bits: prevote.aggregation_bits,
            signature: [3; 96],
        },
    };
    let encoded = borsh::to_vec(&certificate).unwrap();
    assert_eq!(dictionary_count(&encoded), 1);
    assert_eq!(
        borsh::from_slice::<FinalityCert>(&encoded).unwrap(),
        certificate
    );
}

#[test]
fn distinct_exact_quorum_subsets_are_preserved() {
    let mut vote = vote();
    vote.attestations[1].unlock_quorum = Some(quorum(3));
    let encoded = borsh::to_vec(&vote).unwrap();
    assert_eq!(dictionary_count(&encoded), 2);
    assert_eq!(borsh::from_slice::<FinalityVote>(&encoded).unwrap(), vote);
    assert_ne!(quorum(3).commitment(), quorum(7).commitment());
    let mut altered = quorum(7);
    altered.aggregate.signature[0] ^= 1;
    assert_ne!(quorum(7).commitment(), altered.commitment());
}

#[test]
fn dictionary_rejects_missing_unused_duplicate_and_unsorted_entries() {
    let encoded = borsh::to_vec(&vote()).unwrap();
    let quorum_bytes = borsh::to_vec(&quorum(7)).unwrap();
    let tail = &encoded[4 + quorum_bytes.len()..];
    let mut missing = borsh::to_vec(&0_u32).unwrap();
    missing.extend_from_slice(tail);
    assert!(
        borsh::from_slice::<FinalityVote>(&missing)
            .unwrap_err()
            .to_string()
            .contains("missing shared quorum")
    );

    let original = quorum(7);
    let unused = quorum(3);
    let mut extra = Vec::new();
    DictionaryWriter::collect([&original, &unused], bft::MAX_BFT_SIGNERS)
        .unwrap()
        .write(&mut extra)
        .unwrap();
    extra.extend_from_slice(tail);
    assert!(
        borsh::from_slice::<FinalityVote>(&extra)
            .unwrap_err()
            .to_string()
            .contains("unused shared quorum")
    );

    let mut duplicate = borsh::to_vec(&2_u32).unwrap();
    duplicate.extend_from_slice(&quorum_bytes);
    duplicate.extend_from_slice(&quorum_bytes);
    assert_eq!(
        borsh::from_slice::<FinalityVote>(&duplicate)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );

    let mut entries = [original, unused];
    entries.sort_by_key(QuorumCertificate::commitment);
    let mut unsorted = borsh::to_vec(&2_u32).unwrap();
    unsorted.extend(borsh::to_vec(&entries[1]).unwrap());
    unsorted.extend(borsh::to_vec(&entries[0]).unwrap());
    assert_eq!(
        borsh::from_slice::<FinalityVote>(&unsorted)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn dictionary_count_and_bitmap_bounds_reject_before_payload_allocation() {
    let oversized = borsh::to_vec(&(bft::MAX_BFT_SIGNERS + 1)).unwrap();
    assert_eq!(
        borsh::from_slice::<FinalityVote>(&oversized)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    let mut bytes = borsh::to_vec(&1_u32).unwrap();
    bytes.extend(borsh::to_vec(&quorum(7).data).unwrap());
    let oversized_bits = bft::MAX_BFT_SIGNERS + 1;
    bytes.extend(borsh::to_vec(&oversized_bits).unwrap());
    bytes.extend(borsh::to_vec(&oversized_bits.div_ceil(8)).unwrap());
    assert!(
        borsh::from_slice::<FinalityVote>(&bytes)
            .unwrap_err()
            .to_string()
            .contains("bitmap exceeds transport bound")
    );
}

#[test]
fn compressed_references_cannot_amplify_unbounded_semantic_carriers() {
    let mut large = quorum(7);
    large.aggregate.aggregation_bits = BitVec::from_bytes(
        bft::MAX_BFT_SIGNERS,
        vec![0xff; usize::try_from(bft::MAX_BFT_SIGNERS.div_ceil(8)).unwrap()],
    )
    .unwrap();
    let references = MAX_DICTIONARY_BYTES / borsh::object_length(&large).unwrap() + 1;
    let mut bytes = Vec::new();
    DictionaryWriter::collect([&large], bft::MAX_BFT_SIGNERS)
        .unwrap()
        .write(&mut bytes)
        .unwrap();
    let base = vote();
    base.aggregation_bits.serialize(&mut bytes).unwrap();
    base.data.serialize(&mut bytes).unwrap();
    base.signature.serialize(&mut bytes).unwrap();
    u32::try_from(references)
        .unwrap()
        .serialize(&mut bytes)
        .unwrap();
    // Construct only compact wire references, without preallocating their
    // expanded certificate copies in the test fixture itself.
    let encoded_claim = borsh::to_vec(&(
        [2_u8; 96],
        0_u32,
        &base.data,
        Option::<crate::ProofAcceptanceCommitment>::None,
        Some(large.commitment()),
        [3_u8; 96],
    ))
    .unwrap();
    for _ in 0..references {
        bytes.extend_from_slice(&encoded_claim);
    }
    0_u32.serialize(&mut bytes).unwrap(); // No proof manifests.
    assert!(bytes.len() < MAX_DICTIONARY_BYTES);
    assert!(
        borsh::from_slice::<FinalityVote>(&bytes)
            .unwrap_err()
            .to_string()
            .contains("expanded quorum carriers")
    );
}

#[test]
fn signatures_bind_explicit_none_and_exact_full_carrier_hashes() {
    let present = claim(0, Some(quorum(7)));
    let absent = claim(0, None);
    let alternate = claim(0, Some(quorum(3)));
    assert_ne!(
        present.signing_message(DOMAIN),
        absent.signing_message(DOMAIN)
    );
    assert_ne!(
        present.signing_message(DOMAIN),
        alternate.signing_message(DOMAIN)
    );
    let report = reports().reports[0].clone();
    let mut alternate_report = report.clone();
    alternate_report.highest_quorum = Some(quorum(3));
    assert_ne!(
        report.signing_message(DOMAIN),
        alternate_report.signing_message(DOMAIN)
    );
    let proposal = proposal();
    let mut stripped = proposal.clone();
    stripped.round_change_certificate = None;
    assert_ne!(
        proposal.signing_message(DOMAIN),
        stripped.signing_message(DOMAIN)
    );
    stripped = proposal.clone();
    stripped.round_change_certificate.as_mut().unwrap().reports[0].highest_quorum = Some(quorum(3));
    assert_ne!(
        proposal.signing_message(DOMAIN),
        stripped.signing_message(DOMAIN)
    );
}
