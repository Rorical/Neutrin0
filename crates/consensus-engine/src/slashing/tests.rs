//! Detection and native-verification regression coverage.

use super::*;
use crate::ProposerKey;
use neutrin0_consensus_types::{
    AggregatedVote, FinalityVote, FinalityVoteData, FinalityVotePhase, LockEvidence,
};
use neutrin0_crypto::bls::{Signature, aggregate_signatures};
use neutrin0_primitives::{BitVec, BlsSignature, ConsensusDomain, Validator};

const DOMAIN: ConsensusDomain = ConsensusDomain::new(7, [9; 32]);

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn validators_with_keys(n: u8) -> Vec<Validator> {
    (0..n)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: neutrin0_primitives::runtime_account([0x33; 20]),
            effective_stake: 32_000_000_000_000_000_000,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect()
}

fn signed_header(
    proposer_index: ValidatorIndex,
    slot: Slot,
    state_root_byte: u8,
    signer: &ProposerKey,
) -> Header {
    let mut header = Header {
        height: 1,
        slot,
        parent_hash: [0xAA; 32],
        proposer_index,
        vrf_proof: [0; 96],
        state_root: [state_root_byte; 32],
        transactions_root: [0; 32],
        votes_root: [0; 32],
        da_root: [0; 32],
        runtime_extra: [0; 32],
        inputs_root: [0; 32],
        receipts_root: [0; 32],
        gas_used: 0,
        gas_limit: 1_000_000,
        timestamp: 0,
        signature: [0; 96],
    };
    let hash = header.hash();
    header.signature = signer.sign_proposer_message(DOMAIN, &hash);
    header
}

fn signed_indexed_vote(
    chunk_id: ChunkId,
    round: u32,
    phase: FinalityVotePhase,
    chunk_hash_byte: u8,
    signer: &ProposerKey,
) -> IndexedVote {
    let data = FinalityVoteData {
        chunk_id,
        round,
        chunk_hash: [chunk_hash_byte; 32],
        selection: crate::bft_loop::fixture_selection(),
        phase,
    };
    let signature: BlsSignature = signer.sign_finality_vote(DOMAIN, &data);
    IndexedVote { data, signature }
}

fn quorum_certificate_for_data(data: FinalityVoteData, signers: &[u8]) -> QuorumCertificate {
    let signatures: Vec<Signature> = signers
        .iter()
        .map(|signer| {
            let sig = proposer(*signer).sign_finality_vote(DOMAIN, &data);
            Signature::from_bytes(&sig).expect("test signature decodes")
        })
        .collect();
    let signature_refs: Vec<&Signature> = signatures.iter().collect();
    let signature = aggregate_signatures(&signature_refs)
        .expect("aggregate lock quorum signatures")
        .to_bytes();
    let mut aggregation_bits = BitVec::default();
    let max_signer = signers.iter().copied().max().unwrap_or(0);
    for index in 0..=max_signer {
        aggregation_bits.push(signers.contains(&index));
    }
    QuorumCertificate {
        data,
        aggregate: AggregatedVote {
            aggregation_bits,
            signature,
        },
    }
}

fn quorum_certificate_for(vote: &IndexedVote, signers: &[u8]) -> QuorumCertificate {
    quorum_certificate_for_data(
        FinalityVoteData {
            phase: FinalityVotePhase::Prevote,
            ..vote.data.clone()
        },
        signers,
    )
}

fn lock_evidence_for(vote: &IndexedVote, later: &IndexedVote, signers: &[u8]) -> LockEvidence {
    LockEvidence {
        locked_prevote_quorum: quorum_certificate_for(vote, signers),
        attestation: proposer(1).attest_vote(DOMAIN, later.data.clone(), Vec::new(), None),
    }
}

#[test]
fn record_header_detects_double_proposal_at_same_slot() {
    let v0 = proposer(0);
    let mut monitor = SlashingMonitor::new();
    let header_a = signed_header(0, 5, 0x11, &v0);
    let header_b = signed_header(0, 5, 0x22, &v0);
    assert!(monitor.record_header(0, &header_a).is_none());
    let evidence = monitor.record_header(0, &header_b).expect("equivocation");
    assert!(matches!(
        evidence,
        SlashingEvidence::DoubleProposal {
            proposer_index: 0,
            ..
        }
    ));
}

#[test]
fn record_header_ignores_exact_duplicates() {
    let v0 = proposer(0);
    let mut monitor = SlashingMonitor::new();
    let header = signed_header(0, 5, 0x11, &v0);
    assert!(monitor.record_header(0, &header).is_none());
    assert!(monitor.record_header(0, &header).is_none());
}

#[test]
fn record_header_does_not_trigger_across_different_slots() {
    let v0 = proposer(0);
    let mut monitor = SlashingMonitor::new();
    let header_a = signed_header(0, 5, 0x11, &v0);
    let header_b = signed_header(0, 6, 0x22, &v0);
    assert!(monitor.record_header(0, &header_a).is_none());
    assert!(monitor.record_header(0, &header_b).is_none());
}

/// Incrementally maintained byte totals equal a full recount.
fn assert_byte_totals(monitor: &SlashingMonitor) {
    fn recount<K, V: borsh::BorshSerialize>(map: &BTreeMap<K, V>) -> usize {
        map.values()
            .map(|value| borsh::object_length(value).unwrap())
            .sum()
    }
    assert_eq!(
        monitor.seen_bft_proposals.bytes(),
        recount(&monitor.seen_bft_proposals)
    );
    assert_eq!(monitor.attestations.bytes(), recount(&monitor.attestations));
    assert_eq!(
        monitor.observed_prevote_quorums.bytes(),
        recount(&monitor.observed_prevote_quorums)
    );
}

#[test]
fn authenticated_source_floor_prunes_all_observations_without_peer_watermarks() {
    let signer = proposer(0);
    let mut monitor = SlashingMonitor::new();
    for source in 0..=1 {
        let header = signed_header(0, u64::MAX - source, 0x11, &signer);
        assert!(monitor.record_header(source, &header).is_none());
        let vote = signed_indexed_vote(source, 0, FinalityVotePhase::Precommit, 0xAA, &signer);
        monitor.record_prevote_quorum(quorum_for_prevote_data(source, 0, 0xAA, &[0, 1]));
        monitor.record_attestation(signer.attest_vote(DOMAIN, vote.data.clone(), Vec::new(), None));
        assert!(monitor.record_indexed_vote(0, &vote).is_none());
    }
    assert_eq!(monitor.headers_tracked(), 2);
    assert_eq!(monitor.votes_tracked(), 2);
    assert_byte_totals(&monitor);
    monitor.retain_history_window(1);
    assert_eq!(monitor.headers_tracked(), 1);
    assert_eq!(monitor.votes_tracked(), 1);
    assert_eq!(monitor.observed_prevote_quorums.len(), 1);
    assert_eq!(monitor.attestations.len(), 1);
    assert_byte_totals(&monitor);
    assert!(monitor.observed_prevote_quorums.bytes() > 0 && monitor.attestations.bytes() > 0);
    let later = signed_indexed_vote(1, 2, FinalityVotePhase::Prevote, 0xBB, &signer);
    monitor.record_attestation(signer.attest_vote(DOMAIN, later.data.clone(), Vec::new(), None));
    assert!(matches!(
        monitor.record_indexed_vote(0, &later),
        Some(SlashingEvidence::LockViolation { .. })
    ));
    monitor.retain_history_window(2);
    assert_eq!(monitor.headers_tracked(), 0);
    assert_eq!(monitor.votes_tracked(), 0);
    assert!(monitor.observed_prevote_quorums.is_empty());
    assert!(monitor.attestations.is_empty());
    assert_byte_totals(&monitor);
    assert_eq!(
        monitor.observed_prevote_quorums.bytes() + monitor.attestations.bytes(),
        0
    );
}

#[test]
fn header_index_separates_authenticated_validator_contexts() {
    let signer = proposer(0);
    let mut monitor = SlashingMonitor::new();
    let first = signed_header(0, 5, 0x11, &signer);
    let second = signed_header(0, 5, 0x22, &signer);
    let third = signed_header(0, 5, 0x33, &signer);
    assert!(monitor.record_header(0, &first).is_none());
    assert!(monitor.record_header(1, &second).is_none());
    let SlashingEvidence::DoubleProposal {
        header_a, header_b, ..
    } = monitor.record_header(1, &third).unwrap()
    else {
        panic!("the same-source pair remains detectable");
    };
    assert_eq!(header_a, second);
    assert_eq!(header_b, third);
}

#[test]
fn record_indexed_vote_detects_double_prevote() {
    let v1 = proposer(1);
    let mut monitor = SlashingMonitor::new();
    let vote_a = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0x44, &v1);
    let vote_b = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0x55, &v1);
    assert!(monitor.record_indexed_vote(1, &vote_a).is_none());
    let evidence = monitor
        .record_indexed_vote(1, &vote_b)
        .expect("equivocation");
    assert!(matches!(
        evidence,
        SlashingEvidence::DoublePrevote {
            validator_index: 1,
            ..
        }
    ));
}

#[test]
fn record_indexed_vote_detects_double_precommit() {
    let v1 = proposer(1);
    let mut monitor = SlashingMonitor::new();
    let vote_a = signed_indexed_vote(3, 0, FinalityVotePhase::Precommit, 0x66, &v1);
    let vote_b = signed_indexed_vote(3, 0, FinalityVotePhase::Precommit, 0x77, &v1);
    assert!(monitor.record_indexed_vote(1, &vote_a).is_none());
    let evidence = monitor
        .record_indexed_vote(1, &vote_b)
        .expect("equivocation");
    assert!(matches!(
        evidence,
        SlashingEvidence::DoublePrecommit {
            validator_index: 1,
            ..
        }
    ));
}

#[test]
fn record_indexed_vote_keys_on_phase() {
    let v1 = proposer(1);
    let mut monitor = SlashingMonitor::new();
    let prevote = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0x88, &v1);
    let precommit = signed_indexed_vote(3, 0, FinalityVotePhase::Precommit, 0x99, &v1);
    assert!(monitor.record_indexed_vote(1, &prevote).is_none());
    assert!(monitor.record_indexed_vote(1, &precommit).is_none());
}

#[test]
fn extract_single_signer_returns_none_for_aggregated_vote() {
    let v0 = proposer(0);
    let data = FinalityVoteData {
        chunk_id: 1,
        round: 0,
        chunk_hash: [0; 32],
        selection: crate::bft_loop::fixture_selection(),
        phase: FinalityVotePhase::Prevote,
    };
    let mut bits = BitVec::default();
    bits.push(true);
    bits.push(true);
    bits.push(false);
    let vote = FinalityVote {
        proof_manifests: Vec::new(),
        attestations: Vec::new(),
        aggregation_bits: bits,
        data,
        signature: v0.sign_raw(b"junk").to_bytes(),
    };
    assert!(extract_single_signer(&vote, 3).is_none());
}

#[test]
fn extract_single_signer_returns_signer_for_partial_vote() {
    let v2 = proposer(2);
    let data = FinalityVoteData {
        chunk_id: 1,
        round: 0,
        chunk_hash: [0xAB; 32],
        selection: crate::bft_loop::fixture_selection(),
        phase: FinalityVotePhase::Prevote,
    };
    let mut bits = BitVec::default();
    bits.push(false);
    bits.push(false);
    bits.push(true);
    let signature = v2.sign_finality_vote(DOMAIN, &data);
    let vote = FinalityVote {
        proof_manifests: Vec::new(),
        attestations: Vec::new(),
        aggregation_bits: bits,
        data,
        signature,
    };
    let (signer, indexed) = extract_single_signer(&vote, 3).expect("single signer");
    assert_eq!(signer, 2);
    assert_eq!(indexed.signature, signature);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "Exercises every substitution of one signed proof-acceptance claim."
)]
fn exact_proof_opening_attribution_rejects_position_and_envelope_substitution() {
    let signer = proposer(1);
    let proof = neutrin0_consensus_types::BlockProof {
        height: 3,
        block_hash: [3; 32],
        prover_address: [13; 32],
        statement_key: [0; 32],
        proof_bytes: alloc::vec![4, 5],
        public_inputs: neutrin0_consensus_types::BlockProofPublicInputs {
            context: alloc::boxed::Box::default(),
            chain_id: 7,
            height: 3,
            parent_block_hash: [2; 32],
            block_hash: [3; 32],
            state_root_before: [4; 32],
            state_root_after: [5; 32],
            transactions_root: [6; 32],
            receipt_root: [7; 32],
            da_root: [8; 32],
            vm_code_hash: [9; 32],
            block_program: [10; 8],
            gas_used: 11,
            gas_limit: 12,
            proposer_address: [13; 32],
            runtime_extra: [14; 32],
            inputs_root: [0; 32],
        },
    };
    let manifest = neutrin0_consensus_types::ProofManifest {
        proof_hashes: alloc::vec![
            neutrin0_consensus_types::evidence::commitment(&proof),
            [15; 32]
        ],
    };
    let data = FinalityVoteData {
        chunk_id: 1,
        round: 0,
        chunk_hash: [16; 32],
        selection: crate::bft_loop::fixture_selection(),
        phase: FinalityVotePhase::Precommit,
    };
    let claim = signer.attest_vote(DOMAIN, data.clone(), manifest.proof_hashes.clone(), None);
    let vote = IndexedVote {
        signature: signer.sign_finality_vote(DOMAIN, &data),
        data,
    };
    let opening = manifest.opening(0).unwrap();
    let validators = validators_with_keys(2);
    assert!(
        verify_proof_signing_attribution(
            1,
            &vote,
            &claim,
            &proof,
            &opening,
            &validators,
            DOMAIN,
            2
        )
        .is_ok()
    );
    let mut substituted = proof.clone();
    substituted.proof_bytes.push(6);
    assert!(
        verify_proof_signing_attribution(
            1,
            &vote,
            &claim,
            &substituted,
            &opening,
            &validators,
            DOMAIN,
            2
        )
        .is_err()
    );
    substituted = proof.clone();
    substituted.height += 1;
    assert!(
        verify_proof_signing_attribution(
            1,
            &vote,
            &claim,
            &substituted,
            &opening,
            &validators,
            DOMAIN,
            2
        )
        .is_err()
    );
    assert!(
        verify_proof_signing_attribution(
            1,
            &vote,
            &claim,
            &proof,
            &manifest.opening(1).unwrap(),
            &validators,
            DOMAIN,
            2
        )
        .is_err()
    );
    assert!(
        verify_proof_signing_attribution(
            1,
            &vote,
            &claim,
            &proof,
            &opening,
            &validators,
            DOMAIN,
            1
        )
        .is_err()
    );
}

#[test]
fn verify_double_proposal_accepts_genuine_equivocation() {
    let v0 = proposer(0);
    let active_set = validators_with_keys(2);
    let header_a = signed_header(0, 5, 0x11, &v0);
    let header_b = signed_header(0, 5, 0x22, &v0);
    verify_double_proposal_evidence(0, &header_a, &header_b, &active_set, DOMAIN)
        .expect("genuine equivocation verifies");
}

#[test]
fn verify_double_proposal_rejects_matching_headers() {
    let v0 = proposer(0);
    let active_set = validators_with_keys(2);
    let header = signed_header(0, 5, 0x11, &v0);
    assert_eq!(
        verify_double_proposal_evidence(0, &header, &header, &active_set, DOMAIN),
        Err(SlashingError::NotEquivocating)
    );
}

#[test]
fn verify_double_proposal_rejects_mismatched_proposer_index() {
    let v0 = proposer(0);
    let active_set = validators_with_keys(2);
    let header_a = signed_header(0, 5, 0x11, &v0);
    let header_b = signed_header(0, 5, 0x22, &v0);
    assert_eq!(
        verify_double_proposal_evidence(1, &header_a, &header_b, &active_set, DOMAIN),
        Err(SlashingError::EvidenceFieldsInconsistent)
    );
}

#[test]
fn verify_double_proposal_rejects_tampered_signature() {
    let v0 = proposer(0);
    let active_set = validators_with_keys(2);
    let header_a = signed_header(0, 5, 0x11, &v0);
    let mut header_b = signed_header(0, 5, 0x22, &v0);
    header_b.signature[0] ^= 0x80;
    match verify_double_proposal_evidence(0, &header_a, &header_b, &active_set, DOMAIN) {
        Err(SlashingError::BadSignature | SlashingError::InvalidSignatureBytes) => {}
        other => panic!("expected signature failure, got {other:?}"),
    }
}

#[test]
fn verify_double_vote_accepts_genuine_equivocation() {
    let v1 = proposer(1);
    let active_set = validators_with_keys(2);
    let vote_a = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0xAA, &v1);
    let vote_b = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0xBB, &v1);
    verify_double_vote_evidence(
        1,
        FinalityVotePhase::Prevote,
        &vote_a,
        &vote_b,
        &active_set,
        DOMAIN,
    )
    .expect("genuine equivocation verifies");
}

#[test]
fn verify_double_vote_rejects_phase_mismatch() {
    let v1 = proposer(1);
    let active_set = validators_with_keys(2);
    let prevote = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0xCC, &v1);
    let precommit = signed_indexed_vote(3, 0, FinalityVotePhase::Precommit, 0xDD, &v1);
    assert_eq!(
        verify_double_vote_evidence(
            1,
            FinalityVotePhase::Prevote,
            &prevote,
            &precommit,
            &active_set,
            DOMAIN,
        ),
        Err(SlashingError::EvidenceFieldsInconsistent)
    );
}

#[test]
fn verify_double_vote_rejects_matching_chunk_hash() {
    let v1 = proposer(1);
    let active_set = validators_with_keys(2);
    let vote = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0xEE, &v1);
    assert_eq!(
        verify_double_vote_evidence(
            1,
            FinalityVotePhase::Prevote,
            &vote,
            &vote,
            &active_set,
            DOMAIN,
        ),
        Err(SlashingError::NotEquivocating)
    );
}

#[test]
fn verify_double_vote_rejects_wrong_signer_pubkey() {
    let v0 = proposer(0);
    let v1 = proposer(1);
    let active_set = validators_with_keys(2);
    // Forge: claim validator 0 signed, but signatures came from v1.
    let _ = v0;
    let vote_a = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0xFA, &v1);
    let vote_b = signed_indexed_vote(3, 0, FinalityVotePhase::Prevote, 0xFB, &v1);
    assert_eq!(
        verify_double_vote_evidence(
            0,
            FinalityVotePhase::Prevote,
            &vote_a,
            &vote_b,
            &active_set,
            DOMAIN,
        ),
        Err(SlashingError::BadSignature),
    );
}

#[test]
fn record_indexed_vote_does_not_emit_pair_only_lock_violation() {
    let v1 = proposer(1);
    let mut monitor = SlashingMonitor::new();
    let precommit_r0 = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
    let precommit_r1_other = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);

    assert!(monitor.record_indexed_vote(1, &precommit_r0).is_none());
    assert!(
        monitor
            .record_indexed_vote(1, &precommit_r1_other)
            .is_none(),
        "cross-round precommit pairs need lock quorum evidence before they are slashable"
    );
}

#[test]
fn record_indexed_vote_does_not_emit_pair_only_lock_violation_on_late_arrivals() {
    let v1 = proposer(1);
    let mut monitor = SlashingMonitor::new();
    let precommit_r3 = signed_indexed_vote(7, 3, FinalityVotePhase::Precommit, 0xAA, &v1);
    let precommit_r0_other = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xBB, &v1);

    assert!(monitor.record_indexed_vote(1, &precommit_r3).is_none());
    assert!(
        monitor
            .record_indexed_vote(1, &precommit_r0_other)
            .is_none()
    );
}

#[test]
fn record_indexed_vote_does_not_trigger_lock_violation_when_hashes_match_across_rounds() {
    let v1 = proposer(1);
    let mut monitor = SlashingMonitor::new();
    let precommit_r0 = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xCC, &v1);
    let precommit_r1_same = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xCC, &v1);
    assert!(monitor.record_indexed_vote(1, &precommit_r0).is_none());
    assert!(
        monitor.record_indexed_vote(1, &precommit_r1_same).is_none(),
        "re-precommitting the same chunk_hash at a later round is honest behaviour"
    );
}

#[test]
fn record_indexed_vote_prefers_double_precommit_for_same_round_conflict() {
    let v1 = proposer(1);
    let mut monitor = SlashingMonitor::new();
    let precommit_a = signed_indexed_vote(7, 4, FinalityVotePhase::Precommit, 0xAA, &v1);
    let precommit_b = signed_indexed_vote(7, 4, FinalityVotePhase::Precommit, 0xBB, &v1);
    assert!(monitor.record_indexed_vote(1, &precommit_a).is_none());
    let evidence = monitor
        .record_indexed_vote(1, &precommit_b)
        .expect("same-round equivocation");
    assert!(matches!(evidence, SlashingEvidence::DoublePrecommit { .. }));
}

#[test]
fn verify_lock_violation_accepts_genuine_cross_round_conflict() {
    let v1 = proposer(1);
    let active_set = validators_with_keys(2);
    let lock = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
    let violation = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);
    let evidence = lock_evidence_for(&lock, &violation, &[0, 1]);
    verify_lock_violation_evidence(1, &lock, &violation, &evidence, &active_set, DOMAIN, (2, 3))
        .expect("genuine cross-round lock violation verifies");
}

#[test]
fn verify_lock_violation_rejects_bad_lock_quorum_signature() {
    let v1 = proposer(1);
    let active_set = validators_with_keys(2);
    let lock = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
    let violation = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);
    let wrong_message = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xCC, &v1);
    let mut evidence = LockEvidence {
        locked_prevote_quorum: quorum_certificate_for(&wrong_message, &[0, 1]),
        attestation: v1.attest_vote(DOMAIN, violation.data.clone(), Vec::new(), None),
    };
    evidence.locked_prevote_quorum.data = FinalityVoteData {
        phase: FinalityVotePhase::Prevote,
        ..lock.data
    };

    assert_eq!(
        verify_lock_violation_evidence(
            1,
            &lock,
            &violation,
            &evidence,
            &active_set,
            DOMAIN,
            (2, 3)
        ),
        Err(SlashingError::BadSignature)
    );
}

#[test]
fn verify_lock_violation_rejects_valid_unlock_quorum() {
    let v1 = proposer(1);
    let active_set = validators_with_keys(2);
    let lock = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
    let violation = signed_indexed_vote(7, 2, FinalityVotePhase::Precommit, 0xBB, &v1);
    let unlock = quorum_certificate_for_data(
        FinalityVoteData {
            chunk_id: violation.data.chunk_id,
            round: 1,
            chunk_hash: violation.data.chunk_hash,
            selection: crate::bft_loop::fixture_selection(),
            phase: FinalityVotePhase::Prevote,
        },
        &[0, 1],
    );
    let mut evidence = lock_evidence_for(&lock, &violation, &[0, 1]);
    evidence.attestation = v1.attest_vote(DOMAIN, violation.data.clone(), Vec::new(), Some(unlock));

    assert_eq!(
        verify_lock_violation_evidence(
            1,
            &lock,
            &violation,
            &evidence,
            &active_set,
            DOMAIN,
            (2, 3)
        ),
        Err(SlashingError::EvidenceFieldsInconsistent)
    );
}

#[test]
fn verify_lock_violation_rejects_same_round_and_matching_hash() {
    let v1 = proposer(1);
    let active_set = validators_with_keys(2);
    let a = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
    let b_same_round = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xBB, &v1);
    let evidence = lock_evidence_for(&a, &b_same_round, &[0, 1]);
    assert_eq!(
        verify_lock_violation_evidence(
            1,
            &a,
            &b_same_round,
            &evidence,
            &active_set,
            DOMAIN,
            (2, 3)
        ),
        Err(SlashingError::EvidenceFieldsInconsistent),
        "same round + different hash is DoublePrecommit territory, not LockViolation"
    );
    let b_same_hash = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xAA, &v1);
    assert_eq!(
        verify_lock_violation_evidence(1, &a, &b_same_hash, &evidence, &active_set, DOMAIN, (2, 3)),
        Err(SlashingError::NotEquivocating)
    );
}

#[test]
fn verify_lock_violation_rejects_prevote_payloads() {
    let v1 = proposer(1);
    let active_set = validators_with_keys(2);
    let prevote = signed_indexed_vote(7, 0, FinalityVotePhase::Prevote, 0xAA, &v1);
    let precommit = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);
    let evidence = lock_evidence_for(&precommit, &precommit, &[0, 1]);
    assert_eq!(
        verify_lock_violation_evidence(
            1,
            &prevote,
            &precommit,
            &evidence,
            &active_set,
            DOMAIN,
            (2, 3)
        ),
        Err(SlashingError::EvidenceFieldsInconsistent),
        "LockViolation requires two precommits"
    );
}

#[test]
fn verify_lock_violation_rejects_wrong_signer_pubkey() {
    let v1 = proposer(1);
    let active_set = validators_with_keys(2);
    let lock = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
    let violation = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);
    let evidence = lock_evidence_for(&lock, &violation, &[0, 1]);
    // Claim the offender is validator 0 but the signatures are
    // from validator 1.
    assert_eq!(
        verify_lock_violation_evidence(
            0,
            &lock,
            &violation,
            &evidence,
            &active_set,
            DOMAIN,
            (2, 3)
        ),
        Err(SlashingError::BadSignature)
    );
}

// -----------------------------------------------------------
// LockViolation synthesis
// -----------------------------------------------------------

fn quorum_for_prevote_data(
    chunk_id: ChunkId,
    round: u32,
    chunk_hash: u8,
    signers: &[u8],
) -> QuorumCertificate {
    quorum_certificate_for_data(
        FinalityVoteData {
            chunk_id,
            round,
            chunk_hash: [chunk_hash; 32],
            selection: crate::bft_loop::fixture_selection(),
            phase: FinalityVotePhase::Prevote,
        },
        signers,
    )
}

#[test]
fn record_indexed_vote_synthesises_lock_violation_when_lock_quorum_present() {
    // Validator 1 precommits chunk_hash 0xAA at round 0 alongside
    // an observed prevote quorum at the same key (the "lock"),
    // then precommits chunk_hash 0xBB at round 1 with no
    // observed unlock quorum.
    let v1 = proposer(1);
    let mut monitor = SlashingMonitor::new();

    monitor.record_prevote_quorum(quorum_for_prevote_data(7, 0, 0xAA, &[0, 1]));
    let lock_precommit = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
    assert!(monitor.record_indexed_vote(1, &lock_precommit).is_none());

    let conflicting = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);
    monitor.record_attestation(v1.attest_vote(DOMAIN, conflicting.data.clone(), Vec::new(), None));
    let evidence = monitor
        .record_indexed_vote(1, &conflicting)
        .expect("lock violation evidence emitted");
    match evidence {
        SlashingEvidence::LockViolation {
            validator_index,
            vote_a,
            vote_b,
            lock_evidence,
        } => {
            assert_eq!(validator_index, 1);
            assert_eq!(vote_a.data.round, 0);
            assert_eq!(vote_a.data.chunk_hash, [0xAA; 32]);
            assert_eq!(vote_b.data.round, 1);
            assert_eq!(vote_b.data.chunk_hash, [0xBB; 32]);
            assert_eq!(lock_evidence.locked_prevote_quorum.data.round, 0);
            assert!(lock_evidence.attestation.unlock_quorum.is_none());
        }
        other => panic!("expected LockViolation, got {other:?}"),
    }
}

#[test]
fn record_indexed_vote_synthesises_lock_violation_when_quorum_observed_first() {
    // Same scenario as above but the lock quorum is observed
    // BEFORE either precommit — confirms the cache survives
    // arbitrary observation order.
    let v1 = proposer(1);
    let mut monitor = SlashingMonitor::new();

    monitor.record_prevote_quorum(quorum_for_prevote_data(7, 0, 0xAA, &[0, 1]));
    let lock_precommit = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
    let conflicting = signed_indexed_vote(7, 5, FinalityVotePhase::Precommit, 0xBB, &v1);

    assert!(monitor.record_indexed_vote(1, &lock_precommit).is_none());
    monitor.record_attestation(v1.attest_vote(DOMAIN, conflicting.data.clone(), Vec::new(), None));
    let evidence = monitor
        .record_indexed_vote(1, &conflicting)
        .expect("lock violation evidence emitted");
    assert!(matches!(evidence, SlashingEvidence::LockViolation { .. }));
}

#[test]
fn record_indexed_vote_skips_lock_violation_when_unlock_quorum_intervenes() {
    // Validator switches their precommit from 0xAA → 0xBB across
    // rounds 0 → 2 with an HONEST prevote quorum for 0xBB at
    // round 1 in between. The cross-round detector must NOT
    // emit a LockViolation because the unlock was legitimate.
    let v1 = proposer(1);
    let mut monitor = SlashingMonitor::new();

    // Locked prevote quorum at round 0 for 0xAA.
    monitor.record_prevote_quorum(quorum_for_prevote_data(7, 0, 0xAA, &[0, 1]));
    // Honest unlock prevote quorum at round 1 for 0xBB.
    monitor.record_prevote_quorum(quorum_for_prevote_data(7, 1, 0xBB, &[0, 1]));

    let lock_precommit = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
    let switched = signed_indexed_vote(7, 2, FinalityVotePhase::Precommit, 0xBB, &v1);

    assert!(monitor.record_indexed_vote(1, &lock_precommit).is_none());
    assert!(
        monitor.record_indexed_vote(1, &switched).is_none(),
        "honest unlock must not synthesise LockViolation",
    );
}

#[test]
fn record_indexed_vote_skips_lock_violation_when_lock_quorum_arrives_after_both_precommits() {
    // Soundness side of the soundness/completeness trade-off:
    // a lock quorum observed strictly AFTER both precommits
    // does not retroactively trigger the detector. Documented
    // behaviour — see the module docstring.
    let v1 = proposer(1);
    let mut monitor = SlashingMonitor::new();

    let lock_precommit = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
    let conflicting = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);

    assert!(monitor.record_indexed_vote(1, &lock_precommit).is_none());
    assert!(monitor.record_indexed_vote(1, &conflicting).is_none());

    // Lock quorum observed AFTER the conflicting precommit.
    monitor.record_prevote_quorum(quorum_for_prevote_data(7, 0, 0xAA, &[0, 1]));
    // No retroactive emission.
}

#[test]
fn synthesised_lock_violation_passes_engine_verifier() {
    // Round-trip: the cross-round detector emits evidence the
    // shared verifier accepts. Confirms our synthesised
    // LockEvidence shape is compatible with
    // `verify_lock_violation_evidence`.
    let v1 = proposer(1);
    let active_set = validators_with_keys(2);
    let mut monitor = SlashingMonitor::new();

    monitor.record_prevote_quorum(quorum_for_prevote_data(7, 0, 0xAA, &[0, 1]));
    let lock_precommit = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
    let conflicting = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);

    monitor.record_indexed_vote(1, &lock_precommit);
    monitor.record_attestation(v1.attest_vote(DOMAIN, conflicting.data.clone(), Vec::new(), None));
    let evidence = monitor
        .record_indexed_vote(1, &conflicting)
        .expect("evidence emitted");
    let SlashingEvidence::LockViolation {
        validator_index,
        vote_a,
        vote_b,
        lock_evidence,
    } = evidence
    else {
        panic!("expected LockViolation");
    };
    verify_lock_violation_evidence(
        validator_index,
        &vote_a,
        &vote_b,
        &lock_evidence,
        &active_set,
        DOMAIN,
        (2, 3),
    )
    .expect("synthesised LockViolation evidence passes verifier");
}

#[test]
fn record_prevote_quorum_ignores_non_prevote_phase() {
    // The cache only exists to gate LockViolation synthesis;
    // accepting a precommit-tagged quorum would be a programmer
    // error and should be silently ignored.
    let mut monitor = SlashingMonitor::new();
    let precommit_tagged = quorum_certificate_for_data(
        FinalityVoteData {
            chunk_id: 7,
            round: 0,
            chunk_hash: [0xAA; 32],
            selection: crate::bft_loop::fixture_selection(),
            phase: FinalityVotePhase::Precommit,
        },
        &[0, 1],
    );
    monitor.record_prevote_quorum(precommit_tagged);

    let v1 = proposer(1);
    let lock_precommit = signed_indexed_vote(7, 0, FinalityVotePhase::Precommit, 0xAA, &v1);
    let conflicting = signed_indexed_vote(7, 1, FinalityVotePhase::Precommit, 0xBB, &v1);
    monitor.record_indexed_vote(1, &lock_precommit);
    assert!(
        monitor.record_indexed_vote(1, &conflicting).is_none(),
        "non-prevote 'quorum' must not enable LockViolation synthesis",
    );
}

// -----------------------------------------------------------
// Double votes over one chunk's selections
// -----------------------------------------------------------

fn signed_vote_for_chunk(chunk_id: u64, hash: [u8; 32], key: &ProposerKey) -> IndexedVote {
    let data = FinalityVoteData {
        chunk_id,
        round: 0,
        chunk_hash: hash,
        selection: crate::bft_loop::fixture_selection(),
        phase: FinalityVotePhase::Precommit,
    };
    let signature = key.sign_finality_vote(DOMAIN, &data);
    IndexedVote { data, signature }
}

#[test]
fn two_selections_of_one_chunk_in_a_round_are_a_double_vote() {
    // A value is the chunk with its payment selection (design 08): signing
    // the same chunk under another selection in one round equivocates.
    let key = proposer(1);
    let validators = validators_with_keys(2);
    let vote_a = signed_vote_for_chunk(5, [0xDD; 32], &key);
    let mut data = vote_a.data.clone();
    data.selection = [0x11; 32];
    let vote_b = IndexedVote {
        signature: key.sign_finality_vote(DOMAIN, &data),
        data,
    };
    let mut monitor = SlashingMonitor::new();
    assert_eq!(monitor.record_indexed_vote(1, &vote_a), None);
    assert!(matches!(
        monitor.record_indexed_vote(1, &vote_b),
        Some(SlashingEvidence::DoublePrecommit { .. })
    ));
    assert_eq!(
        verify_double_vote_evidence(
            1,
            FinalityVotePhase::Precommit,
            &vote_a,
            &vote_b,
            &validators,
            DOMAIN
        ),
        Ok(())
    );
    assert_eq!(
        verify_double_vote_evidence(
            1,
            FinalityVotePhase::Precommit,
            &vote_a,
            &vote_a,
            &validators,
            DOMAIN
        ),
        Err(SlashingError::NotEquivocating)
    );
}

#[test]
fn a_leader_proposing_one_chunk_with_two_selections_equivocates() {
    let chunk = neutrin0_consensus_types::Chunk {
        chunk_id: 3,
        start_height: 1,
        end_height: 4,
        start_state_root: [1; 32],
        end_state_root: [2; 32],
        start_block_hash: [3; 32],
        end_block_hash: [4; 32],
        block_hash_root: [5; 32],
        block_proof_root: [6; 32],
        vrf_proof_root: [7; 32],
        active_validator_set_root: [8; 32],
        next_validator_set_root: [9; 32],
        next_identity_sanctions_root: [10; 32],
        da_root: [11; 32],
    };
    let proposal = neutrin0_consensus_types::BftProposal {
        chunk,
        round: 0,
        proposer_index: 0,
        valid_quorum: None,
        round_change_certificate: None,
        proposal_slot: 40,
        receipts: Vec::new(),
        ratified_chunk_proofs: Vec::new(),
        signature: [0; 96],
    };
    let mut monitor = SlashingMonitor::new();
    assert!(monitor.record_bft_proposal(&proposal).is_none());
    assert!(monitor.record_bft_proposal(&proposal).is_none());
    let mut reselected = proposal.clone();
    reselected.proposal_slot = 41;
    assert!(matches!(
        monitor.record_bft_proposal(&reselected),
        Some(SlashingEvidence::DoubleBftProposal { .. })
    ));
}
