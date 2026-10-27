use super::*;

#[test]
fn proving_input_envelope_bound_is_authenticated_and_fail_closed() {
    let mut anchor = EvidenceAnchor::default();
    let commitment_before = commitment(&anchor);
    assert!(anchor.accepts_proving_input_size(anchor.max_block_proving_input_bytes));
    assert!(!anchor.accepts_proving_input_size(anchor.max_block_proving_input_bytes + 1));
    anchor.max_block_proving_input_bytes += 1;
    assert_ne!(commitment(&anchor), commitment_before);
    anchor.max_block_proving_input_bytes = 0;
    assert!(!anchor.accepts_proving_input_size(0));
    anchor.max_block_proving_input_bytes = EvidenceAnchor::MAX_PROVING_INPUT_BYTES + 1;
    assert!(!anchor.is_well_formed());
}

fn artifact() -> EvidenceArtifact {
    let mut artifact = EvidenceArtifact {
        membership: EvidenceMembership::default(),
        evidence_guest_vk_digest: [2; 8],
        statement: EvidenceStatement {
            reporter: None,
            chain_id: 7,
            chain_spec_hash: [3; 32],
            block_guest_vk_digest: [1; 8],
            context: EvidenceContext {
                source_runtime_code_hash: [0; 32],
                source_block_guest_vk_digest: [1; 8],
                chunk_id: 0,
                chunk_hash: [4; 32],
                end_height: 1,
                validators_root: [5; 32],
                seed: [6; 32],
                start_boundary: [9; 32],
            },
            offender: Validator {
                pubkey: [7; 48],
                withdrawal_credentials: neutrin0_primitives::runtime_account([8; 20]),
                effective_stake: 100,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
            },
            kind: SanctionKind::Slash,
            offence_id: [9; 32],
            facts_commitment: [10; 32],
        },
        proof_bytes: alloc::vec![1],
    };
    artifact.membership =
        EvidenceMembership::build(core::slice::from_ref(&artifact.statement), 0, [3; 8]).unwrap();
    artifact
}

#[test]
fn statement_identity_binds_program_and_facts_but_not_proof_encoding() {
    let original = artifact();
    let mut alternate = original.clone();
    alternate.proof_bytes.push(2);
    assert_eq!(original.statement_id(), alternate.statement_id());
    alternate.evidence_guest_vk_digest[0] ^= 1;
    assert_ne!(original.statement_id(), alternate.statement_id());
    assert!(!alternate.binds(
        &original.statement,
        &original.evidence_guest_vk_digest,
        &[3; 8]
    ));
    alternate = original.clone();
    alternate.statement.reporter = Some([42; 32]);
    assert_eq!(
        alternate.statement.offence_id,
        original.statement.offence_id
    );
    assert_eq!(
        alternate.statement.facts_commitment,
        original.statement.facts_commitment
    );
    assert_ne!(alternate.statement_id(), original.statement_id());
    assert!(!alternate.membership.binds(&alternate.statement, &[3; 8]));
    alternate = original.clone();
    alternate.statement.facts_commitment[0] ^= 1;
    assert_ne!(original.statement_id(), alternate.statement_id());
    assert!(!alternate.binds(
        &original.statement,
        &original.evidence_guest_vk_digest,
        &[3; 8]
    ));
}

#[test]
fn reports_roundtrip_with_bounded_proof_and_history_decoding() {
    let artifact = artifact();
    let report = EvidenceReport {
        history: crate::history::HistoryPath::build(&[commitment(&artifact.statement.context)], 0)
            .unwrap(),
        artifact,
    };
    let bytes = borsh::to_vec(&report).unwrap();
    assert_eq!(borsh::from_slice::<EvidenceReport>(&bytes).unwrap(), report);
    let mut no_history = borsh::to_vec(&report.artifact).unwrap();
    assert!(borsh::from_slice::<EvidenceReport>(&no_history).is_err());
    no_history.extend_from_slice(&0_u64.to_le_bytes());
    no_history.extend_from_slice(&1_u64.to_le_bytes());
    no_history.extend_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        borsh::from_slice::<EvidenceReport>(&no_history)
            .unwrap_err()
            .kind(),
        borsh::io::ErrorKind::InvalidData
    );
    for length in [
        0,
        u32::try_from(MAX_EVIDENCE_PROOF_BYTES).unwrap() + 1,
        u32::MAX,
    ] {
        let prefix = borsh::to_vec(&(
            &report.artifact.membership,
            report.artifact.evidence_guest_vk_digest,
            &report.artifact.statement,
            length,
        ))
        .unwrap();
        let error = borsh::from_slice::<EvidenceReport>(&prefix).unwrap_err();
        assert_eq!(error.kind(), borsh::io::ErrorKind::InvalidData);
    }
}

#[test]
fn consensus_body_commitments_and_transactions_do_not_contain_proof_bytes() {
    let original = artifact();
    let submission = EvidenceSubmission {
        statement: original.statement.clone(),
        history: crate::history::HistoryPath::default(),
    };
    let mut body = crate::Body {
        transactions: alloc::vec![borsh::to_vec(&submission).unwrap()],
        evidence_proofs: alloc::vec![original],
        ..crate::Body::default()
    };
    let original_body = body.clone();
    body.evidence_proofs[0].proof_bytes.push(2);
    assert!(body.same_consensus_content(&original_body));
    assert_ne!(
        borsh::to_vec(&body).unwrap(),
        borsh::to_vec(&original_body).unwrap()
    );
    body.transactions[0].push(0);
    assert!(!body.same_consensus_content(&original_body));
}

#[test]
fn historical_openings_bind_every_shape_count_and_position() {
    for count in 1..70 {
        let leaves: Vec<_> = (0..count)
            .map(|n| crate::tagged_commitment(b"leaf", &n))
            .collect();
        let root = counted_merkle_root(count as u64, merkle_root_from_hashes(leaves.clone()));
        for index in 0..count {
            let opening = MerkleOpening::build(&leaves, index).unwrap();
            assert!(opening.verify(leaves[index], root));
            let mut tampered = opening.clone();
            tampered.count += 1;
            assert!(!tampered.verify(leaves[index], root));
            let mut tampered = opening;
            tampered.siblings.push([0; 32]);
            assert!(!tampered.verify(leaves[index], root));
        }
    }
    assert!(!MerkleOpening::default().verify([0; 32], [0; 32]));
}

#[test]
fn liveness_window_includes_the_eighth_chunk_and_exact_block_age() {
    use crate::history::{HistoryPath, history_root};

    let mut statement = artifact().statement;
    statement.kind = SanctionKind::Inactivity;
    statement.context.end_height = 128;
    let mut leaves = alloc::vec![[0; 32]; 8];
    leaves[0] = commitment(&statement.context);
    let mut anchor = EvidenceAnchor {
        chain_spec_hash: statement.chain_spec_hash,
        chunk_id: 8,
        history_root: history_root(&leaves),
        block_guest_vk_digest: statement.block_guest_vk_digest,
        ..EvidenceAnchor::default()
    };
    let mut submission = EvidenceSubmission {
        statement,
        history: HistoryPath::build(&leaves, 0).unwrap(),
    };
    assert!(submission.binds(7, 1025, &anchor));
    assert!(submission.binds(7, 1153, &anchor));
    assert!(submission.within_age(1152, 1024));
    assert!(!submission.within_age(1153, 1024));
    assert!(submission.within_age(1153, 2048));

    leaves.push([1; 32]);
    anchor.chunk_id = 9;
    anchor.history_root = history_root(&leaves);
    submission.history = HistoryPath::build(&leaves, 0).unwrap();
    assert!(submission.history.verify(leaves[0], anchor.history_root));
    assert!(!submission.binds(7, 1153, &anchor));
}

#[test]
fn safety_claims_bind_to_any_finalized_chunk_regardless_of_age() {
    use crate::history::{HistoryPath, history_root};

    let mut statement = artifact().statement;
    statement.kind = SanctionKind::Slash;
    statement.context.end_height = 128;
    let mut leaves = alloc::vec![[0; 32]; 40];
    leaves[0] = commitment(&statement.context);
    let anchor = EvidenceAnchor {
        chain_spec_hash: statement.chain_spec_hash,
        chunk_id: 40,
        history_root: history_root(&leaves),
        block_guest_vk_digest: statement.block_guest_vk_digest,
        unbonding_delay_blocks: 6_000,
        chunk_size: 128,
        ..EvidenceAnchor::default()
    };
    assert!(anchor.is_well_formed());
    let submission = EvidenceSubmission {
        statement,
        history: HistoryPath::build(&leaves, 0).unwrap(),
    };
    // Chunk 0 is 40 chunks behind the anchor, far outside the eight-chunk
    // liveness window and older than the unbonding delay, yet a safety
    // claim still binds: whether it is admissible is decided by the
    // offender's remaining slashable balance, not by the signature's age.
    assert!(submission.binds(7, 5_128, &anchor));
    assert!(submission.binds(7, 1_000_000, &anchor));
    assert!(submission.within_age(1_000_000, 1));
    assert!(!submission.within_age(128, 1));
    let mut liveness = submission;
    liveness.statement.kind = SanctionKind::Inactivity;
    assert!(!liveness.binds(7, 5_128, &anchor));
    let mut tight = anchor;
    tight.unbonding_delay_blocks = 128;
    assert!(!tight.is_well_formed());
}
