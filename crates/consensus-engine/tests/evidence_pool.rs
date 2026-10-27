//! Storage invariants; marker receipts here test persistence, not authentication.
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use neutrin0_consensus_engine::store::ChainStore;
use neutrin0_consensus_types::evidence::{
    EvidenceArtifact, EvidenceContext, EvidenceReport, EvidenceStatement, MAX_EVIDENCE_PROOF_BYTES,
    SanctionKind,
};
use neutrin0_storage::{Column, Database, MemoryDatabase};

fn artifact(id: u64) -> EvidenceArtifact {
    let (witness, _, _) = support::fixture([1; 8], [4; 32]);
    let mut offence_id = [0; 32];
    offence_id[..8].copy_from_slice(&id.to_le_bytes());
    EvidenceArtifact {
        membership: neutrin0_consensus_types::evidence::EvidenceMembership::default(),
        evidence_guest_vk_digest: [2; 8],
        statement: EvidenceStatement {
            reporter: None,
            chain_id: 7,
            chain_spec_hash: witness.chain_spec.hash(),
            block_guest_vk_digest: [1; 8],
            context: EvidenceContext {
                source_runtime_code_hash: witness.context.programs.runtime_code_hash,
                source_block_guest_vk_digest: [1; 8],
                chunk_id: 0,
                chunk_hash: [3; 32],
                end_height: 1,
                validators_root: witness.chain_spec.genesis_validator_set_root,
                seed: [0; 32],
                start_boundary: [0; 32],
            },
            offender: witness.context.active_validators[0].clone(),
            kind: SanctionKind::Slash,
            offence_id,
            facts_commitment: [5; 32],
        },
        proof_bytes: vec![1],
    }
}

fn report(artifact: &EvidenceArtifact) -> EvidenceReport {
    let leaf = neutrin0_consensus_types::evidence::commitment(&artifact.statement.context);
    EvidenceReport {
        artifact: artifact.clone(),
        history: neutrin0_consensus_types::history::HistoryPath::build(&[leaf], 0).unwrap(),
    }
}

#[test]
fn verified_pool_survives_restart_preserves_first_receipt_and_expires_at_finality() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let mut original = artifact(1);
    original.statement.kind = SanctionKind::Inactivity;
    store.put_evidence_report(&report(&original)).unwrap();
    let mut alternate = original.clone();
    alternate.proof_bytes.push(2);
    store.put_evidence_report(&report(&alternate)).unwrap();
    let mut restarted = ChainStore::new(store.into_db());
    assert_eq!(
        restarted.evidence_artifacts().unwrap(),
        vec![original.clone()]
    );
    restarted.prune_evidence_artifacts(10, 10, &[]).unwrap();
    assert_eq!(restarted.evidence_artifacts().unwrap(), vec![original]);
    restarted.prune_evidence_artifacts(11, 10, &[]).unwrap();
    assert_eq!(
        restarted.evidence_artifacts().unwrap(),
        [] as [EvidenceArtifact; 0]
    );
}

#[test]
fn safety_receipts_never_age_out_but_leave_once_their_identity_is_finalized_slashed() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let safety = artifact(1);
    store.put_evidence_report(&report(&safety)).unwrap();
    // A million blocks past the source chunk the receipt is still pooled: a
    // safety claim has no age window.
    store.prune_evidence_artifacts(1_000_000, 10, &[]).unwrap();
    assert_eq!(store.evidence_artifacts().unwrap(), vec![safety.clone()]);
    store
        .db_mut()
        .put(
            Column::FinalizedSlashes,
            &safety.statement.offender.pubkey,
            &1_u64.to_be_bytes(),
        )
        .unwrap();
    store.prune_evidence_artifacts(1_000_000, 10, &[]).unwrap();
    assert_eq!(
        store.evidence_artifacts().unwrap(),
        [] as [EvidenceArtifact; 0]
    );
}

#[test]
fn persistent_pool_enforces_receipt_and_entry_bounds() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let mut item = artifact(0);
    item.proof_bytes = vec![0; MAX_EVIDENCE_PROOF_BYTES + 1];
    assert!(store.put_evidence_report(&report(&item)).is_err());
    item.proof_bytes = vec![1];
    for id in 0_u64..256 {
        item.statement.offence_id[..8].copy_from_slice(&id.to_le_bytes());
        store.put_evidence_report(&report(&item)).unwrap();
    }
    item.statement.offence_id[..8].copy_from_slice(&256_u64.to_le_bytes());
    assert!(store.put_evidence_report(&report(&item)).is_err());
    assert_eq!(store.evidence_artifacts().unwrap().len(), 256);
    store
        .db_mut()
        .put(Column::FinalizedOffences, &[0; 32], &1_u64.to_be_bytes())
        .unwrap();
    store.prune_evidence_artifacts(1, 1024, &[]).unwrap();
    store.put_evidence_report(&report(&item)).unwrap();
    assert_eq!(store.evidence_artifacts().unwrap().len(), 256);
}

#[test]
fn finalization_releases_cache_capacity_without_discarding_reorg_candidates() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let original = artifact(1);
    let pending = artifact(2);
    store.put_evidence_report(&report(&original)).unwrap();
    store.put_evidence_report(&report(&pending)).unwrap();
    // The index receives admissions only in the proof-gated finalization batch.
    // A receipt consumed merely on the materialized head remains recoverable.
    store
        .db_mut()
        .put(
            Column::FinalizedOffences,
            &original.statement.offence_id,
            &1_u64.to_be_bytes(),
        )
        .unwrap();
    let mut store = ChainStore::new(store.into_db());
    store.prune_evidence_artifacts(1, 1024, &[]).unwrap();
    assert_eq!(store.evidence_artifacts().unwrap(), vec![pending]);
}

#[test]
fn finalized_safety_sanction_releases_every_receipt_against_the_identity() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let first = artifact(1);
    let mut second = artifact(2);
    second.statement.facts_commitment = [6; 32];
    let mut liveness = artifact(3);
    liveness.statement.kind = SanctionKind::Inactivity;
    for item in [&first, &second, &liveness] {
        store.put_evidence_report(&report(item)).unwrap();
    }
    let identity = first.statement.offender.pubkey;
    assert!(!store.is_identity_slashed(&identity).unwrap());
    assert!(!store.is_receipt_finalized(&second.statement).unwrap());
    // The finalization batch records the sanctioned identity, not only the
    // admitted offence: the tombstone outlives the safety window, so no other
    // safety receipt against the key can ever be admitted.
    store
        .db_mut()
        .put(Column::FinalizedSlashes, &identity, &1_u64.to_be_bytes())
        .unwrap();
    assert!(store.is_identity_slashed(&identity).unwrap());
    assert!(store.is_receipt_finalized(&second.statement).unwrap());
    assert!(!store.is_receipt_finalized(&liveness.statement).unwrap());
    store.prune_evidence_artifacts(1, 1024, &[]).unwrap();
    assert_eq!(store.evidence_artifacts().unwrap(), vec![liveness]);
}

#[test]
fn pool_identity_is_scoped_to_program_and_exact_statement() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let original = artifact(1);
    let mut other_program = original.clone();
    other_program.evidence_guest_vk_digest[0] ^= 1;
    let mut other_statement = original.clone();
    other_statement.statement.facts_commitment[0] ^= 1;
    for item in [&original, &other_program, &other_statement] {
        store.put_evidence_report(&report(item)).unwrap();
    }
    assert_eq!(store.evidence_artifacts().unwrap().len(), 3);
    store
        .db_mut()
        .put(
            Column::FinalizedOffences,
            &original.statement.offence_id,
            &1_u64.to_be_bytes(),
        )
        .unwrap();
    store.prune_evidence_artifacts(1, 1024, &[]).unwrap();
    assert_eq!(
        store.evidence_artifacts().unwrap(),
        [] as [EvidenceArtifact; 0]
    );
}

#[test]
fn attachment_bytes_do_not_change_roots_and_survive_body_archive() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let original = artifact(1);
    let mut body = neutrin0_consensus_types::Body {
        transactions: vec![
            borsh::to_vec(&neutrin0_runtime_abi::RuntimeTransaction::SubmitEvidence(
                Box::new(neutrin0_consensus_types::evidence::EvidenceSubmission {
                    statement: original.statement.clone(),
                    history: neutrin0_consensus_types::history::HistoryPath {
                        index: 0,
                        count: 1,
                        siblings: vec![[0; 32]; 64],
                    },
                }),
            ))
            .unwrap(),
        ],
        evidence_proofs: vec![original],
        ..neutrin0_consensus_types::Body::default()
    };
    let roots = neutrin0_consensus_engine::body::compute_body_roots(&body);
    body.evidence_proofs[0].proof_bytes.push(2);
    assert_eq!(
        neutrin0_consensus_engine::body::compute_body_roots(&body),
        roots
    );
    store.put_body(&[7; 32], &body).unwrap();
    let reopened = ChainStore::new(store.into_db());
    assert_eq!(reopened.get_body(&[7; 32]).unwrap(), Some(body));
}

#[test]
fn receipts_under_replaced_programs_leave_while_usable_ones_stay() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let current = artifact(1);
    let mut replaced = artifact(2);
    replaced.evidence_guest_vk_digest = [9; 8];
    for item in [&current, &replaced] {
        store.put_evidence_report(&report(item)).unwrap();
    }
    let usable = neutrin0_primitives::ExecutionPrograms {
        fact: current.membership.batch.fact_guest_vk_digest,
        evidence: current.evidence_guest_vk_digest,
        block: current.statement.block_guest_vk_digest,
    };
    store.prune_evidence_artifacts(1, 1024, &[usable]).unwrap();
    assert_eq!(store.evidence_artifacts().unwrap(), vec![current]);
}
