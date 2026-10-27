use super::{FactUse, MAX_PREPROVED_REQUESTS, fit_cached_facts};
use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofError;
use neutrin0_prover_chunk::{
    evidence::MAX_EVIDENCE_FACT_STATEMENTS,
    facts::{FactStatement, MAX_FACTS, ProvenFact},
};
use std::collections::BTreeSet;

fn fact_id(index: usize) -> Hash {
    let mut id = [0; 32];
    id[..4].copy_from_slice(
        &u32::try_from(index)
            .expect("bounded test index")
            .to_le_bytes(),
    );
    id
}

fn statement(indices: impl IntoIterator<Item = usize>) -> FactStatement {
    FactStatement {
        facts: indices
            .into_iter()
            .map(|index| ProvenFact {
                id: fact_id(index),
                valid: index.is_multiple_of(2),
            })
            .collect(),
    }
}

#[test]
fn preproving_is_not_bounded_by_one_evidence_batch() {
    // A full preproving call alone fills a whole evidence batch's
    // statement budget, so any covering cached receipt exceeds it.
    // Preproving must still accept and cache everything it proves.
    assert!(FactUse::Preprove.admits(0, MAX_PREPROVED_REQUESTS));
    assert!(FactUse::Preprove.admits(1, MAX_PREPROVED_REQUESTS));
    assert!(FactUse::Preprove.admits(MAX_EVIDENCE_FACT_STATEMENTS, MAX_PREPROVED_REQUESTS));
    assert!(!FactUse::EvidenceBatch.admits(1, MAX_PREPROVED_REQUESTS));
}

#[test]
fn evidence_batches_keep_the_guest_statement_bound() {
    let full = MAX_EVIDENCE_FACT_STATEMENTS * MAX_FACTS;
    let batch = FactUse::EvidenceBatch;
    assert!(batch.admits(0, 0));
    assert!(batch.admits(0, full));
    assert!(!batch.admits(0, full + 1));
    assert!(batch.admits(MAX_EVIDENCE_FACT_STATEMENTS, 0));
    assert!(!batch.admits(MAX_EVIDENCE_FACT_STATEMENTS + 1, 0));
    // A partial statement still costs a whole statement.
    assert!(batch.admits(MAX_EVIDENCE_FACT_STATEMENTS - 1, MAX_FACTS));
    assert!(!batch.admits(MAX_EVIDENCE_FACT_STATEMENTS - 1, MAX_FACTS + 1));
}

#[test]
fn sparse_cached_receipts_leave_room_for_fresh_fact_groups() {
    let cached: Vec<_> = (0..MAX_EVIDENCE_FACT_STATEMENTS)
        .map(|index| statement([index]))
        .collect();
    let statements: Vec<_> = cached.iter().collect();
    let requested: BTreeSet<_> = (0..=MAX_EVIDENCE_FACT_STATEMENTS).map(fact_id).collect();
    let (retained, missing) =
        fit_cached_facts(&requested, &statements, FactUse::EvidenceBatch).unwrap();
    assert_eq!(retained, MAX_EVIDENCE_FACT_STATEMENTS - 1);
    assert_eq!(
        missing,
        BTreeSet::from([
            fact_id(MAX_EVIDENCE_FACT_STATEMENTS - 1),
            fact_id(MAX_EVIDENCE_FACT_STATEMENTS),
        ])
    );
    assert!(FactUse::EvidenceBatch.admits(retained, missing.len()));
    // Explicit cached negative verdicts remain exact metadata. A dropped
    // receipt leaves its request missing so the fresh Guest rechecks it.
    assert!(!cached[MAX_EVIDENCE_FACT_STATEMENTS - 1].facts[0].valid);
    assert!(missing.contains(&cached[MAX_EVIDENCE_FACT_STATEMENTS - 1].facts[0].id));
}

#[test]
fn fresh_packing_still_fits_when_every_sparse_cached_receipt_must_be_dropped() {
    let cached: Vec<_> = (0..MAX_EVIDENCE_FACT_STATEMENTS)
        .map(|index| statement([index]))
        .collect();
    let statements: Vec<_> = cached.iter().collect();
    let full = MAX_EVIDENCE_FACT_STATEMENTS * MAX_FACTS;
    let requested: BTreeSet<_> = (0..full).map(fact_id).collect();
    let (retained, missing) =
        fit_cached_facts(&requested, &statements, FactUse::EvidenceBatch).unwrap();
    assert_eq!(retained, 0);
    assert_eq!(missing, requested);
    assert!(FactUse::EvidenceBatch.admits(retained, missing.len()));
}

#[test]
fn dense_prefix_is_reused_and_only_truly_oversized_fact_sets_are_rejected() {
    let mut cached = vec![statement(0..MAX_FACTS)];
    cached.extend(
        (MAX_FACTS..MAX_FACTS + MAX_EVIDENCE_FACT_STATEMENTS - 1).map(|index| statement([index])),
    );
    let statements: Vec<_> = cached.iter().collect();
    let full = MAX_EVIDENCE_FACT_STATEMENTS * MAX_FACTS;
    let requested: BTreeSet<_> = (0..full).map(fact_id).collect();
    let (retained, missing) =
        fit_cached_facts(&requested, &statements, FactUse::EvidenceBatch).unwrap();
    assert_eq!(retained, 1);
    assert_eq!(missing, (MAX_FACTS..full).map(fact_id).collect());

    let oversized: BTreeSet<_> = (0..=full).map(fact_id).collect();
    assert_eq!(
        fit_cached_facts(&oversized, &statements, FactUse::EvidenceBatch),
        Err(ProofError::InvalidWitness)
    );
    let (retained, missing) = fit_cached_facts(&oversized, &statements, FactUse::Preprove).unwrap();
    assert_eq!(retained, statements.len());
    assert_eq!(
        missing,
        (MAX_FACTS + MAX_EVIDENCE_FACT_STATEMENTS - 1..=full)
            .map(fact_id)
            .collect()
    );
}
