use super::{attached_fact_coverage, publish_successful_coverage};
use neutrin0_proof_system::ProofError;
use neutrin0_prover_chunk::{
    consensus::MAX_CONSENSUS_FACT_STATEMENTS,
    facts::{FactStatement, ProvenFact},
};
use std::{collections::BTreeSet, sync::Mutex};

#[test]
fn discarded_receipts_do_not_count_as_attached_coverage() {
    let statements: Vec<_> = (0..MAX_CONSENSUS_FACT_STATEMENTS + 8)
        .map(|index| FactStatement {
            facts: vec![ProvenFact {
                id: neutrin0_primitives::blake3_256(&index.to_le_bytes()),
                valid: true,
            }],
        })
        .collect();
    let requested = statements
        .iter()
        .map(|statement| statement.facts[0].id)
        .collect();
    let attached = &statements[..MAX_CONSENSUS_FACT_STATEMENTS];
    assert_eq!(attached_fact_coverage(&requested, attached), (64, 72));
}

#[test]
fn coverage_counts_unique_requested_positive_verdicts_only() {
    let requested = BTreeSet::from([[1; 32], [2; 32]]);
    let attached = [FactStatement {
        facts: vec![
            ProvenFact {
                id: [1; 32],
                valid: true,
            },
            ProvenFact {
                id: [1; 32],
                valid: true,
            },
            ProvenFact {
                id: [2; 32],
                valid: false,
            },
            ProvenFact {
                id: [3; 32],
                valid: true,
            },
        ],
    }];
    assert_eq!(attached_fact_coverage(&requested, &attached), (1, 2));
}

#[test]
fn failed_proving_preserves_last_successful_snapshot() {
    let snapshot = Mutex::new(None);
    let failed: Result<(), ProofError> = Err(ProofError::BackendRejected);
    publish_successful_coverage(&snapshot, (8, 9), &failed);
    assert_eq!(*snapshot.lock().unwrap(), None);
    publish_successful_coverage(&snapshot, (0, 0), &Ok(()));
    assert_eq!(*snapshot.lock().unwrap(), Some((0, 0)));
    publish_successful_coverage(&snapshot, (4, 5), &Ok(()));
    publish_successful_coverage(&snapshot, (8, 9), &failed);
    assert_eq!(*snapshot.lock().unwrap(), Some((4, 5)));
}
