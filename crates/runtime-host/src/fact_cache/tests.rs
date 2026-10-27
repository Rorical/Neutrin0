use super::covering_indices;
use neutrin0_prover_chunk::facts::{FactStatement, ProvenFact};
use std::collections::BTreeSet;

fn statement(ids: &[u8]) -> FactStatement {
    FactStatement {
        facts: ids
            .iter()
            .map(|byte| ProvenFact {
                id: [*byte; 32],
                valid: true,
            })
            .collect(),
    }
}

#[test]
fn dense_old_receipt_wins_over_new_singletons_before_the_guest_cap() {
    let dense = statement(&(0..64).collect::<Vec<_>>());
    let singleton: Vec<_> = (0..72).map(|id| statement(&[id])).collect();
    let mut candidates = vec![(&dense, 100)];
    candidates.extend(singleton.iter().map(|statement| (statement, 100)));
    let mut wanted: BTreeSet<_> = (0..72).map(|id| [id; 32]).collect();
    let selected = covering_indices(&candidates, &mut wanted, 9);
    assert_eq!(selected.len(), 9);
    assert_eq!(selected[0], 0);
    assert!(wanted.is_empty());
}

#[test]
fn uncovered_requests_survive_the_limit_and_overlap_is_not_double_counted() {
    let a = statement(&[1, 2, 3]);
    let b = statement(&[1, 2]);
    let c = statement(&[4, 5]);
    let unrelated = statement(&[6, 7, 8, 9]);
    let candidates = [(&a, 200), (&b, 1), (&c, 200), (&unrelated, 1)];
    let mut wanted = BTreeSet::from([[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]]);
    assert_eq!(covering_indices(&candidates, &mut wanted, 1), vec![0]);
    assert_eq!(wanted, BTreeSet::from([[4; 32], [5; 32]]));
    assert_eq!(covering_indices(&candidates, &mut wanted, 1), vec![2]);
    assert!(wanted.is_empty());
}

#[test]
fn coverage_ties_prefer_small_receipts_then_recency_and_zero_budget_is_empty() {
    let statement = statement(&[1, 2]);
    let candidates = [(&statement, 200), (&statement, 100), (&statement, 100)];
    let mut wanted = BTreeSet::from([[1; 32], [2; 32]]);
    assert_eq!(
        covering_indices(&candidates, &mut wanted, 0),
        Vec::<usize>::new()
    );
    assert_eq!(wanted.len(), 2);
    assert_eq!(covering_indices(&candidates, &mut wanted, 1), vec![2]);
    assert!(wanted.is_empty());
}

#[test]
fn repeated_fact_ids_cannot_inflate_a_receipts_unique_coverage() {
    let repeated = statement(&[1, 1, 1]);
    let complete = statement(&[1, 2]);
    let mut wanted = BTreeSet::from([[1; 32], [2; 32]]);
    assert_eq!(
        covering_indices(&[(&repeated, 1), (&complete, 2)], &mut wanted, 1),
        vec![1]
    );
    assert!(wanted.is_empty());
}
