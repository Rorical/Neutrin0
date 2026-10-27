//! Supplied old openings and bounded ordinary-node caches are independent lifecycles.

use super::*;
use neutrin0_consensus_types::evidence::{
    EvidenceArtifact, EvidenceMembership, EvidenceReport, EvidenceStatement, SanctionKind,
};
use neutrin0_consensus_types::history::{HistoryFrontier, HistoryPath};

pub(super) fn archive(count: u64) -> Engine<MemoryDatabase> {
    let mut engine = fixture(MemoryDatabase::new(), 0);
    engine
        .set_retention_policy(RetentionPolicy::Archive)
        .unwrap();
    for _ in 0..count {
        append(&mut engine);
    }
    engine
}

pub(super) fn report<DB: Database>(engine: &Engine<DB>, source: u64) -> EvidenceReport
where
    DB::Error: std::fmt::Debug,
{
    let record = engine.store().historical_chunk(source).unwrap().unwrap();
    let statement = EvidenceStatement {
        reporter: None,
        chain_id: engine.chain_spec().chain_id,
        chain_spec_hash: engine.chain_spec_hash(),
        block_guest_vk_digest: [3; 8],
        context: record.evidence_context(),
        offender: record.validators[0].clone(),
        kind: SanctionKind::Slash,
        offence_id: [91; 32],
        facts_commitment: [92; 32],
    };
    let history = engine
        .store()
        .history_path(
            source,
            engine.finalized_next_chunk_id(),
            commitment(&statement.context),
        )
        .unwrap();
    let membership =
        EvidenceMembership::build(std::slice::from_ref(&statement), 0, [1; 8]).unwrap();
    EvidenceReport {
        artifact: EvidenceArtifact {
            membership,
            evidence_guest_vk_digest: [2; 8],
            statement,
            proof_bytes: vec![1],
        },
        history,
    }
}

#[test]
fn old_source_uses_supplied_path_after_the_local_record_and_opening_expire() {
    let source = archive(40);
    let supplied = report(&source, 0);
    let mut target = fixture(MemoryDatabase::new(), 40);
    target.prune_finalized_history().unwrap();
    assert!(target.store().historical_chunk(0).unwrap().is_none());
    assert!(
        target
            .evidence_submission(supplied.artifact.statement.clone())
            .is_err()
    );
    let accepted = target
        .evidence_submission_with_path(&supplied.artifact.statement, &supplied.history)
        .unwrap();
    assert_eq!(accepted.history, supplied.history);

    let mut forged = supplied.history.clone();
    forged.siblings[0][0] ^= 1;
    assert!(matches!(
        target.evidence_submission_with_path(&supplied.artifact.statement, &forged),
        Err(crate::FinalizeError::Backend(
            neutrin0_proof_system::ProofError::InvalidWitness
        ))
    ));
    let mut wrong_source = supplied.history.clone();
    wrong_source.index = 1;
    assert!(
        target
            .evidence_submission_with_path(&supplied.artifact.statement, &wrong_source)
            .is_err()
    );
    let mut wrong_context = supplied.artifact.statement.clone();
    wrong_context.context.chunk_hash[0] ^= 1;
    assert!(
        target
            .evidence_submission_with_path(&wrong_context, &supplied.history)
            .is_err()
    );
}

#[test]
fn source_age_is_unbounded_but_supplied_anchor_refresh_is_bounded() {
    let source = archive(40);
    let supplied = report(&source, 0);
    let target = fixture(MemoryDatabase::new(), 40);
    let leaf = commitment(&supplied.artifact.statement.context);
    let recent_anchor = source.store().history_path(0, 32, leaf).unwrap();
    let refreshed = target
        .evidence_submission_with_path(&supplied.artifact.statement, &recent_anchor)
        .unwrap();
    assert_eq!(refreshed.history, supplied.history);
    let stale_anchor = source.store().history_path(0, 31, leaf).unwrap();
    assert!(matches!(
        target.evidence_submission_with_path(&supplied.artifact.statement, &stale_anchor),
        Err(crate::FinalizeError::Engine(crate::EngineError::Store(
            StoreError::Corrupt("evidence history anchor requires refresh")
        )))
    ));
}

#[test]
fn pooled_path_advances_across_cache_expiry_restart_and_failed_finalization() {
    let mut engine = fixture(FaultDb::default(), 1);
    let original = report(&engine, 0);
    engine.store_mut().put_evidence_report(&original).unwrap();
    for _ in 0..20 {
        append(&mut engine);
    }
    engine.prune_finalized_history().unwrap();
    assert!(engine.store().historical_chunk(0).unwrap().is_none());
    let stored = engine.store().evidence_reports().unwrap().remove(0);
    assert_eq!(stored.history.count, 21);
    assert_eq!(stored.artifact, original.artifact);
    assert!(stored.history.verify(
        commitment(&stored.artifact.statement.context),
        engine.canonical_boundary(21).unwrap().history_root
    ));
    let mut restarted =
        Engine::open(engine.chain_spec().clone(), engine.store().db().clone()).unwrap();
    assert_eq!(
        restarted.store().evidence_reports().unwrap(),
        vec![stored.clone()]
    );

    let mut next_record = restarted.store().historical_chunk(20).unwrap().unwrap();
    next_record.chunk.chunk_id = 21;
    next_record.chunk.start_height = 22;
    next_record.chunk.end_height = 22;
    let mut batch = Batch::new();
    restarted
        .store()
        .append_history_batch(&mut batch, &next_record)
        .unwrap();
    restarted.store_mut().db_mut().fail_batch = true;
    assert!(restarted.store_mut().db_mut().write_batch(batch).is_err());
    assert_eq!(restarted.store().evidence_reports().unwrap(), vec![stored]);
    assert!(restarted.store().history_frontier(22).is_err());
    assert!(restarted.store().historical_chunk(21).unwrap().is_none());
    restarted.store_mut().db_mut().fail_batch = false;
    append(&mut restarted);
    assert_eq!(
        restarted.store().evidence_reports().unwrap()[0]
            .history
            .count,
        22
    );
}

#[test]
fn caches_stay_bounded_and_drop_frontiers_outside_the_recent_window() {
    let mut engine = fixture(MemoryDatabase::new(), 100);
    for column in [Column::HistoryFrontiers, Column::HistoryPaths] {
        let count = engine.store().db().iter_column(column).unwrap().len();
        let maximum = if column == Column::HistoryFrontiers {
            9
        } else {
            8 + 8 * 8
        };
        assert!(count <= maximum);
    }
    assert_eq!(
        engine
            .store()
            .db()
            .iter_column(Column::HistoryNodes)
            .unwrap(),
        [] as [(Vec<u8>, Vec<u8>); 0]
    );
    assert!(engine.store().history_frontier(5).is_err());
    append(&mut engine);
    assert!(engine.store().history_frontier(92).is_err());
    engine.store().history_frontier(93).unwrap();
    engine.store().validate_history_cache().unwrap();
}

#[test]
fn restart_refuses_missing_and_corrupt_cached_openings() {
    let engine = fixture(MemoryDatabase::new(), 10);
    let mut key = [0; 16];
    key[..8].copy_from_slice(&10u64.to_be_bytes());
    key[8..].copy_from_slice(&9u64.to_be_bytes());
    let mut missing = engine.store().db().clone();
    missing.delete(Column::HistoryPaths, &key).unwrap();
    assert!(Engine::open(engine.chain_spec().clone(), missing).is_err());

    let mut corrupt = engine.store().db().clone();
    let bytes = corrupt.get(Column::HistoryPaths, &key).unwrap().unwrap();
    let (leaf, mut path): (Hash, HistoryPath) = borsh::from_slice(&bytes).unwrap();
    path.siblings[0][0] ^= 1;
    corrupt
        .put(
            Column::HistoryPaths,
            &key,
            &borsh::to_vec(&(leaf, path)).unwrap(),
        )
        .unwrap();
    assert!(Engine::open(engine.chain_spec().clone(), corrupt).is_err());

    let mut wrong_frontier = engine.store().db().clone();
    let leaves = [[42; 32]; 10];
    let frontier = HistoryFrontier::from_leaves(&leaves).unwrap();
    let path = HistoryPath::build(&leaves, 9).unwrap();
    let mut root = neutrin0_consensus_types::history::history_leaf_hash(Some(leaves[9]));
    for (level, sibling) in path.siblings.iter().enumerate() {
        root = if (path.index >> level) & 1 == 0 {
            neutrin0_consensus_types::history::history_node_hash(level, root, *sibling)
        } else {
            neutrin0_consensus_types::history::history_node_hash(level, *sibling, root)
        };
    }
    // Internal consistency cannot replace the authenticated canonical boundary.
    wrong_frontier
        .put(
            Column::HistoryFrontiers,
            &10u64.to_be_bytes(),
            &borsh::to_vec(&(frontier, root)).unwrap(),
        )
        .unwrap();
    assert!(Engine::open(engine.chain_spec().clone(), wrong_frontier).is_err());
}

#[test]
fn pool_insertion_rejects_noncurrent_openings_and_restart_checks_saved_anchor() {
    let mut engine = fixture(MemoryDatabase::new(), 2);
    let original = report(&engine, 0);
    let mut forged = original.clone();
    forged.history.siblings[0][0] ^= 1;
    assert!(engine.store_mut().put_evidence_report(&forged).is_err());
    let mut future = original.clone();
    future.history.count = 3;
    assert!(engine.store_mut().put_evidence_report(&future).is_err());
    assert_eq!(
        engine.store().evidence_reports().unwrap(),
        [] as [EvidenceReport; 0]
    );
    engine.store_mut().put_evidence_report(&original).unwrap();
    append(&mut engine);
    assert!(engine.store_mut().put_evidence_report(&original).is_err());
    let stored = engine.store().evidence_reports().unwrap().remove(0);
    assert_eq!(stored.history.count, 3);

    let mut corrupt = engine.store().db().clone();
    let key = original.artifact.statement_id();
    let mut bytes = corrupt.get(Column::EvidenceProofs, &key).unwrap().unwrap();
    // The locally authenticated root is stored after the bounded report.
    *bytes.last_mut().unwrap() ^= 1;
    corrupt.put(Column::EvidenceProofs, &key, &bytes).unwrap();
    assert!(Engine::open(engine.chain_spec().clone(), corrupt).is_err());
}
