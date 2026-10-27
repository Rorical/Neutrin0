//! Bootstrap storage tests start after receipt and trust-policy verification.
//! Fixture receipts are never passed through production cryptographic acceptance.

use super::*;
use neutrin0_prover_chunk::history::HistoricalOpening;

struct Snapshot {
    receipt: crate::store::StoredChunkReceipt,
    statement: ConsensusStatement,
    header: neutrin0_consensus_types::Header,
    consensus: ConsensusState,
    recent: Vec<HistoricalOpening>,
    state: Trie,
    identity_sanctions: Trie,
}

fn snapshot(count: u64) -> Snapshot {
    let source = fixture(MemoryDatabase::new(), count);
    let first = count.saturating_sub(HISTORY_RETENTION_CHUNKS);
    let recent = (first..count)
        .map(|id| source.store().historical_opening(id, count).unwrap())
        .collect();
    let state = source.state().detached().unwrap();
    let identity_sanctions = source.identity_sanctions.detached().unwrap();
    let proof = source.store().get_chunk_proof(count - 1).unwrap().unwrap();
    let statement = source.store().chunk_statement(count - 1).unwrap().unwrap();
    Snapshot {
        receipt: crate::store::StoredChunkReceipt::new(proof, &statement, 0),
        statement,
        header: source
            .store()
            .get_header(&source.head_hash())
            .unwrap()
            .unwrap(),
        consensus: source.store().get_consensus_state().unwrap().unwrap(),
        recent,
        state,
        identity_sanctions,
    }
}

fn commit<DB: Database>(target: &mut Engine<DB>, snapshot: &Snapshot)
where
    DB::Error: std::fmt::Debug,
{
    let genesis = ConsensusBoundary::genesis(target.chain_spec());
    if target.store().state_install().unwrap().is_none() {
        install_snapshot(target, &snapshot.state, &snapshot.identity_sanctions);
    }
    target
        .store_mut()
        .commit_bootstrap(
            Some((&snapshot.receipt, &snapshot.statement)),
            &genesis,
            &snapshot.header,
            &snapshot.consensus,
            &snapshot.recent,
            &[],
        )
        .unwrap();
    target.publish_bootstrap_state(&snapshot.consensus);
}

#[test]
fn bootstrapped_endpoint_keeps_its_authenticated_producer_runtime() {
    let snapshot = snapshot(18);
    // The installed receipt's start boundary rules chunk 17; the record alone
    // authenticates the producer of chunk 16, whose boundary is absent.
    let records = &snapshot.recent;
    let expected = records[records.len() - 2].record.runtime_code_hash;
    let last = records.last().unwrap().record.runtime_code_hash;
    let mut target = fixture(MemoryDatabase::new(), 0);
    commit(&mut target, &snapshot);
    assert_eq!(
        target.canonical_boundary(17).unwrap(),
        snapshot.statement.start
    );
    assert!(target.canonical_boundary(16).is_err());
    assert!(target.programs_for_height(17).is_err());
    assert_eq!(target.runtime_code_hash_for(17).unwrap(), expected);
    assert_eq!(target.runtime_code_hash_for(18).unwrap(), last);
    let mut reopened =
        Engine::open(target.chain_spec().clone(), target.store().db().clone()).unwrap();
    assert_eq!(reopened.runtime_code_hash_for(17).unwrap(), expected);
    append(&mut reopened);
    assert_eq!(reopened.runtime_code_hash_for(17).unwrap(), expected);
}

#[test]
fn bootstrapped_endpoint_rejects_a_changed_producer_runtime() {
    let snapshot = snapshot(18);
    let mut target = fixture(MemoryDatabase::new(), 0);
    commit(&mut target, &snapshot);
    let mut record = target.store().historical_chunk(16).unwrap().unwrap();
    record.runtime_code_hash[0] ^= 1;
    target
        .store_mut()
        .db_mut()
        .put(
            Column::HistoricalChunks,
            &16_u64.to_be_bytes(),
            &borsh::to_vec(&record).unwrap(),
        )
        .unwrap();
    assert!(target.runtime_code_hash_for(17).is_err());
}

#[test]
fn sparse_bootstrap_tree_reopens_and_appends_across_binary_carries() {
    for count in [1, 7, 8, 9, 16, 17, 32, 33] {
        let snapshot = snapshot(count);
        let mut target = fixture(MemoryDatabase::new(), 0);
        commit(&mut target, &snapshot);
        let mut reopened =
            Engine::open(target.chain_spec().clone(), target.store().db().clone()).unwrap();
        assert_eq!(reopened.head_hash(), snapshot.header.hash());
        assert_eq!(reopened.finalized_next_chunk_id(), count);
        // The installed endpoint receipt is served as the History proof.
        assert_eq!(
            reopened
                .latest_history_proof()
                .unwrap()
                .unwrap()
                .end()
                .next_chunk_id,
            count
        );
        assert_eq!(reopened.state().root(), snapshot.state.root());
        assert_eq!(
            reopened.state().get(b"counter").unwrap(),
            Some(count.to_be_bytes().to_vec())
        );
        let first = count.saturating_sub(HISTORY_RETENTION_CHUNKS);
        for expected in &snapshot.recent {
            assert_eq!(
                reopened
                    .store()
                    .historical_opening(expected.record.chunk.chunk_id, count)
                    .unwrap(),
                *expected
            );
        }
        assert_eq!(
            reopened.retention_info().unwrap().pruned_before_chunk,
            count
        );
        assert_eq!(
            reopened
                .store()
                .db()
                .iter_column(Column::Blocks)
                .unwrap()
                .len(),
            0
        );
        assert!(
            reopened
                .set_retention_policy(RetentionPolicy::Archive)
                .is_err()
        );
        reopened.prune_finalized_history().unwrap();
        for id in first..count {
            reopened.store().historical_opening(id, count).unwrap();
        }
        append(&mut reopened);
        for id in count
            .saturating_add(1)
            .saturating_sub(HISTORY_RETENTION_CHUNKS)..=count
        {
            reopened.store().historical_opening(id, count + 1).unwrap();
        }
        reopened.prune_finalized_history().unwrap();
        assert_eq!(
            reopened.retention_info().unwrap().pruned_before_chunk,
            count
        );
        assert!(
            reopened
                .store()
                .db()
                .get(Column::Blocks, &reopened.head_hash())
                .unwrap()
                .is_some()
        );
        let again =
            Engine::open(reopened.chain_spec().clone(), reopened.store().db().clone()).unwrap();
        for id in (count + 1).saturating_sub(HISTORY_RETENTION_CHUNKS)..=count {
            again.store().historical_opening(id, count + 1).unwrap();
        }
    }
}

#[test]
fn bootstrap_pruning_tracks_new_consensus_window_without_expiring_live_state() {
    let count = 17;
    let snapshot = snapshot(count);
    let mut target = fixture(MemoryDatabase::new(), 0);
    commit(&mut target, &snapshot);
    for _ in 0..10 {
        append(&mut target);
        let latest = target.finalized_next_chunk_id();
        target.prune_finalized_history().unwrap();
        let first = latest.saturating_sub(HISTORY_RETENTION_CHUNKS);
        let expected_floor = count.max(first);
        assert_eq!(
            target.retention_info().unwrap().pruned_before_chunk,
            expected_floor
        );
        for id in first..latest {
            target.store().historical_opening(id, latest).unwrap();
        }
        if first > 0 {
            assert!(
                target
                    .store()
                    .historical_chunk(first - 1)
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(
            target.state().get(b"counter").unwrap(),
            Some(latest.to_be_bytes().to_vec())
        );
        let again = Engine::open(target.chain_spec().clone(), target.store().db().clone()).unwrap();
        assert_eq!(
            again.retention_info().unwrap(),
            target.retention_info().unwrap()
        );
    }
}

#[test]
fn failed_durable_bootstrap_batch_leaves_disk_and_live_pointers_unchanged() {
    let snapshot = snapshot(9);
    let mut target = fixture(FaultDb::default(), 2);
    let head = target.head_hash();
    let root = target.state().root();
    let finalized = target.finalized_next_chunk_id();
    install_snapshot(&mut target, &snapshot.state, &snapshot.identity_sanctions);
    let disk: Vec<_> = neutrin0_storage::ALL_COLUMNS
        .iter()
        .map(|column| (*column, target.store().db().iter_column(*column).unwrap()))
        .collect();
    target.store_mut().db_mut().fail_batch = true;
    let genesis = ConsensusBoundary::genesis(target.chain_spec());
    assert!(matches!(
        target.store_mut().commit_bootstrap(
            Some((&snapshot.receipt, &snapshot.statement)),
            &genesis,
            &snapshot.header,
            &snapshot.consensus,
            &snapshot.recent,
            &[]
        ),
        Err(StoreError::Database(_))
    ));
    assert_eq!(target.head_hash(), head);
    assert_eq!(target.state().root(), root);
    assert_eq!(target.finalized_next_chunk_id(), finalized);
    assert_eq!(target.store().bootstrap_source_floor().unwrap(), 0);
    for (column, entries) in disk {
        assert_eq!(target.store().db().iter_column(column).unwrap(), entries);
    }
    target.store_mut().db_mut().fail_batch = false;
    commit(&mut target, &snapshot);
    let reopened = Engine::open(target.chain_spec().clone(), target.store().db().clone()).unwrap();
    assert_eq!(reopened.head_hash(), snapshot.header.hash());
    assert_eq!(reopened.store().bootstrap_source_floor().unwrap(), 9);
}

#[test]
fn malformed_opening_cannot_publish_a_partial_bootstrap() {
    let mut snapshot = snapshot(9);
    snapshot.recent[0].path.siblings[0][0] ^= 1;
    let mut target = fixture(MemoryDatabase::new(), 0);
    let head = target.head_hash();
    install_snapshot(&mut target, &snapshot.state, &snapshot.identity_sanctions);
    let disk = target.store().db().clone();
    let genesis = ConsensusBoundary::genesis(target.chain_spec());
    assert!(
        target
            .store_mut()
            .commit_bootstrap(
                Some((&snapshot.receipt, &snapshot.statement)),
                &genesis,
                &snapshot.header,
                &snapshot.consensus,
                &snapshot.recent,
                &[]
            )
            .is_err()
    );
    assert_eq!(target.head_hash(), head);
    for column in neutrin0_storage::ALL_COLUMNS {
        assert_eq!(
            target.store().db().iter_column(column).unwrap(),
            disk.iter_column(column).unwrap()
        );
    }
}

#[test]
fn bootstrap_publication_preserves_the_local_signing_journal() {
    let snapshot = snapshot(9);
    let mut target = fixture(MemoryDatabase::new(), 0);
    // The store must preserve journal bytes independently of their signing-layer
    // schema. Decoding and enforcing their semantics belong to signing tests.
    target
        .store_mut()
        .db_mut()
        .put(Column::SigningJournal, b"persisted-key", b"signing-intent")
        .unwrap();
    commit(&mut target, &snapshot);
    assert_eq!(
        target
            .store()
            .db()
            .get(Column::SigningJournal, b"persisted-key")
            .unwrap(),
        Some(b"signing-intent".to_vec())
    );
}

#[test]
fn bootstrap_preserves_old_reports_dormant_until_a_holder_refreshes_the_path() {
    let snapshot = snapshot(20);
    let mut target = fixture(MemoryDatabase::new(), 2);
    let original = super::evidence_path_retention_tests::report(&target, 0);
    target.store_mut().put_evidence_report(&original).unwrap();
    commit(&mut target, &snapshot);
    let mut restarted =
        Engine::open(target.chain_spec().clone(), target.store().db().clone()).unwrap();
    assert_eq!(
        restarted.store().evidence_reports().unwrap(),
        vec![original.clone()]
    );
    append(&mut restarted);
    assert_eq!(
        restarted.store().evidence_reports().unwrap(),
        vec![original.clone()]
    );
    assert!(
        restarted
            .evidence_submission_with_path(&original.artifact.statement, &original.history)
            .is_err()
    );
    let holder = super::evidence_path_retention_tests::archive(21);
    let refreshed = super::evidence_path_retention_tests::report(&holder, 0);
    restarted
        .store_mut()
        .put_evidence_report(&refreshed)
        .unwrap();
    let stored = restarted.store().evidence_reports().unwrap().remove(0);
    assert_eq!(stored.artifact, original.artifact);
    assert_eq!(stored.history, refreshed.history);
    append(&mut restarted);
    assert_eq!(
        restarted.store().evidence_reports().unwrap()[0]
            .history
            .count,
        22
    );
    Engine::open(
        restarted.chain_spec().clone(),
        restarted.store().db().clone(),
    )
    .unwrap();
}

#[test]
fn bootstrap_refreshes_reports_covered_by_its_authenticated_recent_openings() {
    let snapshot = snapshot(20);
    let mut target = fixture(MemoryDatabase::new(), 15);
    let original = super::evidence_path_retention_tests::report(&target, 14);
    target.store_mut().put_evidence_report(&original).unwrap();
    commit(&mut target, &snapshot);
    let stored = target.store().evidence_reports().unwrap().remove(0);
    assert_eq!(stored.artifact, original.artifact);
    assert_eq!(stored.history.count, 20);
    assert_eq!(
        stored.history,
        snapshot
            .recent
            .iter()
            .find(|opening| opening.path.index == 14)
            .unwrap()
            .path
    );
    Engine::open(target.chain_spec().clone(), target.store().db().clone()).unwrap();
}
