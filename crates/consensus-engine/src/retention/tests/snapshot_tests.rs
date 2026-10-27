//! Execution-state snapshot leases do not retain old raw blockchain history.

use super::*;

fn lease_key(root: Hash) -> Vec<u8> {
    // Inspect the persisted transport lease without exposing a test-only store API.
    let mut key = b"state_snapshot_lease/".to_vec();
    key.extend_from_slice(&root);
    key
}

fn lease<DB: Database>(engine: &Engine<DB>, root: Hash) -> Option<(u64, u64)>
where
    DB::Error: std::fmt::Debug,
{
    engine
        .store()
        .db()
        .get(Column::Meta, &lease_key(root))
        .unwrap()
        .map(|bytes| borsh::from_slice(&bytes).unwrap())
}

#[test]
fn only_manifest_pins_create_leases_and_expired_reads_cannot_revive_them() {
    let mut engine = fixture(MemoryDatabase::new(), 1);
    let root = engine.state().root();
    engine
        .store_mut()
        .refresh_state_snapshot(root, 1_000)
        .unwrap();
    assert_eq!(lease(&engine, root), None);
    engine.store_mut().pin_state_snapshot(root, 1_000).unwrap();
    assert_eq!(lease(&engine, root), Some((1_000, 1_300)));
    // Renewal waits until the idle window runs low.
    engine
        .store_mut()
        .refresh_state_snapshot(root, 1_100)
        .unwrap();
    assert_eq!(lease(&engine, root), Some((1_000, 1_300)));
    engine
        .store_mut()
        .refresh_state_snapshot(root, 1_200)
        .unwrap();
    assert_eq!(lease(&engine, root), Some((1_000, 1_500)));
    // Expiry itself is exclusive; ordinary state reads cannot establish trust in
    // a new manifest or start another lifetime after this deadline.
    engine
        .store_mut()
        .refresh_state_snapshot(root, 1_500)
        .unwrap();
    let mut expired = Batch::new();
    assert_eq!(
        engine
            .store()
            .snapshot_retention(&mut expired, 1_500)
            .unwrap(),
        Vec::<Hash>::new()
    );
    engine
        .store_mut()
        .db_mut()
        .write_batch_durable(expired)
        .unwrap();
    assert_eq!(lease(&engine, root), None);
    assert!(
        !engine
            .store_mut()
            .refresh_state_snapshot(root, 1_501)
            .unwrap()
    );
    assert_eq!(lease(&engine, root), None);
    // A newly served, independently authenticated manifest may start a new lease.
    engine.store_mut().pin_state_snapshot(root, 1_501).unwrap();
    assert_eq!(lease(&engine, root), Some((1_501, 1_801)));
}

#[test]
fn a_clock_stepped_back_neither_corrupts_a_lease_nor_stops_pruning() {
    let mut engine = fixture(MemoryDatabase::new(), 1);
    let root = engine.state().root();
    engine.store_mut().pin_state_snapshot(root, 1_000).unwrap();
    // The clock steps back below the creation time: the lifetime restarts
    // there instead of expiring before it began.
    engine.store_mut().pin_state_snapshot(root, 600).unwrap();
    assert_eq!(lease(&engine, root), Some((600, 900)));
    assert!(
        engine
            .store_mut()
            .refresh_state_snapshot(root, 800)
            .unwrap()
    );
    assert_eq!(lease(&engine, root), Some((600, 1_100)));
    let mut batch = Batch::new();
    assert_eq!(
        engine.store().snapshot_retention(&mut batch, 800).unwrap(),
        vec![root]
    );
    // A lease already written malformed is released, never failing a prune.
    engine
        .store_mut()
        .db_mut()
        .put(
            Column::Meta,
            &lease_key(root),
            &borsh::to_vec(&(1_000_u64, 900_u64)).unwrap(),
        )
        .unwrap();
    let mut batch = Batch::new();
    assert_eq!(
        engine.store().snapshot_retention(&mut batch, 800).unwrap(),
        Vec::<Hash>::new()
    );
    engine.store_mut().db_mut().write_batch(batch).unwrap();
    assert_eq!(lease(&engine, root), None);
}

#[test]
fn continuous_activity_never_extends_one_manifest_beyond_twenty_four_hours() {
    let mut engine = fixture(MemoryDatabase::new(), 1);
    let root = engine.state().root();
    let created = 1_000;
    let deadline = created + 24 * 60 * 60;
    engine
        .store_mut()
        .pin_state_snapshot(root, created)
        .unwrap();
    for elapsed in (250..24 * 60 * 60).step_by(250) {
        engine
            .store_mut()
            .refresh_state_snapshot(root, created + elapsed)
            .unwrap();
        let (saved_created, expires) = lease(&engine, root).unwrap();
        assert_eq!(saved_created, created);
        assert!(expires <= deadline);
    }
    engine
        .store_mut()
        .refresh_state_snapshot(root, deadline - 1)
        .unwrap();
    assert_eq!(lease(&engine, root), Some((created, deadline)));
    engine
        .store_mut()
        .refresh_state_snapshot(root, deadline)
        .unwrap();
    assert_eq!(lease(&engine, root), Some((created, deadline)));
    let mut batch = Batch::new();
    assert_eq!(
        engine
            .store()
            .snapshot_retention(&mut batch, deadline)
            .unwrap(),
        Vec::<Hash>::new()
    );
}

#[test]
fn a_full_lease_table_frees_the_least_recently_renewed_and_reclaims_expired_slots() {
    let mut engine = fixture(MemoryDatabase::new(), 10);
    let roots: Vec<_> = (1..=10)
        .map(|id| engine.canonical_boundary(id).unwrap().state_root)
        .collect();
    for root in &roots[..8] {
        engine.store_mut().pin_state_snapshot(*root, 1_000).unwrap();
    }
    // Renewing a known root uses its existing slot, preserving its creation time.
    engine
        .store_mut()
        .refresh_state_snapshot(roots[0], 1_200)
        .unwrap();
    assert_eq!(lease(&engine, roots[0]), Some((1_000, 1_500)));
    // A ninth root, such as a newer endpoint, is never refused: the least
    // recently renewed lease makes room.
    engine
        .store_mut()
        .pin_state_snapshot(roots[8], 1_201)
        .unwrap();
    let held = roots
        .iter()
        .filter(|root| lease(&engine, **root).is_some())
        .count();
    assert_eq!(held, 8);
    assert_eq!(lease(&engine, roots[0]), Some((1_000, 1_500)));
    assert_eq!(lease(&engine, roots[8]), Some((1_201, 1_501)));
    // Expired slots are reclaimed before anything is evicted.
    engine
        .store_mut()
        .pin_state_snapshot(roots[9], 1_300)
        .unwrap();
    assert_eq!(lease(&engine, roots[0]), Some((1_000, 1_500)));
    for root in &roots[1..8] {
        assert_eq!(lease(&engine, *root), None);
    }
    assert_eq!(lease(&engine, roots[8]), Some((1_201, 1_501)));
    assert_eq!(lease(&engine, roots[9]), Some((1_300, 1_600)));
    assert!(
        engine
            .store_mut()
            .pin_state_snapshot([99; 32], 1_300)
            .is_err()
    );
}

#[test]
fn failed_pin_or_refresh_cannot_publish_a_lease() {
    let mut engine = fixture(FaultDb::default(), 1);
    let root = engine.state().root();
    let before = engine.store().db().iter_column(Column::Meta).unwrap();
    engine.store_mut().db_mut().fail_batch = true;
    assert!(engine.store_mut().pin_state_snapshot(root, 1_000).is_err());
    assert_eq!(
        engine.store().db().iter_column(Column::Meta).unwrap(),
        before
    );
    assert_eq!(lease(&engine, root), None);
    engine.store_mut().db_mut().fail_batch = false;
    engine.store_mut().pin_state_snapshot(root, 1_000).unwrap();
    let before = engine.store().db().iter_column(Column::Meta).unwrap();
    engine.store_mut().db_mut().fail_batch = true;
    assert!(
        engine
            .store_mut()
            .refresh_state_snapshot(root, 1_200)
            .is_err()
    );
    assert_eq!(
        engine.store().db().iter_column(Column::Meta).unwrap(),
        before
    );
    assert_eq!(lease(&engine, root), Some((1_000, 1_300)));
}

#[test]
fn lease_preserves_an_old_state_root_without_delaying_raw_pruning() {
    let mut engine = fixture(MemoryDatabase::new(), 20);
    let old_root = engine.canonical_boundary(1).unwrap().state_root;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    engine
        .store_mut()
        .pin_state_snapshot(old_root, now)
        .unwrap();
    let retention = engine.prune_finalized_history().unwrap();
    assert_eq!(retention.pruned_before_chunk, 12);
    assert!(engine.store().get_header_by_height(1).unwrap().is_none());
    assert!(engine.store().get_chunk_proof(0).unwrap().is_none());
    let snapshot = engine.store().state_at(old_root);
    assert_eq!(
        snapshot.get(b"counter").unwrap(),
        Some(1_u64.to_be_bytes().to_vec())
    );
    let reopened = Engine::open(spec(), engine.store().db().clone()).unwrap();
    assert_eq!(lease(&reopened, old_root), lease(&engine, old_root));
    assert!(
        reopened
            .store()
            .db()
            .get(Column::TrieNodes, &old_root)
            .unwrap()
            .is_some()
    );
    // Expire the durable lease without waiting. Repeated pruning reclaims state
    // even when the raw watermark has not moved since the preceding operation.
    engine
        .store_mut()
        .db_mut()
        .put(
            Column::Meta,
            &lease_key(old_root),
            &borsh::to_vec(&(now - 1_000, now - 1)).unwrap(),
        )
        .unwrap();
    assert_eq!(
        engine
            .prune_finalized_history()
            .unwrap()
            .pruned_before_chunk,
        12
    );
    assert_eq!(lease(&engine, old_root), None);
    assert!(
        engine
            .store()
            .db()
            .get(Column::TrieNodes, &old_root)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        engine.state().get(b"counter").unwrap(),
        Some(20_u64.to_be_bytes().to_vec())
    );
}
