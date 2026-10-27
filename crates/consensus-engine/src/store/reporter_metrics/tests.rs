use super::*;
use neutrin0_storage::MemoryDatabase;

#[test]
fn batch_overlay_replacement_deletion_and_restart_keep_exact_inventory() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let mut batch = Batch::new();
    batch.put(
        Column::ReporterValidators,
        [1; 48],
        borsh::to_vec(&vec![[2_u8; 32]]).unwrap(),
    );
    batch.put(
        Column::ReporterValidators,
        [1; 48],
        borsh::to_vec(&vec![[2_u8; 32], [3_u8; 32]]).unwrap(),
    );
    store.write_observed_batch(batch, true).unwrap();
    let stats = store.reporter_storage_stats().unwrap();
    assert_eq!(stats.validators.records, 1);
    assert_eq!(stats.validators.bytes, 48 + 4 + 64);
    let mut restarted = ChainStore::new(store.into_db());
    assert_eq!(
        restarted.reporter_storage_stats().unwrap(),
        ReporterStorageStats {
            revision: stats.revision + 1,
            tracked_revision: stats.tracked_revision + 1,
            ..stats
        }
    );
    let mut batch = Batch::new();
    batch.delete(Column::ReporterValidators, [1; 48]);
    batch.delete(Column::ReporterValidators, [1; 48]);
    restarted.write_observed_batch(batch, false).unwrap();
    let stats = restarted.reporter_storage_stats().unwrap();
    assert_eq!(stats.validators, RetainedInventory::default());
    assert_eq!(stats.cleaned_records, 1);
    assert_eq!(stats.cleaned_bytes, 116);
}

#[test]
fn failed_atomic_batch_does_not_publish_inventory_or_cleanup() {
    let mut store = ChainStore::new(crate::test_db::FaultDb::default());
    let before = store.reporter_storage_stats().unwrap();
    store.db_mut().fail_batch = true;
    let mut batch = Batch::new();
    batch.put(
        Column::ReporterValidators,
        [1; 48],
        borsh::to_vec(&vec![[2_u8; 32]]).unwrap(),
    );
    assert!(store.write_observed_batch(batch, false).is_err());
    assert_eq!(
        store.reporter_storage_stats().unwrap(),
        ReporterStorageStats {
            revision: before.revision + 1,
            tracked_revision: before.tracked_revision + 1,
            ..before
        }
    );
}

#[test]
fn dirty_raw_mutation_changes_inventory_generation_without_finalization() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let before = store.reporter_storage_stats().unwrap();
    store
        .db_mut()
        .put(
            Column::ReporterValidators,
            &[1; 48],
            &borsh::to_vec(&vec![[2_u8; 32]]).unwrap(),
        )
        .unwrap();
    let after = store.reporter_storage_stats().unwrap();
    assert!(after.revision > before.revision);
    assert!(after.tracked_revision > before.tracked_revision);
    assert_eq!(after.validators.records, 1);
    assert_eq!(after.validators.bytes, 84);
    // Once indexed, repeated sampling neither scans nor changes generation.
    assert_eq!(store.reporter_storage_stats().unwrap(), after);
}

#[test]
fn tracked_generation_ignores_unrelated_and_identical_mutations() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let before = store.reporter_storage_stats().unwrap();
    let mut batch = Batch::new();
    batch.put(Column::ReporterIndex, [1; 32], vec![2]);
    store.write_observed_batch(batch, true).unwrap();
    let indexed = store.reporter_storage_stats().unwrap();
    assert!(indexed.revision > before.revision);
    assert_eq!(indexed.tracked_revision, before.tracked_revision);

    let addresses = borsh::to_vec(&vec![[3_u8; 32]]).unwrap();
    let mut batch = Batch::new();
    batch.put(Column::ReporterValidators, [4; 48], addresses.clone());
    store.write_observed_batch(batch, true).unwrap();
    let tracked = store.reporter_storage_stats().unwrap();
    assert_eq!(tracked.tracked_revision, indexed.tracked_revision + 1);

    let mut batch = Batch::new();
    batch.put(Column::ReporterValidators, [4; 48], addresses);
    batch.put(Column::ReporterIndex, [1; 32], vec![5]);
    store.write_observed_batch(batch, true).unwrap();
    let refreshed = store.reporter_storage_stats().unwrap();
    assert!(refreshed.revision > tracked.revision);
    assert_eq!(refreshed.tracked_revision, tracked.tracked_revision);

    // Changing the withdrawal account set is relevant even if its BLS key
    // and validator inventory count are unchanged.
    let mut batch = Batch::new();
    batch.put(
        Column::ReporterValidators,
        [4; 48],
        borsh::to_vec(&vec![[3_u8; 32], [6_u8; 32]]).unwrap(),
    );
    store.write_observed_batch(batch, true).unwrap();
    let expanded = store.reporter_storage_stats().unwrap();
    assert_eq!(expanded.tracked_revision, refreshed.tracked_revision + 1);
    assert_eq!(expanded.validators.records, refreshed.validators.records);
}
