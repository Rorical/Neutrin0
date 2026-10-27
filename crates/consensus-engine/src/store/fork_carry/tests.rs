use super::*;
use crate::RetentionInfo;
use neutrin0_storage::MemoryDatabase;

/// A `policy` store of specification `spec` that finalized `count` chunks.
fn store(spec: Hash, policy: RetentionPolicy, count: u64) -> ChainStore<MemoryDatabase> {
    let mut store = ChainStore::new(MemoryDatabase::new());
    let db = store.db_mut();
    db.put(Column::Meta, super::super::pointers::CHAIN_SPEC_HASH, &spec)
        .unwrap();
    db.put(
        Column::Finalized,
        super::super::pointers::LATEST_FINALIZED_CHUNK_ID,
        &super::super::keys::chunk_id_key(count - 1),
    )
    .unwrap();
    let info = RetentionInfo {
        policy,
        pruned_before_chunk: 0,
        first_retained_height: 1,
    };
    db.put(
        Column::Meta,
        super::super::retention::RETENTION_KEY,
        &borsh::to_vec(&info).unwrap(),
    )
    .unwrap();
    store
}

fn accounts(accounts: &[[u8; 32]]) -> Vec<u8> {
    borsh::to_vec(&accounts.to_vec()).unwrap()
}

#[test]
fn carried_rows_reach_only_the_roles_that_keep_them() {
    let mut source = store([3; 32], RetentionPolicy::Archive, 4);
    let db = source.db_mut();
    db.put(Column::SlashingPool, &[1; 32], b"offence").unwrap();
    db.put(Column::HistoryNodes, &[2; 32], b"node").unwrap();
    db.put(Column::ReporterValidators, &[4; 48], &accounts(&[[5; 32]]))
        .unwrap();
    let mut file = Vec::new();
    let exported = source.export_fork_carry(&mut file).unwrap();
    assert_eq!(
        (
            exported.chain_spec_hash,
            exported.finalized_count,
            exported.rows
        ),
        ([3; 32], 4, 3)
    );
    let row = |store: &ChainStore<MemoryDatabase>, column, key: &[u8]| {
        store.db().get(column, key).unwrap()
    };

    let mut archive = store([9; 32], RetentionPolicy::Archive, 4);
    // A carry must belong to the predecessor and end at or before the fork.
    assert!(
        archive
            .import_fork_carry(&mut file.as_slice(), [8; 32], 4)
            .is_err()
    );
    assert!(
        archive
            .import_fork_carry(&mut file.as_slice(), [3; 32], 3)
            .is_err()
    );
    let imported = archive
        .import_fork_carry(&mut file.as_slice(), [3; 32], 4)
        .unwrap()
        .unwrap();
    assert_eq!(imported.rows, 2);
    assert!(row(&archive, Column::SlashingPool, &[1; 32]).is_some());
    assert!(row(&archive, Column::HistoryNodes, &[2; 32]).is_some());
    assert!(row(&archive, Column::ReporterValidators, &[4; 48]).is_none());
    assert_eq!(
        archive
            .import_fork_carry(&mut file.as_slice(), [3; 32], 4)
            .unwrap(),
        None
    );

    // A reporter merges each identity's accounts and keeps no tree.
    let mut reporter = store([9; 32], RetentionPolicy::Reporter, 4);
    reporter
        .db_mut()
        .put(Column::ReporterValidators, &[4; 48], &accounts(&[[6; 32]]))
        .unwrap();
    reporter
        .import_fork_carry(&mut file.as_slice(), [3; 32], 4)
        .unwrap();
    assert_eq!(
        row(&reporter, Column::ReporterValidators, &[4; 48]),
        Some(accounts(&[[5; 32], [6; 32]]))
    );
    assert!(row(&reporter, Column::HistoryNodes, &[2; 32]).is_none());

    // An archive takes History only from an archive.
    let mut pruned_file = Vec::new();
    store([3; 32], RetentionPolicy::Pruned, 4)
        .export_fork_carry(&mut pruned_file)
        .unwrap();
    let mut archive = store([9; 32], RetentionPolicy::Archive, 4);
    assert!(
        archive
            .import_fork_carry(&mut pruned_file.as_slice(), [3; 32], 4)
            .is_err()
    );
}
