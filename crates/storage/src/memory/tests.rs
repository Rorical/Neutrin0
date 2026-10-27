use super::*;

fn get(db: &MemoryDatabase, column: Column, key: &[u8]) -> Option<Vec<u8>> {
    db.get(column, key).expect("memory get is infallible")
}

#[test]
fn starts_empty() {
    let db = MemoryDatabase::new();
    assert!(db.is_empty(Column::Meta));
    assert_eq!(get(&db, Column::Meta, b"missing"), None);
}

#[test]
fn put_get_overwrite_delete_roundtrip() {
    let mut db = MemoryDatabase::new();
    db.put(Column::Meta, b"chain", b"a")
        .expect("memory put is infallible");
    assert_eq!(get(&db, Column::Meta, b"chain"), Some(b"a".to_vec()));
    db.put(Column::Meta, b"chain", b"b")
        .expect("memory put is infallible");
    assert_eq!(get(&db, Column::Meta, b"chain"), Some(b"b".to_vec()));
    db.delete(Column::Meta, b"chain")
        .expect("memory delete is infallible");
    assert_eq!(get(&db, Column::Meta, b"chain"), None);
    assert!(db.is_empty(Column::Meta));
}

#[test]
fn columns_are_isolated() {
    let mut db = MemoryDatabase::new();
    db.put(Column::Headers, b"same-key", b"header")
        .expect("memory put is infallible");
    db.put(Column::Blocks, b"same-key", b"block")
        .expect("memory put is infallible");
    assert_eq!(
        get(&db, Column::Headers, b"same-key"),
        Some(b"header".to_vec())
    );
    assert_eq!(
        get(&db, Column::Blocks, b"same-key"),
        Some(b"block".to_vec())
    );
}

#[test]
fn all_columns_can_store_same_key_independently() {
    let mut db = MemoryDatabase::new();
    for (index, column) in crate::ALL_COLUMNS.iter().copied().enumerate() {
        db.put(
            column,
            b"shared-key",
            &[u8::try_from(index).expect("index fits u8")],
        )
        .expect("memory put is infallible");
    }

    for (index, column) in crate::ALL_COLUMNS.iter().copied().enumerate() {
        assert_eq!(
            get(&db, column, b"shared-key"),
            Some(vec![u8::try_from(index).expect("index fits u8")])
        );
        assert_eq!(db.len(column), 1);
    }
}

#[test]
fn empty_key_and_empty_value_roundtrip() {
    let mut db = MemoryDatabase::new();
    db.put(Column::StateValues, b"", b"")
        .expect("memory put is infallible");
    assert_eq!(get(&db, Column::StateValues, b""), Some(Vec::new()));
}

#[test]
fn binary_keys_and_values_are_preserved() {
    let mut db = MemoryDatabase::new();
    let key = [0, 255, 1, 254, 2, 253];
    let value = [255, 0, 128, 64, 32, 16, 8, 4, 2, 1];
    db.put(Column::TrieNodes, &key, &value)
        .expect("memory put is infallible");
    assert_eq!(get(&db, Column::TrieNodes, &key), Some(value.to_vec()));
}

#[test]
fn get_returns_owned_copy() {
    let mut db = MemoryDatabase::new();
    db.put(Column::Meta, b"k", b"stored")
        .expect("memory put is infallible");

    let mut first = get(&db, Column::Meta, b"k").expect("value exists");
    first[0] = b'X';

    assert_eq!(get(&db, Column::Meta, b"k"), Some(b"stored".to_vec()));
}

#[test]
fn clone_is_independent_after_mutation() {
    let mut db = MemoryDatabase::new();
    db.put(Column::Meta, b"k", b"before")
        .expect("memory put is infallible");
    let mut cloned = db.clone();

    cloned
        .put(Column::Meta, b"k", b"after")
        .expect("memory put is infallible");

    assert_eq!(get(&db, Column::Meta, b"k"), Some(b"before".to_vec()));
    assert_eq!(get(&cloned, Column::Meta, b"k"), Some(b"after".to_vec()));
}

#[test]
fn deleting_missing_key_is_noop() {
    let mut db = MemoryDatabase::new();
    db.delete(Column::Meta, b"missing")
        .expect("memory delete is infallible");
    assert!(db.is_empty(Column::Meta));
}

#[test]
fn batch_applies_ordered_operations() {
    let mut db = MemoryDatabase::new();
    let mut batch = Batch::new();
    batch.put(Column::Meta, b"a".to_vec(), b"1".to_vec());
    batch.put(Column::Meta, b"a".to_vec(), b"2".to_vec());
    batch.delete(Column::Meta, b"missing".to_vec());
    batch.put(Column::Headers, b"h".to_vec(), b"header".to_vec());
    db.write_batch(batch).expect("memory batch is infallible");
    assert_eq!(get(&db, Column::Meta, b"a"), Some(b"2".to_vec()));
    assert_eq!(get(&db, Column::Headers, b"h"), Some(b"header".to_vec()));
}

#[test]
fn batch_final_delete_wins() {
    let mut db = MemoryDatabase::new();
    let mut batch = Batch::new();
    batch.put(Column::Meta, b"a".to_vec(), b"1".to_vec());
    batch.delete(Column::Meta, b"a".to_vec());
    db.write_batch(batch).expect("memory batch is infallible");
    assert_eq!(get(&db, Column::Meta, b"a"), None);
    assert!(db.is_empty(Column::Meta));
}

#[test]
fn batch_delete_then_put_wins() {
    let mut db = MemoryDatabase::new();
    db.put(Column::Meta, b"a", b"old")
        .expect("memory put is infallible");

    let mut batch = Batch::new();
    batch.delete(Column::Meta, b"a".to_vec());
    batch.put(Column::Meta, b"a".to_vec(), b"new".to_vec());
    db.write_batch(batch).expect("memory batch is infallible");

    assert_eq!(get(&db, Column::Meta, b"a"), Some(b"new".to_vec()));
    assert_eq!(db.len(Column::Meta), 1);
}

#[test]
fn batch_delete_removes_prior_value() {
    let mut db = MemoryDatabase::new();
    db.put(Column::Meta, b"a", b"1")
        .expect("memory put is infallible");
    let mut batch = Batch::new();
    batch.delete(Column::Meta, b"a".to_vec());
    db.write_batch(batch).expect("memory batch is infallible");
    assert_eq!(get(&db, Column::Meta, b"a"), None);
    assert!(db.is_empty(Column::Meta));
}

#[test]
fn empty_batch_is_noop() {
    let mut db = MemoryDatabase::new();
    db.put(Column::Meta, b"a", b"1")
        .expect("memory put is infallible");
    let before = db.clone();
    db.write_batch(Batch::new())
        .expect("memory batch is infallible");
    assert_eq!(db, before);
}

#[test]
fn counters_accumulate_and_live_readers_see_later_writes() {
    let mut db = MemoryDatabase::new();
    let reader = db.read_handle();
    let mut batch = Batch::new();
    batch.add_count(Column::StateRefs, b"node".to_vec(), 2);
    batch.add_count(Column::StateRefs, b"node".to_vec(), -1);
    db.write_batch(batch).expect("memory batch is infallible");
    let count = |reader: &dyn ReadHandle| {
        reader
            .get(Column::StateRefs, b"node")
            .unwrap()
            .as_deref()
            .and_then(decode_count)
    };
    assert_eq!(count(reader.as_ref()), Some(1));
    let copy = db.clone();
    db.delete(Column::StateRefs, b"node")
        .expect("memory delete is infallible");
    assert_eq!(count(reader.as_ref()), None);
    assert_eq!(count(copy.read_handle().as_ref()), Some(1));
}

#[test]
fn len_tracks_column_entries_after_deletes() {
    let mut db = MemoryDatabase::new();
    db.put(Column::Blocks, b"a", b"1")
        .expect("memory put is infallible");
    db.put(Column::Blocks, b"b", b"2")
        .expect("memory put is infallible");
    assert_eq!(db.len(Column::Blocks), 2);

    db.delete(Column::Blocks, b"a")
        .expect("memory delete is infallible");
    assert_eq!(db.len(Column::Blocks), 1);
    assert!(!db.is_empty(Column::Blocks));

    db.delete(Column::Blocks, b"b")
        .expect("memory delete is infallible");
    assert_eq!(db.len(Column::Blocks), 0);
    assert!(db.is_empty(Column::Blocks));
}
