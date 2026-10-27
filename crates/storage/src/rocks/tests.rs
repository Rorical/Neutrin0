use super::*;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn get(db: &RocksDbDatabase, column: Column, key: &[u8]) -> Option<Vec<u8>> {
    db.get(column, key).expect("rocksdb get succeeds")
}

fn temp_db_path(test_name: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "neutrin0-storage-{test_name}-{}-{nonce}",
        std::process::id()
    ))
}

#[test]
fn rocksdb_put_get_delete_roundtrip() {
    let path = temp_db_path("roundtrip");
    {
        let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
        db.put(Column::Meta, b"chain", b"a").expect("put");
        assert_eq!(get(&db, Column::Meta, b"chain"), Some(b"a".to_vec()));
        db.delete(Column::Meta, b"chain").expect("delete");
        assert_eq!(get(&db, Column::Meta, b"chain"), None);
    }
    fs::remove_dir_all(&path).expect("remove temp rocksdb");
}

#[test]
fn rocksdb_empty_key_and_empty_value_roundtrip() {
    let path = temp_db_path("empty-key-value");
    {
        let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
        db.put(Column::StateValues, b"", b"").expect("put empty");
        assert_eq!(get(&db, Column::StateValues, b""), Some(Vec::new()));
    }
    fs::remove_dir_all(&path).expect("remove temp rocksdb");
}

#[test]
fn rocksdb_binary_keys_and_values_are_preserved() {
    let path = temp_db_path("binary");
    let key = [0, 255, 1, 254, 2, 253];
    let value = [255, 0, 128, 64, 32, 16, 8, 4, 2, 1];
    {
        let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
        db.put(Column::TrieNodes, &key, &value).expect("put binary");
        assert_eq!(get(&db, Column::TrieNodes, &key), Some(value.to_vec()));
    }
    fs::remove_dir_all(&path).expect("remove temp rocksdb");
}

#[test]
fn rocksdb_all_columns_are_created_and_isolated() {
    let path = temp_db_path("all-columns");
    {
        let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
        for (index, column) in ALL_COLUMNS.iter().copied().enumerate() {
            db.put(
                column,
                b"shared-key",
                &[u8::try_from(index).expect("index fits u8")],
            )
            .expect("put column value");
        }

        for (index, column) in ALL_COLUMNS.iter().copied().enumerate() {
            assert_eq!(
                get(&db, column, b"shared-key"),
                Some(vec![u8::try_from(index).expect("index fits u8")])
            );
        }
    }
    fs::remove_dir_all(&path).expect("remove temp rocksdb");
}

#[test]
fn rocksdb_persists_values_after_reopen() {
    let path = temp_db_path("persist");
    {
        let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
        db.put(Column::Headers, b"h", b"header").expect("put");
    }
    {
        let db = RocksDbDatabase::open(&path).expect("reopen rocksdb");
        assert_eq!(get(&db, Column::Headers, b"h"), Some(b"header".to_vec()));
    }
    fs::remove_dir_all(&path).expect("remove temp rocksdb");
}

#[test]
fn rocksdb_counters_merge_and_live_readers_survive_reopen() {
    let path = temp_db_path("counters");
    let count = |reader: &dyn ReadHandle| {
        reader
            .get(Column::StateRefs, b"node")
            .expect("reader get succeeds")
            .as_deref()
            .and_then(decode_count)
    };
    {
        let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
        let reader = db.read_handle();
        let mut batch = Batch::new();
        batch.add_count(Column::StateRefs, b"node".to_vec(), 3);
        batch.add_count(Column::StateRefs, b"node".to_vec(), -1);
        db.write_batch(batch).expect("batch");
        assert_eq!(count(reader.as_ref()), Some(2));
        let mut batch = Batch::new();
        batch.add_count(Column::StateRefs, b"node".to_vec(), 5);
        db.write_batch(batch).expect("batch");
        assert_eq!(count(reader.as_ref()), Some(7));
    }
    {
        let db = RocksDbDatabase::open(&path).expect("reopen rocksdb");
        assert_eq!(count(db.read_handle().as_ref()), Some(7));
        assert_eq!(
            db.entries_from(Column::StateRefs, &[], 1)
                .expect("scan")
                .len(),
            1
        );
    }
    fs::remove_dir_all(&path).expect("remove temp rocksdb");
}

#[test]
fn durable_signing_batch_preserves_prior_finality_after_abrupt_exit() {
    use std::io::{BufRead, Read, Write};
    use std::process::Stdio;

    const CHILD_PATH: &str = "NEUTRIN0_DURABILITY_CHILD_DB";
    const SYNCED: &str = "NEUTRIN0_DURABILITY_SYNCED\n";
    if let Some(path) = std::env::var_os(CHILD_PATH) {
        let mut db = RocksDbDatabase::open(path).expect("open child database");
        let mut finality = Batch::new();
        finality.put(Column::Finalized, b"latest_chunk_id", 9_u64.to_be_bytes());
        db.write_batch(finality).expect("ordinary finality write");
        let mut signing = Batch::new();
        signing.put(Column::SigningJournal, b"identity", b"reserved-message");
        signing.put(Column::BftSessions, b"chunk", b"saved-session");
        db.write_batch_durable(signing)
            .expect("synchronize signing and prior WAL");
        // The parent kills this process only after the synchronized write.
        // Waiting avoids libc/C++ exit handlers and normal database flushes.
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(SYNCED.as_bytes())
            .expect("signal synchronized write");
        stdout.flush().expect("flush synchronization signal");
        std::io::stdin()
            .read_exact(&mut [0])
            .expect("parent keeps input open until terminating child");
        panic!("parent must terminate the synchronized child without shutdown");
    }
    let path = temp_db_path("durable-abrupt-exit");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("rocks::tests::durable_signing_batch_preserves_prior_finality_after_abrupt_exit")
        .arg("--nocapture")
        .env(CHILD_PATH, &path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("run crash child");
    let mut output = std::io::BufReader::new(child.stdout.take().expect("child output pipe"));
    let mut transcript = String::new();
    while !transcript.ends_with(SYNCED) {
        assert_ne!(
            output
                .read_line(&mut transcript)
                .expect("read synchronization signal"),
            0,
            "child exited before synchronizing its write: {transcript}"
        );
    }
    child.kill().expect("terminate without database shutdown");
    let status = child.wait().expect("reap terminated child");
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            status.signal(),
            Some(9),
            "child must be killed with SIGKILL"
        );
    }
    #[cfg(not(unix))]
    assert!(!status.success(), "child must be forcibly terminated");
    let db = RocksDbDatabase::open(&path).expect("recover child WAL");
    assert_eq!(
        get(&db, Column::Finalized, b"latest_chunk_id"),
        Some(9_u64.to_be_bytes().to_vec())
    );
    assert_eq!(
        get(&db, Column::SigningJournal, b"identity"),
        Some(b"reserved-message".to_vec())
    );
    assert_eq!(
        get(&db, Column::BftSessions, b"chunk"),
        Some(b"saved-session".to_vec())
    );
    drop(db);
    fs::remove_dir_all(&path).expect("remove crash child database");
}

#[test]
fn rocksdb_key_pages_match_entry_pages() {
    let path = temp_db_path("key-pages");
    {
        let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
        for key in [b"a1", b"b1", b"b2", b"b3", b"c1"] {
            db.put(Column::Meta, key, &[7; 4096]).expect("put");
        }
        let first = db.keys_from(Column::Meta, b"b", 2).expect("first page");
        assert_eq!(first, vec![b"b1".to_vec(), b"b2".to_vec()]);
        let mut after = first[1].clone();
        after.push(0);
        assert_eq!(
            db.keys_from(Column::Meta, &after, 8).expect("second page"),
            db.entries_from(Column::Meta, &after, 8)
                .expect("entry page")
                .into_iter()
                .map(|(key, _)| key)
                .collect::<Vec<_>>()
        );
    }
    fs::remove_dir_all(&path).expect("remove temp rocksdb");
}

#[test]
fn rocksdb_delete_persists_after_reopen() {
    let path = temp_db_path("delete-persists");
    {
        let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
        db.put(Column::Headers, b"h", b"header").expect("put");
        db.delete(Column::Headers, b"h").expect("delete");
    }
    {
        let db = RocksDbDatabase::open(&path).expect("reopen rocksdb");
        assert_eq!(get(&db, Column::Headers, b"h"), None);
    }
    fs::remove_dir_all(&path).expect("remove temp rocksdb");
}

#[test]
fn rocksdb_batch_is_atomic_and_ordered() {
    let path = temp_db_path("batch");
    {
        let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
        let mut batch = Batch::new();
        batch.put(Column::Meta, b"a".to_vec(), b"1".to_vec());
        batch.put(Column::Meta, b"a".to_vec(), b"2".to_vec());
        batch.put(Column::Blocks, b"a".to_vec(), b"block".to_vec());
        db.write_batch(batch).expect("write batch");
        assert_eq!(get(&db, Column::Meta, b"a"), Some(b"2".to_vec()));
        assert_eq!(get(&db, Column::Blocks, b"a"), Some(b"block".to_vec()));
    }
    fs::remove_dir_all(&path).expect("remove temp rocksdb");
}

#[test]
fn rocksdb_batch_final_delete_wins() {
    let path = temp_db_path("batch-final-delete");
    {
        let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
        let mut batch = Batch::new();
        batch.put(Column::Meta, b"a".to_vec(), b"1".to_vec());
        batch.delete(Column::Meta, b"a".to_vec());
        db.write_batch(batch).expect("write batch");
        assert_eq!(get(&db, Column::Meta, b"a"), None);
    }
    fs::remove_dir_all(&path).expect("remove temp rocksdb");
}

#[test]
fn rocksdb_batch_delete_then_put_wins() {
    let path = temp_db_path("batch-delete-put");
    {
        let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
        db.put(Column::Meta, b"a", b"old").expect("put old");
        let mut batch = Batch::new();
        batch.delete(Column::Meta, b"a".to_vec());
        batch.put(Column::Meta, b"a".to_vec(), b"new".to_vec());
        db.write_batch(batch).expect("write batch");
        assert_eq!(get(&db, Column::Meta, b"a"), Some(b"new".to_vec()));
    }
    fs::remove_dir_all(&path).expect("remove temp rocksdb");
}

#[test]
fn rocksdb_key_scans_skip_values_and_stop_at_the_bound() {
    let path = temp_db_path("key_scans");
    let mut db = RocksDbDatabase::open(&path).unwrap();
    for count in [3_u64, 1, 2, 7] {
        db.put(Column::Chunks, &count.to_be_bytes(), &[0xAA; 64])
            .unwrap();
    }
    let below: Vec<u64> = db
        .keys_below(Column::Chunks, &3_u64.to_be_bytes())
        .unwrap()
        .into_iter()
        .map(|key| u64::from_be_bytes(key.try_into().unwrap()))
        .collect();
    assert_eq!(below, [1, 2]);
    assert_eq!(db.iter_keys(Column::Chunks).unwrap().len(), 4);
    drop(db);
    let _ = fs::remove_dir_all(path);
}

#[test]
fn rocksdb_deleting_missing_key_is_noop() {
    let path = temp_db_path("missing-delete");
    {
        let mut db = RocksDbDatabase::open(&path).expect("open rocksdb");
        db.delete(Column::Meta, b"missing").expect("delete missing");
        assert_eq!(get(&db, Column::Meta, b"missing"), None);
    }
    fs::remove_dir_all(&path).expect("remove temp rocksdb");
}
#[test]
fn statistics_record_actual_operations_without_scanning_records() {
    let path = temp_db_path("statistics");
    {
        let mut db = RocksDbDatabase::open(&path).unwrap();
        db.put(Column::Meta, b"key", b"value").unwrap();
        assert_eq!(
            db.get(Column::Meta, b"key").unwrap(),
            Some(b"value".to_vec())
        );
        let mut batch = Batch::new();
        batch.put(Column::Meta, b"durable", b"value");
        db.write_batch_durable(batch).unwrap();
        let before = db.statistics().unwrap();
        let after = db.statistics().unwrap();
        assert_eq!(before.attempts, [1, 1, 0, 0, 1, 0, 0]);
        assert_eq!(before.failures, [0; 7]);
        assert_eq!(before.attempts, after.attempts);
        assert!(before.memtable_bytes.is_some());
    }
    fs::remove_dir_all(path).unwrap();
}
