use super::*;

#[test]
fn concurrent_atomic_writes_never_share_a_temporary_file() {
    let dir = std::env::temp_dir().join(format!(
        "neutrin0-write-atomic-{}-{}",
        std::process::id(),
        TEMP_SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vk.bin");
    // With one shared temporary name, a writer could rename another's
    // half-written file into place or find its own file already renamed.
    std::thread::scope(|scope| {
        for writer in 0..8_u8 {
            let path = &path;
            scope.spawn(move || {
                let bytes = vec![writer; 64 * 1024];
                for _ in 0..16 {
                    write_atomic(path, &bytes).expect("every concurrent write lands");
                }
            });
        }
    });
    let written = fs::read(&path).unwrap();
    assert_eq!(written.len(), 64 * 1024);
    assert!(written.iter().all(|byte| *byte == written[0]));
    let names: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, ["vk.bin"]);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn cache_pruning_drops_other_circuits_and_the_oldest_fact_directories() {
    let dir = std::env::temp_dir().join(format!(
        "neutrin0-cache-prune-{}-{}",
        std::process::id(),
        TEMP_SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    let current_vk = dir.join(format!("vk-sp1-{SP1_CIRCUIT_VERSION}-aa.bin"));
    let stale_vk = dir.join("vk-sp1-v0.0.0-aa.bin");
    fs::write(&current_vk, b"vk").unwrap();
    fs::write(&stale_vk, b"vk").unwrap();
    fs::create_dir_all(dir.join("facts-v0.0.0-key")).unwrap();
    let start = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
    for (age, key) in ["old", "middle", "new"].into_iter().enumerate() {
        let facts = dir.join(format!("facts-{SP1_CIRCUIT_VERSION}-{key}"));
        fs::create_dir_all(&facts).unwrap();
        fs::File::open(&facts)
            .unwrap()
            .set_modified(start + std::time::Duration::from_secs(age as u64))
            .unwrap();
    }
    prune_cache(&dir);
    let mut names: Vec<_> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            format!("facts-{SP1_CIRCUIT_VERSION}-middle"),
            format!("facts-{SP1_CIRCUIT_VERSION}-new"),
            format!("vk-sp1-{SP1_CIRCUIT_VERSION}-aa.bin"),
        ]
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_damaged_cache_file_is_not_opened() {
    let sealed = seal(b"verifying key");
    assert_eq!(open_sealed(&sealed), Some(&b"verifying key"[..]));
    let mut altered = sealed.clone();
    *altered.last_mut().unwrap() ^= 1;
    assert_eq!(open_sealed(&altered), None);
    assert_eq!(open_sealed(&sealed[..31]), None);
}
