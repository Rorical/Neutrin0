use std::collections::BTreeSet;

use super::*;

#[test]
fn memory_mode_preserves_cold_authenticated_sources_and_refuses_unbounded_growth() {
    let store = ProgramStore::in_memory();
    let mut first = None;
    for index in 0..MAX_MEMORY_SOURCES {
        let mut bytes = b"\0asmmemory-source".to_vec();
        bytes.extend(u32::try_from(index).unwrap().to_le_bytes());
        let hash = content_hash(&bytes).unwrap();
        let identity = ArtifactIdentity::Runtime(blake3_256(&bytes));
        store.remember_identity(&hash, &bytes, identity).unwrap();
        if first.is_none() {
            first = Some((identity, bytes));
        }
    }
    let (identity, bytes) = first.unwrap();
    assert_eq!(store.read_identity(identity).unwrap(), bytes);
    let extra = b"\0asmone-more-protected-source";
    let hash = content_hash(extra).unwrap();
    let extra_identity = ArtifactIdentity::Runtime(blake3_256(extra));
    assert!(
        store
            .remember_identity(&hash, extra, extra_identity)
            .is_err()
    );
    store.retain_sources(&BTreeSet::from([identity]), &BTreeSet::new());
    store
        .remember_identity(&hash, extra, extra_identity)
        .unwrap();
    assert_eq!(store.read_identity(identity).unwrap(), bytes);
    assert_eq!(store.read_identity(extra_identity).unwrap(), extra);
}

#[test]
fn proposed_guest_content_has_no_verified_key_index_and_is_pruned_when_abandoned() {
    let dir = std::env::temp_dir().join(format!(
        "neutrin0-proposal-source-{}-{}",
        std::process::id(),
        NEXT_TEMP_FILE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let store = ProgramStore::open(&dir).unwrap();
    let bytes = b"\x7fELFbounded-unapproved-proposal";
    let hash = content_hash(bytes).unwrap();
    store.stage_authenticated(&hash, bytes).unwrap().accept();
    let claimed = ArtifactIdentity::Guest([7; 8]);
    assert!(store.has_persisted(&hash));
    assert!(store.read_identity(claimed).is_none());
    store.retain_sources(&BTreeSet::new(), &BTreeSet::from([hash]));
    assert!(store.has_persisted(&hash));
    store.retain_sources(&BTreeSet::new(), &BTreeSet::new());
    assert!(!store.has_persisted(&hash));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn opening_sweeps_temporary_files_a_crash_left_behind() {
    let dir = std::env::temp_dir().join(format!(
        "neutrin0-program-sweep-{}-{}",
        std::process::id(),
        NEXT_TEMP_FILE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let store = ProgramStore::open(&dir).unwrap();
    let bytes = b"\0asmkept-across-a-crash";
    let hash = content_hash(bytes).unwrap();
    store
        .remember_identity(&hash, bytes, ArtifactIdentity::Runtime(blake3_256(bytes)))
        .unwrap();
    drop(store);
    let artifact = ProgramStore::artifact_path(&dir, &hash);
    let leftovers = [
        artifact.with_extension("7-3.tmp"),
        dir.join("identity-00.pending"),
    ];
    for leftover in &leftovers {
        fs::write(leftover, b"partial").unwrap();
    }
    let reopened = ProgramStore::open(&dir).unwrap();
    assert!(leftovers.iter().all(|leftover| !leftover.exists()));
    assert!(artifact.exists());
    drop(reopened);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn authenticated_runtime_index_survives_restart_and_rechecks_exact_bytes() {
    let dir = std::env::temp_dir().join(format!(
        "neutrin0-runtime-source-{}-{}",
        std::process::id(),
        NEXT_TEMP_FILE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let store = ProgramStore::open(&dir).unwrap();
    let bytes = b"\0asmbounded-locally-authenticated-source";
    let hash = content_hash(bytes).unwrap();
    let identity = ArtifactIdentity::Runtime(blake3_256(bytes));
    store.remember_identity(&hash, bytes, identity).unwrap();
    drop(store);
    let reopened = ProgramStore::open(&dir).unwrap();
    reopened.retain_sources(&BTreeSet::from([identity]), &BTreeSet::new());
    assert_eq!(reopened.read_identity(identity).unwrap(), bytes);
    fs::write(
        ProgramStore::artifact_path(&dir, &hash),
        b"\0asmchanged-content",
    )
    .unwrap();
    assert!(reopened.read_identity(identity).is_none());
    fs::remove_dir_all(dir).unwrap();
}

fn wanted(bytes: &[u8]) -> BTreeSet<Hash> {
    BTreeSet::from([content_hash(bytes).unwrap()])
}

#[test]
fn pieces_assemble_in_any_order_and_forged_or_unwanted_pieces_are_dropped() {
    let store = ProgramStore::in_memory();
    let artifact: Vec<u8> = (0..(MAX_PROGRAM_PIECE_BYTES * 2 + 3000))
        .map(|i| u8::try_from(i % 251).expect("below 256"))
        .collect();
    let hash = content_hash(&artifact).unwrap();
    let mut pieces = split_into_pieces(&artifact).unwrap();
    assert_eq!(pieces.len(), 3);
    assert!(pieces.iter().all(ProgramPiece::authenticates));
    pieces.reverse();
    let wanted = wanted(&artifact);
    assert_eq!(store.absorb(&pieces[..2], &wanted), Vec::<Hash>::new());
    // A forged piece for this artifact never enters the assembly.
    let mut forged = pieces[2].clone();
    forged.bytes[0] ^= 1;
    assert!(!forged.authenticates());
    assert_eq!(store.absorb(&[forged], &wanted), Vec::<Hash>::new());
    assert_eq!(store.absorb(&pieces[2..], &wanted), vec![hash]);
    assert_eq!(store.artifact(&hash).as_deref(), Some(&artifact));
    // Artifacts governance never named are not assembled at all.
    let other = vec![7_u8; 2000];
    let other_pieces = split_into_pieces(&other).unwrap();
    assert_eq!(store.absorb(&other_pieces, &wanted), Vec::<Hash>::new());
    assert_eq!(store.status().assembling.len(), 0);
}

#[test]
fn reserved_lengths_bound_assembly_memory() {
    let store = ProgramStore::in_memory();
    // Nine 16 MiB declarations exceed the 128 MiB budget: the ninth is
    // refused even though only one piece of each has arrived.
    let mut wanted = BTreeSet::new();
    let mut firsts = Vec::new();
    for seed in 0..9_u8 {
        let artifact = vec![seed; MAX_PROGRAM_BYTES as usize];
        let pieces = split_into_pieces(&artifact).unwrap();
        wanted.insert(pieces[0].content_hash());
        firsts.push(pieces[0].clone());
    }
    assert_eq!(store.absorb(&firsts, &wanted), Vec::<Hash>::new());
    assert_eq!(store.status().assembling.len(), 8);
}

/// Small single-piece artifacts with their content hashes.
fn small_artifacts(count: usize, salt: u8) -> Vec<(Hash, Vec<u8>)> {
    (0..count)
        .map(|index| {
            let bytes = vec![salt ^ u8::try_from(index).expect("few artifacts"); 64];
            (content_hash(&bytes).unwrap(), bytes)
        })
        .collect()
}

#[test]
fn completed_artifacts_are_evicted_oldest_first() {
    let store = ProgramStore::in_memory();
    let mut artifacts = small_artifacts(MAX_COMPLETE_ARTIFACTS + 1, 0);
    // Complete in descending hash order, so the newest completion has the
    // smallest hash: evicting by hash would drop it as soon as it arrives.
    artifacts.sort_by_key(|(hash, _)| std::cmp::Reverse(*hash));
    for (hash, bytes) in &artifacts {
        let pieces = split_into_pieces(bytes).unwrap();
        let named = BTreeSet::from([*hash]);
        assert_eq!(store.absorb(&pieces, &named), vec![*hash]);
        // Every reported completion still has bytes for the installer.
        assert_eq!(store.artifact(hash).as_deref(), Some(bytes));
    }
    let complete = store.status().complete;
    assert_eq!(complete.len(), MAX_COMPLETE_ARTIFACTS);
    assert!(!complete.contains(&artifacts[0].0), "oldest is evicted");
    for (hash, _) in &artifacts[1..] {
        assert!(complete.contains(hash));
    }
}

#[test]
fn an_absorption_never_evicts_an_artifact_it_reports() {
    let store = ProgramStore::in_memory();
    let artifacts = small_artifacts(MAX_COMPLETE_ARTIFACTS + 1, 0x80);
    let named: BTreeSet<Hash> = artifacts.iter().map(|(hash, _)| *hash).collect();
    let pieces: Vec<ProgramPiece> = artifacts
        .iter()
        .flat_map(|(_, bytes)| split_into_pieces(bytes).unwrap())
        .collect();
    let completed = store.absorb(&pieces, &named);
    // The bounds hold the first completions; the excess one is refused
    // rather than reported without bytes.
    assert_eq!(completed.len(), MAX_COMPLETE_ARTIFACTS);
    for hash in &completed {
        assert!(store.artifact(hash).is_some());
    }
    assert_eq!(store.status().complete.len(), MAX_COMPLETE_ARTIFACTS);
}

#[test]
fn persisted_artifacts_round_trip_and_publication_streams_a_file() {
    let dir = std::env::temp_dir().join(format!("neutrin0-programs-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let store = ProgramStore::open(&dir).unwrap();
    let artifact = vec![b'\0', b'a', b's', b'm', 1, 2, 3];
    let hash = content_hash(&artifact).unwrap();
    assert_eq!(
        store.absorb(&split_into_pieces(&artifact).unwrap(), &wanted(&artifact)),
        vec![hash]
    );
    // Completion alone never touches disk; only installation persists.
    assert_eq!(store.persisted(), Vec::<(Hash, Vec<u8>)>::new());
    store.persist(&hash, &artifact);
    store.mark_installed(&hash);
    assert_eq!(store.persisted(), vec![(hash, artifact.clone())]);
    assert_eq!(ArtifactKind::of(&artifact), ArtifactKind::Wasm);
    // Publication: a 3-piece file yields two pieces per block.
    let file: Vec<u8> = vec![9; MAX_PROGRAM_PIECE_BYTES * 2 + 10];
    fs::write(dir.join("publish").join("upgrade.elf"), &file).unwrap();
    let first = store.next_pieces(2);
    assert_eq!(first.len(), 2);
    assert_eq!(first[0].content_hash(), content_hash(&file).unwrap());
    assert_eq!(store.status().publishing.map(|p| p.1), Some(2));
    let last = store.next_pieces(2);
    assert_eq!(last.len(), 1);
    assert_eq!(last[0].bytes.len(), 10);
    assert_eq!(store.next_pieces(2), Vec::<ProgramPiece>::new());
    assert!(dir.join("published").join("upgrade.elf").exists());
    let rebuilt = ProgramStore::in_memory();
    let mut all = first;
    all.extend(last);
    assert_eq!(
        rebuilt.absorb(&all, &wanted(&file)),
        vec![content_hash(&file).unwrap()]
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rejected_stage_preserves_an_existing_authenticated_artifact() {
    let dir = std::env::temp_dir().join(format!(
        "neutrin0-program-stage-existing-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    let store = ProgramStore::open(&dir).unwrap();
    let bytes = b"\x7fELFpreviously-accepted-guest".to_vec();
    let hash = content_hash(&bytes).unwrap();
    store.persist_authenticated(&hash, &bytes).unwrap();
    let stage = store.stage_authenticated(&hash, &bytes).unwrap();
    assert!(!stage.created);
    // A failed expected-key check rejects this attempt, without undoing the
    // preceding installation which owns the same content-addressed file.
    drop(stage);
    assert_eq!(store.persisted(), vec![(hash, bytes)]);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn rejected_stage_does_not_delete_a_concurrent_commit() {
    let dir = std::env::temp_dir().join(format!(
        "neutrin0-program-stage-concurrent-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    let store = Arc::new(ProgramStore::open(&dir).unwrap());
    let bytes = b"\x7fELFconcurrently-accepted-guest".to_vec();
    let hash = content_hash(&bytes).unwrap();
    let stage = store.stage_authenticated(&hash, &bytes).unwrap();
    assert!(stage.created);
    assert!(matches!(
        store.persistence.try_lock(),
        Err(std::sync::TryLockError::WouldBlock)
    ));
    let (started, ready) = std::sync::mpsc::channel();
    let (committed, finished) = std::sync::mpsc::channel();
    let writer_store = Arc::clone(&store);
    let writer_bytes = bytes.clone();
    let writer = std::thread::spawn(move || {
        started.send(()).unwrap();
        writer_store
            .persist_authenticated(&hash, &writer_bytes)
            .unwrap();
        committed.send(()).unwrap();
    });
    ready.recv().unwrap();
    // The writer cannot publish while this rejected stage owns the scope.
    assert!(finished.try_recv().is_err());
    drop(stage);
    finished.recv().unwrap();
    writer.join().unwrap();
    assert_eq!(store.persisted(), vec![(hash, bytes)]);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn rejected_new_stage_removes_only_its_provisional_file() {
    let dir = std::env::temp_dir().join(format!(
        "neutrin0-program-stage-reject-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    let store = ProgramStore::open(&dir).unwrap();
    let trusted = b"\x7fELFtrusted-guest".to_vec();
    let trusted_hash = content_hash(&trusted).unwrap();
    store
        .persist_authenticated(&trusted_hash, &trusted)
        .unwrap();
    let rejected = b"\x7fELFwrong-guest-for-requested-key".to_vec();
    let rejected_hash = content_hash(&rejected).unwrap();
    drop(
        store
            .stage_authenticated(&rejected_hash, &rejected)
            .unwrap(),
    );
    assert_eq!(store.persisted(), vec![(trusted_hash, trusted)]);
    assert!(!ProgramStore::artifact_path(&dir, &rejected_hash).exists());
    fs::remove_dir_all(&dir).unwrap();
}
