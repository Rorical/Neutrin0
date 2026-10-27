//! Identity persistence and no-clobber first-start publication.

use std::sync::{Arc, Barrier};

use super::*;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "neutrin0-network-key-{}-{}",
            std::process::id(),
            Keypair::generate_ed25519().public().to_peer_id()
        ));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn config(path: &Path) -> NodeConfig {
    NodeConfig {
        network_key_path: Some(path.to_path_buf()),
        ..NodeConfig::default()
    }
}

fn assert_only_key(directory: &Path, expected: &Path) {
    let paths: Vec<_> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(paths, vec![expected.to_path_buf()]);
}

#[test]
fn first_start_creates_a_private_key_and_restart_preserves_peer_id() {
    let directory = TestDirectory::new();
    let path = directory.0.join("keys/p2p-key");
    let config = config(&path);
    let first = load_network_identity(&config).unwrap();
    let original = fs::read(&path).unwrap();
    let second = load_network_identity(&config).unwrap();
    assert_eq!(first.public().to_peer_id(), second.public().to_peer_id());
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_only_key(path.parent().unwrap(), &path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }
}

#[test]
fn explicit_path_overrides_data_directory_and_default_uses_data_directory() {
    let directory = TestDirectory::new();
    let data = directory.0.join("data");
    let default_config = NodeConfig {
        data_dir: Some(data.clone()),
        ..NodeConfig::default()
    };
    let default_key = load_network_identity(&default_config).unwrap();
    let explicit_path = directory.0.join("separate-key");
    let mut explicit_config = config(&explicit_path);
    explicit_config.data_dir = Some(data.clone());
    let explicit_key = load_network_identity(&explicit_config).unwrap();
    assert_ne!(
        default_key.public().to_peer_id(),
        explicit_key.public().to_peer_id()
    );
    assert_eq!(
        load_network_identity(&default_config)
            .unwrap()
            .public()
            .to_peer_id(),
        default_key.public().to_peer_id()
    );
    assert_eq!(
        load_network_identity(&explicit_config)
            .unwrap()
            .public()
            .to_peer_id(),
        explicit_key.public().to_peer_id()
    );
    assert!(data.join("p2p-key").is_file());
    assert!(explicit_path.is_file());
}

#[test]
fn ephemeral_configuration_creates_no_persistent_identity() {
    let config = NodeConfig::default();
    let first = load_network_identity(&config)
        .unwrap()
        .public()
        .to_peer_id();
    let second = load_network_identity(&config)
        .unwrap()
        .public()
        .to_peer_id();
    assert_ne!(first, second);
}

#[test]
fn malformed_existing_key_is_rejected_without_replacement() {
    let directory = TestDirectory::new();
    let path = directory.0.join("p2p-key");
    let _ = load_network_identity(&config(&path)).unwrap();
    fs::write(&path, b"invalid protobuf private key").unwrap();
    let original = fs::read(&path).unwrap();
    assert!(matches!(
        load_network_identity(&config(&path)),
        Err(NetworkIdentityError::InvalidKey { .. })
    ));
    // Also exercise publication losing to a corrupt existing winner: it must
    // not replace that key or fall back to its own temporary identity.
    assert!(matches!(
        create_identity(&path),
        Err(NetworkIdentityError::InvalidKey { .. })
    ));
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_only_key(&directory.0, &path);
}

#[test]
fn directory_or_non_directory_parent_errors_do_not_generate_a_new_identity() {
    let directory = TestDirectory::new();
    assert!(matches!(
        load_network_identity(&config(&directory.0)),
        Err(NetworkIdentityError::NotRegular { .. })
    ));
    let file = directory.0.join("not-a-directory");
    fs::write(&file, b"existing file").unwrap();
    assert!(matches!(
        load_network_identity(&config(&file.join("p2p-key"))),
        Err(NetworkIdentityError::Io { .. })
    ));
    assert_eq!(fs::read(&file).unwrap(), b"existing file");
}

#[cfg(unix)]
#[test]
fn loose_or_missing_permissions_are_rejected_without_changing_the_key() {
    use std::os::unix::fs::PermissionsExt;
    let directory = TestDirectory::new();
    let path = directory.0.join("p2p-key");
    let _ = load_network_identity(&config(&path)).unwrap();
    let original = fs::read(&path).unwrap();
    for mode in [0o644, 0o660, 0o400, 0o000] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(matches!(
            load_network_identity(&config(&path)),
            Err(NetworkIdentityError::Permissions { mode: observed, .. }) if observed == mode
        ));
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_only_key(&directory.0, &path);
}

#[cfg(unix)]
#[test]
fn symlink_key_paths_are_rejected() {
    use std::os::unix::fs::symlink;
    let directory = TestDirectory::new();
    let actual = directory.0.join("actual-key");
    let _ = load_network_identity(&config(&actual)).unwrap();
    let link = directory.0.join("linked-key");
    symlink(&actual, &link).unwrap();
    assert!(matches!(
        load_network_identity(&config(&link)),
        Err(NetworkIdentityError::NotRegular { .. })
    ));
}

#[test]
fn concurrent_first_start_and_publication_share_one_complete_identity() {
    let directory = TestDirectory::new();
    let path = directory.0.join("p2p-key");
    let config = Arc::new(config(&path));
    let barrier = Arc::new(Barrier::new(8));
    #[allow(
        clippy::needless_collect,
        reason = "spawn all barrier participants before joining; a lazy iterator deadlocks"
    )]
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let config = Arc::clone(&config);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                load_network_identity(&config)
                    .unwrap()
                    .public()
                    .to_peer_id()
            })
        })
        .collect();
    let peers: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert!(peers.iter().all(|peer| *peer == peers[0]));
    assert_eq!(
        load_network_identity(&config)
            .unwrap()
            .public()
            .to_peer_id(),
        peers[0]
    );
    // Exercise every no-clobber loser path even when some initial readers saw
    // the winner before they needed to create their own staging file.
    for _ in 0..3 {
        assert_eq!(
            create_identity(&path).unwrap().public().to_peer_id(),
            peers[0]
        );
    }
    assert_only_key(&directory.0, &path);
}
