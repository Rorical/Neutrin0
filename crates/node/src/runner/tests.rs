use super::NodeError;
use super::engine::load_trusted_checkpoint;
use super::proposer::proposer_keys;
use super::workers::topic_from_name;
use crate::config::{NodeConfig, RemoteSignerConfig};
use neutrin0_network::Topic;

/// The validator key comes from exactly one source: an encrypted keystore
/// or a remote signer serves it as an IKM would.
#[test]
fn a_validator_key_comes_from_one_keystore_or_remote_signer() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = std::env::temp_dir().join(format!("neutrin0-key-sources-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let secret = neutrin0_crypto::bls::SecretKey::key_gen(&[6; 32], &[]).unwrap();
    let identity = secret.public_key().to_bytes();
    let keystore = dir.join("v0.keystore.json");
    let password = dir.join("password");
    std::fs::write(
        &keystore,
        neutrin0_keystore::Keystore::encrypt(&secret, "correct horse", "v0")
            .unwrap()
            .to_json()
            .unwrap(),
    )
    .unwrap();
    std::fs::write(&password, "correct horse\n").unwrap();
    std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
    let encrypted = NodeConfig {
        proposer_keystore_path: Some(keystore),
        proposer_keystore_password_path: Some(password),
        ..NodeConfig::default()
    };
    assert_eq!(
        *proposer_keys(&encrypted, 3).unwrap().0.public_key_bytes(),
        identity
    );
    let ambiguous = NodeConfig {
        proposer_ikm_hex: Some("42".repeat(32)),
        ..encrypted
    };
    assert!(matches!(
        proposer_keys(&ambiguous, 0),
        Err(NodeError::ProposerKey(_))
    ));

    let socket = dir.join("signer.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let signer = std::sync::Arc::new(neutrin0_signer::Signer::new(
        neutrin0_primitives::ConsensusDomain::new(7, [9; 32]),
        vec![secret],
        neutrin0_storage::MemoryDatabase::new(),
    ));
    std::thread::spawn(move || signer.serve_unix(&listener));
    let remote = NodeConfig {
        remote_signer: Some(RemoteSignerConfig {
            unix_socket: Some(socket),
            ..RemoteSignerConfig::default()
        }),
        ..NodeConfig::default()
    };
    let key = proposer_keys(&remote, 1).unwrap().0;
    assert_eq!(*key.public_key_bytes(), identity);
    let nil = neutrin0_consensus_engine::SignRequest::NilVote(
        neutrin0_consensus_types::NilVoteAttestation {
            validator_index: 1,
            vote: neutrin0_consensus_types::NilVoteData {
                chunk_id: 0,
                round: 0,
                phase: neutrin0_consensus_types::FinalityVotePhase::Prevote,
            },
            vote_signature: [0; 96],
            signature: [0; 96],
        },
    );
    assert!(
        key.sign(neutrin0_primitives::ConsensusDomain::new(7, [9; 32]), &nil)
            .is_ok()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn light_client_trusted_checkpoint_is_read_within_its_limit() {
    const REFUSED: &str = "trusted checkpoint exceeds size limit";
    let path = std::env::temp_dir().join(format!(
        "neutrin0-light-checkpoint-{}.borsh",
        std::process::id()
    ));
    std::fs::write(&path, vec![0; 1025]).unwrap();
    let oversized = load_trusted_checkpoint(&path);
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(oversized, Err(NodeError::ProofSystem(message)) if message == REFUSED));
    // An unbounded source is refused after reading only the limit.
    #[cfg(unix)]
    assert!(matches!(
        load_trusted_checkpoint(std::path::Path::new("/dev/zero")),
        Err(NodeError::ProofSystem(message)) if message == REFUSED
    ));
}

#[test]
fn configured_topics_include_valid_aggregate_subnets() {
    assert_eq!(
        topic_from_name("/neutrin0/aggregate_finality_votes_0/borsh"),
        Some(Topic::AggregateFinalityVotes(0))
    );
    assert_eq!(
        topic_from_name("/neutrin0/aggregate_finality_votes_15/borsh"),
        Some(Topic::AggregateFinalityVotes(15))
    );
    assert_eq!(
        topic_from_name("/neutrin0/aggregate_finality_votes_16/borsh"),
        None
    );
    assert_eq!(topic_from_name("/unknown/topic"), None);
}
