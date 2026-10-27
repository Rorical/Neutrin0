use std::path::Path;
use std::time::Duration;

use super::trust::MAX_TRUSTED_CHECKPOINT_BYTES;
use super::*;

#[test]
fn trusted_checkpoint_reads_are_bounded() {
    let path = std::env::temp_dir().join(format!(
        "neutrin0-trusted-checkpoint-{}.borsh",
        std::process::id()
    ));
    let limit = usize::try_from(MAX_TRUSTED_CHECKPOINT_BYTES).unwrap();
    std::fs::write(&path, vec![7; limit]).unwrap();
    assert_eq!(
        read_trusted_checkpoint(&path).unwrap(),
        Some(vec![7; limit])
    );
    std::fs::write(&path, vec![7; limit + 1]).unwrap();
    assert_eq!(read_trusted_checkpoint(&path).unwrap(), None);
    std::fs::remove_file(&path).unwrap();
    assert!(read_trusted_checkpoint(&path).is_err());
    // An unbounded source is refused after reading only the limit; an
    // unbounded `fs::read` would never return here.
    #[cfg(unix)]
    assert_eq!(
        read_trusted_checkpoint(Path::new("/dev/zero")).unwrap(),
        None
    );
}

#[test]
fn network_identity_and_health_configuration_parse_with_defaults() {
    let minimal: NodeConfig = toml::from_str("chain_id = 1").unwrap();
    assert!(minimal.network_key_path.is_none());
    assert_eq!(minimal.health, HealthConfig::default());
    assert!(minimal.health.validate().is_ok());
    let explicit: NodeConfig = toml::from_str(
        "chain_id = 1\nnetwork_key_path = 'keys/network'\n[health]\nmin_peers = 0\nfinality_stall_timeout_secs = 120\n",
    )
    .unwrap();
    assert_eq!(
        explicit.network_key_path,
        Some(PathBuf::from("keys/network"))
    );
    assert_eq!(explicit.health.min_peers, 0);
    assert_eq!(explicit.health.finality_stall_timeout_secs, Some(120));
    assert!(explicit.health.validate().is_ok());
    let invalid: NodeConfig =
        toml::from_str("chain_id = 1\n[health]\nfinality_stall_timeout_secs = 0\n").unwrap();
    assert!(invalid.health.validate().is_err());
    assert!(toml::from_str::<NodeConfig>("chain_id = 1\n[health]\nmin_peer = 1").is_err());
}

#[test]
fn reporter_config_requires_nonzero_recipient_and_pruned_nonvalidator_mode() {
    let config: NodeConfig = toml::from_str(&format!(
        "chain_id = 1\nrole = 'reporter'\n[reporter]\nreward_address_hex = '{}{}'\n",
        "00".repeat(12),
        "ab".repeat(20)
    ))
    .unwrap();
    let mut expected = [0xab; 32];
    expected[..12].fill(0);
    assert_eq!(config.reporter_reward_address().unwrap(), Some(expected));
    assert_eq!(config.role.sync_mode(), neutrin0_sync::SyncMode::Snap);
    assert_eq!(
        config.role.retention_policy(),
        neutrin0_consensus_engine::RetentionPolicy::Reporter
    );
    assert!(config.proposer_ikm_path.is_none());
    assert!(config.proposer_ikm_hex.is_none());
    // Zero, short, malformed, and a value the runtime could never pay.
    for hex in [
        "00".repeat(32),
        "ab".repeat(31),
        "zz".repeat(32),
        "ab".repeat(32),
    ] {
        let mut invalid = config.clone();
        invalid.reporter.as_mut().unwrap().reward_address_hex = hex;
        assert!(invalid.reporter_reward_address().is_err());
    }
    let mut missing = config.clone();
    missing.reporter = None;
    assert!(missing.reporter_reward_address().is_err());
    let mut wrong_role = config;
    wrong_role.role = NodeRole::Full;
    assert!(wrong_role.reporter_reward_address().is_err());
}

#[tokio::test]
async fn invalid_reporter_config_fails_before_chain_spec_or_network() {
    let config: NodeConfig = toml::from_str("chain_id = 1\nrole = 'reporter'\n").unwrap();
    let error = crate::run(config).await.unwrap_err();
    assert!(error.to_string().contains("reward_address_hex"));
}

#[test]
fn parses_validator_production_fields() {
    let cfg: NodeConfig = toml::from_str(
        r#"
chain_id = 7
role = "validator"
proposer_ikm_hex = "4242424242424242424242424242424242424242424242424242424242424242"
proposer_index = 3
"#,
    )
    .expect("parse node config");

    assert_eq!(cfg.role, NodeRole::Validator);
    assert_eq!(cfg.proposer_index, Some(3));
    assert!(cfg.proposer_ikm_hex.is_some());
}

#[test]
fn parses_rpc_config_section() {
    let cfg: NodeConfig = toml::from_str(
        r#"
chain_id = 1

[rpc]
listen = "127.0.0.1:9933"
max_connections = 64
"#,
    )
    .expect("parse node config with rpc");

    let rpc = cfg.rpc.expect("rpc section present");
    assert_eq!(rpc.listen, "127.0.0.1:9933");
    assert_eq!(rpc.max_connections, 64);
    // Defaults filled in for unspecified fields.
    assert_eq!(rpc.max_request_body_size, 10 * 1024 * 1024);
    assert_eq!(rpc.max_response_body_size, 15 * 1024 * 1024);

    let runtime_cfg = rpc.to_runtime_config().expect("listen parses");
    assert_eq!(runtime_cfg.listen.port(), 9933);
    assert_eq!(runtime_cfg.max_connections, 64);
}

#[test]
fn rpc_limits_default_and_parse() {
    let cfg: NodeConfig = toml::from_str(
        r#"
chain_id = 1
[rpc]
listen = "127.0.0.1:9933"
max_concurrent_requests = 8
runtime_call_timeout_ms = 250
trusted_proxies = ["127.0.0.1"]
[execution]
query_fuel = 1000000
"#,
    )
    .unwrap();
    let rpc = cfg.rpc.unwrap().to_runtime_config().unwrap();
    assert_eq!(rpc.max_concurrent_requests, 8);
    assert_eq!(rpc.requests_per_second_per_client, 50);
    assert_eq!(
        (rpc.max_ws_connections, rpc.max_connections_per_client),
        (32, 16)
    );
    assert_eq!(
        rpc.trusted_proxies,
        vec![std::net::IpAddr::from([127, 0, 0, 1])]
    );
    assert_eq!(rpc.max_batch_requests, 16);
    assert_eq!(rpc.runtime_call_timeout, Duration::from_millis(250));
    let limits = cfg.execution.to_wasm_limits();
    assert_eq!(limits.query_fuel, 1_000_000);
    assert_eq!(
        limits.validate_tx_fuel,
        neutrin0_runtime_host::wasm::WasmLimits::default().validate_tx_fuel
    );
}

#[test]
fn execution_mode_defaults_follow_the_role() {
    let unset: NodeConfig = toml::from_str("chain_id = 1").unwrap();
    assert_eq!(unset.execution.mode, None);
    for (role, expected) in [
        (NodeRole::Full, ExecutionMode::ProofFollow),
        (NodeRole::Reporter, ExecutionMode::ProofFollow),
        (NodeRole::Validator, ExecutionMode::ProofFollow),
        (NodeRole::Archive, ExecutionMode::Execute),
        (NodeRole::LightClient, ExecutionMode::Execute),
    ] {
        assert_eq!(unset.execution.effective_mode(role), expected, "{role:?}");
        assert!(unset.execution.validate(role).is_ok(), "{role:?}");
    }
    let explicit: NodeConfig =
        toml::from_str("chain_id = 1\nrole = \"full\"\n[execution]\nmode = \"execute\"\n").unwrap();
    assert_eq!(
        explicit.execution.effective_mode(explicit.role),
        ExecutionMode::Execute
    );
    let follow: NodeConfig =
        toml::from_str("chain_id = 1\n[execution]\nmode = \"proof_follow\"\n").unwrap();
    assert!(follow.execution.validate(NodeRole::Full).is_ok());
    assert!(follow.execution.validate(NodeRole::Reporter).is_ok());
    assert!(follow.execution.validate(NodeRole::Archive).is_ok());
    assert!(follow.execution.validate(NodeRole::Validator).is_ok());
    assert!(follow.execution.validate(NodeRole::LightClient).is_err());
    assert!(toml::from_str::<NodeConfig>("chain_id = 1\n[execution]\nmode = \"wasm\"\n").is_err());
}

#[test]
fn proposer_ikm_comes_from_one_source_and_checks_permissions() {
    let dir = std::env::temp_dir().join(format!("neutrin0-ikm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("validator.ikm");
    std::fs::write(&path, "  aa".repeat(16) + "\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let cfg = NodeConfig {
            chain_id: 1,
            proposer_ikm_path: Some(path.clone()),
            ..NodeConfig::default()
        };
        assert!(matches!(
            cfg.resolve_proposer_ikm_hex(),
            Err(ProposerIkmError::Permissions { .. })
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::write(&path, format!("{}\n", "ab".repeat(32))).unwrap();
    let both = NodeConfig {
        chain_id: 1,
        proposer_ikm_path: Some(path.clone()),
        proposer_ikm_hex: Some("cd".repeat(32)),
        ..NodeConfig::default()
    };
    assert!(matches!(
        both.resolve_proposer_ikm_hex(),
        Err(ProposerIkmError::MultipleSources)
    ));
    let cfg = NodeConfig {
        chain_id: 1,
        proposer_ikm_path: Some(path),
        ..NodeConfig::default()
    };
    let (hex, source) = cfg.resolve_proposer_ikm_hex().unwrap().unwrap();
    assert_eq!(source, ProposerIkmSource::File);
    assert_eq!(hex, "ab".repeat(32));
    let inline = NodeConfig {
        chain_id: 1,
        proposer_ikm_hex: Some("cd".repeat(32)),
        ..NodeConfig::default()
    };
    assert_eq!(
        inline.resolve_proposer_ikm_hex().unwrap().unwrap().1,
        ProposerIkmSource::Inline
    );
    assert!(
        NodeConfig {
            chain_id: 1,
            ..NodeConfig::default()
        }
        .resolve_proposer_ikm_hex()
        .unwrap()
        .is_none()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn metrics_section_parses_and_defaults_off() {
    let cfg: NodeConfig =
        toml::from_str("chain_id = 1\n[metrics]\nlisten = \"127.0.0.1:9615\"\n").unwrap();
    assert_eq!(cfg.metrics.unwrap().listen, "127.0.0.1:9615");
    assert!(
        toml::from_str::<NodeConfig>("chain_id = 1\n")
            .unwrap()
            .metrics
            .is_none()
    );
}

#[test]
fn rpc_config_omitted_means_no_rpc_listener() {
    let cfg: NodeConfig = toml::from_str("chain_id = 1\n").expect("parse minimal config");
    assert!(cfg.rpc.is_none());
}

#[test]
fn proving_defaults_to_cpu_and_parses_explicit_cuda_device() {
    let cfg: NodeConfig = toml::from_str("chain_id = 1").unwrap();
    assert_eq!(cfg.proving.backend, ProvingBackend::Cpu);
    assert_eq!(cfg.proving.cuda_device, None);
    assert_eq!(cfg.proving.concurrency, 2);
    assert_eq!(cfg.proving.capacity, 16);
    assert_eq!(cfg.proving.chunk_proof_fallback_secs, 180);
    assert!(cfg.proving.validate().is_ok());
    let cfg: NodeConfig = toml::from_str(
        "chain_id = 1\n[proving]\nbackend = 'cuda'\ncuda_device = 3\nconcurrency = 1",
    )
    .unwrap();
    assert_eq!(cfg.proving.backend, ProvingBackend::Cuda);
    assert_eq!(cfg.proving.cuda_device, Some(3));
    assert_eq!(cfg.proving.concurrency, 1);
    assert_eq!(cfg.proving.capacity, 16);
}

#[test]
fn proving_parses_a_hex_prover_address_and_rejects_malformed_ones() {
    let cfg: NodeConfig = toml::from_str("chain_id = 1").unwrap();
    assert_eq!(cfg.proving.prover_address, None);
    let hex = format!("{}{}", "00".repeat(12), "11".repeat(20));
    let cfg: NodeConfig = toml::from_str(&format!(
        "chain_id = 1\n[proving]\nprover_address = '0x{hex}'"
    ))
    .unwrap();
    let mut expected = [0x11; 32];
    expected[..12].fill(0);
    assert_eq!(cfg.proving.prover_address, Some(HexAddress(expected)));
    // A value the runtime could never pay is refused at startup.
    for malformed in ["0x11", "zz", &"11".repeat(33), &"11".repeat(32)] {
        assert!(
            toml::from_str::<NodeConfig>(&format!(
                "chain_id = 1\n[proving]\nprover_address = '{malformed}'"
            ))
            .is_err(),
            "{malformed}"
        );
    }
}

#[test]
fn proving_rejects_unknown_backends_fields_and_invalid_budgets() {
    for options in [
        "backend = 'mock'",
        "backend = 'network'",
        "backned = 'cuda'",
        "cuda_device = -1",
    ] {
        assert!(
            toml::from_str::<NodeConfig>(&format!("chain_id = 1\n[proving]\n{options}")).is_err()
        );
    }
    for options in [
        "cuda_device = 0",
        "concurrency = 0",
        "concurrency = 65",
        "concurrency = 3\ncapacity = 2",
        "capacity = 1025",
        "chunk_proof_fallback_secs = 3601",
    ] {
        let cfg: NodeConfig =
            toml::from_str(&format!("chain_id = 1\n[proving]\n{options}")).unwrap();
        assert!(cfg.proving.validate().is_err(), "accepted {options}");
    }
}

#[tokio::test]
async fn invalid_proving_config_fails_before_network_and_chain_spec_for_every_role() {
    for role in ["validator", "full", "archive", "light-client", "reporter"] {
        let cfg: NodeConfig = toml::from_str(&format!(
            "chain_id = 1\nrole = '{role}'\n[proving]\ncuda_device = 0"
        ))
        .unwrap();
        assert!(matches!(
            crate::run(cfg).await,
            Err(crate::NodeError::ProofSystem(_))
        ));
    }
}

#[cfg(not(all(feature = "cuda", target_os = "linux", target_arch = "x86_64")))]
#[tokio::test]
async fn unsupported_cuda_is_rejected_without_cpu_fallback() {
    let cfg: NodeConfig = toml::from_str("chain_id = 1\n[proving]\nbackend = 'cuda'").unwrap();
    let Err(crate::NodeError::ProofSystem(error)) = crate::run(cfg).await else {
        panic!("unsupported CUDA must fail before any node services start");
    };
    let expected = if cfg!(feature = "cuda") {
        "Linux x86-64"
    } else {
        "--features cuda"
    };
    assert!(error.contains(expected), "{error}");
}
