//! Exercise the actual command-line binary against a bounded local RPC service.

use jsonrpsee::{
    server::{RpcModule, Server},
    types::ErrorObjectOwned,
};
use neutrin0_rpc::{BytesHex, HashHex, RuntimeCallResultJson};
use serde_json::{Value, json};

async fn invoke(endpoint: String, arguments: &[&str]) -> std::process::Output {
    let args: Vec<String> = arguments
        .iter()
        .map(|argument| (*argument).into())
        .collect();
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_neutrin0-cli"))
            .args(args)
            .args(["--rpc", &endpoint, "--json"])
            .output()
            .expect("run CLI")
    })
    .await
    .expect("join CLI")
}

async fn provider() -> (String, jsonrpsee::server::ServerHandle) {
    let mut module = RpcModule::new(());
    module
        .register_method("system_chainId", |_params, _context, _extensions| 7_u64)
        .expect("chain id");
    module.register_method("system_health", |_params, _context, _extensions| Ok::<_, ErrorObjectOwned>(json!({
        "peers": 1, "is_syncing": false, "runtime_available": true, "mempool": 0, "head_height": 9,
    }))).expect("health");
    module
        .register_method("system_info", |_params, _context, _extensions| {
            Ok::<_, ErrorObjectOwned>(json!({"runtime_code_hash": HashHex([4; 32])}))
        })
        .expect("info");
    module
        .register_method("chain_head", |_params, _context, _extensions| {
            Ok::<_, ErrorObjectOwned>(json!({
                "height": 9, "slot": 9, "hash": HashHex([9; 32]), "state_root": HashHex([3; 32]),
            }))
        })
        .expect("head");
    module.register_method("chain_finalized", |_params, _context, _extensions| Ok::<_, ErrorObjectOwned>(json!({
        "chunk_id": 0, "height": 8, "block_hash": HashHex([8; 32]), "state_root": HashHex([3; 32]),
    }))).expect("finalized");
    module
        .register_method("history_getRetention", |_params, _context, _extensions| {
            Ok::<_, ErrorObjectOwned>(json!({
                "archive": false, "retained_from_chunk": 0, "retained_from_height": 1,
                "finalized_chunks": 1,
            }))
        })
        .expect("retention");
    module
        .register_method("system_diagnostics", |_params, _context, _extensions| {
            Ok::<_, ErrorObjectOwned>(json!({
                "chain_spec_hash": HashHex([5; 32]), "chunk_size": 8, "unbonding_delay_blocks": 64,
                "proof_only": false, "bootstrap_pending": false, "trust_anchor_expired": false,
                "history_conflict": false, "storage_pressure": false,
                "sync": null,
                "bft_sessions": [], "proof_work": [], "queued_block_proofs": 0,
            }))
        })
        .expect("diagnostics");
    module
        .register_method("runtime_call", |params, _context, _extensions| {
            let call: Value = params.parse()?;
            assert_eq!(call["at"], json!(HashHex([8; 32])));
            let payload = match call["method"].as_str().expect("query name") {
                "runtime_info" => borsh::to_vec(&neutrin0_primitives::RuntimeInfo {
                    spec_name: *b"NEUTRIN0_EVM\0\0\0\0",
                })
                .expect("metadata"),
                "evm:account" => {
                    assert_eq!(call["args"], json!(BytesHex(vec![1; 20])));
                    borsh::to_vec(&neutrin0_runtime_abi::ethereum::EvmAccount {
                        nonce: 3,
                        balance: [0xFF; 32],
                        code_hash: [0; 32],
                    })
                    .expect("account")
                }
                _ => panic!("unexpected query"),
            };
            Ok::<_, ErrorObjectOwned>(RuntimeCallResultJson {
                code: 0,
                payload: BytesHex(payload),
                gas_used: 0,
            })
        })
        .expect("query");
    module
        .register_method("chain_getBlock", |_params, _context, _extensions| {
            Err::<Value, _>(ErrorObjectOwned::owned(
                -32024,
                "pruned",
                Some(json!({"retained_from_height": 80})),
            ))
        })
        .expect("block");
    let server = Server::builder().build("127.0.0.1:0").await.expect("bind");
    let endpoint = format!("http://{}", server.local_addr().expect("address"));
    (endpoint, server.start(module))
}

#[tokio::test]
async fn status_and_watch_report_finality_as_history_coverage() {
    let (endpoint, handle) = provider().await;
    let result = invoke(endpoint.clone(), &["node", "status"]).await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).expect("JSON");
    assert_eq!(value["head"]["height"], 9);
    assert_eq!(value["finalized"]["height"], 8);
    assert_eq!(value["retention"]["finalized_chunks"], 1);
    let result = invoke(
        endpoint,
        &["node", "watch", "--count", "2", "--interval-secs", "1"],
    )
    .await;
    assert!(result.status.success());
    let stdout = String::from_utf8(result.stdout).expect("UTF-8");
    let lines: Vec<Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("NDJSON"))
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[1]["chain_id"], 7);
    handle.stop().expect("stop");
}

#[tokio::test]
async fn account_queries_pin_finalized_state_and_keep_large_balances_exact() {
    let (endpoint, handle) = provider().await;
    // Padded credentials and the bare 20-byte address name the same account.
    let address = format!("0x{}{}", "00".repeat(12), "01".repeat(20));
    let result = invoke(endpoint, &["account", "get", "--address", &address]).await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).expect("JSON");
    assert_eq!(value["at"]["height"], 8);
    assert_eq!(value["account"]["nonce"], 3);
    assert_eq!(
        value["account"]["balance"],
        alloy_primitives::U256::MAX.to_string()
    );
    handle.stop().expect("stop");
}

#[tokio::test]
async fn pruned_data_and_unknown_options_have_machine_readable_failures() {
    let (endpoint, handle) = provider().await;
    let result = invoke(endpoint.clone(), &["block", "get", "--at", "1"]).await;
    assert_eq!(result.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&result.stderr).expect("error JSON");
    assert_eq!(value["error"]["code"], -32024);
    assert_eq!(value["error"]["data"]["retained_from_height"], 80);
    let result = invoke(endpoint, &["node", "status", "--typo", "x"]).await;
    assert_eq!(result.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&result.stderr).expect("usage JSON");
    assert_eq!(value["error"]["kind"], "invalid_arguments");
    handle.stop().expect("stop");
}

#[tokio::test]
async fn proof_download_writes_exact_envelope_and_preserves_existing_output() {
    use neutrin0_primitives::blake3_256;
    use neutrin0_rpc::types::{ArtifactIdJson, ArtifactInfoJson, ArtifactSliceJson, BytesHex};
    let bytes = vec![1, 7, 9, 11];
    let hash = HashHex(blake3_256(&bytes));
    let mut module = RpcModule::new(());
    module
        .register_method("chain_getArtifact", move |params, _context, _extensions| {
            let (id,): (ArtifactIdJson,) = params.parse()?;
            assert_eq!(id, ArtifactIdJson::Certificate { chunk: 7 });
            Ok::<_, ErrorObjectOwned>(ArtifactInfoJson {
                id,
                artifact_hash: hash,
                encoded_bytes: 4,
                proof_bytes: 0,
                public_values: None,
            })
        })
        .unwrap();
    let original = bytes.clone();
    module
        .register_method(
            "chain_getArtifactBytes",
            move |params, _context, _extensions| {
                let (id, expected, offset, length): (ArtifactIdJson, HashHex, u64, u32) =
                    params.parse()?;
                assert_eq!(id, ArtifactIdJson::Certificate { chunk: 7 });
                assert_eq!(expected, hash);
                assert_eq!(offset, 0);
                assert_eq!(length, 1024 * 1024);
                Ok::<_, ErrorObjectOwned>(ArtifactSliceJson {
                    artifact_hash: hash,
                    encoded_bytes: 4,
                    offset,
                    bytes: BytesHex(original.clone()),
                })
            },
        )
        .unwrap();
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", server.local_addr().unwrap());
    let handle = server.start(module);
    let path = std::env::temp_dir().join(format!(
        "neutrin0-artifact-{}-{:?}.borsh",
        std::process::id(),
        std::time::SystemTime::now()
    ));
    let arguments = [
        "proof",
        "get",
        "--kind",
        "certificate",
        "--id",
        "7",
        "--out",
        path.to_str().unwrap(),
    ];
    let result = invoke(endpoint.clone(), &arguments).await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let result = invoke(endpoint, &arguments).await;
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    std::fs::remove_file(path).unwrap();
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn event_commands_resume_from_supplied_cursor_and_count_applied_events() {
    let mut module = RpcModule::new(());
    module.register_method("chain_getEvents", |params, _context, _extensions| {
        let (after, limit): (Value, u32) = params.parse()?;
        assert_eq!(after, json!({"stream_id": HashHex([2; 32]), "sequence": "41"}));
        assert!([1, 128].contains(&limit));
        let cursor = json!({"stream_id": HashHex([2; 32]), "sequence": "42"});
        let point = json!({"hash": HashHex([3; 32]), "height": 7});
        let status = json!({"chain_spec_hash": HashHex([1; 32]), "head": point, "finalized": point,
            "finalized_chunks": 1, "latest": cursor, "replay_from": {"stream_id": HashHex([2; 32]), "sequence": "0"}, "retention_events": 4096});
        let event = json!({"cursor": cursor, "kind": "finalized", "previous_head": point, "head": point,
            "common_ancestor": point, "previous_finalized": {"hash": HashHex([4; 32]), "height": 0},
            "finalized": point, "previous_finalized_chunks": 0, "finalized_chunks": 1});
        Ok::<_, ErrorObjectOwned>(json!({"status": status, "events": [event], "next": cursor, "has_more": false}))
    }).unwrap();
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", server.local_addr().unwrap());
    let handle = server.start(module);
    let stream = format!("0x{}", "02".repeat(32));
    let result = invoke(
        endpoint.clone(),
        &[
            "chain",
            "events",
            "--after-stream",
            &stream,
            "--after-sequence",
            "41",
            "--limit",
            "1",
        ],
    )
    .await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let page: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(page["next"]["sequence"], "42");
    let result = invoke(
        endpoint.clone(),
        &[
            "chain",
            "watch-events",
            "--after-stream",
            &stream,
            "--after-sequence",
            "41",
            "--count",
            "1",
        ],
    )
    .await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let event: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(event["cursor"]["sequence"], "42");
    let result = invoke(endpoint, &["chain", "events", "--after-sequence", "41"]).await;
    assert_eq!(result.status.code(), Some(2));
    handle.stop().unwrap();
    handle.stopped().await;
}
