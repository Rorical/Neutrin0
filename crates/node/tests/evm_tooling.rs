//! Real Forge/Cast clients over HTTP against ordinary WASM EVM execution.
//! Proof/finality acceptance is a separate real-compressed gate; this fixture
//! does not finalize chunks or manufacture recursive proofs.

use alloy_primitives::{Address, U256, keccak256};
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_node::{ChainBackend, ChainSpecFile, build_genesis_state};
use neutrin0_primitives::fixed_u128_from_integer;
use neutrin0_rpc::{RpcBackend, build_module};
use neutrin0_runtime_host::{Sp1ProofSystem, WasmExecutor, wasm::WasmRuntime};
use neutrin0_storage::MemoryDatabase;
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

type Backend = ChainBackend<MemoryDatabase, Sp1ProofSystem<sp1_sdk::blocking::MockProver>>;
// Public development key used only by this isolated, funded test chain.
const KEY: &str = "0707070707070707070707070707070707070707070707070707070707070707";

fn account() -> Address {
    let key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    Address::from_slice(&keccak256(&key.verifying_key().to_sec1_point(false).as_bytes()[1..])[12..])
}

fn backend() -> Arc<Backend> {
    let proposer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let mut file = ChainSpecFile::from_toml_str(&format!(
        "name=\"forge-cast\"\nchain_id=7\ninitial_base_fee=10\ngenesis_time=0\ngenesis_gas_limit=1000000\n[[validators]]\npubkey_hex=\"{}\"\nwithdrawal_credentials_hex=\"{}\"\npop_hex=\"{}\"\neffective_stake=\"32000000000000000000\"\n[[accounts]]\naddress_hex=\"{}\"\nbalance=1000000000000000000\n",
        hex::encode(proposer.public_key_bytes()), hex::encode([9; 20]),
        hex::encode(proposer.prove_registration(&neutrin0_primitives::runtime_account([9; 20])).to_bytes()),
        hex::encode(account()),
    )).unwrap();
    file.pin_embedded_programs().unwrap();
    let genesis = build_genesis_state(&file).unwrap();
    let mut spec = file.to_chain_spec().unwrap();
    spec.consensus.expected_proposers_per_slot = fixed_u128_from_integer(8);
    let package = file.runtime_package().unwrap();
    let proof = package
        .proof_system(sp1_sdk::blocking::ProverClient::builder().mock().build())
        .unwrap();
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).unwrap();
    engine.install_genesis_state(genesis.trie).unwrap();
    let backend = Arc::new(ChainBackend::new(engine, proof));
    backend.set_block_executor(WasmExecutor::new(WasmRuntime::new(&package.wasm).unwrap()));
    backend
}

struct Fixture {
    server: ServerHandle,
    stop: Arc<AtomicBool>,
    producer: Option<std::thread::JoinHandle<()>>,
}

impl Fixture {
    async fn shutdown(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(producer) = self.producer.take() {
            // A producer panic must fail the successful test path, while Drop
            // still cleans up when another assertion is already unwinding.
            tokio::task::spawn_blocking(move || producer.join().unwrap())
                .await
                .unwrap();
        }
        self.server.stop().unwrap();
        tokio::time::timeout(Duration::from_secs(10), self.server.clone().stopped())
            .await
            .expect("RPC shutdown deadline");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(producer) = self.producer.take() {
            let _ = producer.join();
        }
        let _ = self.server.stop();
    }
}

async fn command(binary: &str, arguments: &[&str], cwd: &Path) -> String {
    let mut command = tokio::process::Command::new(binary);
    command.args(arguments).current_dir(cwd).kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(180), command.output())
        .await
        .expect("tool deadline")
        .expect("installed Forge/Cast binary");
    assert!(
        output.status.success(),
        "{binary} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

async fn rpc(url: &str, method: &str, parameters: &[Value], cwd: &Path) -> Value {
    let parameters: Vec<_> = parameters
        .iter()
        .map(|value| serde_json::to_string(value).unwrap())
        .collect();
    let mut arguments = vec!["rpc", "--rpc-url", url, method];
    arguments.extend(parameters.iter().map(String::as_str));
    serde_json::from_str(&command("cast", &arguments, cwd).await).unwrap()
}

async fn send(url: &str, destination: &str, signature: &str, value: &str, cwd: &Path) -> Value {
    serde_json::from_str(
        &command(
            "cast",
            &[
                "send",
                destination,
                signature,
                value,
                "--rpc-url",
                url,
                "--private-key",
                KEY,
                "--gas-limit",
                "300000",
                "--gas-price",
                "100",
                "--priority-gas-price",
                "3",
                "--json",
            ],
            cwd,
        )
        .await,
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "Forge/Cast HTTP integration; install Foundry v1.4.4 and Solidity 0.8.30"]
#[allow(
    clippy::too_many_lines,
    reason = "One external wallet flow shares its live HTTP fixture, deployment and historical receipt/log assertions."
)]
async fn forge_and_cast_deploy_transfer_simulate_and_read_receipts() {
    let cwd = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts");
    let bytecode = command("forge", &["inspect", "WalletFixture", "bytecode"], &cwd).await;
    assert!(bytecode.starts_with("0x"));
    let backend = tokio::task::spawn_blocking(backend).await.unwrap();
    let facade: Arc<dyn RpcBackend> = backend.clone();
    let server = ServerBuilder::default().build("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", server.local_addr().unwrap());
    let handle = server.start(build_module(facade).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = Arc::clone(&stop);
    let producer = std::thread::spawn(move || {
        let proposer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
        let mut slot = 1;
        while !stopped.load(Ordering::Acquire) {
            if backend.mempool_len() > 0 {
                assert!(
                    backend
                        .try_produce_block(slot, &proposer)
                        .unwrap()
                        .is_some(),
                    "isolated proposer must be eligible"
                );
                slot += 1;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    let fixture = Fixture {
        server: handle,
        stop,
        producer: Some(producer),
    };
    assert_eq!(
        command("cast", &["chain-id", "--rpc-url", &url], &cwd).await,
        "7"
    );
    let deployment: Value = serde_json::from_str(
        &command(
            "cast",
            &[
                "send",
                "--rpc-url",
                &url,
                "--private-key",
                KEY,
                "--gas-limit",
                "500000",
                "--gas-price",
                "100",
                "--priority-gas-price",
                "3",
                "--json",
                "--create",
                &bytecode,
            ],
            &cwd,
        )
        .await,
    )
    .unwrap();
    assert_eq!(deployment["status"], "0x1");
    let contract = deployment["contractAddress"].as_str().unwrap();
    let code = rpc(
        &url,
        "eth_getCode",
        &[json!(contract), json!("latest")],
        &cwd,
    )
    .await;
    assert!(code.as_str().unwrap().len() > 2);
    let receipt = send(&url, contract, "set(uint256)", "42", &cwd).await;
    assert_eq!(receipt["status"], "0x1");
    let submitted = rpc(
        &url,
        "eth_getTransactionByHash",
        &[receipt["transactionHash"].clone()],
        &cwd,
    )
    .await;
    assert_eq!(submitted["type"], "0x2");
    assert_eq!(submitted["maxFeePerGas"], "0x64");
    assert_eq!(submitted["maxPriorityFeePerGas"], "0x3");
    let value = command(
        "cast",
        &["call", contract, "value()(uint256)", "--rpc-url", &url],
        &cwd,
    )
    .await;
    assert_eq!(value.split_whitespace().next(), Some("42"));
    let estimate = command(
        "cast",
        &[
            "estimate",
            contract,
            "set(uint256)",
            "43",
            "--from",
            &format!("{:#x}", account()),
            "--rpc-url",
            &url,
        ],
        &cwd,
    )
    .await;
    assert!(estimate.parse::<u64>().unwrap() > 21_000);
    let rollback_data = command("cast", &["calldata", "rollback(uint256)", "99"], &cwd).await;
    // The standard RPC revert object must be consumable by external tools and
    // simulation must not replace the committed value or publish its log.
    // Cast exits unsuccessfully for an RPC error; invoke it separately so the
    // expected failure does not go through the success-only command helper.
    let encoded = json!({"to":contract,"data":rollback_data}).to_string();
    let latest = json!("latest").to_string();
    let mut command = tokio::process::Command::new("cast");
    command
        .args(["rpc", "--rpc-url", &url, "eth_call", &encoded, &latest])
        .current_dir(&cwd)
        .kill_on_drop(true);
    let rejected = tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .unwrap()
        .unwrap();
    assert!(!rejected.status.success());
    let diagnostic = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        diagnostic.contains("execution reverted"),
        "wrong failure: {diagnostic}"
    );
    let mut revert_data = hex::decode("08c379a0").unwrap();
    revert_data.extend(U256::from(32).to_be_bytes::<32>());
    revert_data.extend(U256::from(8).to_be_bytes::<32>());
    let mut message = [0; 32];
    message[..8].copy_from_slice(b"rollback");
    revert_data.extend(message);
    assert!(
        diagnostic.contains(&hex::encode(revert_data)),
        "missing ABI revert data: {diagnostic}"
    );
    let value = command_value(&url, contract, &cwd).await;
    assert_eq!(value, "42");
    let logs = rpc(
        &url,
        "eth_getLogs",
        &[json!({
            "address":contract,"fromBlock":receipt["blockNumber"],"toBlock":receipt["blockNumber"]
        })],
        &cwd,
    )
    .await;
    assert_eq!(logs.as_array().unwrap().len(), 1);
    assert_eq!(logs[0]["transactionHash"], receipt["transactionHash"]);
    let historic = rpc(
        &url,
        "eth_getStorageAt",
        &[
            json!(contract),
            json!("0x0"),
            json!({"blockHash":receipt["blockHash"],"requireCanonical":true}),
        ],
        &cwd,
    )
    .await;
    assert_eq!(
        historic,
        format!("0x{}", hex::encode(U256::from(42).to_be_bytes::<32>()))
    );
    let destination = "0x4444444444444444444444444444444444444444";
    let transfer: Value =
        serde_json::from_str(&command_send_transfer(&url, destination, &cwd).await).unwrap();
    assert_eq!(transfer["status"], "0x1");
    let balance = rpc(
        &url,
        "eth_getBalance",
        &[json!(destination), json!("latest")],
        &cwd,
    )
    .await;
    assert_eq!(balance, "0x7b");
    let found = rpc(
        &url,
        "eth_getTransactionReceipt",
        &[receipt["transactionHash"].clone()],
        &cwd,
    )
    .await;
    assert_eq!(found["blockHash"], receipt["blockHash"]);
    let rpc_logs = found["logs"].as_array().unwrap();
    let cast_logs = receipt["logs"].as_array().unwrap();
    assert_eq!(rpc_logs.len(), cast_logs.len());
    // Cast reserializes typed receipts and may include optional presentation
    // fields. Compare the complete Ethereum log identity and payload.
    for (rpc_log, cast_log) in rpc_logs.iter().zip(cast_logs) {
        for field in [
            "address",
            "topics",
            "data",
            "blockHash",
            "blockNumber",
            "transactionHash",
            "transactionIndex",
            "logIndex",
            "removed",
        ] {
            assert_eq!(rpc_log[field], cast_log[field], "Cast log field {field}");
        }
    }
    fixture.shutdown().await;
}

async fn command_value(url: &str, contract: &str, cwd: &Path) -> String {
    command(
        "cast",
        &["call", contract, "value()(uint256)", "--rpc-url", url],
        cwd,
    )
    .await
    .split_whitespace()
    .next()
    .unwrap()
    .to_owned()
}

async fn command_send_transfer(url: &str, destination: &str, cwd: &Path) -> String {
    command(
        "cast",
        &[
            "send",
            destination,
            "--value",
            "123",
            "--rpc-url",
            url,
            "--private-key",
            KEY,
            "--gas-limit",
            "21000",
            "--gas-price",
            "100",
            "--priority-gas-price",
            "3",
            "--json",
        ],
        cwd,
    )
    .await
}
