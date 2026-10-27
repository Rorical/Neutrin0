//! Real WASM execution through the Ethereum RPC facade, using Solidity 0.8.30
//! bytecode from contracts/WalletFixture.sol. Compressed proving has its own gate.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Signature, TxKind, U256, keccak256};
use jsonrpsee::core::client::SubscriptionClientT as _;
use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_node::{ChainBackend, ChainSpecFile, build_genesis_state};
use neutrin0_primitives::fixed_u128_from_integer;
use neutrin0_rpc::{RpcBackend, RpcContext, build_module};
use neutrin0_runtime_host::{
    Sp1ProofSystem, WasmExecutor,
    wasm::{EVM_MASTER_WASM, WasmRuntime},
};
use neutrin0_storage::MemoryDatabase;
#[path = "support/proven.rs"]
pub mod proven;
use serde_json::{Value, json};
use std::sync::Arc;

type Backend = ChainBackend<MemoryDatabase, Sp1ProofSystem<sp1_sdk::blocking::MockProver>>;
fn key() -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap()
}
fn sender() -> Address {
    let point = key().verifying_key().to_sec1_point(false);
    Address::from_slice(&keccak256(&point.as_bytes()[1..])[12..])
}
fn proposer() -> ProposerKey {
    ProposerKey::from_ikm(&[42; 32], 0).unwrap()
}
fn backend() -> Arc<Backend> {
    backend_with_chunk_size(neutrin0_primitives::DEFAULT_CHUNK_SIZE)
}
fn backend_with_chunk_size(chunk_size: u64) -> Arc<Backend> {
    let credentials = format!("{}{}", "00".repeat(12), "09".repeat(20));
    let text = format!(
        "name=\"evm-rpc\"\nchain_id=7\ninitial_base_fee=10\ngenesis_time=0\ngenesis_gas_limit=1000000\ngenesis_seed_hex=\"{}\"\ngenesis_block_hash_hex=\"{}\"\n[[validators]]\npubkey_hex=\"{}\"\nwithdrawal_credentials_hex=\"{credentials}\"\npop_hex=\"{pop}\"\neffective_stake=\"32000000000000000000\"\n[[accounts]]\naddress_hex=\"{}\"\nbalance=1000000000000000000\n",
        "08".repeat(32),
        "06".repeat(32),
        hex::encode(proposer().public_key_bytes()),
        hex::encode(sender()),
        pop = hex::encode(
            proposer()
                .prove_registration(&neutrin0_primitives::runtime_account([9; 20]))
                .to_bytes()
        ),
    );
    let mut file = ChainSpecFile::from_toml_str(&text).unwrap();
    file.pin_embedded_programs().unwrap();
    file.chunk_size = Some(chunk_size);
    let state = build_genesis_state(&file).unwrap();
    let mut spec = file.to_chain_spec().unwrap();
    spec.consensus.expected_proposers_per_slot = fixed_u128_from_integer(8);
    let package = file.runtime_package().unwrap();
    let proof = package
        .proof_system(sp1_sdk::blocking::ProverClient::builder().mock().build())
        .unwrap();
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).unwrap();
    engine.install_genesis_state(state.trie).unwrap();
    let backend = Arc::new(ChainBackend::new(engine, proof));
    backend.set_block_executor(WasmExecutor::new(
        WasmRuntime::new(EVM_MASTER_WASM).unwrap(),
    ));
    backend
}
fn raw(nonce: u64, to: TxKind, value: u64, input: Vec<u8>, fee: u128, tip: u128) -> Vec<u8> {
    let transaction = TxEip1559 {
        chain_id: 7,
        nonce,
        gas_limit: 300_000,
        max_fee_per_gas: fee,
        max_priority_fee_per_gas: tip,
        to,
        value: U256::from(value),
        input: input.into(),
        ..Default::default()
    };
    signed_raw(transaction)
}
fn signed_raw(transaction: TxEip1559) -> Vec<u8> {
    signed_raw_by(transaction, &key())
}
fn signed_raw_by(transaction: TxEip1559, signer: &k256::ecdsa::SigningKey) -> Vec<u8> {
    let (signature, recovery) =
        signer.sign_prehash_recoverable(transaction.signature_hash().as_slice());
    let bytes = signature.to_bytes();
    let signature = Signature::from_scalars_and_parity(
        B256::from_slice(&bytes[..32]),
        B256::from_slice(&bytes[32..]),
        recovery.is_y_odd(),
    );
    TxEnvelope::from(transaction.into_signed(signature)).encoded_2718()
}

#[test]
fn unfunded_zero_fee_spam_cannot_displace_a_funded_transfer() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();
    let backend = backend();
    let attacker = k256::ecdsa::SigningKey::from_slice(&[8; 32]).unwrap();
    for nonce in 1..=64 {
        let bytes = signed_raw_by(
            TxEip1559 {
                chain_id: 7,
                nonce,
                gas_limit: 1_000_000,
                max_fee_per_gas: 0,
                max_priority_fee_per_gas: 0,
                to: TxKind::Call(Address::from([9; 20])),
                input: vec![0; 4096].into(),
                ..Default::default()
            },
            &attacker,
        );
        assert_eq!(
            backend.submit_transaction(
                borsh::to_vec(&neutrin0_runtime_abi::RuntimeTransaction::User(bytes)).unwrap()
            ),
            Err(neutrin0_mempool::InsertError::ZeroFee)
        );
    }
    assert_eq!(backend.mempool_len(), 0);
    let honest = signed_raw(TxEip1559 {
        chain_id: 7,
        nonce: 0,
        gas_limit: 1_000_000,
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(Address::from([9; 20])),
        input: vec![0; 32 * 1024].into(),
        ..Default::default()
    });
    backend
        .submit_transaction(
            borsh::to_vec(&neutrin0_runtime_abi::RuntimeTransaction::User(honest)).unwrap(),
        )
        .unwrap();
    assert_eq!(backend.mempool_len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
#[allow(
    clippy::too_many_lines,
    reason = "One pending RPC flow covers the proof barrier, contiguous pool sequence and disposable state."
)]
async fn pending_queries_at_chunk_barrier_keep_head_context_and_full_pool_nonce() {
    let backend = tokio::task::spawn_blocking(|| backend_with_chunk_size(1))
        .await
        .unwrap();
    let producer = backend.clone();
    tokio::task::spawn_blocking(move || {
        {
            let outcome = producer.try_produce_block(1, &proposer()).unwrap().unwrap();
            // `latest` serves the executed candidate; prove it too so `safe` agrees (design 08).
            producer.prove_block(&outcome.block_hash).unwrap();
            outcome
        }
    })
    .await
    .unwrap();
    let facade: Arc<dyn RpcBackend> = backend.clone();
    let module = build_module(facade).unwrap();
    let address = hex_data(sender().as_slice());
    let recipient = Address::from([4; 20]);
    for nonce in 0..5 {
        let transaction = signed_raw(TxEip1559 {
            chain_id: 7,
            nonce,
            gas_limit: 1_000_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 3,
            to: TxKind::Call(recipient),
            value: U256::from(7),
            ..Default::default()
        });
        rpc(
            &module,
            "eth_sendRawTransaction",
            json!([hex_data(&transaction)]),
        )
        .await
        .unwrap();
    }
    let head = backend.head().await.unwrap();
    let finalized = backend.finalized().await.unwrap();
    assert_eq!(head.height, 1);
    assert_eq!(
        rpc(
            &module,
            "eth_getTransactionCount",
            json!([address, "latest"])
        )
        .await
        .unwrap(),
        "0x0"
    );
    assert_eq!(
        rpc(
            &module,
            "eth_getTransactionCount",
            json!([address, "pending"])
        )
        .await
        .unwrap(),
        "0x5"
    );
    let pending = rpc(&module, "eth_getBlockByNumber", json!(["pending", false]))
        .await
        .unwrap();
    assert_eq!(pending["neutrin0PendingMode"], "head-local");
    assert_eq!(pending["number"], "0x1");
    assert_eq!(pending["hash"], Value::Null);
    assert_eq!(pending["transactions"].as_array().unwrap().len(), 1);
    assert_eq!(
        rpc(
            &module,
            "eth_getBalance",
            json!([hex_data(recipient.as_slice()), "pending"])
        )
        .await
        .unwrap(),
        "0x7"
    );
    assert_eq!(
        rpc(
            &module,
            "eth_getBalance",
            json!([hex_data(recipient.as_slice()), "latest"])
        )
        .await
        .unwrap(),
        "0x0"
    );
    let call = json!({"from": address, "to": hex_data(recipient.as_slice())});
    assert_eq!(
        rpc(&module, "eth_call", json!([call, "pending"]))
            .await
            .unwrap(),
        "0x"
    );
    assert_eq!(
        rpc(&module, "eth_estimateGas", json!([call, "pending"]))
            .await
            .unwrap(),
        "0x5208"
    );
    assert_eq!(backend.head().await.unwrap(), head);
    assert_eq!(backend.finalized().await.unwrap(), finalized);
    assert_eq!(backend.mempool_len(), 5);
    assert_eq!(
        rpc(
            &module,
            "eth_getTransactionCount",
            json!([address, "pending"])
        )
        .await
        .unwrap(),
        "0x5"
    );
}
fn hex_data(data: &[u8]) -> Value {
    json!(format!("0x{}", hex::encode(data)))
}
async fn rpc(
    module: &jsonrpsee::server::RpcModule<RpcContext>,
    method: &str,
    params: Value,
) -> Result<Value, Value> {
    let request = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let (response, _) = module.raw_json_request(&request, 1).await.unwrap();
    let response: Value = serde_json::from_str(response.get()).unwrap();
    response.get("error").map_or_else(
        || Ok(response["result"].clone()),
        |error| Err(error.clone()),
    )
}
async fn pin_branch(backend: Arc<Backend>, hash: [u8; 32], number: u64) {
    tokio::task::spawn_blocking(move || {
        backend.with_engine_mut_for_test(|engine| {
            let chunk = neutrin0_consensus_types::Chunk {
                next_identity_sanctions_root: [0; 32],

                chunk_id: number,
                start_height: 1,
                end_height: 3,
                start_state_root: [0; 32],
                end_state_root: [0; 32],
                start_block_hash: [0; 32],
                end_block_hash: hash,
                block_hash_root: [0; 32],
                block_proof_root: [0; 32],
                vrf_proof_root: [0; 32],
                active_validator_set_root: [0; 32],
                next_validator_set_root: [0; 32],
                da_root: [0; 32],
            };
            let chunk_hash = engine.fork_choice_mut_for_test().add_chunk(&chunk);
            engine.fork_choice_mut_for_test().add_vote(
                0,
                neutrin0_consensus_fork_choice::ChunkVote {
                    data: neutrin0_consensus_types::FinalityVoteData {
                        chunk_id: number,
                        round: 0,
                        chunk_hash,
                        selection: [0; 32],
                        phase: neutrin0_consensus_types::FinalityVotePhase::Precommit,
                    },
                    weight: 100_000_000_000,
                },
            );
        });
    })
    .await
    .unwrap();
}
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)] // One wallet flow verifies queueing, replacement, mining and historical views.
async fn queued_nonces_replacement_receipts_solidity_calls_and_logs() {
    let backend = tokio::task::spawn_blocking(backend).await.unwrap();
    let facade: Arc<dyn RpcBackend> = backend.clone();
    let module = build_module(facade).unwrap();
    let address = hex_data(sender().as_slice());
    let recipient = Address::from([4; 20]);
    assert_eq!(rpc(&module, "eth_chainId", json!([])).await.unwrap(), "0x7");
    assert_eq!(
        rpc(&module, "eth_getBlockByNumber", json!(["0x0", false]))
            .await
            .unwrap()["number"],
        "0x0"
    );
    let future = raw(1, TxKind::Call(recipient), 5, Vec::new(), 100, 3);
    let future_hash = rpc(
        &module,
        "eth_sendRawTransaction",
        json!([hex_data(&future)]),
    )
    .await
    .unwrap();
    assert_eq!(
        rpc(
            &module,
            "eth_getTransactionCount",
            json!([address, "pending"])
        )
        .await
        .unwrap(),
        "0x0"
    );
    let first = raw(0, TxKind::Call(recipient), 7, Vec::new(), 100, 3);
    rpc(&module, "eth_sendRawTransaction", json!([hex_data(&first)]))
        .await
        .unwrap();
    let inadequate = raw(0, TxKind::Call(recipient), 7, Vec::new(), 110, 3);
    assert!(
        rpc(
            &module,
            "eth_sendRawTransaction",
            json!([hex_data(&inadequate)])
        )
        .await
        .is_err()
    );
    let replacement = raw(0, TxKind::Call(recipient), 7, Vec::new(), 110, 4);
    let replacement_hash = rpc(
        &module,
        "eth_sendRawTransaction",
        json!([hex_data(&replacement)]),
    )
    .await
    .unwrap();
    assert_eq!(
        rpc(
            &module,
            "eth_getTransactionCount",
            json!([address, "pending"])
        )
        .await
        .unwrap(),
        "0x2"
    );
    let producer = backend.clone();
    let block = tokio::task::spawn_blocking(move || {
        {
            let outcome = producer.try_produce_block(1, &proposer()).unwrap().unwrap();
            // `latest` serves the executed candidate; prove it too so `safe` agrees (design 08).
            producer.prove_block(&outcome.block_hash).unwrap();
            outcome
        }
    })
    .await
    .unwrap();
    assert_eq!(backend.mempool_len(), 0);
    let batch = rpc(
        &module,
        "eth_getBlockReceipts",
        json!([hex_data(&block.block.hash())]),
    )
    .await
    .unwrap();
    assert_eq!(batch.as_array().unwrap().len(), 2);
    assert_eq!(
        batch[0],
        rpc(
            &module,
            "eth_getTransactionReceipt",
            json!([replacement_hash])
        )
        .await
        .unwrap()
    );
    assert_eq!(
        batch[1],
        rpc(&module, "eth_getTransactionReceipt", json!([future_hash]))
            .await
            .unwrap()
    );
    assert_eq!(
        batch,
        rpc(&module, "eth_getBlockReceipts", json!(["0x1"]))
            .await
            .unwrap()
    );
    assert_eq!(
        rpc(&module, "eth_getBlockReceipts", json!(["earliest"]))
            .await
            .unwrap(),
        json!([])
    );
    assert_eq!(
        rpc(
            &module,
            "eth_getBlockReceipts",
            json!([hex_data(&[255; 32])])
        )
        .await
        .unwrap(),
        Value::Null
    );
    assert_eq!(
        rpc(&module, "eth_getBlockReceipts", json!(["pending"]))
            .await
            .unwrap_err()["code"],
        -32602
    );
    assert_eq!(
        rpc(
            &module,
            "eth_getTransactionReceipt",
            json!([replacement_hash])
        )
        .await
        .unwrap()["status"],
        "0x1"
    );
    assert_eq!(
        rpc(&module, "eth_getTransactionReceipt", json!([future_hash]))
            .await
            .unwrap()["cumulativeGasUsed"],
        "0xa410"
    );
    assert_eq!(
        rpc(
            &module,
            "eth_getBalance",
            json!([hex_data(recipient.as_slice()), "latest"])
        )
        .await
        .unwrap(),
        "0xc"
    );
    assert_eq!(
        rpc(
            &module,
            "eth_getBalance",
            json!([hex_data(recipient.as_slice()), "earliest"])
        )
        .await
        .unwrap(),
        "0x0"
    );
    assert_eq!(
        rpc(
            &module,
            "eth_getBlockByHash",
            json!([hex_data(&block.block.hash()), false])
        )
        .await
        .unwrap()["transactions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let creation =
        hex::decode(include_str!("fixtures/wallet_fixture_creation.hex").trim()).unwrap();
    let deploy = raw(2, TxKind::Create, 0, creation, 100, 3);
    let hash = rpc(
        &module,
        "eth_sendRawTransaction",
        json!([hex_data(&deploy)]),
    )
    .await
    .unwrap();
    let producer = backend.clone();
    tokio::task::spawn_blocking(move || {
        {
            let outcome = producer.try_produce_block(2, &proposer()).unwrap().unwrap();
            // `latest` serves the executed candidate; prove it too so `safe` agrees (design 08).
            producer.prove_block(&outcome.block_hash).unwrap();
            outcome
        }
    })
    .await
    .unwrap();
    let receipt = rpc(&module, "eth_getTransactionReceipt", json!([hash]))
        .await
        .unwrap();
    let contract = receipt["contractAddress"].clone();
    let contract_address = Address::from_slice(
        &hex::decode(contract.as_str().unwrap().trim_start_matches("0x")).unwrap(),
    );
    let server = jsonrpsee::server::ServerBuilder::default()
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let server_address = server.local_addr().unwrap();
    let server_handle = server.start(module.clone());
    let websocket = jsonrpsee::ws_client::WsClientBuilder::default()
        .build(format!("ws://{server_address}"))
        .await
        .unwrap();
    let mut heads = websocket
        .subscribe::<Value, _>(
            "eth_subscribe",
            jsonrpsee::rpc_params!["newHeads"],
            "eth_unsubscribe",
        )
        .await
        .unwrap();
    let mut events = websocket
        .subscribe::<Value, _>(
            "eth_subscribe",
            jsonrpsee::rpc_params!["logs", json!({"address":contract})],
            "eth_unsubscribe",
        )
        .await
        .unwrap();
    let filter = rpc(
        &module,
        "eth_newFilter",
        json!([{"address":contract,"fromBlock":"latest"}]),
    )
    .await
    .unwrap();
    let mut data = keccak256(b"set(uint256)")[..4].to_vec();
    data.extend(U256::from(42).to_be_bytes::<32>());
    let simulation = rpc(
        &module,
        "eth_call",
        json!([{"from":address,"to":contract,"data":hex_data(&data)},"latest"]),
    )
    .await
    .unwrap();
    assert_eq!(simulation, "0x");
    let estimate = rpc(
        &module,
        "eth_estimateGas",
        json!([{"from":address,"to":contract,"data":hex_data(&data)},"pending"]),
    )
    .await
    .unwrap();
    assert!(
        u64::from_str_radix(estimate.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
            > 21_000
    );
    assert!(
        rpc(
            &module,
            "eth_call",
            json!([{"from":address,"to":contract},"latest",{}]),
        )
        .await
        .is_err()
    );
    let tx = raw(3, TxKind::Call(contract_address), 0, data, 100, 3);
    let set_hash = rpc(&module, "eth_sendRawTransaction", json!([hex_data(&tx)]))
        .await
        .unwrap();
    let producer = backend.clone();
    tokio::task::spawn_blocking(move || {
        {
            let outcome = producer.try_produce_block(3, &proposer()).unwrap().unwrap();
            // `latest` serves the executed candidate; prove it too so `safe` agrees (design 08).
            producer.prove_block(&outcome.block_hash).unwrap();
            outcome
        }
    })
    .await
    .unwrap();
    assert_eq!(
        rpc(
            &module,
            "eth_getStorageAt",
            json!([contract, "0x0", "latest"])
        )
        .await
        .unwrap(),
        hex_data(&U256::from(42).to_be_bytes::<32>())
    );
    assert_eq!(
        rpc(&module, "eth_getStorageAt", json!([contract, "0x0", "0x2"]))
            .await
            .unwrap(),
        hex_data(&[0; 32])
    );
    let logs = rpc(&module, "eth_getFilterChanges", json!([filter]))
        .await
        .unwrap();
    assert_eq!(logs.as_array().unwrap().len(), 1);
    assert_eq!(logs[0]["removed"], false);
    let head = tokio::time::timeout(std::time::Duration::from_secs(5), heads.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(head["number"], "0x3");
    let event = tokio::time::timeout(std::time::Duration::from_secs(5), events.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(event, logs[0]);
    let fresh_filter = rpc(
        &module,
        "eth_newFilter",
        json!([{"address":contract,"fromBlock":"latest"}]),
    )
    .await
    .unwrap();
    assert_eq!(
        rpc(&module, "eth_getFilterChanges", json!([fresh_filter]))
            .await
            .unwrap()
            .as_array()
            .unwrap(),
        &Vec::<Value>::new()
    );

    assert_eq!(
        rpc(&module, "eth_getFilterChanges", json!([filter]))
            .await
            .unwrap()
            .as_array()
            .unwrap(),
        &Vec::<Value>::new()
    );
    assert_eq!(
        rpc(
            &module,
            "eth_getLogs",
            json!([{"address":contract,"fromBlock":"0x3","toBlock":"0x3"}])
        )
        .await
        .unwrap()
        .as_array()
        .unwrap()
        .len(),
        1
    );
    assert_eq!(
        rpc(&module, "eth_feeHistory", json!(["0x3", "latest", [50]]))
            .await
            .unwrap()["baseFeePerGas"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    let old_head = backend.head().await.unwrap().hash;
    pin_branch(backend.clone(), old_head, 1).await;
    let alternative = tokio::task::spawn_blocking(self::backend).await.unwrap();
    let mut replacement_blocks = Vec::new();
    for slot in 1..=3 {
        let producer = alternative.clone();
        replacement_blocks.push(
            tokio::task::spawn_blocking(move || {
                proven::produce_publication(&producer, slot, &proposer())
            })
            .await
            .unwrap(),
        );
    }
    for publication in &replacement_blocks {
        proven::import_blocking(&backend, vec![publication.clone()])
            .await
            .unwrap();
    }
    pin_branch(
        backend.clone(),
        replacement_blocks.last().unwrap().block.hash(),
        2,
    )
    .await;
    let follower = backend.clone();
    tokio::task::spawn_blocking(move || follower.try_materialise_to_fork_choice_head().unwrap())
        .await
        .unwrap();
    assert_eq!(
        backend.head().await.unwrap().hash,
        replacement_blocks.last().unwrap().block.hash()
    );
    let removed = rpc(&module, "eth_getFilterChanges", json!([filter]))
        .await
        .unwrap();
    assert_eq!(removed.as_array().unwrap().len(), 1);
    assert_eq!(removed[0]["removed"], true);
    let removed_event = tokio::time::timeout(std::time::Duration::from_secs(5), events.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(removed_event, removed[0]);
    assert_eq!(
        rpc(&module, "eth_getTransactionReceipt", json!([set_hash]))
            .await
            .unwrap(),
        Value::Null
    );
    assert_eq!(
        rpc(
            &module,
            "eth_getTransactionCount",
            json!([address, "latest"])
        )
        .await
        .unwrap(),
        "0x0"
    );
    assert_eq!(
        rpc(
            &module,
            "eth_getTransactionCount",
            json!([address, "pending"])
        )
        .await
        .unwrap(),
        "0x4"
    );
    assert!(
        rpc(
            &module,
            "eth_getBalance",
            json!([address,{"blockHash":hex_data(&old_head),"requireCanonical":true}])
        )
        .await
        .is_err()
    );
    assert_eq!(
        rpc(
            &module,
            "eth_getStorageAt",
            json!([contract,"0x0",{"blockHash":hex_data(&old_head)}])
        )
        .await
        .unwrap(),
        hex_data(&U256::from(42).to_be_bytes::<32>())
    );
    heads.unsubscribe().await.unwrap();
    events.unsubscribe().await.unwrap();
    server_handle.stop().unwrap();
    server_handle.stopped().await;
    assert!(
        rpc(&module, "eth_getBalance", json!([address, "0xff"]))
            .await
            .is_err()
    );
    assert_eq!(
        rpc(&module, "eth_getBlockByNumber", json!(["0xff", false]))
            .await
            .unwrap(),
        Value::Null
    );
    let genesis = backend.genesis_info().await.unwrap().unwrap();
    assert_eq!(
        rpc(
            &module,
            "eth_getLogs",
            json!([{"blockHash":hex_data(&genesis.hash)}])
        )
        .await
        .unwrap()
        .as_array()
        .unwrap(),
        &Vec::<Value>::new()
    );
}
