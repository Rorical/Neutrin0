//! In-process method-dispatch tests for the JSON-RPC module.
//!
//! Builds the canonical [`RpcModule`] against a mock [`RpcBackend`]
//! and exercises every method through [`RpcModule::call`] — no TCP
//! socket required. Verifies request parsing, parameter shapes, and
//! the JSON envelope of each method's response.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use jsonrpsee::server::RpcModule;
use neutrin0_consensus_types::{Block, Body, Header};
use neutrin0_primitives::{BlockHash, ChainId, Hash, Height, Slot, Validator};
use neutrin0_rpc::{
    BlockId, FinalizedInfo, HeadInfo, QueryError, RpcBackend, RpcContext, RuntimeCallError,
    RuntimeCallResponse, SubmitError, build_module, build_module_with,
};
use serde_json::{Value, json};

/// Call a method through `raw_json_request`, parse the response, and
/// return the `result` field (or `error` if non-null).
async fn call_named(
    module: &RpcModule<RpcContext>,
    method: &str,
    params: Value,
) -> Result<Value, Value> {
    let req = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    })
    .to_string();
    let (response, _rx) = module.raw_json_request(&req, 1).await.expect("dispatch");
    let parsed: Value = serde_json::from_str(response.get()).expect("response json");
    parsed.get("error").map_or_else(
        || Ok(parsed.get("result").cloned().unwrap_or(Value::Null)),
        |error| Err(error.clone()),
    )
}

#[tokio::test]
async fn ethereum_zero_argument_methods_accept_omitted_null_and_empty_params() {
    let module = build_module(Arc::new(MockBackend::default())).unwrap();
    for params in [None, Some(Value::Null), Some(json!([]))] {
        let mut request = json!({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId"});
        if let Some(params) = params {
            request["params"] = params;
        }
        let (response, _) = module
            .raw_json_request(&request.to_string(), 1)
            .await
            .unwrap();
        let response: Value = serde_json::from_str(response.get()).unwrap();
        assert_eq!(response["result"], "0x7", "{response}");
        assert!(response.get("error").is_none());
    }
}

#[tokio::test]
async fn ethereum_empty_params_still_enforce_argument_shapes_and_counts() {
    let module = build_module(Arc::new(MockBackend::default())).unwrap();
    for params in [json!([null]), json!({})] {
        let error = call_named(&module, "eth_chainId", params)
            .await
            .expect_err("no arguments accepted");
        assert_eq!(error["code"], -32602);
    }
    let error = call_named(&module, "eth_getBalance", Value::Null)
        .await
        .expect_err("an address is required");
    assert_eq!(error["code"], -32602);
}

struct MockBackend {
    chain_id: ChainId,
    head_hash: BlockHash,
    runtime_attached: bool,
    runtime_call_response: RuntimeCallResponse,
    query_error: Option<QueryError>,
    runtime_error: Option<RuntimeCallError>,
    runtime_delay: Option<Duration>,
    status_delay: Option<Duration>,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self {
            chain_id: 7,
            head_hash: [0xAA; 32],
            runtime_attached: true,
            query_error: None,
            runtime_error: None,
            runtime_delay: None,
            status_delay: None,
            runtime_call_response: RuntimeCallResponse {
                code: 0,
                payload: vec![1, 2, 3, 4],
                gas_used: 100,
            },
        }
    }
}

#[async_trait]
impl RpcBackend for MockBackend {
    async fn history_retention(&self) -> Result<neutrin0_rpc::HistoryRetention, QueryError> {
        Ok(neutrin0_rpc::HistoryRetention {
            archive: false,
            retained_from_chunk: Some(4),
            retained_from_height: Some(8_193),
            finalized_chunks: 12,
        })
    }
    fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    fn runtime_code_hash(&self) -> Option<neutrin0_primitives::Hash> {
        if let Some(delay) = self.status_delay {
            std::thread::sleep(delay);
        }
        if self.runtime_attached {
            Some([7; 32])
        } else {
            None
        }
    }
    fn runtime_available(&self) -> bool {
        self.runtime_attached
    }
    fn mempool_len(&self) -> usize {
        3
    }
    async fn head(&self) -> Result<HeadInfo, QueryError> {
        if let Some(error) = &self.query_error {
            return Err(error.clone());
        }
        Ok(HeadInfo {
            height: 42,
            hash: self.head_hash,
            slot: 42,
            state_root: [0xBB; 32],
        })
    }
    async fn finalized(&self) -> Result<FinalizedInfo, QueryError> {
        if let Some(error) = &self.query_error {
            return Err(error.clone());
        }
        Ok(FinalizedInfo {
            chunk_id: Some(0),
            block_hash: [0xCC; 32],
            height: 8,
            state_root: [0xDD; 32],
        })
    }
    async fn active_validator_set(&self) -> Vec<Validator> {
        vec![Validator {
            pubkey: [0xEE; 48],
            withdrawal_credentials: neutrin0_primitives::runtime_account([0xFF; 20]),
            effective_stake: 1_000_000,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        }]
    }
    async fn resolve_block_id(&self, id: &BlockId) -> Result<Option<BlockHash>, QueryError> {
        if let Some(error) = &self.query_error {
            return Err(error.clone());
        }
        Ok(match id {
            BlockId::Latest | BlockId::Safe => Some(self.head_hash),
            BlockId::Finalized => Some([0xCC; 32]),
            BlockId::Hash(h) => Some(*h),
            BlockId::Height(h) if *h == 42 => Some(self.head_hash),
            BlockId::Height(_) => None,
        })
    }
    async fn header_by_hash(&self, hash: BlockHash) -> Result<Option<Header>, QueryError> {
        Ok(if hash == self.head_hash {
            Some(sample_header(42, hash))
        } else {
            None
        })
    }
    async fn header_by_height(&self, height: Height) -> Result<Option<Header>, QueryError> {
        Ok(if height == 42 {
            Some(sample_header(42, self.head_hash))
        } else {
            None
        })
    }
    async fn block_by_hash(&self, hash: BlockHash) -> Result<Option<Block>, QueryError> {
        Ok(if hash == self.head_hash {
            Some(Block {
                header: sample_header(42, hash),
                body: Body::default(),
            })
        } else {
            None
        })
    }
    async fn block_by_height(&self, height: Height) -> Result<Option<Block>, QueryError> {
        Ok(if height == 42 {
            Some(Block {
                header: sample_header(42, self.head_hash),
                body: Body::default(),
            })
        } else {
            None
        })
    }
    async fn storage_at(&self, key: &[u8], _at: &BlockId) -> Result<Option<Vec<u8>>, QueryError> {
        if let Some(error) = &self.query_error {
            return Err(error.clone());
        }
        Ok(if key == b"present" {
            Some(b"hello".to_vec())
        } else {
            None
        })
    }
    async fn submit_transaction(&self, _bytes: Vec<u8>) -> Result<Hash, SubmitError> {
        Ok([0x42; 32])
    }
    async fn runtime_call(
        &self,
        _method: String,
        _args: Vec<u8>,
        _at: &BlockId,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        if let Some(delay) = self.runtime_delay {
            tokio::time::sleep(delay).await;
        }
        if let Some(error) = &self.query_error {
            return Err(error.clone().into());
        }
        if let Some(error) = &self.runtime_error {
            return Err(error.clone());
        }
        if self.runtime_attached {
            Ok(self.runtime_call_response.clone())
        } else {
            Err(RuntimeCallError::RuntimeNotConfigured)
        }
    }
}

const fn sample_header(height: Height, hash_seed: BlockHash) -> Header {
    Header {
        height,
        slot: height as Slot,
        parent_hash: [0; 32],
        proposer_index: 0,
        vrf_proof: [0; 96],
        state_root: hash_seed,
        transactions_root: [0; 32],
        votes_root: [0; 32],
        da_root: [0; 32],
        runtime_extra: [0; 32],
        inputs_root: [0; 32],
        receipts_root: [0; 32],
        gas_used: 0,
        gas_limit: 1_000_000,
        timestamp: 1_700_000_000,
        signature: [0; 96],
    }
}

#[tokio::test]
async fn system_chain_id_returns_configured_chain_id() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: ChainId = module.call("system_chainId", [(); 0]).await.unwrap();
    assert_eq!(result, 7);
}

#[tokio::test]
async fn system_health_reports_runtime_and_mempool() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("system_health", [(); 0]).await.unwrap();
    assert_eq!(result["mempool"], 3);
    assert_eq!(result["runtime_available"], true);
    assert_eq!(result["head_height"], 42);
}

#[tokio::test]
async fn system_info_includes_runtime_hash_when_attached() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("system_info", [(); 0]).await.unwrap();
    assert_eq!(
        result["runtime_code_hash"],
        format!("0x{}", "07".repeat(32))
    );
}

#[tokio::test]
async fn chain_head_returns_head_summary() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("chain_head", [(); 0]).await.unwrap();
    assert_eq!(result["height"], 42);
    assert_eq!(result["slot"], 42);
    assert!(result["hash"].as_str().unwrap().starts_with("0xaaaaaaaaaa"));
}

#[tokio::test]
async fn chain_get_header_defaults_to_latest() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("chain_getHeader", [(); 0]).await.unwrap();
    assert_eq!(result["height"], 42);
}

#[tokio::test]
async fn chain_get_header_accepts_height_number() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("chain_getHeader", [42_u64]).await.unwrap();
    assert_eq!(result["height"], 42);
}

#[tokio::test]
async fn chain_get_header_accepts_latest_string() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("chain_getHeader", ["latest"]).await.unwrap();
    assert_eq!(result["height"], 42);
}

#[tokio::test]
async fn chain_get_header_returns_null_for_unknown_height() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("chain_getHeader", [9999_u64]).await.unwrap();
    assert!(result.is_null());
}

#[tokio::test]
async fn chain_get_validator_set_returns_active_set() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("chain_getValidatorSet", [(); 0]).await.unwrap();
    let arr = result.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["effective_stake"], "1000000");
}

#[tokio::test]
async fn state_get_storage_returns_value_at_present_key() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result = call_named(
        &module,
        "state_getStorage",
        json!({"key": format!("0x{}", hex::encode(b"present"))}),
    )
    .await
    .unwrap();
    assert_eq!(result, json!(format!("0x{}", hex::encode(b"hello"))));
}

#[tokio::test]
async fn state_get_storage_returns_null_for_missing_key() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result = call_named(
        &module,
        "state_getStorage",
        json!({"key": format!("0x{}", hex::encode(b"missing"))}),
    )
    .await
    .unwrap();
    assert!(result.is_null());
}

#[tokio::test]
async fn mempool_submit_transaction_returns_hash() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result = call_named(
        &module,
        "mempool_submitTransaction",
        json!({"bytes": format!("0x{}", hex::encode([1, 2, 3]))}),
    )
    .await
    .unwrap();
    assert_eq!(
        result["hash"].as_str().unwrap(),
        format!("0x{}", hex::encode([0x42; 32]))
    );
}

#[tokio::test]
async fn mempool_status_returns_pending_count() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result: Value = module.call("mempool_status", [(); 0]).await.unwrap();
    assert_eq!(result["pending"], 3);
}

#[tokio::test]
async fn runtime_call_returns_payload_and_gas_used() {
    let backend = Arc::new(MockBackend::default());
    let module = build_module(backend).unwrap();
    let result = call_named(
        &module,
        "runtime_call",
        json!({
            "method": "account_get",
            "args": format!("0x{}", hex::encode([0xAA; 32])),
        }),
    )
    .await
    .unwrap();
    assert_eq!(result["code"], 0);
    assert_eq!(result["gas_used"], 100);
    assert_eq!(result["payload"].as_str().unwrap(), "0x01020304");
}

#[tokio::test]
async fn runtime_call_errors_when_runtime_not_configured() {
    let backend = Arc::new(MockBackend {
        runtime_attached: false,
        ..MockBackend::default()
    });
    let module = build_module(backend).unwrap();
    let err = call_named(
        &module,
        "runtime_call",
        json!({"method": "x", "args": "0x"}),
    )
    .await
    .expect_err("expected error");
    let msg = err["message"].as_str().unwrap_or("");
    assert!(msg.contains("runtime"), "unexpected error payload: {msg}");
}

#[tokio::test(start_paused = true)]
async fn runtime_call_reports_execution_failures_apart_from_its_deadline() {
    let call = json!({"method": "account_get", "args": "0x"});
    for (error, code) in [
        (RuntimeCallError::RuntimeNotConfigured, -32010),
        (RuntimeCallError::Runtime("trap".to_owned()), -32014),
        (RuntimeCallError::Decode("truncated".to_owned()), -32013),
    ] {
        let module = build_module(Arc::new(MockBackend {
            runtime_error: Some(error),
            ..MockBackend::default()
        }))
        .unwrap();
        let error = call_named(&module, "runtime_call", call.clone())
            .await
            .expect_err("runtime failure");
        assert_eq!(error["code"], code);
    }

    // Only an expired wall-clock budget reports the timeout code.
    let module = build_module_with(
        Arc::new(MockBackend {
            runtime_delay: Some(Duration::from_secs(60)),
            ..MockBackend::default()
        }),
        Duration::from_millis(10),
    )
    .unwrap();
    let error = call_named(&module, "runtime_call", call)
        .await
        .expect_err("deadline");
    assert_eq!(error["code"], -32012);
    assert_eq!(error["message"], "runtime_call timed out");
}

#[tokio::test]
async fn finalized_summary_identifies_the_chunk_boundary() {
    let module = build_module(Arc::new(MockBackend::default())).unwrap();
    let result: Value = module.call("chain_finalized", [(); 0]).await.unwrap();
    assert_eq!(result["chunk_id"], 0);
    assert_eq!(result["height"], 8);
    assert!(result.get("index").is_none());
}

#[tokio::test]
async fn unavailable_data_is_an_error_instead_of_a_null_result() {
    for (error, code) in [
        (QueryError::BlockNotFound, -32020),
        (QueryError::StateUnavailable, -32021),
        (QueryError::Storage("disk read failed".to_owned()), -32022),
        (QueryError::BodyUnavailable, -32023),
        (QueryError::HistoryUnavailable, -32025),
        (
            QueryError::Pruned {
                retained_from_chunk: 4,
                retained_from_height: 8_193,
            },
            -32024,
        ),
    ] {
        let module = build_module(Arc::new(MockBackend {
            query_error: Some(error),
            ..MockBackend::default()
        }))
        .unwrap();
        for (method, params) in [
            (
                "state_getStorage",
                json!({"key": "0x00", "at": "finalized"}),
            ),
            (
                "runtime_call",
                json!({"method": "account_get", "at": "finalized"}),
            ),
            ("chain_getHeader", json!(["latest"])),
            ("chain_getBlock", json!(["latest"])),
            ("chain_head", json!([])),
            ("chain_finalized", json!([])),
            ("system_health", json!([])),
        ] {
            let error = call_named(&module, method, params).await.expect_err(method);
            assert_eq!(error["code"], code);
            if code == -32024 {
                assert_eq!(
                    error["data"],
                    json!({ "retained_from_chunk": 4, "retained_from_height": 8_193 })
                );
            }
        }
    }
}

#[tokio::test]
async fn history_retention_reports_actual_availability_and_finality() {
    let module = build_module(Arc::new(MockBackend::default())).unwrap();
    let result: Value = module.call("history_getRetention", [(); 0]).await.unwrap();
    assert_eq!(
        result,
        json!({
            "archive": false,
            "retained_from_chunk": 4,
            "retained_from_height": 8_193,
            "finalized_chunks": 12,
        })
    );
}

#[tokio::test]
async fn blocking_status_reads_leave_the_transport_executor_responsive() {
    let backend = MockBackend {
        status_delay: Some(Duration::from_millis(250)),
        ..MockBackend::default()
    };
    let module = build_module(Arc::new(backend)).unwrap();
    let status = call_named(&module, "system_info", json!([]));
    tokio::pin!(status);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut status)
            .await
            .is_err()
    );
    assert_eq!(
        call_named(&module, "system_chainId", json!([]))
            .await
            .unwrap(),
        7
    );
    assert!(status.await.unwrap()["runtime_code_hash"].is_string());
}
