//! In-process History RPC contract, without network sockets. The History proof
//! is the latest finalized chunk receipt.

use std::sync::Arc;

use async_trait::async_trait;
use jsonrpsee::core::server::MethodsError;
use neutrin0_consensus_types::{Block, Header};
use neutrin0_primitives::{BlockHash, ChainId, Hash, Height, Validator};
use neutrin0_rpc::{
    BlockId, BytesHex, FinalizedInfo, HashHex, HeadInfo, QueryError, RpcBackend, RuntimeCallError,
    RuntimeCallResponse, SubmitError, build_module,
};

const PROOF: &[u8] = &[0, 1, 127, 128, 255];

struct Backend {
    latest: Option<Vec<u8>>,
}

#[async_trait]
impl RpcBackend for Backend {
    async fn history_latest(&self) -> Result<Vec<u8>, QueryError> {
        self.latest.clone().ok_or(QueryError::HistoryUnavailable)
    }

    fn chain_id(&self) -> ChainId {
        7
    }
    fn runtime_code_hash(&self) -> Option<Hash> {
        None
    }
    fn runtime_available(&self) -> bool {
        false
    }
    fn mempool_len(&self) -> usize {
        0
    }
    async fn head(&self) -> Result<HeadInfo, QueryError> {
        Err(QueryError::BlockNotFound)
    }
    async fn finalized(&self) -> Result<FinalizedInfo, QueryError> {
        Err(QueryError::BlockNotFound)
    }
    async fn active_validator_set(&self) -> Vec<Validator> {
        Vec::new()
    }
    async fn resolve_block_id(&self, _: &BlockId) -> Result<Option<BlockHash>, QueryError> {
        Ok(None)
    }
    async fn header_by_hash(&self, _: BlockHash) -> Result<Option<Header>, QueryError> {
        Ok(None)
    }
    async fn header_by_height(&self, _: Height) -> Result<Option<Header>, QueryError> {
        Ok(None)
    }
    async fn block_by_hash(&self, _: BlockHash) -> Result<Option<Block>, QueryError> {
        Ok(None)
    }
    async fn block_by_height(&self, _: Height) -> Result<Option<Block>, QueryError> {
        Ok(None)
    }
    async fn storage_at(&self, _: &[u8], _: &BlockId) -> Result<Option<Vec<u8>>, QueryError> {
        Ok(None)
    }
    async fn submit_transaction(&self, _: Vec<u8>) -> Result<Hash, SubmitError> {
        Err(SubmitError::Full)
    }
    async fn runtime_call(
        &self,
        _: String,
        _: Vec<u8>,
        _: &BlockId,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        Err(RuntimeCallError::RuntimeNotConfigured)
    }
}

fn error_code(error: MethodsError) -> i32 {
    let MethodsError::JsonRpc(error) = error else {
        panic!("expected JSON-RPC error")
    };
    error.code()
}

#[tokio::test]
async fn latest_history_proof_preserves_exact_bytes() {
    let module = build_module(Arc::new(Backend {
        latest: Some(PROOF.to_vec()),
    }))
    .unwrap();
    let latest: BytesHex = module.call("history_getLatest", [(); 0]).await.unwrap();
    assert_eq!(latest.0, PROOF);
}

#[tokio::test]
async fn missing_history_proof_reports_unavailability() {
    let module = build_module(Arc::new(Backend { latest: None })).unwrap();
    let error = module
        .call::<_, BytesHex>("history_getLatest", [(); 0])
        .await
        .unwrap_err();
    assert_eq!(error_code(error), -32025);
}

#[tokio::test]
async fn range_and_job_methods_are_not_served() {
    let module = build_module(Arc::new(Backend {
        latest: Some(PROOF.to_vec()),
    }))
    .unwrap();
    for method in ["history_proveRange", "history_getProof"] {
        let error = module
            .call::<_, serde_json::Value>(method, [HashHex([2; 32]), HashHex([3; 32])])
            .await
            .unwrap_err();
        assert_eq!(error_code(error), -32601);
    }
    let error = module
        .call::<_, serde_json::Value>("history_getJob", [HashHex([1; 32])])
        .await
        .unwrap_err();
    assert_eq!(error_code(error), -32601);
    assert!(
        module
            .subscribe("history_subscribeJob", [HashHex([1; 32])], 1)
            .await
            .is_err()
    );
}
