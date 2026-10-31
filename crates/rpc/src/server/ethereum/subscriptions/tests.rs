use super::*;
use crate::backend::{
    BlockId, FinalizedInfo, HeadInfo, QueryError, RpcBackend, RuntimeCallError,
    RuntimeCallResponse, SubmitError,
};
use async_trait::async_trait;
use neutrin0_consensus_types::{Block, Header};
use neutrin0_primitives::{Hash, Validator};
use neutrin0_runtime_abi::ethereum::EvmArtifacts;
use std::sync::atomic::{AtomicBool, Ordering};

struct DelayedHeader {
    block: Block,
    artifacts: EvmArtifacts,
    delay: AtomicBool,
}

#[async_trait]
impl RpcBackend for DelayedHeader {
    fn chain_id(&self) -> u64 {
        7
    }
    fn runtime_code_hash(&self) -> Option<Hash> {
        Some([1; 32])
    }
    fn runtime_available(&self) -> bool {
        true
    }
    fn mempool_len(&self) -> usize {
        0
    }
    async fn head(&self) -> Result<HeadInfo, QueryError> {
        Ok(HeadInfo {
            height: 1,
            hash: self.block.hash(),
            slot: 2,
            state_root: self.block.header.state_root,
        })
    }
    async fn finalized(&self) -> Result<FinalizedInfo, QueryError> {
        Ok(FinalizedInfo {
            chunk_id: None,
            height: 0,
            block_hash: [0; 32],
            state_root: [0; 32],
        })
    }
    async fn active_validator_set(&self) -> Vec<Validator> {
        Vec::new()
    }
    async fn resolve_block_id(&self, _: &BlockId) -> Result<Option<Hash>, QueryError> {
        Ok(Some(self.block.hash()))
    }
    async fn header_by_hash(&self, _: Hash) -> Result<Option<Header>, QueryError> {
        Ok(Some(self.block.header.clone()))
    }
    async fn header_by_height(&self, _: u64) -> Result<Option<Header>, QueryError> {
        Ok(Some(self.block.header.clone()))
    }
    async fn block_by_hash(&self, _: Hash) -> Result<Option<Block>, QueryError> {
        Ok(Some(self.block.clone()))
    }
    async fn block_by_height(&self, _: u64) -> Result<Option<Block>, QueryError> {
        Ok(Some(self.block.clone()))
    }
    async fn storage_at(&self, _: &[u8], _: &BlockId) -> Result<Option<Vec<u8>>, QueryError> {
        Err(QueryError::StateUnavailable)
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
    async fn runtime_artifact_call(
        &self,
        _: String,
        _: Vec<u8>,
        _: Hash,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        if self.delay.swap(false, Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Ok(RuntimeCallResponse {
            code: 0,
            payload: borsh::to_vec(&self.artifacts).unwrap(),
            gas_used: 0,
        })
    }
}

#[tokio::test]
async fn timed_out_header_rendering_retries_without_losing_the_head() {
    let (block, artifacts) = super::super::tests::projection_fixture();
    let expected = super::super::codec::bytes(&block.hash());
    let ctx = RpcContext {
        backend: Arc::new(DelayedHeader {
            block,
            artifacts,
            delay: AtomicBool::new(true),
        }),
        runtime_call_timeout: Duration::from_millis(20),
        blocking_slots: Arc::new(tokio::sync::Semaphore::new(1)),
        ethereum_filters: Arc::default(),
        chain_subscriptions: Arc::new(crate::server::clients::ClientSlots::new(1, 1)),
        ethereum_subscriptions: Arc::new(crate::server::clients::ClientSlots::new(1, 1)),
    };
    let mut filter = PollFilter {
        last_used: Instant::now(),
        initialized: true,
        kind: FilterKind::Blocks,
        cursor: 0,
        known: std::collections::BTreeMap::new(),
        pending: BTreeSet::new(),
    };
    assert!(
        tokio::time::timeout(
            ctx.runtime_call_timeout,
            subscription_changes(&ctx, "newHeads", &mut filter)
        )
        .await
        .is_err()
    );
    assert_eq!(filter.cursor, 0);
    assert!(filter.known.is_empty());
    let values = subscription_changes(&ctx, "newHeads", &mut filter)
        .await
        .unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["hash"], expected);
    assert_eq!(filter.cursor, 1);
    assert_eq!(
        subscription_changes(&ctx, "newHeads", &mut filter)
            .await
            .unwrap(),
        Vec::<Value>::new()
    );
}
