//! Typed node client and canonical-chain transaction confirmation.
//!
//! Responses are observations from the selected provider. This client does not
//! replace light-client proof verification or independently authenticate the provider.

use jsonrpsee::{core::client::Error as RpcError, proc_macros::rpc};

use crate::types::DiagnosticsJson;
use crate::{
    BlockIdJson, BlockJson, BytesHex, FinalizedInfoJson, HashHex, HeadInfoJson, HeaderJson,
    HealthJson, HistoryRetention, ProgramsStatusJson, ProvingStatusJson, RuntimeCallResultJson,
    SubmitResultJson, SystemInfoJson, ValidatorJson,
};

mod node;
mod types;

pub use node::{NodeClient, quantity_u64};
pub use types::{
    EthereumReceiptJson, MempoolStatusJson, NodeStatusJson, PinnedBlock, TransactionConfirmation,
};

/// Canonical typed methods, usable with jsonrpsee HTTP or WebSocket clients.
#[rpc(client)]
pub trait NodeApi {
    /// Immutable genesis facts, even when no genesis header is stored.
    #[method(name = "chain_getGenesis")]
    async fn genesis(&self) -> Result<Option<crate::types::GenesisInfoJson>, RpcError>;
    /// Header-bound execution receipts and runtime identity.
    #[method(name = "chain_getBlockArtifacts")]
    async fn block_artifacts(
        &self,
        block: HashHex,
    ) -> Result<Option<crate::types::BlockArtifactsJson>, RpcError>;
    /// Complete Ethereum transaction projection selected by exact native block hash.
    #[method(name = "eth_getBlockByHash")]
    async fn ethereum_block(
        &self,
        block: HashHex,
        full: bool,
    ) -> Result<Option<serde_json::Value>, RpcError>;
    /// All canonical receipts for an exact block, avoiding per-transaction round trips.
    #[method(name = "eth_getBlockReceipts")]
    async fn block_receipts(
        &self,
        block: serde_json::Value,
    ) -> Result<Option<Vec<EthereumReceiptJson>>, RpcError>;
    /// Locally retained finalized Chunk; null selects the latest finalized chunk.
    #[method(name = "chain_getChunk")]
    async fn chunk(&self, id: Option<u64>) -> Result<Option<crate::types::ChunkJson>, RpcError>;
    /// Mandatory certificate and exact signed proposal metadata.
    #[method(name = "chain_getCertificate")]
    async fn certificate(&self, id: u64)
    -> Result<Option<crate::types::CertificateJson>, RpcError>;
    /// Exact proof/certificate identity and public values.
    #[method(name = "chain_getArtifact")]
    async fn artifact(
        &self,
        id: crate::types::ArtifactIdJson,
    ) -> Result<Option<crate::types::ArtifactInfoJson>, RpcError>;
    /// Bounded download of a pinned exact Borsh envelope.
    #[method(name = "chain_getArtifactBytes")]
    async fn artifact_bytes(
        &self,
        id: crate::types::ArtifactIdJson,
        expected: HashHex,
        offset: u64,
        length: u32,
    ) -> Result<crate::types::ArtifactSliceJson, RpcError>;
    /// Atomic current snapshot or durable replay strictly after a supplied cursor.
    #[method(name = "chain_getEvents")]
    async fn chain_events(
        &self,
        after: Option<crate::types::ChainCursorJson>,
        limit: u32,
    ) -> Result<crate::types::ChainEventPageJson, RpcError>;
    /// Numeric chain identity; the complete chain-spec hash is in diagnostics.
    #[method(name = "system_chainId")]
    async fn chain_id(&self) -> Result<u64, RpcError>;
    /// Basic local health observations.
    #[method(name = "system_health")]
    async fn health(&self) -> Result<HealthJson, RpcError>;
    /// Installed runtime identity.
    #[method(name = "system_info")]
    async fn info(&self) -> Result<SystemInfoJson, RpcError>;
    /// Detailed local observations.
    #[method(name = "system_diagnostics")]
    async fn diagnostics(&self) -> Result<DiagnosticsJson, RpcError>;
    /// Selected unfinalized head.
    #[method(name = "chain_head")]
    async fn head(&self) -> Result<HeadInfoJson, RpcError>;
    /// Complete-chunk finality boundary.
    #[method(name = "chain_finalized")]
    async fn finalized(&self) -> Result<FinalizedInfoJson, RpcError>;
    /// Selected header; a missing result is distinct from unavailable data errors.
    #[method(name = "chain_getHeader")]
    async fn header(&self, at: BlockIdJson) -> Result<Option<HeaderJson>, RpcError>;
    /// Selected block, with opaque runtime transactions.
    #[method(name = "chain_getBlock")]
    async fn block(&self, at: BlockIdJson) -> Result<Option<BlockJson>, RpcError>;
    /// Current consensus validator seats.
    #[method(name = "chain_getValidatorSet")]
    async fn validators(&self) -> Result<Vec<ValidatorJson>, RpcError>;
    /// Raw storage at an exact selected block.
    #[method(name = "state_getStorage", param_kind = map)]
    async fn storage(&self, key: BytesHex, at: BlockIdJson) -> Result<Option<BytesHex>, RpcError>;
    /// Read-only installed-runtime query.
    #[method(name = "runtime_call", param_kind = map)]
    async fn runtime_call(
        &self,
        method: String,
        args: BytesHex,
        at: BlockIdJson,
    ) -> Result<RuntimeCallResultJson, RpcError>;
    /// Submit a canonical runtime envelope. Submission is not execution success.
    #[method(name = "mempool_submitTransaction", param_kind = map)]
    async fn submit(&self, bytes: BytesHex) -> Result<SubmitResultJson, RpcError>;
    /// Current pending count.
    #[method(name = "mempool_status")]
    async fn mempool(&self) -> Result<MempoolStatusJson, RpcError>;
    /// Actual source retention and finality.
    #[method(name = "history_getRetention")]
    async fn retention(&self) -> Result<HistoryRetention, RpcError>;
    /// History proof of the latest finalized endpoint, encoded in Borsh.
    #[method(name = "history_getLatest")]
    async fn history_latest(&self) -> Result<BytesHex, RpcError>;
    /// Program installation and distribution observations.
    #[method(name = "programs_status")]
    async fn programs(&self) -> Result<ProgramsStatusJson, RpcError>;
    /// What the node proves and which account its proofs name (design 08).
    #[method(name = "proving_status")]
    async fn proving(&self) -> Result<ProvingStatusJson, RpcError>;
    /// Submit exact signed Ethereum bytes; returned identifier is Keccak.
    #[method(name = "eth_sendRawTransaction")]
    async fn send_raw_transaction(&self, bytes: BytesHex) -> Result<HashHex, RpcError>;
    /// Canonical receipt for an Ethereum transaction, when retained.
    #[method(name = "eth_getTransactionReceipt")]
    async fn receipt(&self, hash: HashHex) -> Result<Option<EthereumReceiptJson>, RpcError>;
    /// Ethereum transaction, including local pending transactions.
    #[method(name = "eth_getTransactionByHash")]
    async fn ethereum_transaction(
        &self,
        hash: HashHex,
    ) -> Result<Option<serde_json::Value>, RpcError>;
    /// Next nonce including contiguous pending transactions.
    #[method(name = "eth_getTransactionCount")]
    async fn ethereum_nonce(
        &self,
        address: String,
        at: serde_json::Value,
    ) -> Result<String, RpcError>;
    /// Suggested effective fee per gas, as an Ethereum quantity.
    #[method(name = "eth_gasPrice")]
    async fn gas_price(&self) -> Result<String, RpcError>;
    /// Suggested priority fee per gas.
    #[method(name = "eth_maxPriorityFeePerGas")]
    async fn priority_fee(&self) -> Result<String, RpcError>;
    /// Simulate a Solidity call in the selected context.
    #[method(name = "eth_call")]
    async fn ethereum_call(
        &self,
        call: serde_json::Value,
        at: serde_json::Value,
    ) -> Result<BytesHex, RpcError>;
    /// Estimate gas against the selected context and candidate set.
    #[method(name = "eth_estimateGas")]
    async fn estimate_gas(
        &self,
        call: serde_json::Value,
        at: serde_json::Value,
    ) -> Result<String, RpcError>;
}

/// Client transport, runtime response, or confirmation failure.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// RPC error, retaining server codes and structured error data.
    #[error(transparent)]
    Rpc(#[from] RpcError),
    /// Runtime returned a non-success query code; payload is retained verbatim.
    #[error("runtime query `{method}` returned status {code}: {payload:?}")]
    Runtime {
        /// Runtime query name.
        method: String,
        /// Runtime-defined status.
        code: u32,
        /// Exact response bytes.
        payload: BytesHex,
    },
    /// The selected provider response could not be interpreted safely.
    #[error("{0}")]
    InvalidResponse(String),
    /// Requested confirmation did not arrive within the caller's deadline.
    #[error("confirmation deadline elapsed for transaction 0x{0}")]
    ConfirmationTimeout(String),
}

/// Typed WebSocket subscription. Reconnect explicitly using the last applied event cursor.
#[rpc(client)]
pub trait ChainEventsApi {
    /// Replay retained events then follow future durable transitions.
    #[subscription(name = "chain_subscribeEvents" => "chain_event", unsubscribe = "chain_unsubscribeEvents", item = crate::types::ChainNotificationJson)]
    async fn subscribe_events(
        &self,
        after: Option<crate::types::ChainCursorJson>,
    ) -> jsonrpsee::core::SubscriptionResult;
}
