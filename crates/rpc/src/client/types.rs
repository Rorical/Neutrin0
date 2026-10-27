//! Client-side JSON shapes and transaction confirmations.

use serde::{Deserialize, Serialize};

use crate::types::DiagnosticsJson;
use crate::{
    FinalizedInfoJson, HashHex, HeadInfoJson, HealthJson, HistoryRetention, SystemInfoJson,
};

/// Pending count from the node mempool.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MempoolStatusJson {
    /// Local pending envelope count.
    pub pending: u64,
}

/// Receipt fields needed for confirmation, preserving other Ethereum fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthereumReceiptJson {
    /// Exact raw Ethereum transaction identifier.
    pub transaction_hash: HashHex,
    /// Native block hash containing this transaction.
    pub block_hash: HashHex,
    /// Block height encoded as an Ethereum quantity.
    pub block_number: String,
    /// `0x1` for execution success and `0x0` for execution failure.
    pub status: String,
    /// Remaining receipt fields, including logs and gas.
    #[serde(flatten)]
    pub details: serde_json::Map<String, serde_json::Value>,
}

/// Operator status. Separate queries are independent observations, not one atomic snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeStatusJson {
    /// Numeric chain ID.
    pub chain_id: u64,
    /// Basic health observations.
    pub health: HealthJson,
    /// Installed runtime identity.
    pub info: SystemInfoJson,
    /// Selected head at the time of its query.
    pub head: HeadInfoJson,
    /// Finalized boundary at the time of its query.
    pub finalized: FinalizedInfoJson,
    /// History source availability and finality.
    pub retention: HistoryRetention,
    /// Detailed node observations.
    pub diagnostics: DiagnosticsJson,
}

/// A pinned state selector for multi-query operator views.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PinnedBlock {
    /// Exact block identifier.
    pub hash: HashHex,
    /// Height of the selected block.
    pub height: u64,
}

/// Transaction inclusion, separately from execution outcome and finality.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransactionConfirmation {
    /// Ethereum transaction hash.
    pub hash: HashHex,
    /// Canonical block containing the transaction.
    pub block: PinnedBlock,
    /// Complete-chunk finality was observed for this canonical inclusion.
    pub finalized: bool,
    /// Execution outcome from the Ethereum receipt.
    pub execution_success: bool,
}
