//! Indexed keyset pages bound to a canonical generation and normalized query filters.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod lookups;
mod page;

/// Optional normalized filters shared by transaction/log/transfer/proof listings.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Filter {
    /// Account declared/recovered in a transaction or transfer.
    pub address: Option<String>,
    /// Emitting token/log contract.
    pub contract: Option<String>,
    /// First event topic.
    pub topic0: Option<String>,
    /// Exact native block.
    pub block_hash: Option<String>,
    /// Runtime or envelope transaction identifier.
    pub hash: Option<String>,
    /// Runtime action/proof kind.
    pub kind: Option<String>,
    /// Execution outcome.
    pub status: Option<String>,
    /// Return only indexed complete-chunk finalized rows.
    pub finalized_only: bool,
}
impl Filter {
    /// Normalize caller values before binding SQL and cursor scope.
    pub fn normalize(mut self) -> Result<Self> {
        for value in [&mut self.address, &mut self.contract]
            .into_iter()
            .flatten()
        {
            *value = crate::model::address(value)?;
        }
        for value in [&mut self.topic0, &mut self.block_hash, &mut self.hash]
            .into_iter()
            .flatten()
        {
            *value = crate::model::hash(value)?;
        }
        if [&self.kind, &self.status]
            .into_iter()
            .flatten()
            .any(|value| {
                value.len() > 64
                    || !value
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'_')
            })
        {
            return Err(Error::Data("invalid kind/status filter".into()));
        }
        Ok(self)
    }
}
/// Indexed listing category, never taken from untrusted SQL text.
#[derive(Clone, Copy, Debug, Serialize)]
pub enum Kind {
    /// Canonical blocks.
    Blocks,
    /// Canonical transaction attempts.
    Transactions,
    /// Committed EVM logs.
    Logs,
    /// Standard-shaped token transfer events.
    Transfers,
    /// Indexed finalized chunks.
    Chunks,
    /// Observed proof/certificate availability.
    Proofs,
}
/// One page item plus stable order and parent identity.
#[derive(Clone, Debug)]
pub struct Record {
    /// Block/end height.
    pub height: u64,
    /// Native block hash, empty for artifact metadata without one.
    pub block_hash: String,
    /// Transaction/log/kind sequence.
    pub order: u64,
    /// Batch item sequence.
    pub suborder: u64,
    /// Bounded caller-independent cursor.
    pub cursor: String,
    /// Stored typed/projection JSON.
    pub data: Value,
}
/// Keyset page; source event cursors and query cursors are deliberately separate.
pub struct Page {
    /// Ordered items.
    pub records: Vec<Record>,
    /// An additional indexed row exists.
    pub has_more: bool,
}
#[derive(Serialize, Deserialize)]
pub(super) struct Cursor {
    pub(super) generation: u64,
    pub(super) scope: String,
    pub(super) height: u64,
    pub(super) order: u64,
    pub(super) suborder: u64,
}
