//! GraphQL query shapes. Large integers are decimal strings; JSON retains source representations.
use crate::{
    Error,
    db::{ReadView, query::Page},
};
use async_graphql::{Json, SimpleObject};
use serde_json::Value;

mod connections;
mod execution;
mod finality;

pub use connections::*;
pub use execution::*;
pub use finality::*;

/// Stable keyset pagination metadata.
#[derive(Clone, SimpleObject)]
pub struct PageInfo {
    /// More rows follow the last edge.
    pub has_next_page: bool,
    /// First edge cursor.
    pub start_cursor: Option<String>,
    /// Last edge cursor.
    pub end_cursor: Option<String>,
}
impl PageInfo {
    pub(super) fn new(page: &Page) -> Self {
        Self {
            has_next_page: page.has_more,
            start_cursor: page.records.first().map(|r| r.cursor.clone()),
            end_cursor: page.records.last().map(|r| r.cursor.clone()),
        }
    }
}
/// Database and source progress, separate from any claim of local consensus verification.
#[derive(SimpleObject)]
pub struct Status {
    /// Pinned complete chain-specification identity.
    pub chain_spec_hash: String,
    /// Exact numeric chain identity.
    pub chain_id: String,
    /// Genesis block identifier.
    pub genesis_hash: String,
    /// Fixed blocks per Chunk.
    pub chunk_size: String,
    /// Indexed canonical tip height.
    pub indexed_height: String,
    /// Indexed canonical tip identity.
    pub indexed_hash: String,
    /// Source head observed by the worker.
    pub source_height: String,
    /// Source head identity.
    pub source_hash: String,
    /// Last indexed complete Chunk endpoint.
    pub finalized_height: String,
    /// Indexed finalized endpoint identity.
    pub finalized_hash: String,
    /// Source's observed complete Chunk endpoint.
    pub source_finalized_height: String,
    /// Number of indexed finalized Chunks.
    pub finalized_chunks: String,
    /// Canonical block count (indexing begins at height one).
    pub block_count: String,
    /// All canonical common transaction envelopes, including rejected attempts/evidence.
    pub transaction_count: String,
    /// Committed canonical Ethereum log count.
    pub log_count: String,
    /// Exact accumulated canonical gas.
    pub gas_used: String,
    /// Canonical pagination generation.
    pub generation: String,
    /// Last fully reconciled upstream event checkpoint.
    pub event_cursor: Option<Json<Value>>,
    /// starting, backfilling, live or error.
    pub phase: String,
    /// Last explicit sync error.
    pub last_error: Option<String>,
    /// Database observation timestamp.
    pub observed_at: String,
}
impl From<&ReadView> for Status {
    fn from(view: &ReadView) -> Self {
        let s = &view.state;
        Self {
            chain_spec_hash: s.binding.chain_spec_hash.clone(),
            chain_id: s.binding.chain_id.clone(),
            genesis_hash: crate::model::hex(&s.binding.genesis.hash.0),
            chunk_size: s.binding.chunk_size.to_string(),
            indexed_height: s.head.height.to_string(),
            indexed_hash: crate::model::hex(&s.head.hash.0),
            source_height: s.source_head.height.to_string(),
            source_hash: crate::model::hex(&s.source_head.hash.0),
            finalized_height: s.finalized.height.to_string(),
            finalized_hash: crate::model::hex(&s.finalized.hash.0),
            source_finalized_height: s.source_finalized.height.to_string(),
            finalized_chunks: s.finalized_chunks.to_string(),
            block_count: s.head.height.to_string(),
            transaction_count: s.transactions.to_string(),
            log_count: s.logs.to_string(),
            gas_used: s.gas.clone(),
            generation: s.generation.to_string(),
            event_cursor: s
                .cursor
                .as_ref()
                .map(|cursor| Json(serde_json::json!(cursor))),
            phase: s.phase.clone(),
            last_error: s.last_error.clone(),
            observed_at: s.observed_at.clone(),
        }
    }
}
pub(super) fn text(value: &Value, key: &str) -> crate::Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::Data(format!("stored {key} absent")))
}
