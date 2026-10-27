//! GraphQL input filters and their mapping onto indexed query filters.
use crate::db::query::Filter;
use async_graphql::InputObject;

/// Bounded transaction activity filters.
#[derive(Clone, Default, InputObject)]
pub struct TransactionFilter {
    /// Declared/recovered sender or destination.
    pub address: Option<String>,
    /// Exact block identity.
    pub block_hash: Option<String>,
    /// Runtime/envelope transaction ID; lists all native resubmission attempts.
    pub hash: Option<String>,
    /// Runtime action label.
    pub kind: Option<String>,
    /// Execution outcome.
    pub status: Option<String>,
    /// Only indexed finalized rows.
    #[graphql(default)]
    pub finalized_only: bool,
}
/// Log and token movement filters.
#[derive(Clone, Default, InputObject)]
pub struct EventFilter {
    /// Transfer participant; for logs, emitting address when contract is omitted.
    pub address: Option<String>,
    /// Emitter/token contract.
    pub contract: Option<String>,
    /// Topic zero, for logs.
    pub topic0: Option<String>,
    /// Native block.
    pub block_hash: Option<String>,
    /// Runtime transaction identifier.
    pub transaction_hash: Option<String>,
    /// Only indexed finalized rows.
    #[graphql(default)]
    pub finalized_only: bool,
}
pub(super) fn event_filter(filter: Option<EventFilter>) -> Filter {
    let f = filter.unwrap_or_default();
    Filter {
        address: f.address,
        contract: f.contract,
        topic0: f.topic0,
        block_hash: f.block_hash,
        hash: f.transaction_hash,
        finalized_only: f.finalized_only,
        ..Filter::default()
    }
}
