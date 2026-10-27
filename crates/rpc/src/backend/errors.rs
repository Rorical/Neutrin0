//! Failure modes of backend queries, runtime calls and transaction admission.

use neutrin0_primitives::{ChunkId, Height};

/// Failure to resolve or read an authenticated RPC view.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum QueryError {
    /// A known finalized object lacks the requested locally retained artifact.
    #[error("requested consensus artifact is not available locally")]
    ArtifactUnavailable,
    /// A pinned exact artifact has changed since its metadata was fetched.
    #[error("artifact bytes no longer match the requested envelope commitment")]
    ArtifactChanged,
    /// Invalid bounded query parameters.
    #[error("invalid query: {0}")]
    InvalidRequest(String),
    /// A cursor cannot resume safely; the snapshot supports explicit recovery.
    #[error("chain event cursor cannot resume: {reason}")]
    EventCursor {
        /// malformed, wrong_stream, future or expired.
        reason: String,
        /// Current atomic chain snapshot.
        status: Box<crate::types::ChainEventStatusJson>,
    },
    /// The requested hash or height is not known locally.
    #[error("requested block is not known locally")]
    BlockNotFound,
    /// The selected block is known but its state data is not retained locally.
    #[error("state data for the requested block is not available locally")]
    StateUnavailable,
    /// The header is retained but the corresponding block body is unavailable.
    #[error("body for the requested block is not available locally")]
    BodyUnavailable,
    /// The requested History proof or endpoint is unknown or no longer retained.
    #[error("requested History proof is not retained locally")]
    HistoryUnavailable,
    /// The requested historical payload was deliberately pruned.
    #[error(
        "requested data was pruned; retained chunks start at {retained_from_chunk}, blocks at {retained_from_height}"
    )]
    Pruned {
        /// Actual persisted chunk retention watermark.
        retained_from_chunk: ChunkId,
        /// Earliest complete retained block payload.
        retained_from_height: Height,
    },
    /// Local storage failed or contained inconsistent content-addressed data.
    #[error("RPC storage read failed: {0}")]
    Storage(String),
}

/// Failure modes for [`RpcBackend::runtime_call`](super::RpcBackend::runtime_call).
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RuntimeCallError {
    /// The backend has no WASM runtime attached; queries are unavailable.
    #[error("WASM runtime is not configured on this node")]
    RuntimeNotConfigured,
    /// The selected block or its authenticated state could not be loaded.
    #[error(transparent)]
    Query(#[from] QueryError),
    /// The runtime crashed or trapped during the call.
    #[error("runtime invocation failed: {0}")]
    Runtime(String),
    /// The runtime returned bytes the host could not decode as a
    /// `QueryResponse`.
    #[error("runtime returned malformed response: {0}")]
    Decode(String),
}

/// Failure modes for [`RpcBackend::submit_transaction`](super::RpcBackend::submit_transaction).
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SubmitError {
    /// The transaction failed the runtime's admission check.
    #[error("transaction rejected by runtime: {reason}")]
    Rejected {
        /// Diagnostic message describing the rejection cause.
        reason: String,
    },
    /// The mempool is at capacity.
    #[error("mempool is full")]
    Full,
    /// The transaction is already buffered.
    #[error("transaction is already in the mempool")]
    Duplicate,
}
