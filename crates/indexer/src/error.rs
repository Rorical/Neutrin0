//! Explicit sync and query failures; a missing source never becomes an empty index.
/// Indexing/query result.
pub type Result<T> = core::result::Result<T, Error>;
/// Standalone service failures.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid deployment setting.
    #[error("configuration: {0}")]
    Config(String),
    /// Source identity does not match the pinned database.
    #[error("chain/database binding mismatch: {0}")]
    Binding(String),
    /// Source changed while assembling a pinned block/range; retry with a new observation.
    #[error("source branch changed during backfill")]
    BranchChanged,
    /// A selected provider is behind the previously saved finalized checkpoint.
    #[error("source is behind the saved finalized checkpoint")]
    SourceBehind,
    /// Never roll back an indexed finalized chunk.
    #[error("source conflicts with the saved finalized checkpoint")]
    FinalityConflict,
    /// Missing/pruned source data, retaining the provider's structured error.
    #[error("upstream RPC: {0}")]
    Rpc(#[from] jsonrpsee::core::client::Error),
    /// Invalid committed input or projection.
    #[error("invalid indexing data: {0}")]
    Data(String),
    /// Another writer already owns this schema.
    #[error("another indexer owns the PostgreSQL writer lease")]
    WriterBusy,
    /// SQL error.
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    /// Opaque JSON data was malformed.
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Deployment file was malformed.
    #[error("TOML: {0}")]
    Toml(#[from] toml::de::Error),
    /// File/listener error.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    /// Cursor must be restarted after a reorg or filter change.
    #[error("{0}")]
    Cursor(&'static str),
}
