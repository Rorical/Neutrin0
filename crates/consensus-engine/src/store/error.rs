//! Errors produced by the [`ChainStore`](super::ChainStore).

use core::fmt;

/// Failure modes for a [`ChainStore`](super::ChainStore) operation.
///
/// `Database(E)` propagates the backend error verbatim. `Codec(io)`
/// wraps the [`borsh`](borsh) encode/decode error type; for any
/// supported backend a `Codec` error indicates on-disk corruption or a
/// format mismatch (every type stored by the engine has a stable
/// borsh schema that round-trips by construction).
#[derive(Debug)]
pub enum StoreError<E> {
    /// Backend database error.
    Database(E),
    /// Borsh encode / decode error.
    Codec(std::io::Error),
    /// Persisted chain data or pointers violate a canonical-chain invariant.
    Corrupt(&'static str),
}

impl<E: fmt::Display> fmt::Display for StoreError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(err) => write!(f, "database error: {err}"),
            Self::Codec(err) => write!(f, "codec error: {err}"),
            Self::Corrupt(reason) => write!(f, "corrupt chain data: {reason}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for StoreError<E> {}

impl<E> From<std::io::Error> for StoreError<E> {
    fn from(err: std::io::Error) -> Self {
        Self::Codec(err)
    }
}
