use core::fmt;

/// Errors returned by the cryptographic primitives in this crate.
///
/// The variants are intentionally coarse — we do not leak the underlying
/// backend's error detail because doing so can become an oracle for
/// adversaries. Callers that need finer diagnostics should re-derive them
/// from input validation rather than from a verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// A serialized secret key could not be decoded or is out of range.
    InvalidSecretKey,
    /// A serialized public key could not be decoded, was not on the curve,
    /// or failed a subgroup check.
    InvalidPublicKey,
    /// A serialized signature could not be decoded, was not on the curve,
    /// failed a subgroup check, or was the point at infinity.
    InvalidSignature,
    /// Cryptographic verification failed.
    Verification,
    /// An aggregate operation was called with no inputs.
    EmptyInput,
    /// A byte slice or vector had an unexpected length.
    UnexpectedLength {
        /// The length actually provided.
        actual: usize,
        /// The length the operation required.
        expected: usize,
    },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretKey => f.write_str("invalid secret key encoding"),
            Self::InvalidPublicKey => f.write_str("invalid public key encoding"),
            Self::InvalidSignature => f.write_str("invalid signature encoding"),
            Self::Verification => f.write_str("signature verification failed"),
            Self::EmptyInput => f.write_str("aggregate operation requires at least one input"),
            Self::UnexpectedLength { actual, expected } => {
                write!(f, "unexpected length {actual}, expected {expected}")
            }
        }
    }
}

impl std::error::Error for CryptoError {}
