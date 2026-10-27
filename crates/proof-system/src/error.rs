//! Errors returned by every proof-system backend.

use core::fmt;

/// Verification or proving failure surfaced to engine and tooling.
///
/// The variants are shared by every backend.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProofError {
    /// Proof bytes failed structural decoding or sanity checks.
    MalformedProof,
    /// Public inputs supplied to the verifier do not match the proof.
    PublicInputMismatch,
    /// Proving witness was rejected before invoking the backend.
    InvalidWitness,
    /// Required dependency proof (recursive predecessor, chunk proof)
    /// was missing or did not link.
    RecursionLinkBroken,
    /// Requested proof layer is not implemented by the selected backend.
    Unsupported,
    /// Backend rejected the proof or refused to prove for an
    /// implementation-specific reason.
    BackendRejected,
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedProof => f.write_str("malformed proof bytes"),
            Self::PublicInputMismatch => f.write_str("public inputs do not match the proof"),
            Self::InvalidWitness => f.write_str("invalid proving witness"),
            Self::RecursionLinkBroken => f.write_str("recursive proof link is broken"),
            Self::Unsupported => f.write_str("proof layer is not implemented by this backend"),
            Self::BackendRejected => f.write_str("backend rejected the proof"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProofError {}
