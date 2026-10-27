//! Errors of the SP1 host and the conversions every module maps into them.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Crate-visible helpers of a private module; `pub` would be unreachable."
)]

use neutrin0_runtime_abi::RuntimeBlockOutput;
use thiserror::Error;

/// Errors produced by the SP1 host.
#[derive(Debug, Error)]
pub enum Sp1HostError {
    /// SP1 SDK setup, proving, or verification failure.
    #[error("SP1 SDK error: {0}")]
    Sdk(String),
    /// The proof verified cryptographically but its committed
    /// [`RuntimeBlockOutput`] did not match what the caller expected.
    #[error("SP1 proof public output mismatch")]
    PublicOutputMismatch {
        /// Expected output.
        expected: Box<RuntimeBlockOutput>,
        /// Actual output read from the proof.
        actual: Box<RuntimeBlockOutput>,
    },
    /// The proof's public-values buffer could not be borsh-decoded
    /// as an [`RuntimeBlockOutput`]. Indicates a guest/host format mismatch
    /// or adversarial proof.
    #[error("failed to decode committed RuntimeBlockOutput: {0}")]
    DecodeOutput(String),
    /// borsh encode/decode failure on the host side.
    #[error("borsh codec error: {0}")]
    Codec(String),
}

pub(super) fn sdk_err<E: core::fmt::Display>(err: E) -> Sp1HostError {
    Sp1HostError::Sdk(err.to_string())
}

pub(super) fn codec_err<E: core::fmt::Display>(err: E) -> Sp1HostError {
    Sp1HostError::Codec(err.to_string())
}
