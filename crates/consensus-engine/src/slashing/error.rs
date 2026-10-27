//! Failures while verifying ingested slashing evidence.

use core::fmt;

use neutrin0_primitives::ValidatorIndex;

use crate::signature::SignatureError;

/// Failures while verifying ingested slashing evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SlashingError {
    /// Validator index in the evidence is outside the active set.
    ValidatorIndexOutOfBounds {
        /// Referenced validator index.
        index: ValidatorIndex,
        /// Active-set length.
        len: usize,
    },
    /// The validator's stored BLS public-key bytes do not decode.
    InvalidPublicKey {
        /// Validator index whose key bytes were invalid.
        index: ValidatorIndex,
    },
    /// A signature in the evidence is malformed.
    InvalidSignatureBytes,
    /// A signature in the evidence does not verify against the
    /// validator's BLS public key.
    BadSignature,
    /// Both artifacts in the evidence are byte-for-byte identical;
    /// there is no equivocation to slash.
    NotEquivocating,
    /// Two artifacts disagree on a field that must match for the
    /// evidence to be coherent (different proposer indices, different
    /// slots, different chunk ids, etc.).
    EvidenceFieldsInconsistent,
    /// The evidence references a historical chunk the local
    /// node has not finalized yet, so verification cannot complete.
    /// The evidence may still be valid; the caller should drop it
    /// for now and re-ingest once the relevant chunk lands.
    NotYetFinalizedLocally,
    /// The source is neither the current chunk nor one of the preceding eight
    /// authenticated finalized chunks.
    SourceOutsideAccountabilityWindow,
}

impl fmt::Display for SlashingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValidatorIndexOutOfBounds { index, len } => write!(
                f,
                "slashing evidence references validator {index} outside active set of length {len}"
            ),
            Self::InvalidPublicKey { index } => write!(
                f,
                "validator {index} has malformed BLS public-key bytes in the active set"
            ),
            Self::InvalidSignatureBytes => {
                f.write_str("slashing evidence carries malformed BLS signature bytes")
            }
            Self::BadSignature => {
                f.write_str("slashing evidence signature failed BLS verification")
            }
            Self::NotEquivocating => {
                f.write_str("slashing evidence does not show two distinct artifacts")
            }
            Self::EvidenceFieldsInconsistent => {
                f.write_str("slashing evidence fields are internally inconsistent")
            }
            Self::NotYetFinalizedLocally => f.write_str(
                "slashing evidence references a chunk the local node has not finalized yet",
            ),
            Self::SourceOutsideAccountabilityWindow => {
                f.write_str("slashing evidence source is outside the accountability window")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SlashingError {}

impl From<SignatureError> for SlashingError {
    fn from(error: SignatureError) -> Self {
        match error {
            SignatureError::ValidatorIndexOutOfBounds { index, len } => {
                Self::ValidatorIndexOutOfBounds { index, len }
            }
            SignatureError::InvalidPublicKey { index } => Self::InvalidPublicKey { index },
            SignatureError::InvalidSignatureBytes => Self::InvalidSignatureBytes,
            SignatureError::BadSignature => Self::BadSignature,
        }
    }
}
