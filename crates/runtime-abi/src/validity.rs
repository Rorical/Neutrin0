//! The fixed-width transaction-validity result of the admission entrypoint.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::Hash;

/// Minimum byte length of the transaction-validity result returned by
/// [`VALIDATE_TX_ENTRYPOINT`](crate::VALIDATE_TX_ENTRYPOINT).
pub const TX_VALIDITY_ENCODED_LEN: usize = 13;

/// Runtime-issued sequence and fee information; the host never decodes user payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct TransactionDependency {
    /// Runtime-owned transaction identifier, also committed in execution artifacts.
    pub identifier: Hash,
    /// Canonical runtime account or sequence identifier.
    pub account: Hash,
    /// Sequence number this transaction consumes.
    pub nonce: u64,
    /// Account sequence observed at admission.
    pub state_nonce: u64,
    /// Maximum resource-unit bid, used for replacement checks.
    pub fee_cap: u128,
    /// Priority resource-unit bid, also used for replacement checks.
    pub tip_cap: u128,
    /// Maximum execution gas this operation reserves.
    pub gas_limit: u64,
}

/// Runtime-defined transaction validity code returned to the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxValidationCode {
    /// The transaction is valid against the supplied state root.
    Valid,
    /// The transaction bytes are malformed or truncated.
    Malformed,
    /// A transaction signature failed verification.
    BadSignature,
    /// The transaction nonce does not match account state.
    NonceMismatch,
    /// The sender or stake account lacks the required balance.
    InsufficientBalance,
    /// The transaction attempts an operation reserved to another owner.
    Unauthorized,
    /// The transaction type tag is not recognised by this runtime.
    UnknownType,
    /// Runtime state could not be read in the expected format.
    StateReadFailed,
}

impl TxValidationCode {
    /// Convert the validation code into its stable ABI integer.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Valid => 0,
            Self::Malformed => 1,
            Self::BadSignature => 2,
            Self::NonceMismatch => 3,
            Self::InsufficientBalance => 4,
            Self::Unauthorized => 5,
            Self::UnknownType => 6,
            Self::StateReadFailed => 7,
        }
    }

    /// Convert a stable ABI integer back into a validation code.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Valid),
            1 => Some(Self::Malformed),
            2 => Some(Self::BadSignature),
            3 => Some(Self::NonceMismatch),
            4 => Some(Self::InsufficientBalance),
            5 => Some(Self::Unauthorized),
            6 => Some(Self::UnknownType),
            7 => Some(Self::StateReadFailed),
            _ => None,
        }
    }

    /// `true` when this code admits the transaction into a block or mempool.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// Result returned by a runtime transaction-admission entrypoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxValidity {
    /// Validity code produced by the runtime.
    pub code: TxValidationCode,
    /// Runtime-defined mempool priority. Higher values drain first.
    pub priority: u64,
    /// Optional runtime-owned sequence dependency and replacement bids.
    pub dependency: Option<TransactionDependency>,
}

impl TxValidity {
    /// Construct an admitted transaction result.
    #[must_use]
    pub const fn valid(priority: u64) -> Self {
        Self {
            code: TxValidationCode::Valid,
            priority,
            dependency: None,
        }
    }

    /// Construct a rejected transaction result.
    #[must_use]
    pub const fn invalid(code: TxValidationCode) -> Self {
        Self {
            code,
            priority: 0,
            dependency: None,
        }
    }

    /// `true` when this result admits the transaction.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.code.is_valid()
    }

    /// Encode `code:u32 || priority:u64 || borsh(dependency)`, with little-endian integers.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let code = self.code.as_u32().to_le_bytes();
        let priority = self.priority.to_le_bytes();
        let mut bytes = Vec::from([
            code[0],
            code[1],
            code[2],
            code[3],
            priority[0],
            priority[1],
            priority[2],
            priority[3],
            priority[4],
            priority[5],
            priority[6],
            priority[7],
        ]);
        BorshSerialize::serialize(&self.dependency, &mut bytes)
            .expect("canonical admission metadata");
        bytes
    }

    /// Decode the exact current admission format; missing or trailing metadata is rejected.
    pub fn decode(bytes: &[u8]) -> Result<Self, TxValidityDecodeError> {
        if bytes.len() < TX_VALIDITY_ENCODED_LEN {
            return Err(TxValidityDecodeError::WrongLength {
                actual: bytes.len(),
            });
        }
        let code_raw = u32::from_le_bytes(
            bytes[..4]
                .try_into()
                .expect("length checked for validation code"),
        );
        let Some(code) = TxValidationCode::from_u32(code_raw) else {
            return Err(TxValidityDecodeError::UnknownCode { code: code_raw });
        };
        let priority = u64::from_le_bytes(
            bytes[4..12]
                .try_into()
                .expect("length checked for validation priority"),
        );
        let dependency = borsh::from_slice(&bytes[12..])
            .map_err(|_| TxValidityDecodeError::MalformedMetadata)?;
        Ok(Self {
            code,
            priority,
            dependency,
        })
    }
}

/// Errors while decoding a transaction-validity result from the runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxValidityDecodeError {
    /// The dependency record was malformed or carried trailing bytes.
    MalformedMetadata,
    /// The output length did not match [`TX_VALIDITY_ENCODED_LEN`].
    WrongLength {
        /// Actual number of bytes returned by the runtime.
        actual: usize,
    },
    /// The runtime returned an unknown validation code.
    UnknownCode {
        /// Raw code returned by the runtime.
        code: u32,
    },
}
