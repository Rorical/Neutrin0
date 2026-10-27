//! The borsh-encoded read-only query envelope.

use alloc::string::String;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};

/// Borsh-encoded read-only query request passed to
/// [`QUERY_ENTRYPOINT`](crate::QUERY_ENTRYPOINT) through the runtime's input buffer.
///
/// The wire envelope is intentionally narrow: a runtime-defined method
/// name plus opaque bytes. The method is a UTF-8 string so an EVM-style
/// runtime can claim `eth_getBalance`, `eth_call`, etc.; non-EVM
/// runtimes are free to choose any naming scheme. The argument bytes
/// are encoded by the caller in whatever shape the chosen method
/// expects (typically borsh, but the host is agnostic).
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct QueryRequest {
    /// Runtime-defined method name (e.g. `"account_get"` or
    /// `"eth_call"`).
    pub method: String,
    /// Opaque, method-defined argument payload.
    pub args: Vec<u8>,
}

/// Borsh-encoded read-only query response written to the runtime's output
/// buffer.
///
/// A successful query carries `code = 0` and the method's serialised
/// result in `payload`. A failed query carries a non-zero runtime
/// status; the value is consensus-irrelevant (queries never produce
/// state) so runtimes are free to define their own status spaces, but
/// the values listed in [`QueryStatus`] cover the common cases.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct QueryResponse {
    /// Runtime-defined status code. `0` means success.
    pub code: u32,
    /// Method-defined result bytes on success, or an optional error
    /// payload on failure.
    pub payload: Vec<u8>,
}

impl QueryResponse {
    /// Construct a successful response with the given payload.
    #[must_use]
    pub const fn ok(payload: Vec<u8>) -> Self {
        Self {
            code: QueryStatus::Ok.as_u32(),
            payload,
        }
    }

    /// Construct an error response with the given status code and
    /// optional message bytes.
    #[must_use]
    pub fn err(status: QueryStatus, message: impl Into<Vec<u8>>) -> Self {
        Self {
            code: status.as_u32(),
            payload: message.into(),
        }
    }

    /// `true` when this response signals a successful query.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.code == QueryStatus::Ok.as_u32()
    }
}

/// Conventional status codes for [`QueryResponse::code`].
///
/// Runtimes are free to use additional codes >= `1024`; the values
/// below `1024` are reserved for the canonical envelope. The host
/// never inspects the value; it is interpreted by the RPC layer
/// (or whatever consumes the response).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryStatus {
    /// Successful query.
    Ok,
    /// Method name was not recognised by the runtime.
    UnknownMethod,
    /// Method recognised, but the argument bytes were malformed.
    InvalidArguments,
    /// The runtime returned an error specific to the method.
    MethodError,
    /// The host refused the call (e.g. write attempted during query).
    PermissionDenied,
}

impl QueryStatus {
    /// Stable wire encoding of the status.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::UnknownMethod => 1,
            Self::InvalidArguments => 2,
            Self::MethodError => 3,
            Self::PermissionDenied => 4,
        }
    }
}
