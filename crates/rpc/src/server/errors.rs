//! JSON-RPC error codes and backend error mapping.
#![allow(clippy::redundant_pub_crate)] // Error codes shared with metrics keep crate visibility.

use jsonrpsee::types::ErrorObjectOwned;

use crate::backend::{QueryError, RuntimeCallError, SubmitError};

use super::RpcStartError;

/// Per-connection request budget exhausted.
pub(crate) const RATE_LIMITED_CODE: i32 = -32006;
/// Server-wide in-flight request limit reached.
pub(crate) const BUSY_CODE: i32 = -32005;
/// `runtime_call` wall-clock deadline elapsed. Used for nothing else, so the
/// metrics `timeout` outcome counts only deadline expiries.
pub(crate) const RUNTIME_TIMEOUT_CODE: i32 = -32012;
/// The runtime trapped or failed while executing a `runtime_call`.
const RUNTIME_FAILED_CODE: i32 = -32014;

pub(super) fn reg_err(err: impl core::fmt::Display) -> RpcStartError {
    RpcStartError::Registration(err.to_string())
}

pub(super) fn invalid_params(err: impl core::fmt::Display) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32602, format!("invalid params: {err}"), None::<()>)
}

pub(super) fn submit_err(err: &SubmitError) -> ErrorObjectOwned {
    let code = match err {
        SubmitError::Duplicate => -32001,
        SubmitError::Full => -32002,
        SubmitError::Rejected { .. } => -32003,
    };
    ErrorObjectOwned::owned(code, err.to_string(), None::<()>)
}

pub(super) fn runtime_err(err: &RuntimeCallError) -> ErrorObjectOwned {
    let code = match err {
        RuntimeCallError::RuntimeNotConfigured => -32010,
        RuntimeCallError::Query(error) => return query_err(error),
        RuntimeCallError::Runtime(_) => RUNTIME_FAILED_CODE,
        RuntimeCallError::Decode(_) => -32013,
    };
    ErrorObjectOwned::owned(code, err.to_string(), None::<()>)
}

pub(super) fn query_err(err: &QueryError) -> ErrorObjectOwned {
    let code = match err {
        QueryError::InvalidRequest(message) => return invalid_params(message),
        QueryError::ArtifactUnavailable => -32026,
        QueryError::ArtifactChanged => -32027,
        QueryError::EventCursor { reason, status } => {
            return ErrorObjectOwned::owned(
                -32028,
                err.to_string(),
                Some(serde_json::json!({"reason": reason, "status": status})),
            );
        }
        QueryError::BlockNotFound => -32020,
        QueryError::StateUnavailable => -32021,
        QueryError::Storage(_) => -32022,
        QueryError::BodyUnavailable => -32023,
        QueryError::HistoryUnavailable => -32025,
        QueryError::Pruned {
            retained_from_chunk,
            retained_from_height,
        } => {
            return ErrorObjectOwned::owned(
                -32024,
                err.to_string(),
                Some(serde_json::json!({
                    "retained_from_chunk": retained_from_chunk,
                    "retained_from_height": retained_from_height,
                })),
            );
        }
    };
    ErrorObjectOwned::owned(code, err.to_string(), None::<()>)
}
