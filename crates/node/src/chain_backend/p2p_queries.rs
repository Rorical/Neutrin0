//! Checked, bounded P2P reads from the same materialized chain and state as RPC.

mod blocks;
mod history;
mod state;
mod status;

use borsh::BorshSerialize;
use neutrin0_network::rpc;
use neutrin0_rpc::QueryError;
use neutrin0_sync::SyncBackendError;

use super::{ChainBackend, not_available, rpc_queries, storage_error};

pub(super) fn query_error(error: QueryError) -> SyncBackendError {
    match error {
        QueryError::Storage(reason) => SyncBackendError::Storage(reason),
        QueryError::Pruned {
            retained_from_chunk,
            retained_from_height,
        } => SyncBackendError::Pruned {
            retained_from_chunk,
            retained_from_height,
        },
        other => SyncBackendError::NotAvailable(other.to_string()),
    }
}

/// Refuse a response whose encoding would exceed the wire limit. Read-only
/// queries measure it after releasing the engine lock.
fn bounded<T: BorshSerialize>(payload: T) -> Result<T, SyncBackendError> {
    let size = borsh::object_length(&payload).map_err(storage_error)?;
    if u64::try_from(size).unwrap_or(u64::MAX) >= rpc::DEFAULT_MAX_RESPONSE_SIZE {
        return Err(SyncBackendError::NotAvailable(
            "response exceeds the wire size limit".to_owned(),
        ));
    }
    Ok(payload)
}

fn check_count(count: usize, maximum: u64) -> Result<(), SyncBackendError> {
    if u64::try_from(count).unwrap_or(u64::MAX) > maximum {
        return Err(SyncBackendError::InvalidRequest(
            "request exceeds the item limit".to_owned(),
        ));
    }
    Ok(())
}
