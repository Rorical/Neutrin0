//! Serving this node's latest finalized endpoint as a bootstrap manifest.

use neutrin0_consensus_types::bootstrap::BootstrapData;
use neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS;
use neutrin0_primitives::{BoundedBytes, Hash};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;

use super::{ChainBackend, not_available, rejected, storage_error, validate_data};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(in crate::chain_backend) fn serve_bootstrap(
        &self,
        end: Hash,
    ) -> Result<BootstrapData, SyncBackendError> {
        self.with_engine(|engine| {
            let history = engine
                .latest_history_proof()
                .map_err(rejected)?
                .ok_or_else(|| {
                    SyncBackendError::NotAvailable("History proof unavailable".into())
                })?;
            if history.end_checkpoint().hash() != end {
                return Err(SyncBackendError::NotAvailable(
                    "requested bootstrap endpoint is not the latest finalized endpoint".into(),
                ));
            }
            let boundary = *history.end();
            let header = engine
                .store()
                .get_header(&boundary.block_hash)
                .map_err(storage_error)?
                .ok_or_else(|| {
                    SyncBackendError::NotAvailable("bootstrap anchor header unavailable".into())
                })?;
            let validators = engine
                .store()
                .get_validator_set_snapshot(boundary.next_chunk_id)
                .map_err(storage_error)?
                .ok_or_else(|| {
                    SyncBackendError::NotAvailable("bootstrap validator context unavailable".into())
                })?;
            let frontier = engine
                .store()
                .history_frontier(boundary.next_chunk_id)
                .map_err(storage_error)?;
            let first = boundary
                .next_chunk_id
                .saturating_sub(HISTORY_RETENTION_CHUNKS);
            let recent = (first..boundary.next_chunk_id)
                .map(|id| {
                    let opening = engine
                        .store()
                        .historical_opening(id, boundary.next_chunk_id)
                        .map_err(storage_error)?;
                    BoundedBytes::new(borsh::to_vec(&opening).map_err(storage_error)?)
                        .map_err(rejected)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let data = BootstrapData::new(history, header, validators, frontier, recent)
                .map_err(not_available)?;
            validate_data(&data)?;
            // A manifest pins nothing: the first state read under one of the
            // endpoint's roots leases it, so holding state costs the peer
            // the download it claims to make.
            Ok(data)
        })
    }
}
