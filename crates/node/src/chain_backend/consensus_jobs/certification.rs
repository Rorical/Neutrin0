//! Native certification separates owned verification from the mutation fence.

use neutrin0_consensus_engine::{BftQuorumIdentity, ValidatedExecutionChunk};
use neutrin0_consensus_types::FinalityCert;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;

use super::super::{ChainBackend, rejected};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(super) async fn certify_quorum_execution(
        &self,
        identity: BftQuorumIdentity,
        slot: OwnedSemaphorePermit,
    ) -> Result<(), SyncBackendError> {
        self.certify_execution_certificate(None, Some(identity), slot)
            .await
    }

    pub(in crate::chain_backend) async fn certify_execution_certificate(
        &self,
        certificate: Option<FinalityCert>,
        expected: Option<BftQuorumIdentity>,
        slot: OwnedSemaphorePermit,
    ) -> Result<(), SyncBackendError> {
        let engine = Arc::clone(&self.engine);
        let prover = Arc::clone(&self.proof_system);
        let bootstrap = Arc::clone(&self.bootstrap);
        let (checked, _slot) = tokio::task::spawn_blocking(move || {
            // A cancelled waiter cannot start another verification while this
            // one is running. The slot returns only after the worker finishes.
            let (pending, certificate) = {
                let engine = engine.lock().expect("engine mutex poisoned");
                if super::super::bootstrap::pending(&bootstrap) {
                    return Err(SyncBackendError::NotAvailable(
                        "checkpoint state is downloading".into(),
                    ));
                }
                if let Some(identity) = expected {
                    require_quorum(&engine, identity)?;
                    if engine.certified_execution_witness().is_some() {
                        return Ok((None, slot));
                    }
                }
                let certificate = certificate
                    .or_else(|| {
                        expected.and_then(|identity| {
                            engine
                                .bft_session(identity.chunk_id)
                                .and_then(neutrin0_consensus_engine::BftSession::certificate)
                        })
                    })
                    .ok_or_else(|| {
                        SyncBackendError::NotAvailable("complete certificate unavailable".into())
                    })?;
                let pending = engine
                    .pending_consensus_chunk(
                        certificate.chunk_id,
                        certificate.proposal.chunk.end_block_hash,
                        Some(&certificate.proposal.receipt_keys()),
                    )
                    .map_err(rejected)?;
                drop(engine);
                (pending, certificate)
            };
            let mut prepared = pending
                .prepare::<P, DB::Error>(prover.as_ref())
                .map_err(rejected)?;
            {
                let engine = engine.lock().expect("engine mutex poisoned");
                if super::super::bootstrap::pending(&bootstrap) {
                    return Err(SyncBackendError::NotAvailable(
                        "checkpoint state is downloading".into(),
                    ));
                }
                if let Some(identity) = expected {
                    require_quorum(&engine, identity)?;
                }
                engine
                    .install_finality_certificate(&mut prepared, certificate)
                    .map_err(rejected)?;
            }
            let checked =
                ValidatedExecutionChunk::validate(&prepared, prover.as_ref()).map_err(rejected)?;
            Ok::<_, SyncBackendError>((Some(checked), slot))
        })
        .await
        .map_err(|error| {
            SyncBackendError::NotAvailable(format!("certification worker failed: {error}"))
        })??;
        let Some(checked) = checked else {
            return Ok(());
        };
        let executor = self.replay_executor_snapshot();
        self.with_live_engine_mut(|engine| {
            if let Some(identity) = expected {
                require_quorum(engine, identity)?;
            }
            engine
                .commit_execution_certificate(checked, executor.as_deref())
                .map_err(rejected)?;
            Ok(())
        })
    }
}

fn require_quorum<DB: Database>(
    engine: &neutrin0_consensus_engine::Engine<DB>,
    identity: BftQuorumIdentity,
) -> Result<(), SyncBackendError> {
    if engine.execution_quorum_identity(identity.chunk_id) != Some(identity) {
        return Err(SyncBackendError::NotAvailable(
            "BFT quorum changed before certification".into(),
        ));
    }
    Ok(())
}
