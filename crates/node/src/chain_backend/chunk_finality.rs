//! Chunk finality: local finalization, imported complete chunk proofs and
//! the bookkeeping every newly finalized boundary triggers.

use neutrin0_consensus_engine::{Engine, FinalizeError, FinalizeOutcome, ProposerKey};
use neutrin0_consensus_types::ChunkProof;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use neutrin0_sync::{ChunkProofImported, SyncBackendError};
use tracing::debug;

use super::{ChainBackend, rejected, storage_error};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Record finality while the successful commit still holds the engine lock.
    /// The commit order makes constant-size highest-ID deduplication safe;
    /// bootstrap prefix data is not inferred.
    pub(super) fn record_finalized_execution(&self, engine: &Engine<DB>, chunk_id: u64) {
        let mut observed = self
            .metrics
            .execution
            .observed_finalized
            .lock()
            .expect("finalized execution metrics");
        if observed.is_some_and(|previous| previous >= chunk_id) {
            return;
        }
        self.metrics.execution.finalized(chunk_id);
        let result = (|| {
            let chunk = engine.store().get_chunk(chunk_id).ok().flatten()?;
            let mut transactions = 0_u64;
            let mut gas = 0_u64;
            for height in chunk.start_height..=chunk.end_height {
                let header = engine.store().get_header_by_height(height).ok().flatten()?;
                let body = engine.store().get_body(&header.hash()).ok().flatten()?;
                transactions =
                    transactions.checked_add(u64::try_from(body.transactions.len()).ok()?)?;
                gas = gas.checked_add(header.gas_used)?;
            }
            Some((transactions, gas))
        })();
        let metrics = &self.metrics.execution;
        match result {
            Some((transactions, gas)) => {
                metrics
                    .finalized_transactions
                    .fetch_add(transactions, std::sync::atomic::Ordering::Relaxed);
                metrics
                    .finalized_gas
                    .fetch_add(gas, std::sync::atomic::Ordering::Relaxed);
                metrics
                    .finalized_chunks
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            None => {
                metrics
                    .finalized_observation_failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        *observed = Some(chunk_id);
    }

    /// Another valid proof of a finalized chunk competes for ratification
    /// (design 08); a new one is retained and propagated.
    pub(super) async fn import_alternative_chunk_proof(
        &self,
        proof: &ChunkProof,
        source: neutrin0_network::PeerId,
    ) -> Result<Option<ChunkProofImported>, SyncBackendError> {
        if self.block_program().is_none()
            || !self.with_engine(|engine| {
                engine
                    .latest_finalized_chunk_id()
                    .is_some_and(|id| id >= proof.chunk_id)
            })
        {
            return Ok(None);
        }
        // Each new prover address is a new statement the engine verifies
        // under its lock; a peer has a bounded number of them verified per
        // chunk, so no peer can spend another's verifications.
        if !self
            .chunk_proof_budget
            .lock()
            .expect("chunk proof budget poisoned")
            .admit(
                (source, proof.chunk_id),
                neutrin0_primitives::blake3_256(&proof.proof_bytes),
            )
        {
            return Err(SyncBackendError::NotAvailable(
                "chunk proof verification budget spent".into(),
            ));
        }
        self.verify_alternative_off_lock(proof).await?;
        let retained = self.with_live_engine_mut(|engine| {
            engine
                .import_alternative_chunk_proof(proof, self.proof_system.as_ref())
                .map_err(Self::map_import_err)
        })?;
        Ok(retained.then_some(ChunkProofImported {
            chunk_id: proof.chunk_id,
            end_height: proof.public_inputs.end_height,
        }))
    }

    /// Verify an alternative chunk proof on a blocking worker, so the import
    /// that follows finds the verdict cached and holds the engine lock only
    /// to record it. A proof that needs nothing is left to the import.
    async fn verify_alternative_off_lock(
        &self,
        proof: &ChunkProof,
    ) -> Result<(), SyncBackendError> {
        let Some(expected) = self
            .with_engine(|engine| engine.alternative_chunk_statement(proof))
            .map_err(Self::map_import_err)?
        else {
            return Ok(());
        };
        let proof_system = std::sync::Arc::clone(&self.proof_system);
        let bytes = proof.proof_bytes.clone();
        tokio::task::spawn_blocking(move || {
            let decoded: P::ChunkProof = borsh::from_slice(&bytes).map_err(rejected)?;
            proof_system
                .verify_consensus_chunk(&decoded, &expected)
                .map_err(rejected)
        })
        .await
        .map_err(storage_error)?
    }

    /// Prove and finalize chunk `chunk_id` on the materialized canonical
    /// branch, certified by `voter`.
    ///
    /// The BFT loop certifies and proves chunks on its own path; integration
    /// tests drive finality through this. Returns the engine
    /// [`FinalizeOutcome`] so the caller can persist + gossip the resulting
    /// chunk proof.
    ///
    /// # Errors
    ///
    /// Surfaces any [`FinalizeError`] variant raised by
    /// [`Engine::finalize_chunk`].
    pub fn finalize_chunk(
        &self,
        chunk_id: u64,
        voter: &ProposerKey,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        let outcome = self.with_engine_mut(|e| {
            if self.bootstrap_pending() {
                return Err(FinalizeError::Backend(
                    neutrin0_proof_system::ProofError::BackendRejected,
                ));
            }
            let outcome = e.finalize_chunk(chunk_id, self.proof_system.as_ref(), voter)?;
            self.record_finalized_execution(e, chunk_id);
            Ok(outcome)
        })?;
        self.after_chunk_finality();
        Ok(outcome)
    }

    /// Follow a newly finalized boundary: reporter retention is refreshed
    /// against it, history below the window is pruned and the endpoint whose
    /// History proof this node now serves is announced.
    pub(super) fn after_chunk_finality(&self) {
        self.schedule_mempool_revalidation();
        self.refresh_reporter_tracking();
        self.advance_history();
    }

    /// Verify and import a gossipped complete chunk proof; a proof of an
    /// already finalized chunk is retained as a ratification alternative.
    pub(super) async fn accept_chunk_proof(
        &self,
        proof: ChunkProof,
        source: neutrin0_network::PeerId,
    ) -> Result<ChunkProofImported, SyncBackendError> {
        let metric_timer = self.metrics.execution.chunk_verification.timer();
        self.reject_light()?;
        self.observe_certificate_offences(&proof).await;
        if let Some(imported) = self.import_alternative_chunk_proof(&proof, source).await? {
            return Ok(imported);
        }
        self.ensure_chunk_proof_importable(&proof)?;
        let chunk_id = proof.chunk_id;
        let outcome = self.import_complete_chunk_proof(&proof)?;
        self.after_chunk_finality();
        self.retain_certificate_sources(&proof).await;
        self.resume_proven_successor().await;
        self.submit_execution_claims().await;
        debug!(
            chunk_id,
            end_height = outcome.end_height,
            "persisted gossipped chunk proof"
        );
        metric_timer.finish(true);
        Ok(ChunkProofImported {
            chunk_id: outcome.chunk_id,
            end_height: outcome.end_height,
        })
    }

    async fn observe_certificate_offences(&self, proof: &ChunkProof) {
        let certificate = &proof.finality_cert;
        let chunk = neutrin0_prover_chunk::consensus::as_chunk(&proof.public_inputs);
        let evidence = self
            .with_live_engine_mut(|engine| {
                engine
                    .observe_certificate_for_slashing(&chunk, certificate)
                    .map_err(rejected)
            })
            .unwrap_or_default();
        for item in evidence {
            self.pool_and_gossip_slashing(item).await;
        }
    }

    fn ensure_chunk_proof_importable(&self, proof: &ChunkProof) -> Result<(), SyncBackendError> {
        if self.block_program().is_none() {
            return Ok(());
        }
        self.with_engine(|engine| {
            if engine
                .latest_finalized_chunk_id()
                .is_some_and(|id| id >= proof.chunk_id)
            {
                return Err(SyncBackendError::NotAvailable(
                    "chunk already finalized".to_owned(),
                ));
            }
            if engine.finalized_next_chunk_id() != proof.chunk_id
                || engine
                    .store()
                    .get_header(&proof.public_inputs.end_block_hash)
                    .map_err(storage_error)?
                    .is_none()
            {
                return Err(SyncBackendError::ChainBehind(
                    "chunk dependencies are not available yet".to_owned(),
                ));
            }
            Ok(())
        })
    }

    fn import_complete_chunk_proof(
        &self,
        proof: &ChunkProof,
    ) -> Result<neutrin0_consensus_engine::ImportChunkProofOutcome, SyncBackendError> {
        let chunk_id = proof.chunk_id;
        let executor = self.replay_executor_snapshot();
        self.with_live_engine_mut(|engine| {
            let previous = engine.finalized_next_chunk_id();
            let outcome = match executor.as_ref() {
                Some(executor) => engine.import_chunk_proof_with_dry_run(
                    proof,
                    self.proof_system.as_ref(),
                    executor.as_ref(),
                ),
                None => engine.import_chunk_proof(proof, self.proof_system.as_ref()),
            }
            .map_err(Self::map_import_err)?;
            if engine.finalized_next_chunk_id() > previous {
                self.record_finalized_execution(engine, chunk_id);
            }
            Ok(outcome)
        })
    }

    async fn retain_certificate_sources(&self, proof: &ChunkProof) {
        if self.block_program().is_none() {
            return;
        }
        let certificate = &proof.finality_cert;
        self.retain_availability_vote(&certificate.prevote_vote())
            .await;
        self.retain_availability_vote(&certificate.precommit_vote())
            .await;
        self.retain_availability_bft_message(
            &neutrin0_consensus_types::BftMessage::Proposal(Box::new(certificate.proposal.clone())),
            false,
        )
        .await;
        self.queue_vote_facts(&proof.finality_cert.prevote_vote());
        self.queue_vote_facts(&proof.finality_cert.precommit_vote());
        self.start_evidence_jobs();
    }
}
