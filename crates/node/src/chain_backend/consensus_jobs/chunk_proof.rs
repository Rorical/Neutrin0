//! The complete chunk proof job: preparation under the quorum fence, the
//! blocking prover run and the commit or alternative retention of its result.

use std::sync::{Arc, Mutex};

use neutrin0_consensus_engine::{BftQuorumIdentity, Engine, full_chunk::PreparedConsensusChunk};
use neutrin0_consensus_types::history_proof::GuestPrograms;
use neutrin0_network::Topic;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_prover_chunk::consensus::ConsensusWitness;
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;
use tokio::sync::oneshot;
use tracing::warn;

use super::super::{ChainBackend, not_available, rejected};
use crate::metrics::NodeMetrics;
use crate::proof_metrics::{BacklogGuard, ProofStage};
use crate::proving_budget::ProvingBudget;

/// Everything one complete chunk proof needs on its blocking thread.
struct ConsensusProofJob<DB: Database, P: ProofSystem> {
    identity: BftQuorumIdentity,
    prover: Arc<P>,
    budget: Arc<ProvingBudget>,
    engine: Arc<Mutex<Engine<DB>>>,
    bootstrap: Arc<Mutex<Option<super::super::bootstrap::BootstrapRuntime>>>,
    metrics: Arc<NodeMetrics>,
    pending: BacklogGuard,
}

impl<DB, P> ConsensusProofJob<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Prove once the budget admits the job, unless the quorum changed meanwhile.
    fn prove(self) -> Result<(ConsensusWitness, P::ChunkProof), ProofError> {
        let Self {
            identity,
            prover,
            budget,
            engine,
            bootstrap,
            metrics,
            pending,
        } = self;
        let (prepared, chunk_prover) =
            prepare_consensus_proof(&engine, &bootstrap, prover.as_ref(), identity).map_err(
                |error| {
                    warn!(?identity, %error, "complete chunk preparation failed");
                    ProofError::InvalidWitness
                },
            )?;
        let programs = GuestPrograms {
            execution: prepared.witness.context.programs.execution,
            chunk: prepared.witness.chain_spec.genesis_chunk,
        };
        let _program_lease = budget.setup(|| prover.lease_programs(&programs))?;
        drop(pending);
        let permit = budget
            .request(ProofStage::Chunk)
            .wait_if(|| {
                let engine = engine.lock().expect("engine mutex poisoned");
                !super::super::bootstrap::pending(&bootstrap)
                    && engine.execution_quorum_identity(identity.chunk_id) == Some(identity)
            })
            .ok_or(ProofError::InvalidWitness)?;
        let live = {
            let engine = engine.lock().expect("engine mutex poisoned");
            !super::super::bootstrap::pending(&bootstrap)
                && engine.execution_quorum_identity(identity.chunk_id) == Some(identity)
        };
        if !live {
            return Err(ProofError::InvalidWitness);
        }
        let proof = permit.run(|| {
            metrics.proof_stage(ProofStage::Chunk).time(|| {
                prover.prove_consensus_chunk(
                    &prepared.proofs,
                    &prepared.ratified,
                    &prepared.witness,
                    chunk_prover,
                )
            })
        });
        if proof.is_ok()
            && let Some((covered, total)) = prover.last_chunk_fact_coverage()
        {
            metrics.proof_pipeline.set_fact_coverage(covered, total);
        }
        Ok((prepared.witness, proof?))
    }
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Retain this node's proof of an already finalized chunk as an
    /// alternative for ratification and return its artifact for publication
    /// (design 08). Only a proof of the finalized certificate qualifies.
    fn alternative_chunk_proof(
        &self,
        chunk_id: neutrin0_primitives::ChunkId,
        witness: &neutrin0_prover_chunk::consensus::ConsensusWitness,
        proof: &P::ChunkProof,
    ) -> Option<neutrin0_consensus_types::ChunkProof> {
        self.with_live_engine_mut(|engine| {
            let Some(stored) = engine.store().get_chunk_proof(chunk_id).map_err(rejected)? else {
                return Ok(None);
            };
            if stored.finality_cert != witness.finality_cert {
                return Ok(None);
            }
            let wire = neutrin0_consensus_types::ChunkProof {
                prover_address: self
                    .proof_system
                    .chunk_prover_address(proof)
                    .map_err(rejected)?,
                proof_bytes: borsh::to_vec(proof).map_err(rejected)?,
                ..stored
            };
            let retained = engine
                .import_alternative_chunk_proof(&wire, self.proof_system.as_ref())
                .map_err(rejected)?;
            Ok(retained.then_some(wire))
        })
        .ok()
        .flatten()
    }

    pub(super) fn start_consensus_proof(&self, identity: BftQuorumIdentity) {
        let mut running = self
            .consensus_proof_task
            .lock()
            .expect("proof task mutex poisoned");
        if running.is_some() {
            self.metrics
                .proof_pipeline
                .chunk_busy
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        let notify = Arc::clone(&self.consensus_proof_notify);
        let job = ConsensusProofJob {
            identity,
            prover: Arc::clone(&self.proof_system),
            budget: Arc::clone(&self.proving_budget),
            engine: Arc::clone(&self.engine),
            bootstrap: Arc::clone(&self.bootstrap),
            metrics: Arc::clone(&self.metrics),
            pending: self
                .metrics
                .proof_pipeline
                .chunk_backlog
                .track(usize::try_from(self.chunk_size()).unwrap_or(usize::MAX)),
        };
        let (tx, rx) = oneshot::channel();
        self.spawn_supervised("consensus-proof", false, async move {
            let result = tokio::task::spawn_blocking(move || job.prove())
                .await
                .unwrap_or_else(|error| {
                    if error.is_panic() {
                        std::panic::resume_unwind(error.into_panic());
                    }
                    Err(ProofError::InvalidWitness)
                });
            let _ = tx.send(result);
            notify.notify_one();
        });
        *running = Some((identity, rx));
    }

    pub(super) async fn drain_completed_consensus_proof(&self) {
        let completed = {
            let mut running = self
                .consensus_proof_task
                .lock()
                .expect("proof task mutex poisoned");
            let Some((identity, task)) = running.as_mut() else {
                return;
            };
            let result = match task.try_recv() {
                Ok(result) => result,
                Err(oneshot::error::TryRecvError::Empty) => return,
                Err(oneshot::error::TryRecvError::Closed) => Err(ProofError::InvalidWitness),
            };
            let identity = *identity;
            running.take();
            drop(running);
            (identity, result)
        };
        let (identity, result) = completed;
        let stale = self.with_engine(|engine| {
            engine.execution_quorum_identity(identity.chunk_id) != Some(identity)
        });
        if stale {
            // A proof that lost the race to finality still competes for
            // ratification (design 08): retain and publish it as an alternative.
            if let Ok((witness, proof)) = &result
                && let Some(alternative) =
                    self.alternative_chunk_proof(identity.chunk_id, witness, proof)
            {
                self.publish(Topic::ChunkProofs, &alternative).await;
            }
            if let Some(ready) = self.ready_consensus_quorum() {
                self.handle_quorum_reached(ready).await;
            }
            return;
        }
        let (witness, proof) = match result {
            Ok(result) => result,
            Err(error) => {
                warn!(?identity, %error, "complete chunk proving failed; finality not persisted");
                return;
            }
        };
        let executor = self.replay_executor_snapshot();
        let outcome = self.with_live_engine_mut(|engine| {
            if engine.execution_quorum_identity(identity.chunk_id) != Some(identity) {
                return Err(SyncBackendError::NotAvailable(
                    "BFT quorum changed before commit".into(),
                ));
            }
            let outcome = engine
                .commit_bft_consensus_chunk(
                    &witness,
                    &proof,
                    self.proof_system.as_ref(),
                    executor.as_deref(),
                )
                .map_err(rejected)?;
            self.record_finalized_execution(engine, identity.chunk_id);
            Ok(outcome)
        });
        match outcome {
            Ok(outcome) => {
                // Evidence scheduling refreshes reporter retention first.
                self.start_evidence_jobs();
                self.advance_history();
                self.publish(Topic::ChunkProofs, &outcome.chunk_proof).await;
                self.resume_proven_successor().await;
                self.submit_execution_claims().await;
            }
            Err(error) => warn!(?identity, %error, "complete chunk commit rejected"),
        }
        // A stale completion must not strand a newer quorum behind the old worker.
        if let Some(ready) = self.ready_consensus_quorum() {
            self.handle_quorum_reached(ready).await;
        }
    }
}

/// Gather the durable certified value briefly, then reconstruct and verify its
/// receipts outside the engine lock. Equality binds reuse to the exact witness
/// already authenticated at certification (or during restart recovery).
fn prepare_consensus_proof<DB, P>(
    engine: &Arc<Mutex<Engine<DB>>>,
    bootstrap: &Mutex<Option<super::super::bootstrap::BootstrapRuntime>>,
    prover: &P,
    identity: BftQuorumIdentity,
) -> Result<(PreparedConsensusChunk<P>, Hash), SyncBackendError>
where
    DB: Database,
    DB::Error: core::fmt::Debug + core::fmt::Display,
    P: ProofSystem,
{
    let (pending, certified, chunk_prover) = {
        let engine = engine.lock().expect("engine mutex poisoned");
        if super::super::bootstrap::pending(bootstrap)
            || engine.execution_quorum_identity(identity.chunk_id) != Some(identity)
        {
            return Err(SyncBackendError::NotAvailable(
                "BFT quorum changed before preparation".into(),
            ));
        }
        let certified = engine
            .certified_execution_witness()
            .cloned()
            .ok_or_else(|| {
                SyncBackendError::NotAvailable("certified execution unavailable".into())
            })?;
        let pending = engine
            .pending_consensus_chunk(
                identity.chunk_id,
                certified.finality_cert.proposal.chunk.end_block_hash,
                Some(&certified.finality_cert.proposal.receipt_keys()),
            )
            .map_err(rejected)?;
        (
            pending,
            certified,
            engine.prover_address().map_err(not_available)?,
        )
    };
    let mut prepared = pending.prepare::<P, DB::Error>(prover).map_err(rejected)?;
    {
        let engine = engine.lock().expect("engine mutex poisoned");
        if super::super::bootstrap::pending(bootstrap)
            || engine.execution_quorum_identity(identity.chunk_id) != Some(identity)
            || engine.certified_execution_witness() != Some(&certified)
        {
            return Err(SyncBackendError::NotAvailable(
                "BFT quorum changed before launch".into(),
            ));
        }
        engine
            .install_finality_certificate(&mut prepared, certified.finality_cert.clone())
            .map_err(rejected)?;
    }
    if prepared.witness != certified {
        return Err(SyncBackendError::Rejected(
            "certified witness changed during preparation".into(),
        ));
    }
    if let Some((chunk_id, statement_key)) = prepared.missing_ratified_proof() {
        return Err(SyncBackendError::NotAvailable(format!(
            "ratified chunk proof {statement_key:?} of chunk {chunk_id} is not held"
        )));
    }
    Ok((prepared, chunk_prover))
}
