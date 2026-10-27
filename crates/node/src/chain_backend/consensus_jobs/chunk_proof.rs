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
    programs: GuestPrograms,
    budget: Arc<ProvingBudget>,
    engine: Arc<Mutex<Engine<DB>>>,
    metrics: Arc<NodeMetrics>,
    pending: BacklogGuard,
    prepared: PreparedConsensusChunk<P>,
    chunk_prover: Hash,
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
            programs,
            budget,
            engine,
            metrics,
            pending,
            prepared,
            chunk_prover,
        } = self;
        let _program_lease = budget.setup(|| prover.lease_programs(&programs))?;
        drop(pending);
        let permit = budget
            .request(ProofStage::Chunk)
            .wait_if(|| {
                engine
                    .lock()
                    .expect("engine mutex poisoned")
                    .execution_quorum_identity(identity.chunk_id)
                    == Some(identity)
            })
            .ok_or(ProofError::InvalidWitness)?;
        if engine
            .lock()
            .expect("engine mutex poisoned")
            .execution_quorum_identity(identity.chunk_id)
            != Some(identity)
        {
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

    /// The certified witness, its block and ratified chunk proofs, and the
    /// account the chunk proof credits, while `identity` is still current.
    fn prepare_consensus_proof(
        &self,
        identity: BftQuorumIdentity,
    ) -> Result<(PreparedConsensusChunk<P>, Hash), SyncBackendError> {
        self.with_live_engine_mut(|engine| {
            if engine.execution_quorum_identity(identity.chunk_id) != Some(identity) {
                return Err(SyncBackendError::NotAvailable(
                    "BFT quorum changed before preparation".into(),
                ));
            }
            let prepared = engine
                .prepare_certified_execution(self.proof_system.as_ref())
                .map_err(rejected)?;
            // Design 08: the Guest verifies the ratified chunk proof, so only a
            // node holding it can prove; the proof is fetched by statement key.
            if let Some((chunk_id, statement_key)) = prepared.missing_ratified_proof() {
                return Err(SyncBackendError::NotAvailable(format!(
                    "ratified chunk proof {statement_key:?} of chunk {chunk_id} is not held"
                )));
            }
            if engine.execution_quorum_identity(identity.chunk_id) != Some(identity) {
                return Err(SyncBackendError::NotAvailable(
                    "BFT quorum changed before launch".into(),
                ));
            }
            // Design 08: the chunk proof credits this node's prover account.
            let chunk_prover = engine.prover_address().map_err(not_available)?;
            Ok((prepared, chunk_prover))
        })
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
        let (prepared, chunk_prover) = match self.prepare_consensus_proof(identity) {
            Ok(prepared) => prepared,
            Err(error) => {
                warn!(?identity, %error, "complete chunk preparation failed");
                return;
            }
        };
        let notify = Arc::clone(&self.consensus_proof_notify);
        let job = ConsensusProofJob {
            identity,
            prover: Arc::clone(&self.proof_system),
            programs: GuestPrograms {
                execution: prepared.witness.context.programs.execution,
                chunk: prepared.witness.chain_spec.genesis_chunk,
            },
            budget: Arc::clone(&self.proving_budget),
            engine: Arc::clone(&self.engine),
            metrics: Arc::clone(&self.metrics),
            pending: self
                .metrics
                .proof_pipeline
                .chunk_backlog
                .track(prepared.witness.blocks.len()),
            prepared,
            chunk_prover,
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
                self.handle_quorum_reached(ready);
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
            self.handle_quorum_reached(ready);
        }
    }
}
