//! Intake of raw slashing reports: local detections and peer gossip are
//! authenticated, pooled once and, for non-reporters, relayed.

use neutrin0_consensus_engine::RetentionPolicy;
use neutrin0_consensus_types::{FinalityVote, SlashingEvidence};
use neutrin0_network::Topic;
use neutrin0_primitives::blake3_256;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::{Batch, Column, Database};
use neutrin0_sync::SyncBackendError;
use tracing::{trace, warn};

use super::raw_pool::{accused_identity, raw_report_admissible};
use super::{
    ChainBackend, EvidenceDisposition, availability, rejected, reporter_retention, storage_error,
};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// What remains to do with submitted `evidence`. Only positive
    /// determinations end it: the persistent pool holds it, or a successful
    /// read shows this node can never pool it. Anything undetermined, such as
    /// a pending bootstrap, an unresolved offender or a storage error, is
    /// retried.
    pub(super) fn evidence_disposition(&self, evidence: &SlashingEvidence) -> EvidenceDisposition {
        let Ok(bytes) = borsh::to_vec(evidence) else {
            return EvidenceDisposition::Retry;
        };
        let key = blake3_256(&bytes);
        self.with_raw_pool(|pool, engine| {
            if pool.seen.contains(&key) {
                return EvidenceDisposition::Held;
            }
            if self.bootstrap_pending() {
                return EvidenceDisposition::Retry;
            }
            let Some(accused) = accused_identity(engine, evidence) else {
                // Only a reporter refuses an unresolved offender; any other
                // role pools it, so a failure there was transient. A reporter's
                // refusal is permanent once the chunk's record is gone for
                // good: finalized, outside the retained record window and read
                // as absent.
                let pruned = reporter_retention(engine)
                    && neutrin0_prover_chunk::history::evidence_chunk_id(
                        engine.chain_spec(),
                        evidence,
                    )
                    .is_ok_and(|source| {
                        source < engine.finalized_next_chunk_id()
                            && !engine.in_history_record_window(source)
                            && matches!(engine.store().historical_chunk(source), Ok(None))
                    });
                return if pruned {
                    EvidenceDisposition::Unpoolable
                } else {
                    EvidenceDisposition::Retry
                };
            };
            match engine.store().is_identity_slashed(&accused) {
                Ok(true) => return EvidenceDisposition::Unpoolable,
                Ok(false) => {}
                Err(_) => return EvidenceDisposition::Retry,
            }
            let Ok(retention) = engine.retention_info() else {
                return EvidenceDisposition::Retry;
            };
            if retention.policy == RetentionPolicy::Reporter {
                match engine.store().reporter_tracked_validators() {
                    Ok(tracked) if !tracked.iter().any(|(pubkey, _)| *pubkey == accused) => {
                        return EvidenceDisposition::Unpoolable;
                    }
                    Ok(_) => {}
                    Err(_) => return EvidenceDisposition::Retry,
                }
            }
            EvidenceDisposition::Retry
        })
    }

    /// Insert one evidence item into the in-memory pool and persist
    /// the change to [`Column::SlashingPool`]. Returns `true` if a
    /// new entry was added (i.e. the caller should gossip), `false`
    /// for duplicates / encoding failures.
    ///
    /// Holds the pool lock for the full pool+disk transaction so a
    /// concurrent `drain_slashing_pool` cannot observe a torn
    /// in-memory / on-disk state. Lock ordering is always
    /// `slashing_pool → engine` across the file, so this never
    /// deadlocks.
    pub(super) fn insert_persistent(&self, evidence: &SlashingEvidence) -> bool {
        let Ok(bytes) = borsh::to_vec(evidence) else {
            return false;
        };
        let key = blake3_256(&bytes);
        let installed = self.with_raw_pool(|pool, engine| {
            if pool.seen.contains(&key)
                || self.bootstrap_pending()
                || !raw_report_admissible(engine, evidence)
            {
                return None;
            }
            let accused = accused_identity(engine, evidence);
            if accused.is_some_and(|identity| pool.identity_full(&identity)) {
                return None;
            }
            let evicted = pool.eviction_candidate();
            let mut batch = Batch::new();
            batch.put(Column::SlashingPool, key, bytes);
            if let Some(oldest) = evicted {
                batch.delete(Column::SlashingPool, oldest);
            }
            match engine.store_mut().write_observed_batch(batch, true) {
                Ok(()) => {
                    pool.push_accusing(key, accused);
                    Some(evicted.is_some())
                }
                Err(error) => {
                    warn!(
                        ?error,
                        ?key,
                        "failed to persist slashing evidence; input remains eligible for retry"
                    );
                    None
                }
            }
        });
        let Some(evicted) = installed else {
            return false;
        };
        self.metrics
            .reporter
            .detected
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if evicted {
            self.metrics
                .reporter
                .pool_evictions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        true
    }

    /// Add an [`SlashingEvidence`] to the local pool and, when a
    /// network publisher is configured, gossip it on
    /// `Topic::SlashingEvidence`.
    ///
    /// Deduplicates by `blake3(borsh(evidence))` so two detection
    /// paths that produce the same canonical evidence only enqueue
    /// it once. Persists the new entry to [`Column::SlashingPool`]
    /// so it survives a node restart.
    pub(super) async fn pool_and_gossip_slashing(&self, evidence: SlashingEvidence) {
        if let SlashingEvidence::InvalidProofSigning { rejected_proof, .. } = &evidence
            && !matches!(
                self.signed_proof_verdict(rejected_proof).await,
                Some(availability::ProofVerdict::Rejected(_))
            )
        {
            return;
        }
        if !self.insert_persistent(&evidence) {
            return;
        }
        self.start_evidence_jobs();
        if self.reporter_recipient().is_some() {
            // The reporter advertises its completed proof with the reward
            // recipient already bound, while raw inputs remain durable for retry.
            return;
        }
        self.publish(Topic::SlashingEvidence, &evidence).await;
    }

    // Separate cryptographic source authentication from local replay eligibility;
    // already-finalized offences are neutral gossip, not signature failures.
    fn authenticate_slashing_gossip(
        &self,
        evidence: &SlashingEvidence,
        id: u64,
    ) -> Result<(), SyncBackendError> {
        self.with_engine(|engine| {
            if id < engine.finalized_next_chunk_id() {
                let source = engine.store().historical_chunk(id).map_err(storage_error)?
                    .ok_or_else(|| SyncBackendError::NotAvailable("evidence source unavailable".into()))?;
                // An old receipt is judged under the Block key its finalized
                // record binds, never one a later program switch installed.
                let (_, offence) = neutrin0_prover_chunk::history::authorize_evidence_at_record(engine.chain_spec(), &source, evidence, &source.block_guest_vk_digest)
                    .map_err(|error| SyncBackendError::Rejected(format!("invalid historical evidence: {error:?}")))?;
                if engine.store().is_offence_finalized(&offence).map_err(storage_error)? {
                    return Err(SyncBackendError::NotAvailable("offence already finalized".into()));
                }
                Ok(())
            } else {
                engine.verify_slashing_evidence(evidence).map_err(|error| match error {
                    neutrin0_consensus_engine::SlashingError::NotYetFinalizedLocally
                    | neutrin0_consensus_engine::SlashingError::SourceOutsideAccountabilityWindow => SyncBackendError::NotAvailable(error.to_string()),
                    other => rejected(other),
                })
            }
        })
    }

    /// Offences an authenticated value vote establishes. The observation
    /// mutates the engine, so it rechecks the bootstrap barrier under the
    /// engine lock: a vote that passed the optimistic entry check records
    /// nothing once checkpoint fetching has begun.
    pub(super) fn observe_value_vote_offences(&self, vote: &FinalityVote) -> Vec<SlashingEvidence> {
        self.with_live_engine_mut(|engine| {
            engine.observe_votes_for_slashing(vote).map_err(rejected)
        })
        .unwrap_or_default()
    }

    /// Pool peer-supplied slashing evidence after authenticating it.
    pub(super) async fn accept_slashing_evidence(
        &self,
        evidence: SlashingEvidence,
    ) -> Result<(), SyncBackendError> {
        if self.is_light() || self.bootstrap_pending() {
            return Err(SyncBackendError::NotAvailable(
                "evidence context unavailable".into(),
            ));
        }
        let id = self
            .with_engine(|engine| {
                neutrin0_prover_chunk::history::evidence_chunk_id(engine.chain_spec(), &evidence)
            })
            .map_err(|error| SyncBackendError::Rejected(format!("{error:?}")))?;
        let (next, source_known) = self.with_engine(|engine| {
            let next = engine.finalized_next_chunk_id();
            let known = id == next
                || (id < next && engine.store().historical_chunk(id).ok().flatten().is_some());
            (next, known)
        });
        if !source_known || (id < next && self.block_program().is_none()) {
            return Err(SyncBackendError::NotAvailable(
                "evidence source unavailable".into(),
            ));
        }
        // Verify the peer-supplied evidence cryptographically before
        // pooling it: a forged claim must not poison the pool that
        // the producer will later include in a block body. The
        // ingest path does *not* re-gossip — gossipsub handles
        // mesh-wide propagation and the equivocation detector already
        // gossipped locally-detected items via
        // `pool_and_gossip_slashing`.
        self.authenticate_slashing_gossip(&evidence, id)?;
        // InvalidProofSigning evidence carries the rejected proof
        // envelope so any replayer can independently re-run the
        // SP1 verifier. The engine's signature check passed; now
        // confirm the carried proof actually fails our backend's
        // `verify_block`. If it succeeds, the emitter was wrong
        // (or malicious) about the rejection — drop the evidence.
        if let SlashingEvidence::InvalidProofSigning { rejected_proof, .. } = &evidence {
            match self.signed_proof_verdict(rejected_proof).await {
                Some(availability::ProofVerdict::Rejected(_)) => {}
                Some(availability::ProofVerdict::Valid) => {
                    return Err(SyncBackendError::Rejected(
                        "claimed rejected proof is valid".into(),
                    ));
                }
                None => {
                    return Err(SyncBackendError::NotAvailable(
                        "objective proof verdict unavailable".into(),
                    ));
                }
            }
        }
        if !self.insert_persistent(&evidence) {
            return Err(SyncBackendError::NotAvailable(
                "evidence already handled or pool unavailable".into(),
            ));
        }
        self.start_evidence_jobs();
        trace!("pooled peer-supplied slashing evidence");
        Ok(())
    }
}
