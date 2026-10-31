//! Authenticated branch preparation behind advisory candidate discovery.

mod preparation;

use super::{
    ChainBackend, SyncBackendError, chunk_matches_context, not_available, rejected, storage_error,
};
use neutrin0_consensus_types::BftCandidate;
use neutrin0_network::{Topic, rpc::CandidateByChunkResponse};
use neutrin0_primitives::{ChunkId, Hash, blake3_256};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(super) async fn p2p_bft_candidate(
        &self,
        id: ChunkId,
        hash: Option<Hash>,
    ) -> Result<CandidateByChunkResponse, SyncBackendError> {
        if self.is_light() || self.bootstrap_pending() || self.block_program().is_none() {
            return Err(SyncBackendError::NotAvailable(
                "candidate unavailable".into(),
            ));
        }
        let slot = std::sync::Arc::clone(&self.candidate_slot)
            .acquire_owned()
            .await
            .expect("candidate slot remains open");
        let engine = std::sync::Arc::clone(&self.engine);
        let prover = std::sync::Arc::clone(&self.proof_system);
        let candidate = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            let preparation::CandidateInputs {
                pending,
                candidate,
                certified,
            } = {
                let engine = engine.lock().expect("engine mutex poisoned");
                preparation::capture(&engine, id, hash)?
            };
            let mut prepared = pending
                .prepare::<P, DB::Error>(prover.as_ref())
                .map_err(not_available)?;
            if let Some(certified) = certified {
                engine
                    .lock()
                    .expect("engine mutex poisoned")
                    .install_finality_certificate(&mut prepared, certified.finality_cert.clone())
                    .map_err(not_available)?;
                if prepared.witness != certified {
                    return Err(rejected("certified candidate changed"));
                }
            }
            let chunk =
                neutrin0_prover_chunk::consensus::as_chunk(&prepared.candidate.execution.chunk);
            if candidate
                .as_ref()
                .is_some_and(|candidate| candidate.chunk != chunk)
            {
                return Err(rejected("cached candidate changed"));
            }
            if hash.is_some_and(|hash| chunk.hash() != hash) {
                return Err(not_available("exact candidate is unavailable"));
            }
            Ok(candidate.unwrap_or(BftCandidate {
                chunk,
                round: 0,
                justification: None,
                selection: None,
            }))
        })
        .await
        .map_err(|error| not_available(format!("candidate worker failed: {error}")))??;
        Self::ensure_candidate_transmittable(&candidate)?;
        Ok(CandidateByChunkResponse { candidate })
    }

    fn ensure_candidate_transmittable(candidate: &BftCandidate) -> Result<(), SyncBackendError> {
        if candidate.justification.as_ref().is_some_and(|qc| {
            qc.aggregate.aggregation_bits.bit_len()
                > neutrin0_consensus_types::candidate::MAX_CANDIDATE_SIGNERS
        }) {
            return Err(SyncBackendError::NotAvailable(
                "candidate validator bitmap exceeds transport cap".into(),
            ));
        }
        if borsh::object_length(candidate).map_err(storage_error)?
            > Topic::BftCandidates.max_transmit_size()
        {
            return Err(SyncBackendError::NotAvailable(
                "candidate exceeds transport cap".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn authenticated_bft_candidate_hint(&self, candidate: &BftCandidate) -> bool {
        if self.is_light() || self.bootstrap_pending() {
            return false;
        }
        self.with_engine(|engine| {
            if candidate.chunk.chunk_id > engine.finalized_next_chunk_id() {
                return false;
            }
            let params = &engine.chain_spec().consensus;
            let Ok((context, _, _)) = engine.consensus_boundary(candidate.chunk.chunk_id) else {
                return false;
            };
            if !chunk_matches_context(&candidate.chunk, &context, params.chunk_size) {
                return false;
            }
            // A justification certifies the chunk with one payment selection,
            // which the hint carries for a leader to re-propose (design 08).
            let selection = match (&candidate.justification, &candidate.selection) {
                (None, None) => [0; 32],
                (Some(qc), Some(selection)) if selection.commitment() == qc.data.selection => {
                    qc.data.selection
                }
                _ => return false,
            };
            let vote = neutrin0_consensus_types::FinalityVoteData {
                chunk_id: candidate.chunk.chunk_id,
                chunk_hash: candidate.chunk.hash(),
                selection,
                round: candidate.round,
                phase: neutrin0_consensus_types::FinalityVotePhase::Prevote,
            };
            candidate.justification.as_ref().is_none_or(|qc| {
                neutrin0_prover_chunk::slashing::verify_unlock_quorum(
                    engine.chain_spec().consensus_domain(),
                    &context.active_validators,
                    &vote,
                    qc,
                    params,
                )
                .is_ok()
            })
        })
    }

    pub(super) fn authenticated_missing_bft_candidate(
        &self,
        vote: &neutrin0_consensus_types::FinalityVote,
    ) -> bool {
        if self.is_light() || self.bootstrap_pending() {
            return false;
        }
        self.with_engine(|engine| {
            let validators = engine.active_validator_set();
            let params = &engine.chain_spec().consensus;
            if vote.data.chunk_id != engine.finalized_next_chunk_id()
                || usize::try_from(vote.aggregation_bits.bit_len()).ok() != Some(validators.len())
                || engine
                    .bft_session(vote.data.chunk_id)
                    .is_some_and(|session| session.chunk_hash() == vote.data.chunk_hash)
                || !neutrin0_consensus_types::attestation_coverage_valid(
                    &vote.data,
                    &vote.aggregation_bits,
                    &vote.attestations,
                    params.chunk_size,
                )
            {
                return false;
            }
            neutrin0_prover_chunk::finality::verify_vote(
                engine.chain_spec().consensus_domain(),
                validators,
                vote,
                params,
            )
            .is_ok()
        })
    }

    pub(super) async fn consider_downloaded_bft_candidate(
        &self,
        candidate: &BftCandidate,
    ) -> Result<(), SyncBackendError> {
        if self.is_light() || self.block_program().is_none() {
            return Err(SyncBackendError::NotAvailable(
                "complete consensus backend unavailable".into(),
            ));
        }
        let now = crate::now_secs();
        if !self.authenticated_bft_candidate_hint(candidate) {
            return Err(SyncBackendError::Rejected(
                "candidate hint is not bound to the current context".into(),
            ));
        }
        let actions = self.offer_ready_bft_candidate(candidate, now)?;
        self.handle_bft_actions(actions).await;
        self.retry_deferred_bft_votes().await;
        Ok(())
    }

    fn offer_ready_bft_candidate(
        &self,
        candidate: &BftCandidate,
        now: u64,
    ) -> Result<Vec<neutrin0_consensus_engine::BftAction>, SyncBackendError> {
        self.with_live_engine_mut(|engine| {
            // Backfill authenticates and caches an available branch. Only a
            // signed leader proposal or pacemaker quorum authorizes progression.
            engine
                .offer_bft_candidate(candidate, now, self.proof_system.as_ref())
                .map_err(rejected)
        })
    }

    pub(super) async fn publish_bft_candidate(&self) {
        if self.publisher_snapshot().is_none() {
            return;
        }
        let id = self.with_engine(neutrin0_consensus_engine::Engine::finalized_next_chunk_id);
        // The first publication authenticates the branch. Avoid preparing the
        // same immutable candidate again for every subsequent vote action.
        let known_hash = self.with_engine(|engine| {
            engine
                .bft_candidate(id)
                .and_then(|candidate| borsh::to_vec(&candidate).ok())
                .map(|data| blake3_256(&data))
        });
        if known_hash.is_some()
            && known_hash
                == *self
                    .last_candidate_notice
                    .lock()
                    .expect("candidate notice mutex")
        {
            return;
        }
        let Ok(response) = self.p2p_bft_candidate(id, None).await else {
            return;
        };
        let Ok(data) = borsh::to_vec(&response.candidate) else {
            return;
        };
        let hash = blake3_256(&data);
        if *self
            .last_candidate_notice
            .lock()
            .expect("candidate notice mutex")
            == Some(hash)
        {
            return;
        }
        if self.publish_encoded(Topic::BftCandidates, data).await {
            *self
                .last_candidate_notice
                .lock()
                .expect("candidate notice mutex") = Some(hash);
        }
    }
}
