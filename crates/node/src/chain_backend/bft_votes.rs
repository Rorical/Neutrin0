//! Intake of peer value votes into the open BFT session.

use neutrin0_consensus_engine::{BftAction, Engine};
use neutrin0_consensus_types::FinalityVote;
use neutrin0_primitives::ChunkId;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;
use tracing::{debug, trace};

use super::{ChainBackend, rejected};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    // Once this round's local precommit is durable, incoming votes cannot cause
    // another local signature. Recovery still reauthenticates the full branch
    // through validate_bft_signing_candidate under the running program.
    fn validate_live_vote_signing_candidate(
        &self,
        engine: &mut Engine<DB>,
        chunk_id: ChunkId,
    ) -> Result<(), SyncBackendError> {
        if engine
            .bft_session(chunk_id)
            .is_some_and(neutrin0_consensus_engine::BftSession::local_precommitted)
        {
            return Ok(());
        }
        self.validate_bft_signing_candidate(engine, chunk_id)
    }

    // Apply this only after objective attribution. A delayed or conflicting
    // signed vote can establish an offence without contributing to this session.
    pub(super) fn vote_matches_bft_session(&self, vote: &FinalityVote) -> bool {
        self.with_engine(|engine| {
            vote.data.chunk_id == engine.finalized_next_chunk_id()
                && engine
                    .bft_session(vote.data.chunk_id)
                    .is_some_and(|session| {
                        // The session holds a value vote that precedes the
                        // round's proposal and counts it only for the
                        // selection that proposal names (design 08).
                        session.round() == vote.data.round
                            && session.chunk_hash() == vote.data.chunk_hash
                    })
        })
    }

    /// Shared intake of partial (`subnet` is `None`) and aggregate value votes.
    /// Aggregates retain the same individual attestations and use the same
    /// authenticated accumulator as partial value votes; `subnet` only labels
    /// their trace and rejection logs.
    pub(super) async fn ingest_value_vote(
        &self,
        vote: FinalityVote,
        subnet: Option<u8>,
    ) -> Result<(), SyncBackendError> {
        self.ensure_value_vote_admissible(&vote)?;
        Self::trace_value_vote(&vote, subnet);
        self.observe_value_vote_sources(&vote).await;
        self.verify_live_value_vote(&vote)?;
        if !self.vote_matches_bft_session(&vote) {
            self.defer_bft_vote(vote);
            return Ok(());
        }
        let Some(actions) = self.observe_value_vote(&vote, subnet).await? else {
            self.defer_bft_vote(vote);
            return Ok(());
        };
        self.queue_vote_facts(&vote);
        self.handle_bft_actions(actions).await;
        Ok(())
    }

    /// Refuse a vote this node has no context for, or whose signatures fail.
    fn ensure_value_vote_admissible(&self, vote: &FinalityVote) -> Result<(), SyncBackendError> {
        if self.is_light() || self.bootstrap_pending() {
            return Err(SyncBackendError::NotAvailable(
                "vote context unavailable".into(),
            ));
        }
        if self.with_engine(|engine| {
            let count = engine.finalized_next_chunk_id();
            vote.data.chunk_id > count
                || (vote.data.chunk_id < count
                    && !neutrin0_consensus_types::history::is_recent_history_index(
                        vote.data.chunk_id,
                        count,
                    ))
        }) {
            return Err(SyncBackendError::NotAvailable(
                "vote context unavailable".into(),
            ));
        }
        if !self.availability_source_known(vote.data.chunk_id) {
            return Err(SyncBackendError::NotAvailable(
                "vote history unavailable".into(),
            ));
        }
        if !self.with_engine(|engine| {
            engine.validate_signed_artifact(
                &neutrin0_consensus_types::signed_artifacts::SignedArtifact::Vote(vote.clone()),
            )
        }) {
            return Err(SyncBackendError::Rejected(
                "invalid value vote signatures".into(),
            ));
        }
        Ok(())
    }

    fn trace_value_vote(vote: &FinalityVote, subnet: Option<u8>) {
        if let Some(subnet) = subnet {
            trace!(
                subnet,
                chunk_id = vote.data.chunk_id,
                round = vote.data.round,
                ?vote.data.phase,
                "received aggregate finality vote"
            );
        } else {
            trace!(
                chunk_id = vote.data.chunk_id,
                round = vote.data.round,
                ?vote.data.phase,
                "received finality vote"
            );
        }
    }

    /// Retain the vote's sources and pool the offences it establishes.
    async fn observe_value_vote_sources(&self, vote: &FinalityVote) {
        // Forensic-cache pressure cannot suppress independently verified live BFT.
        self.retain_availability_vote(vote).await;
        // Signed attestations preserve individual attribution through aggregation.
        for item in self.observe_value_vote_offences(vote) {
            self.pool_and_gossip_slashing(item).await;
        }
        // The mandatory precommit attestation binds exact proof envelopes.
        // Invalid-proof evidence retains the rejected original BlockProof so
        // the evidence path can independently confirm the objective rejection.
        let invalid_proof_evidence = self
            .with_engine(|e| e.observe_vote_for_invalid_proof_signing(vote))
            .unwrap_or_default();
        for evidence in invalid_proof_evidence {
            self.pool_and_gossip_slashing(evidence).await;
        }
    }

    fn verify_live_value_vote(&self, vote: &FinalityVote) -> Result<(), SyncBackendError> {
        // Attribution remains independent: a signed invalid unlock claim can
        // establish an offence even though live BFT policy refuses the vote.
        self.with_engine(|engine| {
            if vote.data.chunk_id == engine.finalized_next_chunk_id() {
                engine.verify_bft_value_vote(vote).map_err(rejected)
            } else {
                Ok(())
            }
        })?;
        Ok(())
    }

    /// Feed the vote to its session and collect the actions it triggers;
    /// `None` when the vote can count only once the round's proposal arrives.
    async fn observe_value_vote(
        &self,
        vote: &FinalityVote,
        subnet: Option<u8>,
    ) -> Result<Option<Vec<BftAction>>, SyncBackendError> {
        if !self.with_engine(|engine| {
            engine
                .bft_session(vote.data.chunk_id)
                .is_some_and(neutrin0_consensus_engine::BftSession::local_precommitted)
        }) {
            self.prevalidate_bft_signing_candidate(vote.data.chunk_id)
                .await;
        }
        self.with_live_engine_mut(|engine| {
            self.validate_live_vote_signing_candidate(engine, vote.data.chunk_id)?;
            match engine.observe_finality_vote_at(vote.clone(), crate::now_secs()) {
                Ok(actions) => Ok(Some(actions)),
                Err(err) if err.awaits_proposal() => Ok(None),
                Err(err) => Err(rejected(err)),
            }
        })
        .map_err(|err| {
            if subnet.is_some() {
                debug!(?err, "engine rejected aggregate finality vote");
            } else {
                debug!(?err, "engine rejected finality vote");
            }
            SyncBackendError::NotAvailable(err.to_string())
        })
    }
}
