//! Driving the chunk-BFT loop: the local voter, session opening, round
//! clocks, restored sessions and the broadcast of resulting actions.

use std::sync::Arc;

use neutrin0_consensus_engine::{BftAction, Engine, ProposerKey};
use neutrin0_consensus_types::FinalityVote;
use neutrin0_network::Topic;
use neutrin0_primitives::{ChunkId, Height};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;
use tracing::{debug, error, warn};

use super::{ChainBackend, rejected};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Install the local validator's BLS key used by the BFT loop to
    /// sign prevotes / precommits.
    ///
    /// Without a local key this backend follows the chain without signing
    /// or initiating BFT finalization.
    pub fn set_local_voter(&self, voter: ProposerKey) {
        self.with_engine_mut(|engine| engine.set_local_voter(voter));
    }

    /// Keep the validator's next key; a key rotation seats it in place of the
    /// local voter (design 19), and signing follows the seat.
    pub fn set_standby_voter(&self, voter: ProposerKey) {
        self.with_engine_mut(|engine| engine.set_standby_voter(voter));
    }

    /// Local validator key, if [`Self::set_local_voter`] has been called:
    /// the engine's, which follows a key rotation. Returned as an `Arc`
    /// snapshot so callers hold no lock. Never call it under the engine lock.
    #[must_use]
    pub fn local_voter(&self) -> Option<Arc<ProposerKey>> {
        self.with_engine(|engine| engine.local_voter().cloned().map(Arc::new))
    }

    /// Sign nothing for `chunks` chunks of slots from now (`[doppelganger]
    /// quiet_chunks`).
    pub fn set_doppelganger_quiet_chunks(&self, chunks: u64) {
        self.with_engine_mut(|engine| engine.set_doppelganger_quiet_chunks(chunks));
    }

    /// Log, once per detection, the message by the local key this node did
    /// not sign; the operator's resume clears the detection.
    fn report_doppelganger(&self) {
        let Some(seen) = self.with_engine(|engine| engine.doppelganger().cloned()) else {
            self.doppelganger_reported
                .store(false, std::sync::atomic::Ordering::Release);
            return;
        };
        if !self
            .doppelganger_reported
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            error!(
                identity = %hex::encode(seen.identity),
                seen = %seen.seen,
                "another process signs with the validator key: signing and production paused; stop it, then resume with `validator resume-signing` and `resume-production`"
            );
        }
    }

    /// If the chunk containing `height` now has every block proof in place, open a BFT
    /// session for it and broadcast any resulting actions.
    ///
    /// Called by every code path that imports or proves a block
    /// proof (local production, gossip imports, RPC batches). Cheap
    /// for incomplete chunks. Proofs may finish in any order.
    pub async fn maybe_open_bft_session_for_height(&self, height: Height) {
        if self.bootstrap_pending() {
            return;
        }
        let chunk_size = self.chunk_size().max(1);
        if height == 0 {
            return;
        }
        let chunk_id = (height - 1) / chunk_size;
        let already_finalised = self.with_engine(|e| {
            e.latest_finalized_chunk_id()
                .is_some_and(|latest| latest >= chunk_id)
        });
        if already_finalised {
            return;
        }
        if self.with_engine(|e| e.bft_session(chunk_id).is_some()) {
            return;
        }
        let assembled = if self.block_program().is_some() {
            self.with_engine(|e| {
                let prepared =
                    e.prepare_bft_consensus_chunk(chunk_id, self.proof_system.as_ref())?;
                Ok(Some(neutrin0_prover_chunk::consensus::as_chunk(
                    &prepared.candidate.execution.chunk,
                )))
            })
        } else {
            self.with_engine(|e| e.assemble_chunk(chunk_id))
        };
        let chunk = match assembled {
            Ok(Some(chunk)) => chunk,
            Ok(None) => return,
            Err(err) => {
                debug!(chunk_id, ?err, "assemble_chunk for BFT session failed");
                return;
            }
        };
        // Design 08: a local session opens once every height has a receipt the
        // selection rules allow at this slot; a peer's proposal opens one earlier.
        match self.with_engine(|e| e.chunk_proposable(&chunk)) {
            Ok(true) => {}
            Ok(false) => return,
            Err(err) => {
                debug!(chunk_id, ?err, "receipt selection for BFT session failed");
                return;
            }
        }
        let now_secs = crate::now_secs();
        // Wall-clock bounds of the chunk's last slot, for certificate lag metrics.
        let tail_slot = self.with_engine(|e| {
            let header = e
                .store()
                .get_header_by_height(chunk.end_height)
                .ok()
                .flatten()?;
            let spec = e.chain_spec();
            let slot_secs = spec.consensus.slot_duration_secs;
            let start = spec
                .genesis_time
                .checked_add(header.slot.checked_mul(slot_secs)?)?;
            Some((start, start.checked_add(slot_secs)?))
        });
        let actions = match self
            .with_live_engine_mut(|e| e.open_bft_session_at(chunk, now_secs).map_err(rejected))
        {
            Ok(actions) => actions,
            Err(err) => {
                debug!(chunk_id, ?err, "open_bft_session failed");
                return;
            }
        };
        self.metrics.execution.opened(chunk_id, tail_slot);
        self.project_successor();
        self.handle_bft_actions(actions).await;
        self.retry_deferred_bft_votes().await;
    }

    /// Retry opening the next chunk's session on a slot tick: a block whose
    /// proposer never proved it becomes selectable only when its exclusive
    /// window ends, which no proof completion announces (design 08).
    pub async fn maybe_open_next_bft_session(&self) {
        let Some(height) = self.with_engine(|e| {
            let chunk_id = e.finalized_next_chunk_id();
            if e.bft_session(chunk_id).is_some() {
                return None;
            }
            e.chunk_heights(chunk_id).map(|(_, end)| end)
        }) else {
            // The session exists: keep its successor projected (design 08).
            self.project_successor();
            return;
        };
        self.maybe_open_bft_session_for_height(height).await;
    }

    /// Project the successor of the open session's proven candidate so the
    /// next chunk can be produced before the certificate (design 08).
    fn project_successor(&self) {
        if self.block_program().is_none() {
            return;
        }
        match self.with_live_engine_mut(|engine| {
            engine
                .project_successor_execution(self.proof_system.as_ref())
                .map_err(rejected)
        }) {
            Ok(true) => debug!("projected the successor boundary from the proven candidate"),
            Ok(false) => {}
            Err(error) => debug!(%error, "successor projection unavailable"),
        }
    }

    // Restored FSM flags cannot authorize new signatures under the current program.
    // The engine validates each exact session value once per program set and
    // boundary; later ticks and votes reuse that verdict.
    pub(super) fn validate_bft_signing_candidate(
        &self,
        engine: &mut Engine<DB>,
        chunk_id: ChunkId,
    ) -> Result<(), SyncBackendError> {
        if engine.local_voter().is_none() || self.block_program().is_none() {
            return Ok(());
        }
        engine
            .validate_bft_signing(chunk_id, self.proof_system.as_ref())
            .map_err(rejected)
    }

    /// Validate chunk `chunk_id`'s open value before taking the engine lock to
    /// sign: only gathering its witness holds the lock. The signing path
    /// rechecks the recorded verdict under the lock and validates there only
    /// if the value changed in between.
    pub(super) fn prevalidate_bft_signing_candidate(&self, chunk_id: ChunkId) {
        if self.local_voter().is_none() || self.block_program().is_none() {
            return;
        }
        let pending = match self
            .with_engine(|engine| engine.pending_bft_signing(chunk_id, self.proof_system.as_ref()))
        {
            Ok(Some(pending)) => pending,
            Ok(None) => return,
            Err(error) => {
                debug!(chunk_id, ?error, "BFT value inputs unavailable");
                return;
            }
        };
        match pending.validate() {
            Ok(validated) => self.with_engine_mut(|engine| engine.record_bft_signing(validated)),
            Err(error) => debug!(chunk_id, ?error, "BFT value failed validation"),
        }
    }

    /// Authenticate restored signing work and rebroadcast its original messages.
    /// Call after installing the publisher and the local validator identity.
    pub async fn resume_bft_sessions(&self) -> Result<(), String> {
        if self.bootstrap_pending() {
            return Ok(());
        }
        self.replay_signed_artifact_accountability().await;
        let actions = self
            .with_live_engine_mut(|engine| {
                let chunk_id = engine.finalized_next_chunk_id();
                // A value this node cannot validate yet (its receipts may still
                // be arriving) waits for the round clock, which validates
                // before every signature; it never stops the node.
                if let Err(error) = self.validate_bft_signing_candidate(engine, chunk_id) {
                    warn!(chunk_id, ?error, "restored BFT value is not signable yet");
                    return Ok(Vec::new());
                }
                engine.resume_bft_actions().map_err(rejected)
            })
            .map_err(|error| error.to_string())?;
        self.handle_bft_actions(actions).await;
        self.retry_deferred_bft_votes().await;
        Ok(())
    }

    /// Drain a batch of [`BftAction`]s into network publishes and
    /// chunk-finalisation triggers.
    pub(super) async fn handle_bft_actions(&self, actions: Vec<BftAction>) {
        for action in actions {
            self.metrics.execution.action(&action);
            match action {
                BftAction::BroadcastPrevote(vote) => {
                    self.publish_finality_vote(Topic::FinalityVotesPrevote, &vote)
                        .await;
                }
                BftAction::BroadcastPrecommit(vote) => {
                    self.publish_finality_vote(Topic::FinalityVotesPrecommit, &vote)
                        .await;
                }
                BftAction::PublishAggregatePrevote { subnet, vote }
                | BftAction::PublishAggregatePrecommit { subnet, vote } => {
                    self.publish_finality_vote(Topic::AggregateFinalityVotes(subnet), &vote)
                        .await;
                }
                BftAction::QuorumReached(identity) => {
                    self.handle_quorum_reached(identity);
                }
                BftAction::BroadcastProposal(proposal) => {
                    self.publish_bft_message(&neutrin0_consensus_types::BftMessage::Proposal(
                        proposal,
                    ))
                    .await;
                }
                BftAction::BroadcastNilVote(vote) => {
                    self.publish_bft_message(&neutrin0_consensus_types::BftMessage::Vote(
                        neutrin0_consensus_types::BftVote::Nil(vote),
                    ))
                    .await;
                }
                BftAction::BroadcastRoundChange(report) => {
                    self.publish_bft_message(&neutrin0_consensus_types::BftMessage::RoundChange(
                        report,
                    ))
                    .await;
                }
                BftAction::BroadcastRoundChangeCertificate(certificate) => {
                    self.publish_bft_message(
                        &neutrin0_consensus_types::BftMessage::RoundChangeCertificate(certificate),
                    )
                    .await;
                }
            }
        }
        self.publish_bft_candidate().await;
    }

    async fn publish_finality_vote(&self, topic: Topic, vote: &FinalityVote) {
        if !self.ensure_publishable_vote_sources(vote) {
            return;
        }
        if !self.retain_availability_vote(vote).await {
            return;
        }
        self.queue_vote_facts(vote);
        let message = neutrin0_consensus_types::BftVote::Value(vote.clone());
        self.publish(topic, &message).await;
    }

    /// Tick open sessions' phase deadlines and publish resulting nil votes,
    /// certified round-entry messages or retransmissions.
    ///
    /// `now_secs` is the current wall-clock Unix-second timestamp.
    /// Each phase uses the chain-spec `bft_round_timeout_base_secs + round * step`
    /// budget. A local timeout can select nil or request the next round;
    /// entering that round requires an authenticated round-change certificate.
    ///
    /// The validator's independent BFT clock invokes this once per second,
    /// so production slots and prover completion cannot suppress deadlines.
    /// Tests can pass a deterministic `now_secs` to drive scenarios.
    pub async fn tick_bft_round_timeouts(&self, now_secs: u64) {
        self.report_doppelganger();
        if self.bootstrap_pending() {
            return;
        }
        if let Some(identity) = self.ready_consensus_quorum() {
            self.handle_quorum_reached(identity);
        }
        self.prevalidate_bft_signing_candidate(self.with_engine(Engine::finalized_next_chunk_id));
        let actions = match self.with_live_engine_mut(|engine| {
            let chunk_id = engine.finalized_next_chunk_id();
            self.validate_bft_signing_candidate(engine, chunk_id)?;
            engine.tick_bft_round_timeouts(now_secs).map_err(rejected)
        }) {
            Ok(actions) => actions,
            Err(err) => {
                debug!(?err, "tick_bft_round_timeouts failed");
                return;
            }
        };
        self.metrics.execution.timeout_actions(actions.len());
        if !actions.is_empty() {
            self.handle_bft_actions(actions).await;
            self.retry_deferred_bft_votes().await;
        }
    }
}
