//! Nil votes, round changes and phase deadlines: the pacemaker side of the
//! live protocol, where timeouts never bypass a retained lock.

use alloc::vec::Vec;
use neutrin0_consensus_chunk_bft::TimeoutAction;
use neutrin0_consensus_types::{
    FinalityVotePhase, NilVote, NilVoteData, RoundChange, RoundChangeCertificate,
};
use neutrin0_storage::Database;

use crate::bft_loop::{
    BftAction, BftLoopError, BftSession, LocalVoteProgress, PeerQuorumProgress, conflict,
};
use crate::{Engine, StoreError};

extern crate alloc;

impl<DB: Database> Engine<DB> {
    pub(super) fn sign_bft_nil(
        &mut self,
        session: &mut BftSession,
        phase: FinalityVotePhase,
        actions: &mut Vec<BftAction>,
    ) -> Result<(), BftLoopError<DB::Error>> {
        if match phase {
            FinalityVotePhase::Prevote => session.local_prevoted(),
            FinalityVotePhase::Precommit => session.local_precommitted(),
        } {
            return Ok(());
        }
        let Some(voter) = self.active_local_voter() else {
            return Ok(());
        };
        self.persist_bft_session(session)?;
        self.bft_sessions.insert(session.chunk_id, session.clone());
        let vote = self.sign_nil_vote_durable(
            &voter,
            NilVoteData {
                chunk_id: session.chunk_id,
                round: session.round(),
                phase,
            },
        )?;
        session.bft.add_nil_vote(vote.clone())?;
        session.record_local_signature(phase, *voter.public_key_bytes());
        session.local_nil_votes.push(vote.clone());
        actions.push(BftAction::BroadcastNilVote(vote));
        Ok(())
    }

    /// Record authenticated nil stake without treating it as a value or a lock.
    pub fn observe_nil_vote(
        &mut self,
        vote: NilVote,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let id = vote.data.chunk_id;
        let Some(mut session) = self.bft_sessions.get(&id).cloned() else {
            return Ok(Vec::new());
        };
        self.recover_session_signing(&mut session)?;
        if vote.data.round != session.round() || session.precommit_quorum_observed() {
            return Ok(Vec::new());
        }
        session.bft.add_nil_vote(vote)?;
        let mut actions = Vec::new();
        if session.bft.nil_quorum_reached(FinalityVotePhase::Prevote)
            && session.pacemaker.step() != neutrin0_consensus_chunk_bft::RoundStep::AwaitRound
        {
            session.pacemaker.enter_precommit(now_secs);
            self.sign_bft_nil(&mut session, FinalityVotePhase::Precommit, &mut actions)?;
        }
        if session.bft.nil_quorum_reached(FinalityVotePhase::Precommit) {
            actions.extend(self.request_bft_round_change(&mut session, now_secs)?);
        }
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(id, session);
        // Certified entry above may sign the new leader's proposal and votes.
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }

    fn request_bft_round_change(
        &mut self,
        session: &mut BftSession,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let next_round = session
            .round()
            .checked_add(1)
            .ok_or_else(|| StoreError::Corrupt("BFT round space exhausted"))?;
        session.pacemaker.enter_await_round(now_secs);
        // The phase closes durably before announcing departure; a nil quorum
        // cannot leave a restart able to sign fresh messages in the old phase.
        self.persist_bft_session(session)?;
        self.bft_sessions.insert(session.chunk_id, session.clone());
        let mut actions = Vec::new();
        if let Some(voter) = self.active_local_voter() {
            let report = if let Some(prior) = &session.local_round_report {
                prior.clone()
            } else if let Some(prior) =
                self.reserved_round_change(&voter, session.chunk_id, next_round)?
            {
                session.local_round_report = Some(prior.clone());
                prior
            } else {
                let report = self.sign_round_change_durable(
                    &voter,
                    RoundChange {
                        chunk_id: session.chunk_id,
                        round: next_round,
                        validator_index: voter.validator_index(),
                        highest_quorum: session
                            .valid_value
                            .as_ref()
                            .map(|(_, _, quorum)| quorum.clone()),
                        signature: [0; 96],
                    },
                )?;
                session.local_round_report = Some(report.clone());
                report
            };
            actions.push(BftAction::BroadcastRoundChange(report.clone()));
            if let Some(certificate) = session.pacemaker.accept_round_change(
                self.consensus_domain(),
                self.active_validator_set(),
                self.bft_prevote_quorum(),
                report,
            )? {
                actions.push(BftAction::BroadcastRoundChangeCertificate(
                    certificate.clone(),
                ));
                actions.extend(self.enter_bft_certified_round(
                    session,
                    certificate,
                    now_secs,
                    false,
                )?);
            }
        }
        Ok(actions)
    }

    /// Collect bounded, authenticated round reports. A peer report alone cannot
    /// erase a phase or precommit quorum; entry requires a stake certificate.
    pub fn observe_round_change(
        &mut self,
        report: RoundChange,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let id = report.chunk_id;
        let Some(mut session) = self.bft_sessions.get(&id).cloned() else {
            return Ok(Vec::new());
        };
        // A completed certificate may enter a round and sign; synchronize the
        // signing identity, retained lock and interrupted reservations first.
        self.recover_session_signing(&mut session)?;
        if session.precommit_quorum_observed() || report.round <= session.round() {
            return Ok(Vec::new());
        }
        let certificate = session.pacemaker.accept_round_change(
            self.consensus_domain(),
            self.active_validator_set(),
            self.bft_prevote_quorum(),
            report,
        )?;
        let mut actions = Vec::new();
        if let Some(certificate) = certificate {
            actions.push(BftAction::BroadcastRoundChangeCertificate(
                certificate.clone(),
            ));
            actions.extend(self.enter_bft_certified_round(
                &mut session,
                certificate,
                now_secs,
                false,
            )?);
        }
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(id, session);
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }

    /// Verify a complete certificate before catchup to any later round.
    pub fn observe_round_change_certificate(
        &mut self,
        certificate: RoundChangeCertificate,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let id = certificate.chunk_id;
        let Some(mut session) = self.bft_sessions.get(&id).cloned() else {
            return Ok(Vec::new());
        };
        // Entry may sign at once; synchronize signing state first.
        self.recover_session_signing(&mut session)?;
        if certificate.round <= session.round() || session.precommit_quorum_observed() {
            return Ok(Vec::new());
        }
        neutrin0_prover_chunk::bft::verify_round_change_certificate_using(
            self.consensus_domain(),
            self.active_validator_set(),
            &certificate,
            self.bft_prevote_quorum(),
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| conflict())?;
        let actions = self.enter_bft_certified_round(&mut session, certificate, now_secs, false)?;
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(id, session);
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }

    pub(super) fn enter_bft_certified_round(
        &mut self,
        session: &mut BftSession,
        certificate: RoundChangeCertificate,
        now_secs: u64,
        suppress_proposal: bool,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        if certificate.round <= session.round() {
            return Ok(Vec::new());
        }
        if let Some(quorum) = certificate.highest_quorum()
            && let Some(chunk) = session.candidates.get(&quorum.data.chunk_hash).cloned()
            && let Some(selection) = session.selections.get(&quorum.data.selection).cloned()
        {
            Self::remember_bft_valid_value(session, chunk, selection, quorum.clone());
        }
        session.bft = session.bft.clone().advance_to_round(certificate.round)?;
        session
            .pacemaker
            .advance_round(certificate.round, now_secs)?;
        session.round_started_at_secs = now_secs;
        session.proposal = None;
        // Until this round's proposal names receipts, attest the preferred ones.
        session.proof_hashes = self
            .stored_bft_proof_hashes(&session.chunk, None)?
            .unwrap_or_default();
        session.round_certificate = Some(certificate);
        session.local_round_report = None;
        session.local = LocalVoteProgress::Idle;
        session.local_votes.clear();
        session.local_nil_votes.clear();
        session.peer_quorum = PeerQuorumProgress::BelowPrevote;
        session.prevote_justification = None;
        session.last_published_aggregate_stake = [0; 2];
        session.is_local_aggregator =
            self.local_is_aggregator_for(session.chunk_id, session.round());
        self.persist_bft_session(session)?;
        self.bft_sessions.insert(session.chunk_id, session.clone());
        if suppress_proposal {
            Ok(Vec::new())
        } else {
            self.start_bft_leader_proposal(session, now_secs)
        }
    }

    pub(in crate::bft_loop) fn tick_bft_pacemaker(
        &mut self,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let ids: Vec<_> = self.bft_sessions.keys().copied().collect();
        let mut actions = Vec::new();
        for id in ids {
            let mut session = self
                .bft_sessions
                .get(&id)
                .expect("collected session")
                .clone();
            let recovered = self.recover_session_signing(&mut session)?;
            if session.precommit_quorum_observed() {
                continue;
            }
            if session.round() == u32::MAX
                && now_secs >= session.pacemaker.deadline()
                && session.pacemaker.step() == neutrin0_consensus_chunk_bft::RoundStep::Precommit
            {
                return Err(StoreError::Corrupt("BFT round space exhausted").into());
            }
            let timeout = session.pacemaker.on_timeout(now_secs);
            match timeout {
                Some(TimeoutAction::PrevoteNil) => {
                    self.sign_bft_nil(&mut session, FinalityVotePhase::Prevote, &mut actions)?;
                }
                Some(TimeoutAction::PrecommitNil) => {
                    self.sign_bft_nil(&mut session, FinalityVotePhase::Precommit, &mut actions)?;
                }
                Some(TimeoutAction::RoundChange { .. }) => {
                    actions.extend(self.request_bft_round_change(&mut session, now_secs)?);
                }
                None => {}
            }
            // An idle pacemaker leaves the session exactly as last persisted.
            if recovered || timeout.is_some() {
                self.persist_bft_session(&session)?;
                self.bft_sessions.insert(id, session);
            }
        }
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }
}
