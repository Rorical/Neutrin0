//! Leader proposals as a follower sees them: authentication hints, arrival
//! slots, acceptance after full branch validation and the authorized prevote.

use alloc::vec::Vec;
use neutrin0_consensus_types::{BftProposal, Chunk, FinalityVotePhase};
use neutrin0_proof_system::ProofSystem;
use neutrin0_prover_chunk::consensus::{as_chunk, provable_candidate};
use neutrin0_storage::Database;

use crate::Engine;
use crate::bft_loop::{BftAction, BftLoopError, BftSession, conflict, emit_aggregator_actions};

extern crate alloc;

impl<DB: Database> Engine<DB> {
    /// Authenticate a proposal before allocating branch download resources.
    /// Full block and proof validation is performed by `observe_bft_proposal`.
    pub fn verify_bft_proposal_hint(
        &self,
        proposal: &BftProposal,
    ) -> Result<(), BftLoopError<DB::Error>> {
        if proposal.chunk.chunk_id != self.finalized_next_chunk_id() {
            return Err(conflict());
        }
        neutrin0_prover_chunk::bft::verify_proposal_using(
            self.consensus_domain(),
            self.active_validator_set(),
            &self.finalized_seed(),
            proposal,
            self.bft_prevote_quorum(),
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| conflict())
    }

    /// Authenticate a current-boundary value vote before bounded deferred storage.
    /// This checks policy as well as every retained signature; attribution-only
    /// persistence intentionally performs its separate less restrictive check.
    pub fn verify_bft_value_vote(
        &self,
        vote: &neutrin0_consensus_types::FinalityVote,
    ) -> Result<(), BftLoopError<DB::Error>> {
        if vote.data.chunk_id != self.finalized_next_chunk_id() {
            return Err(conflict());
        }
        neutrin0_prover_chunk::finality::verify_vote_using(
            self.consensus_domain(),
            self.active_validator_set(),
            vote,
            &self.chain_spec().consensus,
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| conflict())
    }

    /// The slot `proposal` first arrived in. Kept for open chunks only, at
    /// most a few proposals per round, so a leader signing many cannot push
    /// out another round's, and a bounded number overall, the oldest
    /// forgotten first.
    pub(super) fn proposal_arrival(&mut self, proposal: &BftProposal) -> neutrin0_primitives::Slot {
        const MAX_TRACKED: usize = 64;
        const MAX_PER_ROUND: usize = 4;
        let floor = self.finalized_next_chunk_id();
        let now = self.local_slot();
        self.proposal_arrivals
            .retain(|_, (chunk_id, _, _)| *chunk_id >= floor);
        let key = neutrin0_consensus_types::tagged_commitment(b"proposal-arrival", proposal);
        if let Some((_, _, slot)) = self.proposal_arrivals.get(&key) {
            return *slot;
        }
        let round = (proposal.chunk.chunk_id, proposal.round);
        if self
            .proposal_arrivals
            .values()
            .filter(|(chunk_id, held_round, _)| (*chunk_id, *held_round) == round)
            .count()
            >= MAX_PER_ROUND
        {
            return now;
        }
        if self.proposal_arrivals.len() >= MAX_TRACKED
            && let Some(oldest) = self
                .proposal_arrivals
                .iter()
                .min_by_key(|(_, (_, _, slot))| *slot)
                .map(|(key, _)| *key)
        {
            self.proposal_arrivals.remove(&oldest);
        }
        self.proposal_arrivals.insert(key, (round.0, round.1, now));
        now
    }

    /// Accept a current-round leader proposal only after full branch validation.
    /// An incompatible retained lock produces a nil prevote, never a relaxed lock.
    pub fn observe_bft_proposal<P: ProofSystem>(
        &mut self,
        proposal: BftProposal,
        now_secs: u64,
        proof_system: &P,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        self.verify_bft_proposal_hint(&proposal)?;
        // Settle what the session already decides before any receipt or
        // branch work: a signed proposal costs its leader nothing to vary,
        // so stale rounds, finished sessions and a second value for the
        // round must never reach chunk preparation.
        let already_accepted = match self.bft_sessions.get(&proposal.chunk.chunk_id) {
            Some(session)
                if proposal.round < session.round() || session.precommit_quorum_observed() =>
            {
                return Ok(Vec::new());
            }
            Some(session) if proposal.round == session.round() => match &session.proposal {
                Some(prior) if prior != &proposal => return Err(conflict()),
                Some(_) => true,
                None => false,
            },
            _ => false,
        };
        // Receipts an authenticated proposal names are kept once they arrive.
        self.await_receipts(proposal.round, &proposal);
        // Design 08: the named receipts must be held and selectable here, as
        // of the slot the proposal first arrived in.
        let arrival = self.proposal_arrival(&proposal);
        self.check_receipt_selection(&proposal, arrival)?;
        let id = proposal.chunk.chunk_id;
        // The accepted proposal's branch was validated when it was accepted.
        if !already_accepted {
            let prepared = self
                .prepare_consensus_chunk_on_branch(
                    id,
                    proposal.chunk.end_block_hash,
                    Some(&proposal.receipt_keys()),
                    proof_system,
                )
                .map_err(BftLoopError::Candidate)?;
            let verified = &prepared.candidate;
            // Design 12: never vote for a chunk the Guest could not prove.
            if as_chunk(&verified.execution.chunk) != proposal.chunk
                || !provable_candidate(&prepared.witness)
            {
                return Err(conflict());
            }
        }
        let mut actions = if self.bft_sessions.contains_key(&id) {
            Vec::new()
        } else {
            self.open_bft_session_initial(
                proposal.chunk.clone(),
                now_secs,
                proposal.round_change_certificate.clone(),
                true,
            )?
        };
        let mut session = self
            .bft_sessions
            .get(&id)
            .expect("opened current session")
            .clone();
        self.recover_session_signing(&mut session)?;
        if proposal.round < session.round() || session.precommit_quorum_observed() {
            return Ok(actions);
        }
        if proposal.round > session.round() {
            let certificate = proposal
                .round_change_certificate
                .clone()
                .ok_or_else(conflict)?;
            Self::remember_bft_candidate(&mut session, proposal.chunk.clone());
            actions.extend(self.enter_bft_certified_round(
                &mut session,
                certificate,
                now_secs,
                true,
            )?);
        }
        actions.extend(self.accept_bft_leader_proposal(&mut session, proposal, now_secs)?);
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(id, session);
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }

    pub(super) fn reset_bft_candidate(
        &self,
        session: &mut BftSession,
        chunk: Chunk,
    ) -> Result<(), BftLoopError<DB::Error>> {
        let old_prevotes = session
            .bft
            .current_nil_aggregate(FinalityVotePhase::Prevote);
        let old_precommits = session
            .bft
            .current_nil_aggregate(FinalityVotePhase::Precommit);
        session.bft = self.new_chunk_bft(
            chunk.clone(),
            session.round(),
            self.previous_validator_set_root()?,
        )?;
        for vote in [old_prevotes, old_precommits].into_iter().flatten() {
            session.bft.add_nil_vote(vote)?;
        }
        session.chunk_hash = chunk.hash();
        session.proof_hashes = self
            .stored_bft_proof_hashes(&chunk, None)?
            .unwrap_or_default();
        session.chunk = chunk;
        Ok(())
    }

    pub(in crate::bft_loop) fn accept_bft_leader_proposal(
        &mut self,
        session: &mut BftSession,
        proposal: BftProposal,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        if let Some(prior) = &session.proposal {
            if prior != &proposal {
                return Err(conflict());
            }
            // Complete the first reservation after a crash between the durable
            // proposal and its prevote without rewinding an observed deadline.
            let mut actions = Vec::new();
            self.sign_bft_authorized_prevote(session, &mut actions)?;
            self.recompute_quorum_transitions(session, &mut actions)?;
            if session.prevote_quorum_observed() {
                session.pacemaker.enter_precommit(now_secs);
            }
            emit_aggregator_actions(session, &mut actions);
            return Ok(actions);
        }
        if proposal.chunk.hash() != session.chunk_hash {
            if !session.local_votes.is_empty() {
                return Err(conflict());
            }
            self.reset_bft_candidate(session, proposal.chunk.clone())?;
        }
        // The round attests exactly the receipts the proposal names (design 08).
        // The network path checked that they are held; precommit signing
        // re-derives them from storage before attesting.
        session.proof_hashes = self
            .stored_bft_proof_hashes(&session.chunk, Some(&proposal.receipt_keys()))?
            .unwrap_or_default();
        session.bft.set_proposal(proposal.clone())?;
        session
            .prevote_justification
            .clone_from(&proposal.valid_quorum);
        // `set_proposal` checked that a valid quorum signed this selection.
        let selection = proposal.payment_selection();
        if let Some(quorum) = &proposal.valid_quorum {
            Self::remember_bft_valid_value(
                session,
                proposal.chunk.clone(),
                selection.clone(),
                quorum.clone(),
            );
        }
        Self::remember_bft_candidate(session, proposal.chunk.clone());
        Self::remember_bft_selection(session, selection);
        // Distinct honest observers may have assembled different valid report
        // subsets. Persist the exact independently verified certificate carried
        // by the accepted leader proposal, while retaining locks/valid values.
        session
            .round_certificate
            .clone_from(&proposal.round_change_certificate);
        session.proposal = Some(proposal);
        session.pacemaker.enter_prevote(now_secs);
        // The exact proposal/target is durable before either value or nil reservation.
        self.persist_bft_session(session)?;
        self.bft_sessions.insert(session.chunk_id, session.clone());
        let mut actions = Vec::new();
        self.sign_bft_authorized_prevote(session, &mut actions)?;
        self.recompute_quorum_transitions(session, &mut actions)?;
        if session.prevote_quorum_observed() {
            session.pacemaker.enter_precommit(now_secs);
        }
        emit_aggregator_actions(session, &mut actions);
        Ok(actions)
    }

    fn sign_bft_authorized_prevote(
        &mut self,
        session: &mut BftSession,
        actions: &mut Vec<BftAction>,
    ) -> Result<(), BftLoopError<DB::Error>> {
        if !session.local_prevoted()
            && session.pacemaker.step() == neutrin0_consensus_chunk_bft::RoundStep::Prevote
        {
            if self.ensure_bft_candidate_lock(session).is_err() {
                self.sign_bft_nil(session, FinalityVotePhase::Prevote, actions)?;
            } else if let (Some(voter), Some(data)) = (
                self.active_local_voter(),
                session.vote_data(FinalityVotePhase::Prevote),
            ) {
                let vote =
                    self.sign_vote_durable(&voter, data, Vec::new(), session.prevote_unlock())?;
                session.bft.add_prevote(vote.clone())?;
                session
                    .record_local_signature(FinalityVotePhase::Prevote, *voter.public_key_bytes());
                session.local_votes.push(vote.clone());
                actions.push(BftAction::BroadcastPrevote(vote));
            }
        }
        Ok(())
    }
}
