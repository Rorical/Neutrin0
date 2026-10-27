//! Resuming restored sessions: interrupted signing reservations are
//! recovered before any timer or publication, then the original messages are
//! re-broadcast.

use alloc::boxed::Box;
use alloc::vec::Vec;
use neutrin0_consensus_types::{Chunk, FinalityVote, FinalityVotePhase};
use neutrin0_primitives::Hash;
use neutrin0_storage::Database;

use super::local_manifest_matches;
use crate::bft_loop::{
    BftAction, BftLoopError, BftSession, LocalVoteProgress, conflict, emit_aggregator_actions,
};
use crate::{Engine, EngineError, StoreError};

extern crate alloc;

/// Restore a reserved precommit only with its durable exact receipts and complete
/// signed prevote coverage; a raw QC cannot replace the retained declarations.
fn recover_reserved_precommit<E>(
    session: &mut BftSession,
    vote: &FinalityVote,
) -> Result<(), BftLoopError<E>> {
    let claim = vote
        .attestations
        .first()
        .expect("durable signer attaches claim");
    if !local_manifest_matches(vote, &session.proof_hashes) {
        return Err(conflict());
    }
    if let Some(lock) = &claim.unlock_quorum {
        let retained = session
            .bft
            .current_aggregate(FinalityVotePhase::Prevote)
            .ok_or_else(|| StoreError::Corrupt("reserved precommit lost its prevote claims"))?;
        if !session.bft.prevote_quorum_reached()
            || (0..lock.aggregate.aggregation_bits.bit_len()).any(|index| {
                lock.aggregate.aggregation_bits.get(index) == Some(true)
                    && retained.aggregation_bits.get(index) != Some(true)
            })
        {
            return Err(StoreError::Corrupt("reserved precommit prevote quorum changed").into());
        }
        session.highest_lock = Some(lock.clone());
    }
    session.bft.add_precommit(vote.clone())?;
    Ok(())
}

fn recover_reserved_value_vote<E>(
    session: &mut BftSession,
    vote: &FinalityVote,
) -> Result<(), BftLoopError<E>> {
    if vote.data.chunk_hash != session.chunk_hash || vote.data.round != session.round() {
        return Err(conflict());
    }
    match vote.data.phase {
        FinalityVotePhase::Prevote => {
            if vote
                .attestations
                .first()
                .is_none_or(|claim| claim.unlock_quorum != session.prevote_unlock())
            {
                return Err(conflict());
            }
            session.bft.add_prevote(vote.clone())?;
        }
        FinalityVotePhase::Precommit => recover_reserved_precommit(session, vote)?,
    }
    if !session
        .local_votes
        .iter()
        .any(|prior| prior.data.phase == vote.data.phase)
    {
        session.local_votes.push(vote.clone());
    }
    Ok(())
}

impl<DB: Database> Engine<DB> {
    /// Artifact ids of the receipts a vote attests, one per height: the
    /// receipts `receipts` names by statement key, or the locally preferred
    /// receipts before a proposal names any (design 08).
    pub(in crate::bft_loop) fn stored_bft_proof_hashes(
        &self,
        chunk: &Chunk,
        receipts: Option<&[Hash]>,
    ) -> Result<Option<Vec<Hash>>, EngineError<DB::Error>> {
        // A proposal naming no receipts never passes selection; fixtures that
        // bypass it attest the locally preferred receipts.
        let receipts = receipts.filter(|keys| !keys.is_empty());
        // An empty range (a fixture's end below its start) names no receipt.
        let len = match chunk.end_height.checked_sub(chunk.start_height) {
            Some(span) => usize::try_from(span)
                .ok()
                .and_then(|span| span.checked_add(1))
                .ok_or(StoreError::Corrupt("BFT chunk range overflow"))?,
            None => 0,
        };
        if receipts.is_some_and(|keys| keys.len() != len) {
            return Ok(None);
        }
        let mut hashes = Vec::new();
        let mut cursor = chunk.end_block_hash;
        for height in (chunk.start_height..=chunk.end_height).rev() {
            let Some(header) = self.store().get_header(&cursor)? else {
                return Ok(None);
            };
            if header.height != height || header.hash() != cursor {
                return Err(StoreError::Corrupt("BFT branch header mismatch").into());
            }
            let stored = match receipts {
                Some(keys) => {
                    let index = usize::try_from(height - chunk.start_height)
                        .map_err(|_| StoreError::Corrupt("BFT chunk range overflow"))?;
                    self.store()
                        .block_receipt_by_key(&cursor, &keys[index])?
                        .map(|receipt| receipt.proof)
                }
                None => self.store().get_block_proof(&cursor)?,
            };
            let Some(proof) = stored else {
                return Ok(None);
            };
            if proof.block_hash != cursor || proof.height != height {
                return Err(StoreError::Corrupt("BFT proof envelope target mismatch").into());
            }
            hashes.push(neutrin0_consensus_types::evidence::commitment(&proof));
            cursor = header.parent_hash;
        }
        hashes.reverse();
        Ok(Some(hashes))
    }

    /// Re-broadcast the original signed messages after restart and resume proven
    /// quorum work and complete a proposal's interrupted first reservation.
    /// Original deadlines and signing reservations are preserved.
    pub fn resume_bft_actions(&mut self) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let ids: Vec<_> = self.bft_sessions.keys().copied().collect();
        let mut actions = Vec::new();
        for id in ids {
            actions.extend(self.resume_bft_session(id)?);
        }
        Ok(actions)
    }

    /// Drive one restored session for both network and direct finalization APIs.
    pub(crate) fn resume_bft_session(
        &mut self,
        id: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let mut actions = Vec::new();
        let mut session = self
            .bft_sessions
            .get(&id)
            .ok_or(BftLoopError::NoSessionForChunk { chunk_id: id })?
            .clone();
        self.recover_session_signing(&mut session)?;
        let now_secs = session.round_started_at_secs;
        if let Some(proposal) = session.proposal.clone() {
            self.accept_bft_leader_proposal(&mut session, proposal, now_secs)?;
        } else {
            self.start_bft_leader_proposal(&mut session, now_secs)?;
        }
        // Publication below includes every original local message exactly once.
        self.recompute_quorum_transitions(&mut session, &mut Vec::new())?;
        // Recovery above refused a different saved identity, and every later
        // local signature is made by the configured key.
        if self.local_voter.is_some() {
            session.is_local_aggregator = self.local_is_aggregator_for(id, session.round());
            if let Some(proposal) = &session.proposal
                && proposal.proposer_index
                    == self
                        .active_local_voter()
                        .map_or(u32::MAX, |v| v.validator_index())
            {
                actions.push(BftAction::BroadcastProposal(Box::new(proposal.clone())));
            }
            for vote in &session.local_nil_votes {
                actions.push(BftAction::BroadcastNilVote(vote.clone()));
            }
            if let Some(report) = &session.local_round_report {
                actions.push(BftAction::BroadcastRoundChange(report.clone()));
            }
            if let Some(certificate) = &session.round_certificate {
                actions.push(BftAction::BroadcastRoundChangeCertificate(
                    certificate.clone(),
                ));
            }
            for vote in &session.local_votes {
                actions.push(BftAction::local_vote(vote));
            }
        }
        if session.precommit_quorum_observed()
            && let Some(identity) = session.quorum_identity()
        {
            actions.push(BftAction::QuorumReached(identity));
        }
        emit_aggregator_actions(&mut session, &mut actions);
        self.persist_bft_session(&session)?;
        if let Some(quorum) = &session.highest_lock {
            self.slashing_monitor.record_prevote_quorum(quorum.clone());
        }
        self.bft_sessions.insert(id, session);
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }

    /// A crash may occur after reserving a signature but before saving the new
    /// session. Recover that reservation before any timer or publication resumes.
    /// Returns whether `session` changed and so must be persisted.
    pub(in crate::bft_loop) fn recover_session_signing(
        &mut self,
        session: &mut BftSession,
    ) -> Result<bool, BftLoopError<DB::Error>> {
        let Some(configured) = self.local_voter.as_ref() else {
            return Ok(false);
        };
        if session
            .local_identity
            .is_some_and(|identity| identity != *configured.public_key_bytes())
        {
            return Err(conflict());
        }
        let Some(voter) = self.bind_active_proposer(configured) else {
            return Ok(false);
        };
        // Pausing signatures must not hide a lock reserved before a crash.
        // One authenticated journal read supplies the retained lock and position.
        let Some(progress) = self.reserved_signing_progress(&voter, session.chunk_id)? else {
            return Ok(false);
        };
        let lock_advanced = progress.locked.as_ref().is_some_and(|lock| {
            session
                .highest_lock
                .as_ref()
                .is_none_or(|prior| prior.data.round < lock.data.round)
        });
        if lock_advanced {
            session.highest_lock.clone_from(&progress.locked);
        }
        if !self.local_signing_enabled() {
            return Ok(lock_advanced);
        }
        // A replacement target is committed before its first signature. A
        // crash in that window leaves only the previous round's journal.
        if progress.round < session.round() && session.local == LocalVoteProgress::Idle {
            return Ok(lock_advanced);
        }
        if progress.round == session.round()
            && progress.prevoted == session.local_prevoted()
            && progress.precommitted == session.local_precommitted()
        {
            return Ok(lock_advanced);
        }
        let messages = self.reserved_local_votes(&voter, &progress)?;
        let round = progress.round;
        let nil_messages = self.reserved_local_nil_votes(&voter, session.chunk_id, round)?;
        if messages.is_empty() && nil_messages.is_empty() {
            return Ok(lock_advanced);
        }
        if round < session.round() {
            return Err(EngineError::Signing(crate::signing::SigningViolation::Regression).into());
        }
        if round > session.round() {
            // Round entry is persisted with its authenticated certificate before
            // signing. A watermark alone cannot replace a missing durable entry.
            return Err(
                StoreError::Corrupt("reserved higher round lost authenticated entry").into(),
            );
        }
        // Local progress is rederived from the journal once every message is restored.
        for vote in nil_messages {
            session.bft.add_nil_vote(vote.clone())?;
            if !session.local_nil_votes.contains(&vote) {
                session.local_nil_votes.push(vote);
            }
        }
        for vote in messages {
            recover_reserved_value_vote(session, &vote)?;
        }
        session.local = LocalVoteProgress::from_flags(progress.prevoted, progress.precommitted);
        session.local_identity = Some(*voter.public_key_bytes());
        let root = self.previous_validator_set_root()?;
        self.advance_peer_quorum(session, root);
        Ok(true)
    }
}
