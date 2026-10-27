//! Availability hints never authorize a leader vote or a round change.

use alloc::vec::Vec;
use neutrin0_consensus_types::{BftCandidate, FinalityVoteData, FinalityVotePhase};
use neutrin0_primitives::ChunkId;
use neutrin0_proof_system::ProofSystem;
use neutrin0_prover_chunk::consensus::{as_chunk, provable_candidate};
use neutrin0_storage::Database;

use super::{BftAction, BftLoopError, BftQuorumIdentity, BftSession, conflict};
use crate::Engine;

extern crate alloc;

impl<DB: Database> Engine<DB> {
    /// Offer a currently available proven branch and its independent valid QC.
    #[must_use]
    pub fn bft_candidate(&self, chunk_id: ChunkId) -> Option<BftCandidate> {
        let session = self.bft_sessions.get(&chunk_id)?;
        let (chunk, selection, justification) = session.valid_value.as_ref().map_or_else(
            || (session.chunk.clone(), None, None),
            |(chunk, selection, quorum)| {
                (chunk.clone(), Some(selection.clone()), Some(quorum.clone()))
            },
        );
        let round = justification
            .as_ref()
            .and_then(|quorum| quorum.data.round.checked_add(1))
            .unwrap_or_else(|| session.round());
        Some(BftCandidate {
            chunk,
            round,
            justification,
            selection,
        })
    }

    /// Exact current certificate identity, used to reject stale proof completion.
    #[must_use]
    pub fn bft_quorum_identity(&self, chunk_id: ChunkId) -> Option<BftQuorumIdentity> {
        self.bft_sessions.get(&chunk_id)?.quorum_identity()
    }

    /// Authenticate and retain an available branch. Its advisory round does not
    /// advance the pacemaker and its availability does not authorize a prevote.
    /// Only a signed designated-leader proposal can select the voting target.
    pub fn offer_bft_candidate<P: ProofSystem>(
        &mut self,
        candidate: &BftCandidate,
        now_secs: u64,
        proof_system: &P,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let id = candidate.chunk.chunk_id;
        let prepared = self
            .prepare_consensus_chunk_on_branch(
                id,
                candidate.chunk.end_block_hash,
                None,
                proof_system,
            )
            .map_err(BftLoopError::Candidate)?;
        let verified = &prepared.candidate;
        if as_chunk(&verified.execution.chunk) != candidate.chunk
            || !provable_candidate(&prepared.witness)
        {
            return Err(conflict());
        }
        if !self.bft_sessions.contains_key(&id) {
            return self.open_bft_session_at(candidate.chunk.clone(), now_secs);
        }
        let mut session = self.bft_sessions.get(&id).expect("checked session").clone();
        self.recover_session_signing(&mut session)?;
        // A justification certifies the chunk with one payment selection; the
        // hint must carry that selection for a leader to re-propose it.
        let selection = match (&candidate.justification, &candidate.selection) {
            (None, None) => None,
            (Some(quorum), Some(selection)) if selection.commitment() == quorum.data.selection => {
                Some(selection.clone())
            }
            _ => return Err(conflict()),
        };
        if let (Some(quorum), Some(selection)) = (&candidate.justification, &selection) {
            let data = FinalityVoteData {
                chunk_id: id,
                chunk_hash: candidate.chunk.hash(),
                selection: quorum.data.selection,
                round: quorum.data.round.checked_add(1).ok_or_else(conflict)?,
                phase: FinalityVotePhase::Prevote,
            };
            self.verify_bft_unlock_quorum(self.active_validator_set(), &data, quorum)
                .map_err(|_| conflict())?;
            if quorum.data.round <= session.round() {
                Self::remember_bft_valid_value(
                    &mut session,
                    candidate.chunk.clone(),
                    selection.clone(),
                    quorum.clone(),
                );
            }
        }
        if let Some(quorum) = session
            .round_certificate
            .as_ref()
            .and_then(neutrin0_consensus_types::RoundChangeCertificate::highest_quorum)
            .cloned()
            && quorum.data.chunk_hash == candidate.chunk.hash()
            && let Some(selection) = selection
                .filter(|selection| selection.commitment() == quorum.data.selection)
                .or_else(|| session.selections.get(&quorum.data.selection).cloned())
        {
            Self::remember_bft_valid_value(
                &mut session,
                candidate.chunk.clone(),
                selection,
                quorum,
            );
        }
        Self::remember_bft_candidate(&mut session, candidate.chunk.clone());
        self.persist_bft_session(&session)?;
        let actions = self.start_bft_leader_proposal(&mut session, now_secs)?;
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(id, session);
        self.feed_broadcast_actions_to_fork_choice(&actions);
        Ok(actions)
    }

    pub(super) fn ensure_bft_candidate_lock(
        &self,
        session: &BftSession,
    ) -> Result<(), BftLoopError<DB::Error>> {
        // No value is prevoted before the round's proposal fixes its payment
        // selection, and a lock on another selection of the same chunk is a
        // lock on another value (design 08).
        let data = session
            .vote_data(FinalityVotePhase::Prevote)
            .ok_or_else(conflict)?;
        if let Some(quorum) = &session.prevote_justification {
            self.verify_bft_unlock_quorum(self.active_validator_set(), &data, quorum)
                .map_err(|_| conflict())?;
        }
        if session.highest_lock.as_ref().is_some_and(|lock| {
            !lock.data.same_value(&data)
                && session
                    .prevote_justification
                    .as_ref()
                    .is_none_or(|quorum| quorum.data.round <= lock.data.round)
        }) {
            return Err(conflict());
        }
        Ok(())
    }
}
