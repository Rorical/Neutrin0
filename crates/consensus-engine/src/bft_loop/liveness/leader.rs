//! The designated leader's own proposal: a retained valid value with its
//! exact selection, or a fresh value once every height has a selectable
//! receipt and the previous chunk's proof is held.

use alloc::boxed::Box;
use alloc::vec::Vec;
use neutrin0_consensus_types::{
    BftProposal, Chunk, PaymentSelection, RoundChangeCertificate, bft_leader,
};
use neutrin0_storage::Database;

use crate::bft_loop::{BftAction, BftLoopError, BftSession, qc_rank};
use crate::{Engine, ProposerKey};

extern crate alloc;

impl<DB: Database> Engine<DB> {
    pub(in crate::bft_loop) fn start_bft_leader_proposal(
        &mut self,
        session: &mut BftSession,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let Some(voter) = self.active_local_voter() else {
            return Ok(Vec::new());
        };
        if !self.leader_proposal_due(session, &voter) {
            return Ok(Vec::new());
        }
        if let Some(proposal) =
            self.reserved_bft_proposal(&voter, session.chunk_id, session.round())?
        {
            let mut actions = vec![BftAction::BroadcastProposal(Box::new(proposal.clone()))];
            actions.extend(self.accept_bft_leader_proposal(session, proposal, now_secs)?);
            return Ok(actions);
        }
        let (chunk, valid) = session.valid_value.as_ref().map_or_else(
            || (session.chunk.clone(), None),
            |(chunk, selection, quorum)| (chunk.clone(), Some((selection.clone(), quorum.clone()))),
        );
        if valid
            .as_ref()
            .is_some_and(|(_, quorum)| quorum.data.round >= session.round())
        {
            return Ok(Vec::new());
        }
        // Design 08: a valid value is re-proposed with the exact selection its
        // quorum signed. A fresh value is proposed only once every height has
        // a selectable receipt at the signed slot, otherwise the leader waits
        // for the proposer's receipt or the end of its exclusive window, and
        // only with the previous chunk's proof to ratify.
        let (selection, valid_quorum) = if let Some((selection, quorum)) = valid {
            (selection, Some(quorum))
        } else {
            let Some(selection) = self.fresh_leader_selection(&chunk)? else {
                return Ok(Vec::new());
            };
            (selection, None)
        };
        if chunk.hash() != session.chunk_hash {
            self.reset_bft_candidate(session, chunk.clone())?;
        }
        self.persist_bft_session(session)?;
        self.bft_sessions.insert(session.chunk_id, session.clone());
        let proposal = self.sign_bft_proposal_durable(
            &voter,
            BftProposal {
                chunk,
                round: session.round(),
                proposer_index: voter.validator_index(),
                valid_quorum,
                round_change_certificate: session.round_certificate.clone(),
                proposal_slot: selection.proposal_slot,
                receipts: selection.receipts,
                ratified_chunk_proofs: selection.ratified_chunk_proofs,
                signature: [0; 96],
            },
        )?;
        let mut actions = vec![BftAction::BroadcastProposal(Box::new(proposal.clone()))];
        actions.extend(self.accept_bft_leader_proposal(session, proposal, now_secs)?);
        Ok(actions)
    }

    /// Whether `voter` leads this round and nothing yet keeps it from
    /// proposing: no proposal or prevote so far, a certified entry for a
    /// nonzero round, and a valid value at least as high as the one that
    /// entry certifies.
    fn leader_proposal_due(&self, session: &BftSession, voter: &ProposerKey) -> bool {
        if session.proposal.is_some()
            || session.local_prevoted()
            || (session.round() > 0 && session.round_certificate.is_none())
            || bft_leader(
                self.chain_spec().chain_id,
                session.chunk_id,
                session.round(),
                &self.finalized_seed(),
                self.active_validator_set(),
            ) != Some(voter.validator_index())
        {
            return false;
        }
        if let Some(required) = session
            .round_certificate
            .as_ref()
            .and_then(RoundChangeCertificate::highest_quorum)
            && session
                .valid_value
                .as_ref()
                .is_none_or(|(_, _, known)| qc_rank(known) < qc_rank(required))
        {
            return false;
        }
        true
    }

    /// The payment selection of a fresh value for `chunk`, or `None` while a
    /// height has no selectable receipt or the previous chunk's proof is not
    /// held.
    fn fresh_leader_selection(
        &self,
        chunk: &Chunk,
    ) -> Result<Option<PaymentSelection>, BftLoopError<DB::Error>> {
        let proposal_slot = self.leader_proposal_slot(chunk)?;
        let Some(receipts) = self.selected_receipts(chunk, proposal_slot)? else {
            return Ok(None);
        };
        let Some(ratified_chunk_proofs) = self.ratification_selection(chunk)? else {
            return Ok(None);
        };
        Ok(Some(PaymentSelection {
            proposal_slot,
            receipts,
            ratified_chunk_proofs,
        }))
    }
}
