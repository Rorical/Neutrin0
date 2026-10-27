//! Quorum transitions: valid values, the local precommit and aggregator
//! publication once a round's accumulated stake crosses a threshold.

use alloc::vec::Vec;

use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
use neutrin0_consensus_types::{BftProposal, FinalityVotePhase, QuorumCertificate};
use neutrin0_primitives::Hash;
use neutrin0_storage::Database;

use super::{BftAction, BftLoopError, BftQuorumIdentity, BftSession, PeerQuorumProgress, conflict};
use crate::engine::Engine;

extern crate alloc;

impl<DB: Database> Engine<DB> {
    /// Advance `session`'s peer progress to what its accumulated authenticated
    /// stake authorizes. Live recompute, signing recovery and restart share this
    /// single rule: a precommit quorum becomes finalizable only together with the
    /// prevote quorum, the round's accepted leader proposal, the committed
    /// `validator_root` and a complete certificate. Raw stake alone never marks
    /// a session finished. Each newly crossed value prevote quorum is recorded
    /// as lock evidence for the slashing monitor's `LockViolation` detector.
    ///
    /// Returns the certificate identity when the precommit quorum newly became
    /// finalizable. Callers apply it only after every local signature of the
    /// round is accumulated, so the frozen identity covers them.
    pub(super) fn advance_peer_quorum(
        &mut self,
        session: &mut BftSession,
        validator_root: Hash,
    ) -> Option<BftQuorumIdentity> {
        // A prevote quorum among votes held before the round's proposal is
        // lock evidence all the same (design 08).
        for quorum in session.bft.pending_prevote_quorums() {
            self.slashing_monitor.record_prevote_quorum(quorum);
        }
        if session.peer_quorum == PeerQuorumProgress::BelowPrevote {
            if !session.bft.prevote_quorum_reached() {
                return None;
            }
            session.peer_quorum = PeerQuorumProgress::PrevoteQuorumObserved;
            if let Some(quorum) = session.current_prevote_quorum() {
                self.slashing_monitor.record_prevote_quorum(quorum);
            }
        }
        if session.peer_quorum != PeerQuorumProgress::PrevoteQuorumObserved
            || session.proposal.is_none()
            || !session.bft.precommit_quorum_reached()
            || !session.bft.validator_set_root_matches(validator_root)
        {
            return None;
        }
        let identity = session.quorum_identity()?;
        session.peer_quorum = PeerQuorumProgress::PrecommitQuorumObserved;
        Some(identity)
    }

    /// Remember the current prevote QC as a valid value and return it, so an
    /// immediate local precommit declares exactly the retained certificate.
    fn retain_bft_valid_quorum(
        &mut self,
        session: &mut BftSession,
        should_precommit: bool,
    ) -> Result<Option<QuorumCertificate>, BftLoopError<DB::Error>> {
        let (Some(quorum), Some(selection)) = (
            session.current_prevote_quorum(),
            session
                .proposal
                .as_ref()
                .map(BftProposal::payment_selection),
        ) else {
            return Ok(None);
        };
        let new_valid_value = Self::remember_bft_valid_value(
            session,
            session.chunk.clone(),
            selection,
            quorum.clone(),
        );
        // Retain the first valid value and the exact QC about to become our lock;
        // later votes cannot change a completed local reservation.
        if new_valid_value || should_precommit {
            self.retain_signed_artifact(&SignedArtifact::Quorum(quorum.clone()), true)?;
        }
        Ok(Some(quorum))
    }

    /// Inspect the session's freshly-updated quorum status and emit the
    /// follow-on actions (precommit broadcast, finalization signal) that
    /// just became newly applicable.
    pub(super) fn recompute_quorum_transitions(
        &mut self,
        session: &mut BftSession,
        actions: &mut Vec<BftAction>,
    ) -> Result<(), BftLoopError<DB::Error>> {
        if session.bft.prevote_quorum_reached() {
            let voter = if !session.local_precommitted()
                && session.proposal.is_some()
                && session.pacemaker.step() != neutrin0_consensus_chunk_bft::RoundStep::AwaitRound
            {
                self.active_local_voter()
            } else {
                None
            };
            // Attest exactly the receipts the proposal names, as held now; no
            // local precommit signed earlier hashes. Without them this node
            // cannot attest the value, so it abstains rather than failing.
            let voter = match voter {
                Some(voter) => {
                    let named = session.named_receipts();
                    self.stored_bft_proof_hashes(&session.chunk, named.as_deref())?
                        .map(|hashes| (voter, hashes))
                }
                None => None,
            };
            let quorum = self.retain_bft_valid_quorum(session, voter.is_some())?;
            if let Some((voter, hashes)) = voter {
                session.proof_hashes = hashes;
                if session
                    .local_identity
                    .is_some_and(|identity| identity != *voter.public_key_bytes())
                {
                    return Err(conflict());
                }
                let unlock = quorum.expect("prevote quorum was reached");
                // Preserve mandatory individual prevote declarations before a
                // precommit reservation; a raw QC cannot recover those claims.
                self.persist_bft_session(session)?;
                self.bft_sessions.insert(session.chunk_id, session.clone());
                let precommit = self.sign_vote_durable(
                    &voter,
                    session
                        .vote_data(FinalityVotePhase::Precommit)
                        .ok_or_else(conflict)?,
                    session.proof_hashes.clone(),
                    Some(unlock.clone()),
                )?;
                session.bft.add_precommit(precommit.clone())?;
                session.record_local_signature(
                    FinalityVotePhase::Precommit,
                    *voter.public_key_bytes(),
                );
                session.local_votes.push(precommit.clone());
                session.highest_lock = Some(unlock);
                actions.push(BftAction::BroadcastPrecommit(precommit));
            }
        }
        // Bind the same validator-set root the chunk committed; if they have
        // drifted, leave the session unfinalized so the finalize path does not
        // produce a cert that the verifier will reject.
        let root = self.previous_validator_set_root()?;
        if let Some(identity) = self.advance_peer_quorum(session, root) {
            actions.push(BftAction::QuorumReached(identity));
        }
        Ok(())
    }
}

/// If the local validator is in the aggregator committee for this
/// session and the union-aggregated stake has grown since the last
/// publish, emit a [`BftAction::PublishAggregatePrevote`] /
/// [`BftAction::PublishAggregatePrecommit`] carrying the
/// current aggregate.
pub(super) fn emit_aggregator_actions(session: &mut BftSession, actions: &mut Vec<BftAction>) {
    if !session.is_local_aggregator {
        return;
    }
    for (published, phase) in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit]
        .into_iter()
        .enumerate()
    {
        let stake = session.bft.aggregate_stake(phase);
        if stake > session.last_published_aggregate_stake[published]
            && let Some(vote) = session.current_vote(phase)
        {
            let subnet = session.subnet;
            actions.push(match phase {
                FinalityVotePhase::Prevote => BftAction::PublishAggregatePrevote { subnet, vote },
                FinalityVotePhase::Precommit => {
                    BftAction::PublishAggregatePrecommit { subnet, vote }
                }
            });
            session.last_published_aggregate_stake[published] = stake;
        }
    }
}
