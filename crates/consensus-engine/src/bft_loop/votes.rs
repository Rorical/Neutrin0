//! Peer value-vote ingestion and feeding accepted votes into fork choice.

use alloc::vec::Vec;

use neutrin0_consensus_chunk_bft::BftError;
use neutrin0_consensus_fork_choice::ChunkVote;
use neutrin0_consensus_types::{FinalityVote, FinalityVoteData, FinalityVotePhase};
use neutrin0_primitives::ValidatorIndex;
use neutrin0_storage::Database;

use super::{BftAction, BftLoopError, BftSession, emit_aggregator_actions};
use crate::engine::Engine;

extern crate alloc;

impl<DB: Database> Engine<DB> {
    /// Ingest a peer-supplied finality vote into the matching BFT
    /// session.
    ///
    /// Returns the [`BftAction`]s the caller should propagate. When
    /// the prevote quorum is freshly crossed and a local voter is
    /// configured, a [`BftAction::BroadcastPrecommit`] is emitted.
    /// When the precommit quorum is freshly crossed, a
    /// [`BftAction::QuorumReached`] is emitted.
    ///
    /// Votes whose chunk id has no open session are silently dropped:
    /// they arrived before the local node observed the corresponding
    /// chunk become proof-ready.
    ///
    /// # Errors
    ///
    /// Returns any inner [`ChunkBft`](neutrin0_consensus_chunk_bft::ChunkBft) error (wrong phase, wrong
    /// target, malformed aggregation bits, etc.).
    pub fn observe_finality_vote(
        &mut self,
        vote: FinalityVote,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let now_secs = self.wall_clock_secs();
        self.observe_finality_vote_at(vote, now_secs)
    }

    /// Ingest a vote with the current clock, preserving a full precommit deadline
    /// when its independently verified prevote quorum is first observed.
    pub fn observe_finality_vote_at(
        &mut self,
        vote: FinalityVote,
        now_secs: u64,
    ) -> Result<Vec<BftAction>, BftLoopError<DB::Error>> {
        let chunk_id = vote.data.chunk_id;
        let next = self.finalized_next_chunk_id();
        if (chunk_id < next
            && !neutrin0_consensus_types::history::is_recent_history_index(chunk_id, next))
            || !self.bft_sessions.contains_key(&chunk_id)
        {
            return Ok(Vec::new());
        }
        // Another round or chunk is ignored here. The accumulator holds a
        // vote that precedes the round's proposal per selection and refuses
        // one for another selection once the proposal is known (design 08).
        if self.bft_sessions.get(&chunk_id).is_some_and(|session| {
            session.round() != vote.data.round || session.chunk_hash != vote.data.chunk_hash
        }) {
            return Ok(Vec::new());
        }
        if self
            .bft_sessions
            .get(&chunk_id)
            .is_some_and(BftSession::precommit_quorum_observed)
        {
            self.authenticate_finished_bft_vote(&vote)?;
            // Freeze the first complete certificate while its proof runs. Node
            // attribution retains later sources before this gate; the node clock
            // independently retries failed proof jobs under the same identity.
            return Ok(Vec::new());
        }

        // Snapshot the peer vote's signers before
        // the phase-routing match consumes `vote`. The snapshot is
        // fed into fork-choice only after the BFT layer accepts the
        // vote (`?` propagation below would discard it otherwise).
        let peer_contributions = self.snapshot_vote_signers_for_fork_choice(&vote);
        let peer_vote_data = vote.data.clone();

        let mut actions = Vec::new();
        let mut session = self
            .bft_sessions
            .get(&chunk_id)
            .expect("contains_key checked above")
            .clone();
        let prior_local = session.local_votes.clone();
        self.recover_session_signing(&mut session)?;
        for local in &session.local_votes {
            if !prior_local.contains(local) {
                actions.push(BftAction::local_vote(local));
            }
        }
        if session.precommit_quorum_observed()
            && let Some(identity) = session.quorum_identity()
        {
            actions.push(BftAction::QuorumReached(identity));
        }
        if session.precommit_quorum_observed() {
            self.authenticate_finished_bft_vote(&vote)?;
        } else {
            match vote.data.phase {
                FinalityVotePhase::Prevote => session.bft.add_prevote(vote)?,
                FinalityVotePhase::Precommit => session.bft.add_precommit(vote)?,
            }
            // Recompute retains valid values in rank order and records a newly
            // crossed prevote quorum as slashing lock evidence.
            self.recompute_quorum_transitions(&mut session, &mut actions)?;
            if session.prevote_quorum_observed() && session.proposal.is_some() {
                session.pacemaker.enter_precommit(now_secs);
            }
        }
        emit_aggregator_actions(&mut session, &mut actions);
        self.persist_bft_session(&session)?;
        self.bft_sessions.insert(chunk_id, session);

        // Feed the peer vote AND every newly-emitted local
        // broadcast vote (prevote on session open / round advance,
        // precommit on prevote-quorum) into fork-choice.
        self.add_vote_signers_to_fork_choice(&peer_contributions, &peer_vote_data);
        self.feed_broadcast_actions_to_fork_choice(&actions);

        Ok(actions)
    }

    fn authenticate_finished_bft_vote(
        &self,
        vote: &FinalityVote,
    ) -> Result<(), BftLoopError<DB::Error>> {
        let validators = self
            .accountability_validators(vote.data.chunk_id)
            .map_err(|_| BftError::InvalidAggregationBits)?;
        neutrin0_prover_chunk::finality::verify_vote_using(
            self.consensus_domain(),
            &validators,
            vote,
            &self.chain_spec().consensus,
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| BftError::InvalidAggregateSignature.into())
    }

    /// Snapshot `(validator_index, effective_stake)` for every
    /// signer of `vote` (one per set bit in `aggregation_bits`).
    /// Mirrors the exclusion rules `ChunkBft::vote_stake` applies:
    /// slashed validators and zero-stake validators contribute
    /// nothing — fork-choice scoring stays in lockstep with
    /// BFT-quorum accounting.
    fn snapshot_vote_signers_for_fork_choice(
        &self,
        vote: &FinalityVote,
    ) -> Vec<(ValidatorIndex, u128)> {
        let bit_len = vote.aggregation_bits.bit_len();
        self.active_validator_set()
            .iter()
            .enumerate()
            .filter_map(|(index, validator)| {
                let idx_u32 = u32::try_from(index).ok()?;
                if idx_u32 >= bit_len {
                    return None;
                }
                if !vote.aggregation_bits.get(idx_u32).unwrap_or(false) {
                    return None;
                }
                if validator.effective_stake == 0 {
                    return None;
                }
                Some((idx_u32, validator.effective_stake))
            })
            .collect()
    }

    /// Feed a pre-snapshotted (signer, weight) pair list plus a
    /// shared `FinalityVoteData` payload into the fork-choice DAG.
    /// One `add_vote` call per signer — fork-choice keys votes by
    /// validator index, so later votes replace prior entries.
    fn add_vote_signers_to_fork_choice(
        &mut self,
        signers: &[(ValidatorIndex, u128)],
        data: &FinalityVoteData,
    ) {
        for (validator_index, weight) in signers {
            self.fork_choice.add_vote(
                *validator_index,
                ChunkVote {
                    data: data.clone(),
                    weight: *weight,
                },
            );
        }
    }

    /// Feed every `BroadcastPrevote` /
    /// `BroadcastPrecommit` action in `actions` into fork-choice.
    /// Used at the end of every public BFT-loop entry point so
    /// the local validator's own vote populates fork-choice
    /// alongside peer votes. The `PublishAggregate*` variants are
    /// re-published unions of partial votes the local node
    /// observed; their per-signer contributions are already fed
    /// via the per-vote ingest paths, so they are skipped here.
    pub(super) fn feed_broadcast_actions_to_fork_choice(&mut self, actions: &[BftAction]) {
        for action in actions {
            let vote_ref = match action {
                BftAction::BroadcastPrevote(v) | BftAction::BroadcastPrecommit(v) => v,
                BftAction::PublishAggregatePrevote { .. }
                | BftAction::PublishAggregatePrecommit { .. }
                | BftAction::QuorumReached(_)
                | BftAction::BroadcastProposal(_)
                | BftAction::BroadcastNilVote(_)
                | BftAction::BroadcastRoundChange(_)
                | BftAction::BroadcastRoundChangeCertificate(_) => continue,
            };
            let signers = self.snapshot_vote_signers_for_fork_choice(vote_ref);
            self.add_vote_signers_to_fork_choice(&signers, &vote_ref.data);
        }
    }
}
