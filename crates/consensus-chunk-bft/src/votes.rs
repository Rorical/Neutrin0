//! Value and explicit nil vote admission for the current round.

use alloc::vec::Vec;

use neutrin0_consensus_types::{
    AggregatedVote, FinalityVote, FinalityVotePhase, NilVote, ProofAcceptanceCommitment,
    ProofManifestIndex, attestation_coverage_valid,
};
use neutrin0_primitives::Hash;

use crate::accumulator::{
    VoteAccumulator, extend_vote_aggregate, merge_signed_claims, nil_already_covers, union_bit_vecs,
};
use crate::stake::{bitmap_stake, nil_stake, quorum_reached, vote_stake};
use crate::verify::{verify_attestations, verify_nil_native, verify_vote_signature};
use crate::{BftError, ChunkBft, MAX_PENDING_SELECTIONS};

impl ChunkBft {
    /// Explicit per-signer commitments retained with the current aggregate.
    #[must_use]
    pub fn current_attestations(
        &self,
        phase: FinalityVotePhase,
    ) -> Vec<neutrin0_consensus_types::VoteAttestation> {
        self.accumulator(phase).attestations.clone()
    }
    /// Canonical full manifests required by the accumulated individual claims.
    #[must_use]
    pub fn current_proof_manifests(
        &self,
        phase: FinalityVotePhase,
    ) -> Vec<neutrin0_consensus_types::ProofManifest> {
        self.accumulator(phase)
            .proof_manifests
            .values()
            .map(|manifest| manifest.as_ref().clone())
            .collect()
    }

    /// The currently-accumulated aggregate vote for `phase`, if any
    /// partial votes have been recorded. Used by the aggregator
    /// role to publish the union-aggregated vote on a subnet topic.
    #[must_use]
    pub fn current_aggregate(&self, phase: FinalityVotePhase) -> Option<AggregatedVote> {
        self.accumulator(phase).aggregate()
    }

    /// Active stake represented by the currently-accumulated
    /// aggregate vote for `phase`. Zero if no votes are recorded.
    #[must_use]
    pub const fn aggregate_stake(&self, phase: FinalityVotePhase) -> u128 {
        match phase {
            FinalityVotePhase::Prevote => self.prevotes.aggregate_stake,
            FinalityVotePhase::Precommit => self.precommits.aggregate_stake,
        }
    }

    /// Adds an aggregated prevote for the current round.
    pub fn add_prevote(&mut self, vote: FinalityVote) -> Result<(), BftError> {
        self.add_vote(vote, FinalityVotePhase::Prevote)
    }

    /// Adds an aggregated precommit for the current round.
    pub fn add_precommit(&mut self, vote: FinalityVote) -> Result<(), BftError> {
        self.add_vote(vote, FinalityVotePhase::Precommit)
    }

    /// Retain a fully authenticated explicit nil vote without changing value locks.
    pub fn add_nil_vote(&mut self, vote: NilVote) -> Result<(), BftError> {
        if vote.data.chunk_id != self.chunk.chunk_id || vote.data.round != self.round {
            return Err(BftError::WrongVoteTarget);
        }
        if self
            .current_nil_aggregate_ref(vote.data.phase)
            .is_some_and(|known| nil_already_covers(known, &vote))
        {
            return Ok(());
        }
        verify_nil_native(self.domain, &self.active_set, &vote)?;
        let existing = match vote.data.phase {
            FinalityVotePhase::Prevote => &mut self.nil_prevotes,
            FinalityVotePhase::Precommit => &mut self.nil_precommits,
        };
        let Some(known) = existing else {
            *existing = Some(vote);
            return Ok(());
        };
        let claims = merge_signed_claims(&known.attestations, vote.attestations, |claim| {
            (claim.validator_index, claim.vote_signature)
        })?;
        let retained = known.attestations.len();
        if claims.len() == retained {
            return Ok(());
        }
        let signature = extend_vote_aggregate(&known.signature, &claims, retained, |claim| {
            claim.vote_signature
        })?;
        let aggregation_bits = union_bit_vecs(&known.aggregation_bits, &vote.aggregation_bits);
        bitmap_stake(&self.active_set, &aggregation_bits)?;
        known.attestations = claims;
        known.signature = signature;
        known.aggregation_bits = aggregation_bits;
        Ok(())
    }

    /// Complete nil aggregate, retaining every individual accountability signature.
    #[must_use]
    pub fn current_nil_aggregate(&self, phase: FinalityVotePhase) -> Option<NilVote> {
        self.current_nil_aggregate_ref(phase).cloned()
    }

    const fn current_nil_aggregate_ref(&self, phase: FinalityVotePhase) -> Option<&NilVote> {
        match phase {
            FinalityVotePhase::Prevote => self.nil_prevotes.as_ref(),
            FinalityVotePhase::Precommit => self.nil_precommits.as_ref(),
        }
    }

    /// Whether nil alone reached the phase's configured active-stake threshold.
    #[must_use]
    pub fn nil_quorum_reached(&self, phase: FinalityVotePhase) -> bool {
        let (vote, fraction) = match phase {
            FinalityVotePhase::Prevote => (self.nil_prevotes.as_ref(), self.prevote_quorum),
            FinalityVotePhase::Precommit => (self.nil_precommits.as_ref(), self.precommit_quorum),
        };
        vote.and_then(|vote| nil_stake(&self.active_set, vote).ok())
            .is_some_and(|stake| quorum_reached(stake, self.total_stake, fraction))
    }

    pub(super) fn add_vote(
        &mut self,
        vote: FinalityVote,
        expected_phase: FinalityVotePhase,
    ) -> Result<(), BftError> {
        self.validate_vote_target(&vote, expected_phase)?;
        let selection = vote.data.selection;
        let (covered, evicted) = self.held_coverage(&vote, expected_phase)?;
        if covered {
            return Ok(());
        }
        let stake = vote_stake(&self.active_set, &vote)?;
        let manifest_roots = self.verify_value_vote(&vote)?;
        // Only a vote that verified displaces the weakest held selection.
        if let Some(weakest) = evicted {
            match expected_phase {
                FinalityVotePhase::Prevote => self.pending_prevotes.remove(&weakest),
                FinalityVotePhase::Precommit => self.pending_precommits.remove(&weakest),
            };
        }
        let target = match (expected_phase, self.proposal.is_some()) {
            (FinalityVotePhase::Prevote, true) => &mut self.prevotes,
            (FinalityVotePhase::Precommit, true) => &mut self.precommits,
            (FinalityVotePhase::Prevote, false) => self
                .pending_prevotes
                .entry(selection)
                .or_insert_with(|| VoteAccumulator::new(FinalityVotePhase::Prevote)),
            (FinalityVotePhase::Precommit, false) => self
                .pending_precommits
                .entry(selection)
                .or_insert_with(|| VoteAccumulator::new(FinalityVotePhase::Precommit)),
        };
        target.record(vote, stake, &self.active_set, manifest_roots)
    }

    /// Whether every signer and claim of `vote` is already retained, and the
    /// weakest held selection a verified `vote` displaces from a full set.
    fn held_coverage(
        &self,
        vote: &FinalityVote,
        expected_phase: FinalityVotePhase,
    ) -> Result<(bool, Option<Hash>), BftError> {
        let pending = match expected_phase {
            FinalityVotePhase::Prevote => &self.pending_prevotes,
            FinalityVotePhase::Precommit => &self.pending_precommits,
        };
        if self.proposal.is_some() {
            return Ok((self.accumulator(expected_phase).already_covers(vote), None));
        }
        if let Some(held) = pending.get(&vote.data.selection) {
            return Ok((held.already_covers(vote), None));
        }
        if pending.len() < MAX_PENDING_SELECTIONS {
            return Ok((false, None));
        }
        let stake = vote_stake(&self.active_set, vote)?;
        let (weakest, weakest_stake) = pending
            .iter()
            .map(|(held, votes)| (*held, votes.aggregate_stake))
            .min_by_key(|(held, stake)| (*stake, *held))
            .expect("a full set holds a selection");
        if stake <= weakest_stake {
            return Err(BftError::PendingSelectionsFull);
        }
        Ok((false, Some(weakest)))
    }

    /// Exact signer and manifest coverage, the aggregate signature and every
    /// individual attestation of `vote`; yields the manifests' commitments.
    fn verify_value_vote(
        &self,
        vote: &FinalityVote,
    ) -> Result<Vec<ProofAcceptanceCommitment>, BftError> {
        let block_count = self
            .chunk
            .end_height
            .checked_sub(self.chunk.start_height)
            .and_then(|count| count.checked_add(1))
            .ok_or(BftError::WrongVoteTarget)?;
        let manifests = ProofManifestIndex::new(&vote.proof_manifests)
            .ok_or(BftError::InvalidAggregateSignature)?;
        if !manifests.covers_exact(&vote.attestations)
            || !attestation_coverage_valid(
                &vote.data,
                &vote.aggregation_bits,
                &vote.attestations,
                block_count,
            )
        {
            return Err(BftError::InvalidAggregateSignature);
        }
        let manifest_roots = manifests.commitments().collect();
        verify_vote_signature(self.domain, &self.active_set, vote)?;
        verify_attestations(
            self.domain,
            &self.active_set,
            self.total_stake,
            vote,
            self.prevote_quorum,
        )?;
        Ok(manifest_roots)
    }

    fn validate_vote_target(
        &self,
        vote: &FinalityVote,
        expected_phase: FinalityVotePhase,
    ) -> Result<(), BftError> {
        if vote.data.phase != expected_phase
            || vote.data.phase != self.accumulator(expected_phase).phase
        {
            return Err(BftError::WrongPhase);
        }
        // A value vote is for the chunk together with the selection of the
        // round's proposal; before the proposal it is held per selection and
        // counted only if the proposal names that selection.
        if vote.data.chunk_id != self.chunk.chunk_id
            || vote.data.round != self.round
            || vote.data.chunk_hash != self.chunk.hash()
            || self
                .proposal
                .as_ref()
                .is_some_and(|proposal| proposal.selection() != vote.data.selection)
        {
            return Err(BftError::WrongVoteTarget);
        }
        Ok(())
    }

    const fn accumulator(&self, phase: FinalityVotePhase) -> &VoteAccumulator {
        match phase {
            FinalityVotePhase::Prevote => &self.prevotes,
            FinalityVotePhase::Precommit => &self.precommits,
        }
    }
}
