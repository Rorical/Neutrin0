//! Construction, round advancement, quorum status and the finality certificate.

use alloc::{collections::BTreeMap, vec::Vec};

use neutrin0_consensus_types::{Chunk, FinalityCert, FinalityVotePhase};
use neutrin0_primitives::{ConsensusDomain, Hash, Seed, Validator};

use crate::accumulator::VoteAccumulator;
use crate::stake::{nil_stake, quorum_reached, total_active_stake, validate_quorum};
use crate::{BftError, ChunkBft, FinalizationStatus};

impl ChunkBft {
    /// Creates chunk-BFT state with the default 2/3 prevote and precommit quorum.
    pub fn new(
        domain: ConsensusDomain,
        chunk: Chunk,
        round: u32,
        active_set: Vec<Validator>,
        active_validator_set_root: Hash,
        seed: Seed,
    ) -> Result<Self, BftError> {
        Self::with_quorum(
            domain,
            chunk,
            round,
            active_set,
            active_validator_set_root,
            seed,
            (2, 3),
            (2, 3),
        )
    }

    /// Creates chunk-BFT state with explicit prevote and precommit quorum fractions.
    #[allow(
        clippy::too_many_arguments,
        reason = "One chunk's complete context: domain, chunk, round, set, root, seed and quorums."
    )]
    pub fn with_quorum(
        domain: ConsensusDomain,
        chunk: Chunk,
        round: u32,
        active_set: Vec<Validator>,
        active_validator_set_root: Hash,
        seed: Seed,
        prevote_quorum: (u64, u64),
        precommit_quorum: (u64, u64),
    ) -> Result<Self, BftError> {
        validate_quorum(prevote_quorum)?;
        validate_quorum(precommit_quorum)?;
        if active_set.len() > usize::try_from(u32::MAX).expect("u32::MAX fits usize") {
            return Err(BftError::ValidatorSetTooLarge);
        }
        let total_stake = total_active_stake(&active_set)?;
        Ok(Self {
            domain,
            chunk,
            round,
            active_set,
            active_validator_set_root,
            seed,
            total_stake,
            prevote_quorum,
            precommit_quorum,
            prevotes: VoteAccumulator::new(FinalityVotePhase::Prevote),
            precommits: VoteAccumulator::new(FinalityVotePhase::Precommit),
            pending_prevotes: BTreeMap::new(),
            pending_precommits: BTreeMap::new(),
            proposal: None,
            nil_prevotes: None,
            nil_precommits: None,
        })
    }

    /// Returns the BFT round currently accepting votes.
    pub const fn round(&self) -> u32 {
        self.round
    }

    /// Eligible total, value-vote and explicit nil stake in this round.
    #[must_use]
    pub fn observed_stake(&self) -> [u128; 5] {
        [
            self.total_stake,
            self.prevotes.aggregate_stake,
            self.precommits.aggregate_stake,
            self.nil_prevotes
                .as_ref()
                .and_then(|vote| nil_stake(&self.active_set, vote).ok())
                .unwrap_or(0),
            self.nil_precommits
                .as_ref()
                .and_then(|vote| nil_stake(&self.active_set, vote).ok())
                .unwrap_or(0),
        ]
    }

    /// Advance the chunk-BFT state to a fresh round.
    ///
    /// Preserves the chain id, chunk, active set, validator-set root,
    /// and quorum fractions. Vote accumulators are reset so the
    /// caller starts collecting fresh prevotes / precommits on the
    /// new round number. `new_round` must be strictly greater than
    /// the current round.
    ///
    /// # Errors
    ///
    /// Returns [`BftError::RoundNotIncreased`] when `new_round <= self.round`.
    pub fn advance_to_round(self, new_round: u32) -> Result<Self, BftError> {
        let chunk = self.chunk.clone();
        self.advance_to_candidate(chunk, new_round)
    }

    /// Reset round accumulators for a later, caller-authenticated candidate.
    /// Lock and proposal authentication remain the durable driver's duties.
    ///
    /// # Errors
    /// Rejects a non-increasing round, changed chunk range or validator-set root.
    pub fn advance_to_candidate(self, chunk: Chunk, new_round: u32) -> Result<Self, BftError> {
        if new_round <= self.round {
            return Err(BftError::RoundNotIncreased {
                current: self.round,
                requested: new_round,
            });
        }
        if chunk.chunk_id != self.chunk.chunk_id
            || chunk.start_height != self.chunk.start_height
            || chunk.end_height != self.chunk.end_height
            || chunk.active_validator_set_root != self.active_validator_set_root
        {
            return Err(BftError::WrongVoteTarget);
        }
        Ok(Self {
            domain: self.domain,
            chunk,
            round: new_round,
            active_set: self.active_set,
            active_validator_set_root: self.active_validator_set_root,
            seed: self.seed,
            total_stake: self.total_stake,
            prevote_quorum: self.prevote_quorum,
            precommit_quorum: self.precommit_quorum,
            prevotes: VoteAccumulator::new(FinalityVotePhase::Prevote),
            precommits: VoteAccumulator::new(FinalityVotePhase::Precommit),
            pending_prevotes: BTreeMap::new(),
            pending_precommits: BTreeMap::new(),
            proposal: None,
            nil_prevotes: None,
            nil_precommits: None,
        })
    }

    /// Whether the carried active-validator-set root matches `root`.
    /// Used by the live BFT loop to refuse surfacing a quorum that
    /// would produce a cert the verifier later rejects.
    #[must_use]
    pub fn validator_set_root_matches(&self, root: Hash) -> bool {
        self.active_validator_set_root == root
    }

    /// Whether the accumulated prevote stake currently meets the
    /// configured 2/3 prevote quorum.
    #[must_use]
    pub const fn prevote_quorum_reached(&self) -> bool {
        quorum_reached(
            self.prevotes.aggregate_stake,
            self.total_stake,
            self.prevote_quorum,
        )
    }

    /// Whether the accumulated precommit stake currently meets the
    /// configured 2/3 precommit quorum.
    #[must_use]
    pub const fn precommit_quorum_reached(&self) -> bool {
        quorum_reached(
            self.precommits.aggregate_stake,
            self.total_stake,
            self.precommit_quorum,
        )
    }

    /// Returns whether finalization currently has all required inputs.
    pub fn finalization_status(
        &self,
        previous_validator_set_root: Hash,
    ) -> Result<FinalizationStatus, BftError> {
        if self.active_validator_set_root != self.chunk.active_validator_set_root
            || self.active_validator_set_root != previous_validator_set_root
        {
            return Err(BftError::ValidatorSetRootMismatch);
        }
        if self.proposal.is_some()
            && quorum_reached(
                self.prevotes.aggregate_stake,
                self.total_stake,
                self.prevote_quorum,
            )
            && quorum_reached(
                self.precommits.aggregate_stake,
                self.total_stake,
                self.precommit_quorum,
            )
        {
            Ok(FinalizationStatus::Finalized)
        } else {
            Ok(FinalizationStatus::Pending)
        }
    }

    /// Attempts to build a finality certificate for the current round.
    pub fn try_finalize(
        &self,
        previous_validator_set_root: Hash,
    ) -> Result<Option<FinalityCert>, BftError> {
        if self.finalization_status(previous_validator_set_root)? != FinalizationStatus::Finalized {
            return Ok(None);
        }
        Ok(Some(FinalityCert {
            proposal: self
                .proposal
                .clone()
                .expect("finalized status requires a proposal"),
            prevote_attestations: self.prevotes.attestations.clone(),
            precommit_attestations: self.precommits.attestations.clone(),
            proof_manifests: self.current_proof_manifests(FinalityVotePhase::Precommit),
            chunk_id: self.chunk.chunk_id,
            round: self.round,
            chunk_hash: self.chunk.hash(),
            prevote: self
                .prevotes
                .aggregate()
                .expect("finalized status implies prevote quorum"),
            precommit: self
                .precommits
                .aggregate()
                .expect("finalized status implies precommit quorum"),
            active_validator_set_root: self.active_validator_set_root,
        }))
    }
}
