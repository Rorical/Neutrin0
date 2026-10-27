//! Cross-round lock violation synthesis from indexed observations.

use neutrin0_consensus_types::{
    FinalityVoteData, FinalityVotePhase, IndexedVote, LockEvidence, SlashingEvidence,
};
use neutrin0_primitives::ValidatorIndex;

use super::SlashingMonitor;

impl SlashingMonitor {
    /// Look for a prior precommit by `validator_index` for the same
    /// `chunk_id`, at a strictly earlier `round`, voting for a
    /// different value than `new_vote`. Returns the prior round + the prior
    /// vote on the newest match so an earlier superseded lock cannot hide a
    /// violation of the validator's latest signed lock.
    fn find_prior_conflicting_precommit(
        &self,
        validator_index: ValidatorIndex,
        new_vote: &FinalityVoteData,
    ) -> Option<(u32, IndexedVote)> {
        let (chunk_id, new_round) = (new_vote.chunk_id, new_vote.round);
        // Keys order by (validator, chunk, round, phase) and `Prevote` is the
        // least phase, so this range is exactly the signer's earlier rounds.
        let earlier = (validator_index, chunk_id, 0, FinalityVotePhase::Prevote)
            ..(
                validator_index,
                chunk_id,
                new_round,
                FinalityVotePhase::Prevote,
            );
        self.seen_votes
            .range(earlier)
            .rev()
            .find_map(|((_, _, round, phase), vote)| {
                if *phase == FinalityVotePhase::Precommit && !vote.data.same_value(new_vote) {
                    Some((*round, vote.clone()))
                } else {
                    None
                }
            })
    }

    /// Attempt to synthesise [`SlashingEvidence::LockViolation`]
    /// from the just-recorded vote. Implements rule 2 of
    /// [`Self::record_indexed_vote`]: needs both a prior
    /// conflicting precommit AND a locally-observed lock quorum at
    /// the prior round, AND no honest-unlock quorum in between.
    pub(super) fn try_synthesize_lock_violation(
        &self,
        validator_index: ValidatorIndex,
        new_vote: &IndexedVote,
    ) -> Option<SlashingEvidence> {
        // The direct claim lookup precedes the range scan; all three are required.
        let attestation = self.attestations.get(&(
            validator_index,
            new_vote.data.chunk_id,
            new_vote.data.round,
            new_vote.data.chunk_hash,
            new_vote.data.selection,
            new_vote.data.phase,
        ))?;
        let (prior_round, prior_vote) =
            self.find_prior_conflicting_precommit(validator_index, &new_vote.data)?;
        if self.relocked_on_target(validator_index, prior_round, &new_vote.data) {
            return None;
        }
        let lock_key = (
            new_vote.data.chunk_id,
            prior_round,
            prior_vote.data.chunk_hash,
            prior_vote.data.selection,
        );
        let lock_quorum = self.observed_prevote_quorums.get(&lock_key)?;
        Some(SlashingEvidence::LockViolation {
            validator_index,
            vote_a: prior_vote,
            vote_b: new_vote.clone(),
            lock_evidence: LockEvidence {
                locked_prevote_quorum: lock_quorum.clone(),
                attestation: attestation.clone(),
            },
        })
    }

    /// Whether the signer precommitted `target`'s value at a round strictly
    /// between `after` and `target.round` under a locally observed prevote
    /// quorum for it.
    ///
    /// That precommit moved the signer's lock to the target value, so a later
    /// vote for it agrees with its lock whatever unlock it declares; any lock
    /// violation lies in that precommit itself and was examined when it arrived.
    fn relocked_on_target(
        &self,
        validator_index: ValidatorIndex,
        after: u32,
        target: &FinalityVoteData,
    ) -> bool {
        let (chunk_id, before) = (target.chunk_id, target.round);
        let Some(first) = after.checked_add(1) else {
            return false;
        };
        if first >= before {
            return false;
        }
        let between = (validator_index, chunk_id, first, FinalityVotePhase::Prevote)
            ..(
                validator_index,
                chunk_id,
                before,
                FinalityVotePhase::Prevote,
            );
        self.seen_votes
            .range(between)
            .any(|((_, _, round, phase), vote)| {
                *phase == FinalityVotePhase::Precommit
                    && vote.data.same_value(target)
                    && self.observed_prevote_quorums.contains_key(&(
                        chunk_id,
                        *round,
                        target.chunk_hash,
                        target.selection,
                    ))
            })
    }
}
