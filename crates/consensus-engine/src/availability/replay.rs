//! Order-independent replay of retained signed sources into the slashing
//! monitor.

use crate::{Engine, StoreError};
use neutrin0_consensus_types::SlashingEvidence;
use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
use neutrin0_primitives::ChunkId;
use neutrin0_storage::Database;

use super::carried_quorums;

impl<DB: Database> Engine<DB> {
    /// Observe authenticated sources; only related same-chunk future votes are
    /// revisited when a delayed prior precommit or locking quorum arrives.
    pub fn observe_signed_artifact(
        &mut self,
        artifact: &SignedArtifact,
    ) -> Result<Vec<SlashingEvidence>, StoreError<DB::Error>> {
        if !self.validate_signed_artifact(artifact) {
            return Err(StoreError::Corrupt("signed source replay authentication"));
        }
        if self.retention_info()?.policy == crate::RetentionPolicy::Reporter {
            let chunk = artifact
                .chunk_id(self.chunk_size())
                .ok_or(StoreError::Corrupt("reporter source range"))?;
            self.store_mut().retain_reporter_source(chunk, artifact)?;
            return self.observe_reporter_artifact(chunk, Some(artifact));
        }
        let restore_precommit = self.introduces_quorum(artifact);
        let mut evidence = self.observe_source(artifact);
        let Some((chunk, round, signers)) = Self::replay_dependency(artifact) else {
            return Ok(evidence);
        };
        let id = artifact.id();
        let mut metadata = self.store().signed_artifact_metadata_for_chunk(chunk)?;
        metadata.sort_by_key(|item| (item.round, item.phase));
        for item in metadata.into_iter().filter(|item| {
            item.kind == neutrin0_consensus_types::signed_artifacts::SignedArtifactKind::Vote
                && item.id != id
                && item.round.is_some_and(|later| {
                    later > round
                        || (restore_precommit
                            && later == round
                            && item.phase
                                == Some(neutrin0_consensus_types::FinalityVotePhase::Precommit))
                })
                && (signers.is_empty()
                    || item.signers.iter().any(|signer| signers.contains(signer)))
        }) {
            if let Some((_, related)) = self.store().signed_artifact(&item.id)?
                && self.validate_signed_artifact(&related)
            {
                evidence.extend(self.observe_source(&related));
            }
        }
        Ok(evidence)
    }

    fn introduces_quorum(&self, artifact: &SignedArtifact) -> bool {
        carried_quorums(artifact)
            .any(|quorum| !self.slashing_monitor.prevote_quorum_is_observed(quorum))
    }

    fn replay_dependency(artifact: &SignedArtifact) -> Option<(u64, u32, Vec<u32>)> {
        let carried = carried_quorums(artifact)
            .map(|quorum| quorum.data.round)
            .min();
        let chunk = match artifact {
            SignedArtifact::Vote(value) => {
                if value.data.phase == neutrin0_consensus_types::FinalityVotePhase::Prevote
                    && carried.is_none()
                {
                    return None;
                }
                let round = carried.map_or(value.data.round, |round| round.min(value.data.round));
                let signers = if carried.is_some() {
                    Vec::new()
                } else {
                    value
                        .attestations
                        .iter()
                        .map(|claim| claim.validator_index)
                        .collect()
                };
                return Some((value.data.chunk_id, round, signers));
            }
            SignedArtifact::Quorum(value) => value.data.chunk_id,
            SignedArtifact::RoundChange(value) => value.chunk_id,
            SignedArtifact::RoundChangeCertificate(value) => value.chunk_id,
            SignedArtifact::Proposal(value) => value.chunk.chunk_id,
            SignedArtifact::BlockProof(_) | SignedArtifact::NilVote(_) => return None,
        };
        Some((chunk, carried?, Vec::new()))
    }

    /// Compare the individually signed parts of an authenticated artifact
    /// with the journal (see [`crate::Doppelganger`]). Votes are compared
    /// one signer at a time where they are attributed.
    fn check_artifact_doppelganger(&mut self, artifact: &SignedArtifact) {
        use crate::signing::Seen;
        let (chunk, signers, seen): (ChunkId, Vec<u32>, Seen<'_>) = match artifact {
            SignedArtifact::NilVote(value) => (
                value.data.chunk_id,
                value
                    .attestations
                    .iter()
                    .map(|claim| claim.validator_index)
                    .collect(),
                Seen::NilVote(&value.data),
            ),
            SignedArtifact::Proposal(value) => (
                value.chunk.chunk_id,
                vec![value.proposer_index],
                Seen::Proposal(value),
            ),
            SignedArtifact::RoundChange(value) => (
                value.chunk_id,
                vec![value.validator_index],
                Seen::RoundChange(value),
            ),
            _ => return,
        };
        let Ok(validators) = self.accountability_validators(chunk) else {
            return;
        };
        for signer in signers {
            if let Some(validator) = validators.get(signer as usize) {
                self.check_doppelganger(&validator.pubkey, &seen);
            }
        }
    }

    fn observe_source(&mut self, artifact: &SignedArtifact) -> Vec<SlashingEvidence> {
        self.check_artifact_doppelganger(artifact);
        // Quorums carried by votes and proposals are checked individually; the
        // other carriers were authenticated together with their quorums.
        let check = matches!(
            artifact,
            SignedArtifact::Vote(_) | SignedArtifact::Proposal(_)
        );
        for quorum in carried_quorums(artifact) {
            if !check || self.authenticate_artifact_quorum(quorum).is_ok() {
                self.slashing_monitor.record_prevote_quorum(quorum.clone());
            }
        }
        match artifact {
            SignedArtifact::Vote(value) => {
                self.observe_votes_for_slashing(value).unwrap_or_default()
            }
            SignedArtifact::NilVote(value) => self.slashing_monitor.record_nil_vote(value),
            SignedArtifact::Proposal(value) => self
                .slashing_monitor
                .record_bft_proposal(value)
                .into_iter()
                .collect(),
            SignedArtifact::Quorum(_)
            | SignedArtifact::RoundChange(_)
            | SignedArtifact::RoundChangeCertificate(_)
            | SignedArtifact::BlockProof(_) => Vec::new(),
        }
    }

    /// Native authenticated nil attribution before consensus target/round filtering.
    pub fn observe_nil_votes_for_slashing(
        &mut self,
        vote: &neutrin0_consensus_types::NilVote,
    ) -> Result<Vec<SlashingEvidence>, crate::SlashingError> {
        let artifact = SignedArtifact::NilVote(vote.clone());
        if !self.validate_signed_artifact(&artifact) {
            return Err(crate::SlashingError::BadSignature);
        }
        Ok(self.observe_source(&artifact))
    }

    /// One restart replay restores quorum dependencies before round-ordered signed
    /// votes; no cached verdict bypasses current historical membership checks.
    pub fn replay_signed_artifacts(
        &mut self,
    ) -> Result<Vec<SlashingEvidence>, StoreError<DB::Error>> {
        let mut metadata = self.store().active_signed_artifact_metadata()?;
        metadata.sort_by_key(|item| {
            (
                item.kind != neutrin0_consensus_types::signed_artifacts::SignedArtifactKind::Quorum,
                item.chunk_id,
                item.round,
            )
        });
        let mut evidence = Vec::new();
        let reporter = self.retention_info()?.policy == crate::RetentionPolicy::Reporter;
        if reporter {
            evidence.extend(self.replay_reporter_sources()?);
        }
        for item in metadata {
            if item.kind
                == neutrin0_consensus_types::signed_artifacts::SignedArtifactKind::BlockProof
            {
                continue;
            }
            if let Some((_, artifact)) = self.store().signed_artifact(&item.id)?
                && self.validate_signed_artifact(&artifact)
            {
                if reporter {
                    evidence.extend(self.observe_signed_artifact(&artifact)?);
                } else {
                    evidence.extend(self.observe_source(&artifact));
                }
            }
        }
        Ok(evidence)
    }

    /// Prune only from local finality, which every finalized chunk receipt
    /// proves from the specification's start; archive nodes retain source
    /// data. Saturation returns an explicit publication error.
    pub fn prune_availability_sources(&mut self) -> Result<(), StoreError<DB::Error>> {
        let floor = self
            .finalized_next_chunk_id()
            .saturating_sub(neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS);
        self.store_mut().prune_signed_artifacts(floor)
    }
}
