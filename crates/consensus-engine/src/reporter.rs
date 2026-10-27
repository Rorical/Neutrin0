//! Selective, durable forensic discovery without widening live BFT history admission.

use crate::availability::carried_quorums;
use crate::{Engine, RetentionPolicy, SlashingError, SlashingMonitor, StoreError};
use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
use neutrin0_consensus_types::{
    FinalityVotePhase, Header, IndexedVote, QuorumCertificate, SlashingEvidence,
};
use neutrin0_primitives::{BlsPublicKey, Seed, Validator};
use neutrin0_storage::Database;

/// Historical BLS identity and the withdrawal address whose slashable balance is queried.
pub type ReporterIdentity = (BlsPublicKey, [u8; 32]);

impl<DB: Database> Engine<DB> {
    /// Conservatively add authenticated active memberships before an economic query can fail.
    pub fn seed_reporter_tracking(&mut self) -> Result<(), StoreError<DB::Error>> {
        let identities: Vec<_> = self
            .active_validator_set()
            .iter()
            .filter(|v| v.effective_stake > 0)
            .map(|v| (v.pubkey, v.withdrawal_credentials))
            .collect();
        self.store_mut().seed_reporter_tracking(&identities)
    }

    /// Durable watched identities plus current active memberships awaiting economic classification.
    pub fn reporter_tracked_validators(
        &self,
    ) -> Result<Vec<ReporterIdentity>, StoreError<DB::Error>> {
        let mut result = self.store().reporter_tracked_validators()?;
        result.extend(
            self.active_validator_set()
                .iter()
                .filter(|v| v.effective_stake > 0)
                .map(|v| (v.pubkey, v.withdrawal_credentials)),
        );
        result.sort_unstable();
        result.dedup();
        Ok(result)
    }

    /// Update material ownership using only the caller's finalized runtime economic query.
    pub fn set_reporter_eligible(
        &mut self,
        identities: &[(BlsPublicKey, [u8; 32])],
    ) -> Result<Vec<neutrin0_primitives::Hash>, StoreError<DB::Error>> {
        let chunk_size = self.chain_spec().consensus.chunk_size;
        self.store_mut()
            .set_reporter_eligible(identities, chunk_size)
    }

    /// Whether this reporter retains any watched historical record.
    pub fn reporter_has_history(&self) -> Result<bool, StoreError<DB::Error>> {
        self.store().reporter_has_history()
    }

    /// Chunk ranges `[from, to)` a snapshot bootstrap jumped over unobserved.
    pub fn reporter_gaps(&self) -> Result<Vec<(u64, u64)>, StoreError<DB::Error>> {
        self.store().reporter_gaps()
    }

    /// Watched chunks whose paths a snapshot bootstrap left dormant.
    pub fn reporter_dormant_chunks(&self) -> Result<Vec<u64>, StoreError<DB::Error>> {
        self.store().reporter_dormant_chunks()
    }

    /// Revive a dormant watched path from a peer's opening of the same leaf
    /// under this node's latest finalized boundary. Returns whether it applied.
    pub fn refresh_reporter_path(
        &mut self,
        opening: &neutrin0_consensus_types::history_proof::AnchorOpening,
    ) -> Result<bool, StoreError<DB::Error>> {
        let count = self.finalized_next_chunk_id();
        if opening.path.count != count || opening.context.chunk_id != opening.path.index {
            return Ok(false);
        }
        let root = self
            .canonical_boundary(count)
            .map_err(|_| StoreError::Corrupt("reporter refresh boundary"))?
            .history_root;
        self.store_mut().refresh_reporter_path(&opening.path, root)
    }

    /// Validators of `chunk`: the accountability window first, then, on a
    /// reporter, its retained record of an older chunk.
    pub(crate) fn forensic_validators(&self, chunk: u64) -> Result<Vec<Validator>, SlashingError> {
        self.forensic_context(chunk)
            .map(|(validators, _)| validators)
    }

    /// [`Self::forensic_validators`] with the chunk's incoming seed, which
    /// draws its round leaders.
    pub(crate) fn forensic_context(
        &self,
        chunk: u64,
    ) -> Result<(Vec<Validator>, Seed), SlashingError> {
        if let Ok(context) = self.accountability_context(chunk) {
            return Ok(context);
        }
        if self
            .retention_info()
            .map_err(|_| SlashingError::NotYetFinalizedLocally)?
            .policy
            != RetentionPolicy::Reporter
        {
            return Err(SlashingError::SourceOutsideAccountabilityWindow);
        }
        let record = self
            .store()
            .reporter_record(chunk)
            .map_err(|_| SlashingError::NotYetFinalizedLocally)?
            .or_else(|| self.store().historical_chunk(chunk).ok().flatten())
            .ok_or(SlashingError::SourceOutsideAccountabilityWindow)?;
        Ok((record.validators, record.seed))
    }

    /// The validator set a header's proposer signed under, with that
    /// proposer active in it.
    pub(crate) fn forensic_header_validators(
        &self,
        header: &Header,
    ) -> Result<Vec<Validator>, SlashingError> {
        let chunk = self
            .chunk_of_height(header.height)
            .ok_or(SlashingError::EvidenceFieldsInconsistent)?;
        let validators = self.forensic_validators(chunk)?;
        let validator = validators
            .get(header.proposer_index as usize)
            .ok_or(SlashingError::EvidenceFieldsInconsistent)?;
        if validator.effective_stake == 0 {
            return Err(SlashingError::EvidenceFieldsInconsistent);
        }
        Ok(validators)
    }

    /// Rebuild a watched chunk from durable sources, restoring all quorum dependencies first.
    pub(crate) fn observe_reporter_artifact(
        &self,
        chunk: u64,
        extra: Option<&SignedArtifact>,
    ) -> Result<Vec<SlashingEvidence>, StoreError<DB::Error>> {
        let mut sources = self.store().reporter_sources_for_chunk(chunk)?;
        if let Some(record) = self.store().historical_chunk(chunk)? {
            sources.push(SignedArtifact::Proposal(Box::new(
                record.finality.proposal.clone(),
            )));
            sources.push(SignedArtifact::Vote(record.finality.prevote_vote()));
            sources.push(SignedArtifact::Vote(record.finality.precommit_vote()));
        }
        if let Some(artifact) = extra {
            sources.push(artifact.clone());
        }
        sources.retain(|artifact| self.validate_signed_artifact(artifact));
        sources.sort_by_key(|source| match source {
            SignedArtifact::Vote(vote) => (vote.data.round, 1u8),
            SignedArtifact::NilVote(vote) => (vote.data.round, 2),
            SignedArtifact::Proposal(value) => (value.round, 3),
            _ => (0, 0),
        });
        let mut monitor = SlashingMonitor::for_reporter();
        for source in &sources {
            self.reporter_quorums(&mut monitor, source);
        }
        let mut evidence = Vec::new();
        for source in &sources {
            match source {
                SignedArtifact::Vote(vote) => {
                    for claim in &vote.attestations {
                        monitor.record_attestation(claim.clone());
                        let indexed = IndexedVote {
                            data: claim.vote.clone(),
                            signature: claim.vote_signature,
                        };
                        evidence
                            .extend(monitor.record_indexed_vote(claim.validator_index, &indexed));
                    }
                }
                SignedArtifact::NilVote(vote) => evidence.extend(monitor.record_nil_vote(vote)),
                SignedArtifact::Proposal(value) => {
                    evidence.extend(monitor.record_bft_proposal(value));
                }
                _ => {}
            }
        }
        let mut headers = self.store().reporter_headers_for_chunk(chunk)?;
        headers.sort_by_key(|header| (header.slot, header.hash()));
        for header in headers {
            if self.chunk_of_height(header.height) != Some(chunk) {
                continue;
            }
            // Only equivocation is an offence: a header whose VRF claim
            // fails can never become canonical, so it is merely rejected.
            if let Ok(validators) = self.forensic_header_validators(&header)
                && crate::signature::verify_header_signature(
                    &header,
                    &validators,
                    self.consensus_domain(),
                )
                .is_ok()
            {
                evidence.extend(monitor.record_header(chunk, &header));
            }
        }
        let validators = self
            .forensic_validators(chunk)
            .map_err(|_| StoreError::Corrupt("reporter source context"))?;
        let eligible: Vec<_> = self
            .store()
            .reporter_tracked_validators()?
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        evidence.retain(|claim| {
            validators
                .get(claim.offender_index() as usize)
                .is_some_and(|v| eligible.contains(&v.pubkey))
                && self.verify_slashing_evidence(claim).is_ok()
        });
        Ok(evidence)
    }

    fn reporter_quorums(&self, monitor: &mut SlashingMonitor, artifact: &SignedArtifact) {
        let mut record = |quorum: &QuorumCertificate| {
            let validators = self
                .forensic_validators(quorum.data.chunk_id)
                .unwrap_or_default();
            let params = &self.chain_spec().consensus;
            if neutrin0_prover_chunk::slashing::verify_quorum_using(
                self.consensus_domain(),
                &validators,
                quorum,
                (
                    params.bft_prevote_quorum_numerator,
                    params.bft_prevote_quorum_denominator,
                ),
                &mut *self.bls_verifier.borrow_mut(),
            )
            .is_ok()
            {
                monitor.record_prevote_quorum(quorum.clone());
            }
        };
        for quorum in carried_quorums(artifact) {
            record(quorum);
        }
        if let SignedArtifact::Vote(vote) = artifact
            && vote.data.phase == FinalityVotePhase::Prevote
        {
            // An aggregate is usable as a lock only if it independently meets quorum weight.
            let quorum = QuorumCertificate {
                data: vote.data.clone(),
                aggregate: neutrin0_consensus_types::AggregatedVote {
                    aggregation_bits: vote.aggregation_bits.clone(),
                    signature: vote.signature,
                },
            };
            record(&quorum);
        }
    }

    /// Restore long-lived sources after restart without relying on the bounded live monitor.
    pub(crate) fn replay_reporter_sources(
        &self,
    ) -> Result<Vec<SlashingEvidence>, StoreError<DB::Error>> {
        let mut evidence = Vec::new();
        for chunk in self.store().reporter_history_chunks()? {
            evidence.extend(self.observe_reporter_artifact(chunk, None)?);
        }
        Ok(evidence)
    }
}
