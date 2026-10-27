//! Slashing observation of headers, votes and certificates under the
//! authenticated accountability window.

extern crate alloc;

use neutrin0_consensus_types::{FinalityVote, Header, SlashingEvidence};
use neutrin0_primitives::{ChunkId, Height, Seed, Validator};
use neutrin0_storage::Database;

use super::{Engine, prevote_quorum};
use crate::slashing::{self, SlashingError};

impl<DB: Database> Engine<DB> {
    /// Observe a signed header for slashing detection.
    ///
    /// Authenticates the header's current or retained historical validator
    /// context, verifies the proposer signature, and then records the header.
    /// Returns [`SlashingEvidence::DoubleProposal`] if
    /// the same proposer has already been observed signing a
    /// *different* header at the same slot.
    ///
    /// Headers that fail signature verification surface
    /// [`SlashingError::BadSignature`] (or the relevant `Invalid*`
    /// variant) and are *not* recorded.
    ///
    /// # Errors
    ///
    /// Returns the matching [`SlashingError`] variant on signature
    /// failure or when the source is outside the accountability window.
    pub fn observe_header_for_slashing(
        &mut self,
        header: &Header,
    ) -> Result<Option<SlashingEvidence>, SlashingError> {
        let source_chunk = self.accountability_chunk_for_height(header.height)?;
        let validators = self.forensic_header_validators(header)?;
        crate::signature::verify_header_signature(header, &validators, self.consensus_domain())?;
        if let Some(validator) = validators.get(header.proposer_index as usize) {
            self.check_doppelganger(&validator.pubkey, &crate::signing::Seen::Header(header));
        }
        if self
            .retention_info()
            .map_err(|_| SlashingError::NotYetFinalizedLocally)?
            .policy
            == crate::RetentionPolicy::Reporter
        {
            self.store_mut()
                .retain_reporter_header(source_chunk, header, &validators)
                .map_err(|_| SlashingError::NotYetFinalizedLocally)?;
            return Ok(self
                .observe_reporter_artifact(source_chunk, None)
                .map_err(|_| SlashingError::NotYetFinalizedLocally)?
                .into_iter()
                .next());
        }
        self.retain_accountability_observations();
        Ok(self.slashing_monitor.record_header(source_chunk, header))
    }

    /// Signed headers this node observed at heights of chunk `chunk_id`,
    /// which abandonment detection compares with the canonical blocks: the
    /// slashing monitor's, and the stale subtree roots kept durably, which a
    /// restart does not lose.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn observed_headers(
        &self,
        chunk_id: ChunkId,
    ) -> Result<alloc::vec::Vec<Header>, crate::StoreError<DB::Error>> {
        let size = self.chain_spec().consensus.chunk_size;
        let first = chunk_id.saturating_mul(size).saturating_add(1);
        let last = chunk_id.saturating_add(1).saturating_mul(size);
        let mut headers = self.store().abandoned_headers(first, last)?;
        for header in self.slashing_monitor.headers_in_chunk(chunk_id) {
            if !headers.iter().any(|kept| kept.hash() == header.hash()) {
                headers.push(header.clone());
            }
        }
        Ok(headers)
    }

    pub(crate) fn accountability_context(
        &self,
        chunk_id: ChunkId,
    ) -> Result<(alloc::vec::Vec<Validator>, Seed), SlashingError> {
        let next = self.finalized_next_chunk_id();
        if chunk_id == next {
            return Ok((self.active_validator_set().to_vec(), self.finalized_seed()));
        }
        if !neutrin0_consensus_types::history::is_recent_history_index(chunk_id, next) {
            return Err(SlashingError::SourceOutsideAccountabilityWindow);
        }
        let record = self
            .store()
            .historical_chunk(chunk_id)
            .map_err(|_| SlashingError::NotYetFinalizedLocally)?
            .ok_or(SlashingError::NotYetFinalizedLocally)?;
        Ok((record.validators, record.seed))
    }

    /// Recheck unlock policy while reusing only the exact BLS equation verdict.
    pub(crate) fn verify_bft_unlock_quorum(
        &self,
        validators: &[Validator],
        vote: &neutrin0_consensus_types::FinalityVoteData,
        quorum: &neutrin0_consensus_types::QuorumCertificate,
    ) -> Result<(), neutrin0_prover_chunk::slashing::EvidenceError> {
        let params = &self.chain_spec().consensus;
        neutrin0_prover_chunk::slashing::verify_unlock_using(
            self.consensus_domain(),
            validators,
            vote,
            quorum,
            (
                params.bft_prevote_quorum_numerator,
                params.bft_prevote_quorum_denominator,
            ),
            &mut *self.bls_verifier.borrow_mut(),
        )
    }

    pub(crate) fn accountability_validators(
        &self,
        chunk_id: ChunkId,
    ) -> Result<alloc::vec::Vec<Validator>, SlashingError> {
        self.accountability_context(chunk_id)
            .map(|(validators, _)| validators)
    }

    pub(super) fn accountability_chunk_for_height(
        &self,
        height: Height,
    ) -> Result<ChunkId, SlashingError> {
        self.chunk_of_height(height)
            .ok_or(SlashingError::EvidenceFieldsInconsistent)
    }

    pub(super) fn retain_accountability_observations(&mut self) {
        let first = self
            .finalized_next_chunk_id()
            .saturating_sub(neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS);
        self.slashing_monitor.retain_history_window(first);
    }

    /// Attribute every signer of an aggregate, retaining all independently valid evidence.
    pub fn observe_votes_for_slashing(
        &mut self,
        vote: &FinalityVote,
    ) -> Result<alloc::vec::Vec<SlashingEvidence>, SlashingError> {
        let votes = self.attributable_votes(vote)?;
        let mut evidence = alloc::vec::Vec::new();
        for individual in votes {
            if let Some(item) = self.observe_vote_for_slashing(&individual)? {
                evidence.push(item);
            }
        }
        Ok(evidence)
    }

    pub(super) fn attributable_votes(
        &self,
        vote: &FinalityVote,
    ) -> Result<alloc::vec::Vec<FinalityVote>, SlashingError> {
        let validators = self.accountability_validators(vote.data.chunk_id)?;
        let manifests = neutrin0_consensus_types::ProofManifestIndex::new(&vote.proof_manifests)
            .filter(|index| index.covers_exact(&vote.attestations))
            .ok_or(SlashingError::EvidenceFieldsInconsistent)?;
        if slashing::extract_single_signer(vote, validators.len()).is_some() {
            return Ok(alloc::vec![vote.clone()]);
        }
        neutrin0_prover_chunk::finality::verify_vote_signatures_using(
            self.consensus_domain(),
            &validators,
            vote,
            &self.chain_spec().consensus,
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| SlashingError::BadSignature)?;
        vote.attestations
            .iter()
            .map(|claim| {
                let mut bits = neutrin0_primitives::BitVec::default();
                for index in 0..vote.aggregation_bits.bit_len() {
                    bits.push(index == claim.validator_index);
                }
                let proof_manifests = claim
                    .proof_acceptance
                    .map(|acceptance| {
                        manifests
                            .get(&acceptance)
                            .cloned()
                            .ok_or(SlashingError::EvidenceFieldsInconsistent)
                    })
                    .transpose()?
                    .into_iter()
                    .collect();
                Ok(FinalityVote {
                    data: claim.vote.clone(),
                    aggregation_bits: bits,
                    signature: claim.vote_signature,
                    attestations: alloc::vec![claim.clone()],
                    proof_manifests,
                })
            })
            .collect()
    }

    /// Observe an authenticated finality certificate, including its locking quorum.
    pub fn observe_certificate_for_slashing(
        &mut self,
        chunk: &neutrin0_consensus_types::Chunk,
        certificate: &neutrin0_consensus_types::FinalityCert,
    ) -> Result<alloc::vec::Vec<SlashingEvidence>, SlashingError> {
        let (validators, seed) = self.accountability_context(chunk.chunk_id)?;
        neutrin0_prover_chunk::finality::verify_finality_using(
            self.consensus_domain(),
            &self.chain_spec().consensus,
            &validators,
            &seed,
            chunk,
            certificate,
            &mut *self.bls_verifier.borrow_mut(),
        )
        .map_err(|_| SlashingError::BadSignature)?;
        self.retain_accountability_observations();
        // Rehydrate the persisted canonical certificate so restart/rotation does
        // not discard attribution for a conflicting finality certificate.
        if let Some(record) = self
            .store()
            .historical_chunk(chunk.chunk_id)
            .map_err(|_| SlashingError::BadSignature)?
        {
            let prior_prevote = record.finality.prevote_vote();
            let prior = record.finality.precommit_vote();
            self.slashing_monitor
                .record_prevote_quorum(prevote_quorum(&record.finality));
            self.observe_votes_for_slashing(&prior_prevote)?;
            self.observe_votes_for_slashing(&prior)?;
        }
        let prevote = certificate.prevote_vote();
        let vote = certificate.precommit_vote();
        self.slashing_monitor
            .record_prevote_quorum(prevote_quorum(certificate));
        let mut evidence = self.observe_votes_for_slashing(&prevote)?;
        evidence.extend(self.observe_votes_for_slashing(&vote)?);
        // The precommit's signers were just authenticated; without a cached
        // rejected envelope there is no proof acceptance left to attribute.
        if !self.rejected_proofs.is_empty() {
            evidence.extend(self.observe_vote_for_invalid_proof_signing(&vote)?);
        }
        Ok(evidence)
    }

    /// Observe a finality vote for slashing detection.
    ///
    /// Only single-signer (partial) votes participate in detection.
    /// Use [`Self::observe_votes_for_slashing`] for aggregate envelopes; it
    /// recovers individually signed votes from their mandatory attestations.
    ///
    /// The vote's BLS signature is verified before recording, reusing the
    /// exact verdict import already reached, so a malicious peer cannot
    /// pollute the monitor with forged commitments. On signature failure the call returns
    /// [`SlashingError::BadSignature`] and nothing is recorded.
    ///
    /// # Errors
    ///
    /// Returns [`SlashingError`] when the vote's signature fails to
    /// verify or the carried validator index is outside the active
    /// set.
    pub fn observe_vote_for_slashing(
        &mut self,
        vote: &FinalityVote,
    ) -> Result<Option<SlashingEvidence>, SlashingError> {
        let validators = self.accountability_validators(vote.data.chunk_id)?;
        let active_set_len = validators.len();
        let Some((signer, indexed)) = slashing::extract_single_signer(vote, active_set_len) else {
            return Ok(None);
        };
        // Round-trip the per-validator signature against the active
        // set so we record nothing that was not actually signed by
        // the claimed validator.
        slashing::verify_indexed_vote_signature_using(
            signer,
            &indexed,
            &validators,
            self.consensus_domain(),
            &mut *self.bls_verifier.borrow_mut(),
        )?;
        if let Some(validator) = validators.get(signer as usize) {
            self.check_doppelganger(
                &validator.pubkey,
                &crate::signing::Seen::Vote(&indexed.data),
            );
        }
        self.retain_accountability_observations();
        for attestation in &vote.attestations {
            if slashing::verify_vote_attestation_using(
                attestation,
                signer,
                &indexed.data,
                &validators,
                self.consensus_domain(),
                &mut *self.bls_verifier.borrow_mut(),
            )
            .is_ok()
            {
                if let Some(quorum) = &attestation.unlock_quorum
                    && quorum.data.chunk_id == indexed.data.chunk_id
                    && quorum.data.round <= indexed.data.round
                    && neutrin0_prover_chunk::slashing::verify_quorum_using(
                        self.consensus_domain(),
                        &validators,
                        quorum,
                        (
                            self.chain_spec().consensus.bft_prevote_quorum_numerator,
                            self.chain_spec().consensus.bft_prevote_quorum_denominator,
                        ),
                        &mut *self.bls_verifier.borrow_mut(),
                    )
                    .is_ok()
                {
                    self.slashing_monitor.record_prevote_quorum(quorum.clone());
                }
                self.slashing_monitor
                    .record_attestation(attestation.clone());
            }
        }
        let evidence = self.slashing_monitor.record_indexed_vote(signer, &indexed);
        Ok(evidence.filter(|evidence| self.verify_slashing_evidence(evidence).is_ok()))
    }
}
