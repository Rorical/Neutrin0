//! Verification of peer-supplied slashing evidence against authenticated
//! validator contexts.

use neutrin0_consensus_types::{FinalityVotePhase, Header, SlashingEvidence};
use neutrin0_primitives::Height;
use neutrin0_storage::Database;

use super::Engine;
use crate::slashing::{
    self, SlashingError, verify_double_proposal_evidence, verify_double_vote_evidence,
    verify_lock_violation_evidence,
};

impl<DB: Database> Engine<DB> {
    /// Verify peer-supplied [`SlashingEvidence`] against the
    /// authenticated current or retained historical validator context and seed.
    ///
    /// Used by the chain backend when ingesting evidence off
    /// `Topic::SlashingEvidence` so a node refuses to pool forged
    /// or stale claims.
    ///
    /// # Errors
    ///
    /// Returns the matching [`SlashingError`] on any failed check.
    pub fn verify_slashing_evidence(
        &self,
        evidence: &SlashingEvidence,
    ) -> Result<(), SlashingError> {
        match evidence {
            SlashingEvidence::DoubleProposal {
                proposer_index,
                header_a,
                header_b,
            } => self.verify_historical_double_proposal(*proposer_index, header_a, header_b),
            SlashingEvidence::DoublePrevote {
                validator_index,
                vote_a,
                vote_b,
            }
            | SlashingEvidence::DoublePrecommit {
                validator_index,
                vote_a,
                vote_b,
            } => {
                let phase = if matches!(evidence, SlashingEvidence::DoublePrevote { .. }) {
                    FinalityVotePhase::Prevote
                } else {
                    FinalityVotePhase::Precommit
                };
                verify_double_vote_evidence(
                    *validator_index,
                    phase,
                    vote_a,
                    vote_b,
                    &self.forensic_validators(vote_a.data.chunk_id)?,
                    self.consensus_domain(),
                )
            }
            SlashingEvidence::ConflictingNilVote {
                validator_index,
                value_vote,
                nil_vote,
            } => self.verify_bft_nil_conflict(*validator_index, value_vote, nil_vote),
            SlashingEvidence::DoubleBftProposal {
                proposer_index,
                proposal_a,
                proposal_b,
            } => self.verify_bft_leader_conflict(*proposer_index, proposal_a, proposal_b),
            SlashingEvidence::LockViolation {
                validator_index,
                vote_a,
                vote_b,
                lock_evidence,
            } => verify_lock_violation_evidence(
                *validator_index,
                vote_a,
                vote_b,
                lock_evidence,
                &self.forensic_validators(vote_a.data.chunk_id)?,
                self.consensus_domain(),
                (
                    self.chain_spec().consensus.bft_prevote_quorum_numerator,
                    self.chain_spec().consensus.bft_prevote_quorum_denominator,
                ),
            ),
            SlashingEvidence::InvalidProofSigning {
                validator_index,
                vote,
                attestation,
                rejected_proof,
                proof_opening,
                reason: _,
            } => slashing::verify_proof_signing_attribution(
                *validator_index,
                vote,
                attestation,
                rejected_proof,
                proof_opening,
                &self.forensic_validators(vote.data.chunk_id)?,
                self.consensus_domain(),
                self.chunk_size(),
            ),
            SlashingEvidence::DaCommitmentFraud {
                proposer_index,
                header,
                fraud_proof,
            } => self.verify_da_commitment_fraud(*proposer_index, header, fraud_proof),
            SlashingEvidence::InvalidExecutionClaim { header, .. } => {
                self.verify_invalid_execution_claim(header.height, evidence)
            }
        }
    }

    /// Authenticate an invalid execution claim against the History record of
    /// its header's chunk (design 08); unavailable until that chunk finalizes.
    fn verify_invalid_execution_claim(
        &self,
        height: Height,
        evidence: &SlashingEvidence,
    ) -> Result<(), SlashingError> {
        let chunk_id = self.accountability_chunk_for_height(height)?;
        let record = self
            .store()
            .historical_chunk(chunk_id)
            .ok()
            .flatten()
            .ok_or(SlashingError::EvidenceFieldsInconsistent)?;
        neutrin0_prover_chunk::history::authorize_evidence_at_record(
            self.chain_spec(),
            &record,
            evidence,
            &record.block_guest_vk_digest,
        )
        .map(|_| ())
        .map_err(|_| SlashingError::EvidenceFieldsInconsistent)
    }

    fn verify_historical_double_proposal(
        &self,
        index: u32,
        header_a: &Header,
        header_b: &Header,
    ) -> Result<(), SlashingError> {
        let source = self.accountability_chunk_for_height(header_a.height)?;
        if self.accountability_chunk_for_height(header_b.height)? != source {
            return Err(SlashingError::EvidenceFieldsInconsistent);
        }
        verify_double_proposal_evidence(
            index,
            header_a,
            header_b,
            &self.forensic_header_validators(header_a)?,
            self.consensus_domain(),
        )
    }

    fn verify_da_commitment_fraud(
        &self,
        index: u32,
        header: &Header,
        fraud: &neutrin0_consensus_types::DaFraudProof,
    ) -> Result<(), SlashingError> {
        if header.proposer_index != index {
            return Err(SlashingError::EvidenceFieldsInconsistent);
        }
        neutrin0_prover_chunk::slashing::verify_da_fraud(
            self.consensus_domain(),
            &self.forensic_header_validators(header)?,
            header,
            fraud,
        )
        .map_err(|_| SlashingError::EvidenceFieldsInconsistent)
    }
}
