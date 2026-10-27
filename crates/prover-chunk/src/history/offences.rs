//! Objective offence authorization over one authenticated historical record.
#![allow(clippy::redundant_pub_crate)] // Crate-internal helpers re-exported by the parent module.

use neutrin0_consensus_types::{FinalityVotePhase, SlashingEvidence};
use neutrin0_primitives::{ChainSpec, ConsensusDomain, Hash, Validator};

use super::HistoryError;
use super::header_offences::{
    authorize_da_commitment_fraud, authorize_double_proposal, authorize_invalid_execution_claim,
};
use super::records::{HistoricalChunk, HistoricalSource, HistoricalView};
use super::vote_offences::{
    authorize_conflicting_nil_vote, authorize_double_bft_proposal, authorize_double_vote,
    authorize_invalid_proof_signing, authorize_lock_violation,
};
use super::witness::HistoryWitness;
use crate::finality::is_active;

pub(super) fn active_validator(
    validators: &[Validator],
    index: u32,
) -> Result<&Validator, HistoryError> {
    validators
        .get(index as usize)
        .filter(|validator| is_active(validator))
        .ok_or(HistoryError::Evidence)
}

/// Authenticate a supported offence and derive its evidence-independent ID.
pub fn authorize_evidence<'a>(
    spec: &ChainSpec,
    history: &'a HistoryWitness,
    evidence: &SlashingEvidence,
    block_key: &[u32; 8],
) -> Result<(&'a Validator, Hash), HistoryError> {
    authorize_evidence_with(
        spec,
        spec.consensus_domain(),
        history.record(evidence_chunk_id(spec, evidence)?)?,
        None,
        evidence,
        block_key,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Resolve the unique historical chunk needed by an offence.
pub fn evidence_chunk_id(
    spec: &ChainSpec,
    evidence: &SlashingEvidence,
) -> Result<u64, HistoryError> {
    let height = match evidence {
        SlashingEvidence::DoubleBftProposal { proposal_a, .. } => {
            return Ok(proposal_a.chunk.chunk_id);
        }
        SlashingEvidence::ConflictingNilVote { value_vote, .. } => {
            return Ok(value_vote.data.chunk_id);
        }
        SlashingEvidence::DoubleProposal { header_a, .. } => header_a.height,
        SlashingEvidence::DaCommitmentFraud { header, .. }
        | SlashingEvidence::InvalidExecutionClaim { header, .. } => header.height,
        SlashingEvidence::DoublePrevote { vote_a, .. }
        | SlashingEvidence::DoublePrecommit { vote_a, .. }
        | SlashingEvidence::LockViolation { vote_a, .. } => return Ok(vote_a.data.chunk_id),
        SlashingEvidence::InvalidProofSigning { vote, .. } => return Ok(vote.data.chunk_id),
    };
    height
        .checked_sub(1)
        .and_then(|h| h.checked_div(spec.consensus.chunk_size))
        .ok_or(HistoryError::Evidence)
}

/// Authenticate an offence using its single historical record. Membership of
/// that record is checked by the consuming block, not chosen by the reporter.
pub fn authorize_evidence_at_record<'a>(
    spec: &ChainSpec,
    source: &'a HistoricalChunk,
    evidence: &SlashingEvidence,
    block_key: &[u32; 8],
) -> Result<(&'a Validator, Hash), HistoryError> {
    authorize_evidence_using(
        spec,
        source,
        evidence,
        block_key,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Derive guilt using immediate or recursively authenticated cryptographic facts.
pub fn authorize_evidence_using<'a>(
    spec: &ChainSpec,
    source: &'a HistoricalChunk,
    evidence: &SlashingEvidence,
    block_key: &[u32; 8],
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<(&'a Validator, Hash), HistoryError> {
    authorize_evidence_with(
        spec,
        spec.consensus_domain(),
        source,
        None,
        evidence,
        block_key,
        verifier,
    )
}

/// The chunk context every offence rule authenticates against.
pub(super) struct OffenceContext<'a, 'c> {
    pub(super) spec: &'c ChainSpec,
    pub(super) domain: ConsensusDomain,
    pub(super) source: HistoricalView<'a>,
    /// Known `commitment(&source.validators)`; `None` computes it where needed.
    pub(super) validators_root: Option<Hash>,
    pub(super) block_key: &'c [u32; 8],
}

impl<'a> OffenceContext<'a, '_> {
    pub(super) const fn record_at(
        &self,
        chunk_id: u64,
    ) -> Result<HistoricalView<'a>, HistoryError> {
        if self.source.chunk.chunk_id == chunk_id {
            Ok(self.source)
        } else {
            Err(HistoryError::Anchor)
        }
    }

    pub(super) fn chunk_for_height(&self, height: u64) -> Result<u64, HistoryError> {
        height
            .checked_sub(1)
            .and_then(|height| height.checked_div(self.spec.consensus.chunk_size))
            .ok_or(HistoryError::Evidence)
    }
}

pub(super) fn invalid<E>(_: E) -> HistoryError {
    HistoryError::Evidence
}

/// [`authorize_evidence_using`] with `domain == spec.consensus_domain()`
/// already derived. A known `validators_root` must equal
/// `commitment(&source.validators)`; `None` computes it where needed.
#[allow(clippy::too_many_lines)] // Exhaustive protocol dispatch keeps each rule explicit.
pub(crate) fn authorize_evidence_with<'a>(
    spec: &ChainSpec,
    domain: ConsensusDomain,
    source: &'a impl HistoricalSource,
    validators_root: Option<Hash>,
    evidence: &SlashingEvidence,
    block_key: &[u32; 8],
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<(&'a Validator, Hash), HistoryError> {
    let context = OffenceContext {
        spec,
        domain,
        source: HistoricalView {
            chunk: source.chunk(),
            validators: source.validators(),
            seed: source.seed(),
        },
        validators_root,
        block_key,
    };
    match evidence {
        SlashingEvidence::DoubleBftProposal {
            proposer_index,
            proposal_a,
            proposal_b,
        } => authorize_double_bft_proposal(
            &context,
            *proposer_index,
            proposal_a,
            proposal_b,
            verifier,
        ),
        SlashingEvidence::ConflictingNilVote {
            validator_index,
            value_vote,
            nil_vote,
        } => authorize_conflicting_nil_vote(
            &context,
            *validator_index,
            value_vote,
            nil_vote,
            verifier,
        ),
        SlashingEvidence::DoubleProposal {
            proposer_index,
            header_a,
            header_b,
        } => authorize_double_proposal(&context, *proposer_index, header_a, header_b, verifier),
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
            authorize_double_vote(&context, phase, *validator_index, vote_a, vote_b, verifier)
        }
        SlashingEvidence::LockViolation {
            validator_index,
            vote_a,
            vote_b,
            lock_evidence,
        } => authorize_lock_violation(
            &context,
            *validator_index,
            vote_a,
            vote_b,
            lock_evidence,
            verifier,
        ),
        SlashingEvidence::InvalidProofSigning {
            validator_index,
            vote,
            attestation,
            rejected_proof,
            proof_opening,
            ..
        } => authorize_invalid_proof_signing(
            &context,
            *validator_index,
            vote,
            attestation,
            rejected_proof,
            proof_opening,
            verifier,
        ),
        SlashingEvidence::InvalidExecutionClaim {
            proposer_index,
            header,
            parent,
            receipt,
        } => authorize_invalid_execution_claim(
            &context,
            *proposer_index,
            header,
            parent.as_ref(),
            receipt,
            verifier,
        ),
        SlashingEvidence::DaCommitmentFraud {
            proposer_index,
            header,
            fraud_proof,
        } => {
            authorize_da_commitment_fraud(&context, *proposer_index, header, fraud_proof, verifier)
        }
    }
}
