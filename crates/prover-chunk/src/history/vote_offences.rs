//! Offences signed BFT votes and leader proposals establish.

use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::{
    BftProposal, BlockProof, FinalityVotePhase, IndexedNilVote, IndexedVote, LockEvidence,
    ProofAcceptanceOpening, VoteAttestation,
};
use neutrin0_primitives::{Hash, Validator};

use super::HistoryError;
use super::offences::{OffenceContext, active_validator, invalid};
use super::penalties::{
    PENALTY_DOUBLE_BFT_PROPOSAL, PENALTY_INVALID_PROOF_SIGNING, PENALTY_LOCK_VIOLATION, penalty_id,
    vote_kind,
};
use crate::slashing;

pub(super) fn authorize_double_bft_proposal<'a>(
    context: &OffenceContext<'a, '_>,
    proposer_index: u32,
    proposal_a: &BftProposal,
    proposal_b: &BftProposal,
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<(&'a Validator, Hash), HistoryError> {
    let record = context.record_at(proposal_a.chunk.chunk_id)?;
    let validator = active_validator(record.validators, proposer_index)?;
    slashing::verify_double_bft_proposal_with_root(
        context.domain,
        record.validators,
        context
            .validators_root
            .unwrap_or_else(|| commitment(record.validators)),
        record.seed,
        proposer_index,
        proposal_a,
        proposal_b,
        verifier,
    )
    .map_err(invalid)?;
    Ok((
        validator,
        penalty_id(
            PENALTY_DOUBLE_BFT_PROPOSAL,
            validator,
            record.chunk.chunk_id,
            proposal_a.round,
        ),
    ))
}

pub(super) fn authorize_conflicting_nil_vote<'a>(
    context: &OffenceContext<'a, '_>,
    validator_index: u32,
    value_vote: &IndexedVote,
    nil_vote: &IndexedNilVote,
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<(&'a Validator, Hash), HistoryError> {
    let record = context.record_at(value_vote.data.chunk_id)?;
    let validator = active_validator(record.validators, validator_index)?;
    slashing::verify_conflicting_nil_vote_using(
        context.domain,
        record.validators,
        validator_index,
        value_vote,
        nil_vote,
        verifier,
    )
    .map_err(invalid)?;
    Ok((
        validator,
        penalty_id(
            vote_kind(value_vote.data.phase),
            validator,
            value_vote.data.chunk_id,
            value_vote.data.round,
        ),
    ))
}

pub(super) fn authorize_double_vote<'a>(
    context: &OffenceContext<'a, '_>,
    phase: FinalityVotePhase,
    validator_index: u32,
    vote_a: &IndexedVote,
    vote_b: &IndexedVote,
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<(&'a Validator, Hash), HistoryError> {
    if vote_a.data.phase != phase
        || vote_b.data.phase != phase
        || vote_a.data.chunk_id != vote_b.data.chunk_id
        || vote_a.data.round != vote_b.data.round
        || vote_a.data.same_value(&vote_b.data)
    {
        return Err(HistoryError::Evidence);
    }
    let record = context.record_at(vote_a.data.chunk_id)?;
    let validator = active_validator(record.validators, validator_index)?;
    for vote in [vote_a, vote_b] {
        slashing::verify_indexed_vote_using(
            context.domain,
            record.validators,
            validator_index,
            vote,
            verifier,
        )
        .map_err(invalid)?;
    }
    Ok((
        validator,
        penalty_id(
            vote_kind(phase),
            validator,
            vote_a.data.chunk_id,
            vote_a.data.round,
        ),
    ))
}

pub(super) fn authorize_lock_violation<'a>(
    context: &OffenceContext<'a, '_>,
    validator_index: u32,
    vote_a: &IndexedVote,
    vote_b: &IndexedVote,
    lock_evidence: &LockEvidence,
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<(&'a Validator, Hash), HistoryError> {
    let quorum = (
        context.spec.consensus.bft_prevote_quorum_numerator,
        context.spec.consensus.bft_prevote_quorum_denominator,
    );
    let record = context.record_at(vote_a.data.chunk_id)?;
    let validator = active_validator(record.validators, validator_index)?;
    slashing::verify_lock_violation_using(
        context.domain,
        record.validators,
        validator_index,
        (vote_a, vote_b),
        lock_evidence,
        quorum,
        verifier,
    )
    .map_err(invalid)?;
    Ok((
        validator,
        penalty_id(
            PENALTY_LOCK_VIOLATION,
            validator,
            vote_b.data.chunk_id,
            vote_b.data.round,
        ),
    ))
}

pub(super) fn authorize_invalid_proof_signing<'a>(
    context: &OffenceContext<'a, '_>,
    validator_index: u32,
    vote: &IndexedVote,
    attestation: &VoteAttestation,
    rejected_proof: &BlockProof,
    proof_opening: &ProofAcceptanceOpening,
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<(&'a Validator, Hash), HistoryError> {
    // A rejection belongs to the verifier that judges it, which a fork
    // may replace: acceptances signed before the specification's
    // first chunk lapse with the fork.
    if vote.data.chunk_id < context.spec.first_chunk() {
        return Err(HistoryError::Evidence);
    }
    let record = context.record_at(vote.data.chunk_id)?;
    let validator = active_validator(record.validators, validator_index)?;
    slashing::verify_indexed_vote_using(
        context.domain,
        record.validators,
        validator_index,
        vote,
        verifier,
    )
    .map_err(invalid)?;
    slashing::verify_attestation_using(
        context.domain,
        record.validators,
        validator_index,
        &vote.data,
        attestation,
        verifier,
    )
    .map_err(invalid)?;
    slashing::verify_proof_acceptance(
        attestation,
        rejected_proof,
        proof_opening,
        context.spec.consensus.chunk_size,
    )
    .map_err(invalid)?;
    if !verifier.rejects_block(rejected_proof, context.block_key)? {
        return Err(HistoryError::Evidence);
    }
    Ok((
        validator,
        penalty_id(
            PENALTY_INVALID_PROOF_SIGNING,
            validator,
            rejected_proof.height,
            0,
        ),
    ))
}
