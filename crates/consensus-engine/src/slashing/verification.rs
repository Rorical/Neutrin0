//! Native attribution and verification of objective slashing evidence.

extern crate alloc;

use super::SlashingError;
use alloc::vec::Vec;
use neutrin0_consensus_types::{
    FinalityVote, FinalityVoteData, FinalityVotePhase, Header, IndexedVote, LockEvidence,
    VoteAttestation,
};
use neutrin0_crypto::bls::{PublicKey, Signature};
use neutrin0_primitives::{ConsensusDomain, Validator, ValidatorIndex};

use crate::signature::verify_header_signature;

/// Build the canonical message bound by a finality-vote BLS signature.
#[must_use]
pub fn finality_vote_signed_message(domain: ConsensusDomain, data: &FinalityVoteData) -> Vec<u8> {
    data.signing_message(domain)
}

/// Authenticate the offender's explicit proof/unlock claim, including `None`.
pub fn verify_vote_attestation(
    attestation: &VoteAttestation,
    validator_index: ValidatorIndex,
    vote: &FinalityVoteData,
    active_set: &[Validator],
    domain: ConsensusDomain,
) -> Result<(), SlashingError> {
    verify_vote_attestation_using(
        attestation,
        validator_index,
        vote,
        active_set,
        domain,
        &mut crate::bls_verdicts::NativeBlsVerifier::default(),
    )
}

#[allow(clippy::redundant_pub_crate)] // Keep the verifier hook within the engine crate.
pub(crate) fn verify_vote_attestation_using(
    attestation: &VoteAttestation,
    validator_index: ValidatorIndex,
    vote: &FinalityVoteData,
    active_set: &[Validator],
    domain: ConsensusDomain,
    verifier: &mut impl neutrin0_prover_chunk::bls::Verifier,
) -> Result<(), SlashingError> {
    let _ = active_vote_validator(validator_index, active_set)?;
    neutrin0_prover_chunk::slashing::verify_attestation_using(
        domain,
        active_set,
        validator_index,
        vote,
        attestation,
        verifier,
    )
    .map_err(map_evidence_error)
}

/// Verify that the signature names this exact proof, at its canonical position.
pub fn verify_proof_acceptance(
    attestation: &VoteAttestation,
    proof: &neutrin0_consensus_types::BlockProof,
    opening: &neutrin0_consensus_types::ProofAcceptanceOpening,
    chunk_size: u64,
) -> Result<(), SlashingError> {
    neutrin0_prover_chunk::slashing::verify_proof_acceptance(
        attestation,
        proof,
        opening,
        chunk_size,
    )
    .map_err(map_evidence_error)
}

/// Authenticate a proof-acceptance claim; the caller must additionally run the
/// proof backend and establish rejection before accepting the evidence.
#[allow(
    clippy::too_many_arguments,
    reason = "Every signed artifact of the claim is authenticated in one call."
)]
pub fn verify_proof_signing_attribution(
    validator_index: ValidatorIndex,
    vote: &IndexedVote,
    attestation: &VoteAttestation,
    proof: &neutrin0_consensus_types::BlockProof,
    opening: &neutrin0_consensus_types::ProofAcceptanceOpening,
    active_set: &[Validator],
    domain: ConsensusDomain,
    chunk_size: u64,
) -> Result<(), SlashingError> {
    verify_indexed_vote_signature(validator_index, vote, active_set, domain)?;
    verify_vote_attestation(attestation, validator_index, &vote.data, active_set, domain)?;
    verify_proof_acceptance(attestation, proof, opening, chunk_size)
}

/// Extract the single signer of a [`FinalityVote`].
///
/// Returns `None` when the vote is aggregated (more than one bit
/// set), unsigned (no bits set), or carries an aggregation-bit
/// vector whose length disagrees with the active validator set.
///
/// Used by the equivocation detector to recover an [`IndexedVote`] from a
/// gossiped partial vote so equivocation can be attributed to a
/// specific validator.
#[must_use]
pub fn extract_single_signer(
    vote: &FinalityVote,
    active_set_len: usize,
) -> Option<(ValidatorIndex, IndexedVote)> {
    let bit_len_u32 = u32::try_from(active_set_len).ok()?;
    if vote.aggregation_bits.bit_len() != bit_len_u32 {
        return None;
    }
    let mut count = 0_usize;
    let mut signer: ValidatorIndex = 0;
    for position in 0..bit_len_u32 {
        if vote.aggregation_bits.get(position).unwrap_or(false) {
            count += 1;
            signer = position;
            if count > 1 {
                return None;
            }
        }
    }
    if count != 1 {
        return None;
    }
    Some((
        signer,
        IndexedVote {
            data: vote.data.clone(),
            signature: vote.signature,
        },
    ))
}

/// Verify a [`neutrin0_consensus_types::SlashingEvidence::DoubleProposal`].
///
/// Requires that both headers name the same proposer at the same
/// slot, have distinct canonical hashes, and that both signatures
/// verify under the proposer's BLS public key looked up in
/// `active_set`.
///
/// # Errors
///
/// Returns the relevant [`SlashingError`] variant on any failure.
pub fn verify_double_proposal_evidence(
    proposer_index: ValidatorIndex,
    header_a: &Header,
    header_b: &Header,
    active_set: &[Validator],
    domain: ConsensusDomain,
) -> Result<(), SlashingError> {
    if header_a.proposer_index != proposer_index || header_b.proposer_index != proposer_index {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    if header_a.slot != header_b.slot {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    if header_a.hash() == header_b.hash() {
        return Err(SlashingError::NotEquivocating);
    }
    verify_header_signature(header_a, active_set, domain)?;
    verify_header_signature(header_b, active_set, domain)?;
    Ok(())
}

/// Verify a [`neutrin0_consensus_types::SlashingEvidence::LockViolation`].
///
/// An earlier precommit and later conflicting vote must be from the same validator on the same
/// `chunk_id`, with different rounds, different chunk hashes, valid
/// per-validator signatures, and a carried [`LockEvidence`] whose
/// locked prevote quorum matches `vote_a` and satisfies
/// `prevote_quorum` against `active_set`.
///
/// The later signer authenticates the exact optional unlock quorum.
/// If that signed claim carries a valid higher-round prevote quorum for
/// `vote_b`'s chunk hash, the precommit switch is treated as an honest
/// unlock rather than a slashable lock violation.
///
/// # Errors
///
/// Returns the relevant [`SlashingError`] variant on any failure.
pub fn verify_lock_violation_evidence(
    validator_index: ValidatorIndex,
    vote_a: &IndexedVote,
    vote_b: &IndexedVote,
    lock_evidence: &LockEvidence,
    active_set: &[Validator],
    domain: ConsensusDomain,
    prevote_quorum: (u64, u64),
) -> Result<(), SlashingError> {
    // A value is the chunk with its payment selection (design 08).
    if vote_a.data.same_value(&vote_b.data) {
        return Err(SlashingError::NotEquivocating);
    }
    neutrin0_prover_chunk::slashing::verify_lock_violation(
        domain,
        active_set,
        validator_index,
        (vote_a, vote_b),
        lock_evidence,
        prevote_quorum,
    )
    .map_err(map_evidence_error)
}

const fn map_evidence_error(
    error: neutrin0_prover_chunk::slashing::EvidenceError,
) -> SlashingError {
    use neutrin0_prover_chunk::slashing::EvidenceError;
    match error {
        EvidenceError::Signature => SlashingError::BadSignature,
        EvidenceError::Binding | EvidenceError::Quorum | EvidenceError::HonestUnlock => {
            SlashingError::EvidenceFieldsInconsistent
        }
    }
}

/// Verify a [`neutrin0_consensus_types::SlashingEvidence::DoublePrevote`] or
/// [`neutrin0_consensus_types::SlashingEvidence::DoublePrecommit`].
///
/// Both votes must name the same `(chunk_id, round)` and carry
/// `expected_phase`; their values (chunk hash and selection) must differ; and
/// both per-validator BLS signatures must verify under the same
/// validator's BLS public key.
///
/// # Errors
///
/// Returns the relevant [`SlashingError`] variant on any failure.
pub fn verify_double_vote_evidence(
    validator_index: ValidatorIndex,
    expected_phase: FinalityVotePhase,
    vote_a: &IndexedVote,
    vote_b: &IndexedVote,
    active_set: &[Validator],
    domain: ConsensusDomain,
) -> Result<(), SlashingError> {
    if vote_a.data.phase != expected_phase || vote_b.data.phase != expected_phase {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    if vote_a.data.chunk_id != vote_b.data.chunk_id || vote_a.data.round != vote_b.data.round {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    if vote_a.data.same_value(&vote_b.data) {
        return Err(SlashingError::NotEquivocating);
    }
    verify_indexed_vote_signature(validator_index, vote_a, active_set, domain)?;
    verify_indexed_vote_signature(validator_index, vote_b, active_set, domain)?;
    Ok(())
}

/// Verify a single [`IndexedVote`]'s BLS signature against the
/// positive, unslashed validator's public key in the source set.
///
/// Exposed for the engine's vote-observation path so a single-
/// signer vote can be authenticated before it is recorded into the
/// equivocation monitor.
///
/// # Errors
///
/// Returns the matching [`SlashingError`] variant on any signature
/// or look-up failure.
pub fn verify_indexed_vote_signature(
    validator_index: ValidatorIndex,
    vote: &IndexedVote,
    active_set: &[Validator],
    domain: ConsensusDomain,
) -> Result<(), SlashingError> {
    let validator = active_vote_validator(validator_index, active_set)?;
    let pk =
        PublicKey::from_bytes(&validator.pubkey).map_err(|_| SlashingError::InvalidPublicKey {
            index: validator_index,
        })?;
    let sig =
        Signature::from_bytes(&vote.signature).map_err(|_| SlashingError::InvalidSignatureBytes)?;
    let message = finality_vote_signed_message(domain, &vote.data);
    pk.verify(&message, &sig)
        .map_err(|_| SlashingError::BadSignature)?;
    Ok(())
}

/// [`verify_indexed_vote_signature`] through a verdict-caching `verifier`, so a
/// vote signature already authenticated at import is not verified again.
///
/// # Errors
///
/// Returns the same [`SlashingError`] variants as
/// [`verify_indexed_vote_signature`].
#[allow(clippy::redundant_pub_crate)] // Keep the verifier hook within the engine crate.
pub(crate) fn verify_indexed_vote_signature_using(
    validator_index: ValidatorIndex,
    vote: &IndexedVote,
    active_set: &[Validator],
    domain: ConsensusDomain,
    verifier: &mut impl neutrin0_prover_chunk::bls::Verifier,
) -> Result<(), SlashingError> {
    let validator = active_vote_validator(validator_index, active_set)?;
    let message = finality_vote_signed_message(domain, &vote.data);
    if verifier.verify(&validator.pubkey, &message, &vote.signature) {
        return Ok(());
    }
    // Verdicts are booleans: classify the failure directly.
    verify_indexed_vote_signature(validator_index, vote, active_set, domain)
        .and(Err(SlashingError::BadSignature))
}

fn active_vote_validator(
    index: ValidatorIndex,
    validators: &[Validator],
) -> Result<&Validator, SlashingError> {
    let position = usize::try_from(index).expect("u32 fits usize on supported targets");
    let validator = validators
        .get(position)
        .ok_or(SlashingError::ValidatorIndexOutOfBounds {
            index,
            len: validators.len(),
        })?;
    if validator.effective_stake == 0 {
        return Err(SlashingError::EvidenceFieldsInconsistent);
    }
    Ok(validator)
}
