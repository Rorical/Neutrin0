//! BFT certificate verification suitable for execution inside an SP1 guest.

use neutrin0_consensus_types::{
    AggregatedVote, Chunk, FinalityCert, FinalityVoteData, FinalityVotePhase, QuorumCertificate,
    VoteAttestation,
};
use neutrin0_primitives::{ConsensusDomain, ConsensusParams, Hash, Seed, Validator};

use crate::slashing::VerifiedQuorums;
use neutrin0_consensus_types::evidence::commitment;

mod stake;
#[cfg(test)]
mod tests;

use stake::precommit_fraction;
pub(crate) use stake::{active_stake_total, is_active, prevote_fraction, signers};

/// Authenticate an embedded vote without requiring that this one envelope
/// already reaches quorum. Every signer must carry a complete,
/// cryptographically authenticated attestation.
pub fn verify_vote(
    domain: ConsensusDomain,
    validators: &[Validator],
    vote: &neutrin0_consensus_types::FinalityVote,
    params: &ConsensusParams,
) -> Result<(), FinalityError> {
    verify_vote_using(
        domain,
        validators,
        vote,
        params,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_vote_using(
    domain: ConsensusDomain,
    validators: &[Validator],
    vote: &neutrin0_consensus_types::FinalityVote,
    params: &ConsensusParams,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    verify_vote_signatures_using(domain, validators, vote, params, verifier)?;
    verify_unlock_claims_with(
        domain,
        validators,
        &vote.data,
        &vote.attestations,
        params,
        verifier,
        &mut VerifiedQuorums::new(prevote_fraction(params)),
    )
}

/// Authenticate a signed vote envelope for objective attribution.
///
/// This checks complete signer coverage and all vote/attestation signatures, but
/// does not validate a signer's declared unlock quorum. An invalid signed unlock
/// can itself establish an offence; consensus admission must use [`verify_vote`].
pub fn verify_vote_signatures(
    domain: ConsensusDomain,
    validators: &[Validator],
    vote: &neutrin0_consensus_types::FinalityVote,
    params: &ConsensusParams,
) -> Result<(), FinalityError> {
    verify_vote_signatures_using(
        domain,
        validators,
        vote,
        params,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Authenticate signed vote artifacts with a shared key cache or fact source.
/// Declared unlock semantics remain separate from this attribution check.
pub fn verify_vote_signatures_using(
    domain: ConsensusDomain,
    validators: &[Validator],
    vote: &neutrin0_consensus_types::FinalityVote,
    params: &ConsensusParams,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    if !neutrin0_consensus_types::proof_manifests_valid(&vote.attestations, &vote.proof_manifests)
        || !neutrin0_consensus_types::attestation_coverage_valid(
            &vote.data,
            &vote.aggregation_bits,
            &vote.attestations,
            params.chunk_size,
        )
        || usize::try_from(vote.aggregation_bits.bit_len()).ok() != Some(validators.len())
    {
        return Err(FinalityError::Membership);
    }
    let Some((keys, _)) = signers(validators, &vote.aggregation_bits) else {
        return Err(FinalityError::Membership);
    };
    let message = vote.data.signing_message(domain);
    if keys.is_empty() || !verifier.aggregate(&keys, &message, &vote.signature) {
        return Err(FinalityError::Signature);
    }
    verify_claim_signatures_with(
        domain,
        validators,
        &vote.data,
        &message,
        &vote.attestations,
        verifier,
    )
}

/// `message` is `data.signing_message(domain)`, encoded once per envelope.
fn verify_claim_signatures_with(
    domain: ConsensusDomain,
    validators: &[Validator],
    data: &FinalityVoteData,
    message: &[u8],
    claims: &[VoteAttestation],
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    for claim in claims {
        crate::slashing::verify_attestation_with(
            domain,
            validators,
            claim.validator_index,
            data,
            message,
            claim,
            verifier,
        )
        .map_err(|_| FinalityError::Signature)?;
    }
    Ok(())
}

fn verify_unlock_claims_with<'a>(
    domain: ConsensusDomain,
    validators: &[Validator],
    data: &FinalityVoteData,
    claims: &'a [VoteAttestation],
    params: &ConsensusParams,
    verifier: &mut impl crate::bls::Verifier,
    quorums: &mut VerifiedQuorums<'a>,
) -> Result<(), FinalityError> {
    for claim in claims {
        if let Some(unlock) = &claim.unlock_quorum {
            crate::slashing::verify_unlock_with(
                domain,
                validators,
                data,
                unlock,
                prevote_fraction(params),
                verifier,
                quorums,
            )
            .map_err(|_| FinalityError::Target)?;
        }
    }
    Ok(())
}

/// A certificate failed a target, membership, threshold or signature check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalityError {
    /// Wrong chunk, validator set or round.
    Target,
    /// Empty/overflowing stake, invalid quorum parameters or signer bitmap.
    Membership,
    /// Signers did not reach the required stake threshold.
    Quorum,
    /// BLS signature verification failed.
    Signature,
}

/// Verify both BFT phases under an authenticated active validator set.
///
/// Membership and key possession must originate at the trusted checkpoint or
/// a proven registration transition, never an unbound host-supplied list.
/// `seed` is the chunk's incoming seed, which draws its round leaders.
pub fn verify_finality(
    domain: ConsensusDomain,
    params: &ConsensusParams,
    validators: &[Validator],
    seed: &Seed,
    chunk: &Chunk,
    certificate: &FinalityCert,
) -> Result<(), FinalityError> {
    verify_finality_using(
        domain,
        params,
        validators,
        seed,
        chunk,
        certificate,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_finality_using(
    domain: ConsensusDomain,
    params: &ConsensusParams,
    validators: &[Validator],
    seed: &Seed,
    chunk: &Chunk,
    certificate: &FinalityCert,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    verify_finality_with_root(
        domain,
        params,
        validators,
        commitment(validators),
        seed,
        chunk,
        certificate,
        verifier,
    )
}

/// [`verify_finality_using`] for a caller already holding
/// `root == commitment(validators)`.
///
/// Every value QC in the certificate is verified once under the prevote
/// fraction; identical carriers still pass their own binding checks.
#[allow(
    clippy::too_many_arguments,
    reason = "The certificate's exact chunk context: domain, rules, set, root and seed."
)]
pub(crate) fn verify_finality_with_root(
    domain: ConsensusDomain,
    params: &ConsensusParams,
    validators: &[Validator],
    root: Hash,
    seed: &Seed,
    chunk: &Chunk,
    certificate: &FinalityCert,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    if certificate.chunk_id != chunk.chunk_id
        || certificate.chunk_hash != chunk.hash()
        || certificate.active_validator_set_root != root
        || chunk.active_validator_set_root != root
        || certificate.proposal.chunk != *chunk
        || certificate.proposal.round != certificate.round
    {
        return Err(FinalityError::Target);
    }
    if !neutrin0_consensus_types::proof_manifests_valid(
        &certificate.precommit_attestations,
        &certificate.proof_manifests,
    ) {
        return Err(FinalityError::Membership);
    }
    let mut quorums = VerifiedQuorums::new(prevote_fraction(params));
    crate::bft::verify_proposal_with(
        domain,
        validators,
        root,
        seed,
        &certificate.proposal,
        prevote_fraction(params),
        verifier,
        &mut quorums,
    )?;
    let total = active_stake_total(validators).ok_or(FinalityError::Membership)?;
    for (phase, fraction, vote, claims) in [
        (
            FinalityVotePhase::Prevote,
            prevote_fraction(params),
            &certificate.prevote,
            &certificate.prevote_attestations,
        ),
        (
            FinalityVotePhase::Precommit,
            precommit_fraction(params),
            &certificate.precommit,
            &certificate.precommit_attestations,
        ),
    ] {
        let data = certificate.vote_data(phase);
        if !neutrin0_consensus_types::attestation_coverage_valid(
            &data,
            &vote.aggregation_bits,
            claims,
            params.chunk_size,
        ) {
            return Err(FinalityError::Membership);
        }
        let message = data.signing_message(domain);
        verify_claim_signatures_with(domain, validators, &data, &message, claims, verifier)?;
        verify_unlock_claims_with(
            domain,
            validators,
            &data,
            claims,
            params,
            verifier,
            &mut quorums,
        )?;
        verify_phase_with(validators, vote, &message, total, fraction, verifier)?;
    }
    Ok(())
}

/// Authenticate a participation quorum for an already-finalized historical target.
pub(crate) fn verify_participation_with(
    domain: ConsensusDomain,
    params: &ConsensusParams,
    validators: &[Validator],
    finalized: &Chunk,
    certificate: &QuorumCertificate,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    // The caller authenticates this already-finalized target and membership.
    // This quorum proves participation only; complete finality still requires
    // the signed proposal, both phases and all accountability attestations.
    if certificate.data.phase != FinalityVotePhase::Precommit
        || certificate.data.chunk_id != finalized.chunk_id
        || certificate.data.chunk_hash != finalized.hash()
        || finalized.active_validator_set_root != commitment(validators)
    {
        return Err(FinalityError::Target);
    }
    let total = active_stake_total(validators).ok_or(FinalityError::Membership)?;
    verify_phase_with(
        validators,
        &certificate.aggregate,
        &certificate.data.signing_message(domain),
        total,
        precommit_fraction(params),
        verifier,
    )
}

/// `message` is the phase's `FinalityVoteData::signing_message`.
fn verify_phase_with(
    validators: &[Validator],
    vote: &AggregatedVote,
    message: &[u8],
    total: u128,
    (numerator, denominator): (u64, u64),
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), FinalityError> {
    if !neutrin0_primitives::quorum_fraction_valid(numerator, denominator)
        || usize::try_from(vote.aggregation_bits.bit_len()).ok() != Some(validators.len())
    {
        return Err(FinalityError::Membership);
    }
    let Some((keys, stake)) = signers(validators, &vote.aggregation_bits) else {
        return Err(FinalityError::Membership);
    };
    if !neutrin0_primitives::quorum_reached(stake, total, numerator, denominator) {
        return Err(FinalityError::Quorum);
    }
    if !verifier.aggregate(&keys, message, &vote.signature) {
        return Err(FinalityError::Signature);
    }
    Ok(())
}
