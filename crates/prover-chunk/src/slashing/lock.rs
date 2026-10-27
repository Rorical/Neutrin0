//! Weighted prevote quorums, unlock declarations and lock violations.
#![allow(clippy::redundant_pub_crate)] // Crate-internal helpers re-exported by the parent module.

use alloc::vec::Vec;
use neutrin0_consensus_types::{
    FinalityVoteData, FinalityVotePhase, IndexedVote, LockEvidence, QuorumCertificate,
};
use neutrin0_primitives::{ConsensusParams, Validator, quorum_fraction_valid, quorum_reached};

use super::{EvidenceError, verify_attestation_using, verify_indexed_vote_using};
use crate::finality::{active_stake_total, signers};

/// Verify a weighted prevote quorum, rejecting inactive signers and overflow.
pub fn verify_quorum(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    quorum: &QuorumCertificate,
    fraction: (u64, u64),
) -> Result<(), EvidenceError> {
    verify_quorum_using(
        domain,
        validators,
        quorum,
        fraction,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_quorum_using(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    quorum: &QuorumCertificate,
    fraction: (u64, u64),
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    let (numerator, denominator) = fraction;
    if quorum.data.phase != FinalityVotePhase::Prevote
        || !quorum_fraction_valid(numerator, denominator)
        || usize::try_from(quorum.aggregate.aggregation_bits.bit_len()).ok()
            != Some(validators.len())
    {
        return Err(EvidenceError::Quorum);
    }
    // Every membership, overflow, empty-set and threshold failure below is the
    // same `Quorum` rejection, so their relative order is not observable.
    let Some((keys, signed)) = signers(validators, &quorum.aggregate.aggregation_bits) else {
        return Err(EvidenceError::Quorum);
    };
    let total = active_stake_total(validators).ok_or(EvidenceError::Quorum)?;
    if !quorum_reached(signed, total, numerator, denominator) {
        return Err(EvidenceError::Quorum);
    }
    if !verifier.aggregate(
        &keys,
        &quorum.data.signing_message(domain),
        &quorum.aggregate.signature,
    ) {
        return Err(EvidenceError::Signature);
    }
    Ok(())
}

/// Value QCs that already passed [`verify_quorum_using`] during one finality or
/// vote verification, under one validator set, signing domain and fraction.
///
/// Only successes are kept, and a QC under another fraction bypasses the cache.
/// Every verifier returns an exact repeated request's earlier verdict (direct,
/// fact and recording verifiers are deterministic and dedupe by request id; the
/// batch verifier's failure is sticky and reported at the failing call), so
/// skipping a repeat cannot change any outcome. Each carrier's own binding
/// checks still run before the cache is consulted.
pub(crate) struct VerifiedQuorums<'a> {
    fraction: (u64, u64),
    verified: Vec<&'a QuorumCertificate>,
}

impl VerifiedQuorums<'_> {
    /// Empty cache for QCs weighed with `fraction`.
    pub(crate) const fn new(fraction: (u64, u64)) -> Self {
        Self {
            fraction,
            verified: Vec::new(),
        }
    }
}

/// [`verify_quorum_using`] that verifies each distinct QC at most once.
/// `quorums` must belong to this exact `domain` and `validators`.
pub(crate) fn verify_quorum_with<'a>(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    quorum: &'a QuorumCertificate,
    fraction: (u64, u64),
    verifier: &mut impl crate::bls::Verifier,
    quorums: &mut VerifiedQuorums<'a>,
) -> Result<(), EvidenceError> {
    let cached = quorums.fraction == fraction;
    if cached && quorums.verified.contains(&quorum) {
        return Ok(());
    }
    verify_quorum_using(domain, validators, quorum, fraction, verifier)?;
    if cached {
        quorums.verified.push(quorum);
    }
    Ok(())
}

/// Authenticate a carried prevote quorum as an unlock declaration for this vote.
pub fn verify_unlock_quorum(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    vote: &FinalityVoteData,
    unlock: &QuorumCertificate,
    params: &ConsensusParams,
) -> Result<(), EvidenceError> {
    verify_unlock_using(
        domain,
        validators,
        vote,
        unlock,
        (
            params.bft_prevote_quorum_numerator,
            params.bft_prevote_quorum_denominator,
        ),
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Authenticate a carried prevote quorum using a shared signature verifier.
///
/// A prevote's justification must predate its own round, preventing the vote from
/// authorizing the very quorum it helps create. Precommits may use their current
/// round's prevote quorum. The caller separately enforces any earlier local lock.
pub fn verify_unlock_using(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    vote: &FinalityVoteData,
    unlock: &QuorumCertificate,
    quorum: (u64, u64),
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    verify_unlock_with(
        domain,
        validators,
        vote,
        unlock,
        quorum,
        verifier,
        &mut VerifiedQuorums::new(quorum),
    )
}

/// [`verify_unlock_using`] sharing already verified QCs; this vote's own
/// unlock binding is always checked.
pub(crate) fn verify_unlock_with<'a>(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    vote: &FinalityVoteData,
    unlock: &'a QuorumCertificate,
    quorum: (u64, u64),
    verifier: &mut impl crate::bls::Verifier,
    quorums: &mut VerifiedQuorums<'a>,
) -> Result<(), EvidenceError> {
    if unlock.data.chunk_id != vote.chunk_id
        || !unlock.data.same_value(vote)
        || match vote.phase {
            FinalityVotePhase::Prevote => unlock.data.round >= vote.round,
            FinalityVotePhase::Precommit => unlock.data.round > vote.round,
        }
    {
        return Err(EvidenceError::Binding);
    }
    verify_quorum_with(domain, validators, unlock, quorum, verifier, quorums)
}

/// Prove a conflicting later vote has an explicitly signed invalid unlock.
/// Missing network observations never enter this decision.
pub fn verify_lock_violation(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    index: u32,
    votes: (&IndexedVote, &IndexedVote),
    evidence: &LockEvidence,
    quorum: (u64, u64),
) -> Result<(), EvidenceError> {
    verify_lock_violation_using(
        domain,
        validators,
        index,
        votes,
        evidence,
        quorum,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_lock_violation_using(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    index: u32,
    votes: (&IndexedVote, &IndexedVote),
    evidence: &LockEvidence,
    quorum: (u64, u64),
    verifier: &mut impl crate::facts::EvidenceVerifier,
) -> Result<(), EvidenceError> {
    let (first, later) = votes;
    if first.data.phase != FinalityVotePhase::Precommit
        || first.data.chunk_id != later.data.chunk_id
        || first.data.round >= later.data.round
        || first.data.same_value(&later.data)
    {
        return Err(EvidenceError::Binding);
    }
    verify_indexed_vote_using(domain, validators, index, first, verifier)?;
    verify_indexed_vote_using(domain, validators, index, later, verifier)?;
    verify_attestation_using(
        domain,
        validators,
        index,
        &later.data,
        &evidence.attestation,
        verifier,
    )?;
    let locked = &evidence.locked_prevote_quorum;
    if locked.data.chunk_id != first.data.chunk_id
        || locked.data.round != first.data.round
        || !locked.data.same_value(&first.data)
    {
        return Err(EvidenceError::Binding);
    }
    verify_quorum_using(domain, validators, locked, quorum, verifier)?;
    if let Some(unlock) = &evidence.attestation.unlock_quorum
        && unlock.data.round > first.data.round
        && verify_unlock_using(domain, validators, &later.data, unlock, quorum, verifier).is_ok()
    {
        return Err(EvidenceError::HonestUnlock);
    }
    Ok(())
}
