//! Native BLS verification of signatures, quorums, reports and attestations.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Crate-visible helpers of a private module; `pub` would be unreachable."
)]

use alloc::vec::Vec;

use neutrin0_consensus_types::{
    FinalityVote, FinalityVoteData, FinalityVotePhase, NilVote, RoundChange,
};
use neutrin0_primitives::{BlsSignature, ConsensusDomain, Validator};

use crate::BftError;
#[cfg(feature = "std")]
use crate::stake::{bitmap_stake, nil_stake};
use crate::stake::{quorum_reached, total_active_stake, validate_quorum, vote_stake};

#[cfg(feature = "std")]
pub(crate) fn verify_individual_native(
    validators: &[Validator],
    index: u32,
    message: &[u8],
    signature: &BlsSignature,
) -> Result<(), BftError> {
    let key = active_signer_key(validators, index)?;
    verify_with_key(&key, message, signature)
}

/// Decoded key of an active, unslashed validator with positive stake.
#[cfg(feature = "std")]
fn active_signer_key(
    validators: &[Validator],
    index: u32,
) -> Result<neutrin0_crypto::bls::PublicKey, BftError> {
    let validator = validators
        .get(index as usize)
        .filter(|validator| validator.effective_stake > 0)
        .ok_or(BftError::InvalidAggregationBits)?;
    neutrin0_crypto::bls::PublicKey::from_bytes(&validator.pubkey)
        .map_err(|_| BftError::InvalidAggregateSignature)
}

#[cfg(feature = "std")]
fn verify_with_key(
    key: &neutrin0_crypto::bls::PublicKey,
    message: &[u8],
    signature: &BlsSignature,
) -> Result<(), BftError> {
    let signature = neutrin0_crypto::bls::Signature::from_bytes(signature)
        .map_err(|_| BftError::InvalidAggregateSignature)?;
    key.verify(message, &signature)
        .map_err(|_| BftError::InvalidAggregateSignature)
}

#[cfg(not(feature = "std"))]
pub(crate) fn verify_individual_native(
    _validators: &[Validator],
    _index: u32,
    _message: &[u8],
    _signature: &BlsSignature,
) -> Result<(), BftError> {
    Err(BftError::SignatureAggregationUnavailable)
}

#[cfg(feature = "std")]
pub(crate) fn verify_nil_native(
    domain: ConsensusDomain,
    validators: &[Validator],
    vote: &NilVote,
) -> Result<(), BftError> {
    nil_stake(validators, vote)?;
    let message = vote.data.signing_message(domain);
    let mut seen = alloc::collections::BTreeSet::new();
    let mut public_keys = Vec::new();
    for claim in &vote.attestations {
        if claim.vote != vote.data
            || !seen.insert(claim.validator_index)
            || vote.aggregation_bits.get(claim.validator_index) != Some(true)
        {
            return Err(BftError::InvalidAggregationBits);
        }
        let key = active_signer_key(validators, claim.validator_index)?;
        verify_with_key(&key, &message, &claim.vote_signature)?;
        verify_with_key(&key, &claim.signing_message(domain), &claim.signature)?;
        public_keys.push(key);
    }
    if seen.len()
        != (0..vote.aggregation_bits.bit_len())
            .filter(|index| vote.aggregation_bits.get(*index) == Some(true))
            .count()
    {
        return Err(BftError::InvalidAggregationBits);
    }
    let refs: Vec<_> = public_keys.iter().collect();
    let signature = neutrin0_crypto::bls::Signature::from_bytes(&vote.signature)
        .map_err(|_| BftError::InvalidAggregateSignature)?;
    neutrin0_crypto::bls::fast_aggregate_verify(&refs, &message, &signature)
        .map_err(|_| BftError::InvalidAggregateSignature)
}

#[cfg(not(feature = "std"))]
pub(crate) fn verify_nil_native(
    _chain_id: ConsensusDomain,
    _validators: &[Validator],
    _vote: &NilVote,
) -> Result<(), BftError> {
    Err(BftError::SignatureAggregationUnavailable)
}

/// Authenticate a carried prevote QC. `total_stake` is the active-set total
/// when already known; `None` computes it at the point the stake check needs it.
pub(crate) fn verify_value_quorum_native(
    domain: ConsensusDomain,
    validators: &[Validator],
    total_stake: Option<u128>,
    quorum: &neutrin0_consensus_types::QuorumCertificate,
    fraction: (u64, u64),
) -> Result<(), BftError> {
    validate_quorum(fraction)?;
    if quorum.data.phase != FinalityVotePhase::Prevote {
        return Err(BftError::WrongPhase);
    }
    let vote = FinalityVote {
        data: quorum.data.clone(),
        aggregation_bits: quorum.aggregate.aggregation_bits.clone(),
        signature: quorum.aggregate.signature,
        attestations: Vec::new(),
        proof_manifests: Vec::new(),
    };
    let stake = vote_stake(validators, &vote)?;
    let total_stake = total_stake.map_or_else(|| total_active_stake(validators), Ok)?;
    if !quorum_reached(stake, total_stake, fraction) {
        return Err(BftError::InvalidQuorum);
    }
    verify_vote_signature(domain, validators, &vote)
}

/// Authenticate one round-change report and its carried QC.
///
/// `total_stake` is as for [`verify_value_quorum_native`]. A QC equal to one
/// in `verified` was already fully checked against these same inputs, so only
/// this report's target checks repeat; each newly verified QC is appended.
pub(crate) fn verify_round_change_native<'a>(
    domain: ConsensusDomain,
    validators: &[Validator],
    total_stake: Option<u128>,
    report: &'a RoundChange,
    fraction: (u64, u64),
    verified: &mut Vec<&'a neutrin0_consensus_types::QuorumCertificate>,
) -> Result<(), BftError> {
    if report.round == 0 {
        return Err(BftError::WrongVoteTarget);
    }
    verify_individual_native(
        validators,
        report.validator_index,
        &report.signing_message(domain),
        &report.signature,
    )?;
    if let Some(quorum) = &report.highest_quorum {
        if quorum.data.chunk_id != report.chunk_id || quorum.data.round >= report.round {
            return Err(BftError::WrongVoteTarget);
        }
        if !verified.contains(&quorum) {
            verify_value_quorum_native(domain, validators, total_stake, quorum, fraction)?;
            verified.push(quorum);
        }
    }
    Ok(())
}

pub(crate) fn verify_round_certificate_native(
    domain: ConsensusDomain,
    validators: &[Validator],
    total_stake: u128,
    certificate: &neutrin0_consensus_types::RoundChangeCertificate,
    fraction: (u64, u64),
) -> Result<(), BftError> {
    validate_quorum(fraction)?;
    let mut seen = alloc::collections::BTreeSet::new();
    let mut verified = Vec::new();
    let mut stake = 0_u128;
    for report in &certificate.reports {
        if report.chunk_id != certificate.chunk_id
            || report.round != certificate.round
            || !seen.insert(report.validator_index)
        {
            return Err(BftError::WrongVoteTarget);
        }
        verify_round_change_native(
            domain,
            validators,
            Some(total_stake),
            report,
            fraction,
            &mut verified,
        )?;
        stake = stake
            .checked_add(validators[report.validator_index as usize].effective_stake)
            .ok_or(BftError::StakeOverflow)?;
    }
    if !quorum_reached(stake, total_stake, fraction) {
        return Err(BftError::InvalidQuorum);
    }
    Ok(())
}

#[cfg(feature = "std")]
pub(crate) fn verify_attestations(
    domain: ConsensusDomain,
    validators: &[Validator],
    total_stake: u128,
    vote: &FinalityVote,
    prevote_quorum: (u64, u64),
) -> Result<(), BftError> {
    let vote_message = finality_vote_signed_message(domain, &vote.data);
    let mut seen = alloc::collections::BTreeSet::new();
    let mut checked_quorums = Vec::new();
    for claim in &vote.attestations {
        if claim.vote != vote.data
            || !vote
                .aggregation_bits
                .get(claim.validator_index)
                .unwrap_or(false)
            || !seen.insert(claim.validator_index)
        {
            return Err(BftError::InvalidAggregateSignature);
        }
        let validator = validators
            .get(claim.validator_index as usize)
            .ok_or(BftError::InvalidAggregationBits)?;
        let key = neutrin0_crypto::bls::PublicKey::from_bytes(&validator.pubkey)
            .map_err(|_| BftError::InvalidAggregateSignature)?;
        let signature = neutrin0_crypto::bls::Signature::from_bytes(&claim.signature)
            .map_err(|_| BftError::InvalidAggregateSignature)?;
        let individual = neutrin0_crypto::bls::Signature::from_bytes(&claim.vote_signature)
            .map_err(|_| BftError::InvalidAggregateSignature)?;
        key.verify(&vote_message, &individual)
            .map_err(|_| BftError::InvalidAggregateSignature)?;
        key.verify(&claim.signing_message(domain), &signature)
            .map_err(|_| BftError::InvalidAggregateSignature)?;
        if let Some(quorum) = &claim.unlock_quorum {
            let prior_round = match vote.data.phase {
                FinalityVotePhase::Prevote => quorum.data.round < vote.data.round,
                FinalityVotePhase::Precommit => quorum.data.round <= vote.data.round,
            };
            if quorum.data.phase != FinalityVotePhase::Prevote
                || quorum.data.chunk_id != vote.data.chunk_id
                || !quorum.data.same_value(&vote.data)
                || !prior_round
            {
                return Err(BftError::WrongVoteTarget);
            }
            let stake = bitmap_stake(validators, &quorum.aggregate.aggregation_bits)?;
            if !quorum_reached(stake, total_stake, prevote_quorum) {
                return Err(BftError::InvalidQuorum);
            }
            if !checked_quorums.contains(&quorum) {
                let quorum_vote = FinalityVote {
                    data: quorum.data.clone(),
                    aggregation_bits: quorum.aggregate.aggregation_bits.clone(),
                    signature: quorum.aggregate.signature,
                    attestations: Vec::new(),
                    proof_manifests: Vec::new(),
                };
                verify_vote_signature(domain, validators, &quorum_vote)?;
                checked_quorums.push(quorum);
            }
        }
    }
    Ok(())
}

#[cfg(not(feature = "std"))]
pub(crate) fn verify_attestations(
    _chain_id: ConsensusDomain,
    _validators: &[Validator],
    _total_stake: u128,
    _vote: &FinalityVote,
    _prevote_quorum: (u64, u64),
) -> Result<(), BftError> {
    Err(BftError::SignatureAggregationUnavailable)
}

pub(crate) fn finality_vote_signed_message(
    domain: ConsensusDomain,
    data: &FinalityVoteData,
) -> Vec<u8> {
    data.signing_message(domain)
}

#[cfg(feature = "std")]
pub(crate) fn verify_vote_signature(
    domain: ConsensusDomain,
    active_set: &[Validator],
    vote: &FinalityVote,
) -> Result<(), BftError> {
    let signature = neutrin0_crypto::bls::Signature::from_bytes(&vote.signature)
        .map_err(|_| BftError::InvalidAggregateSignature)?;
    let mut public_keys = Vec::new();
    for (index, validator) in active_set.iter().enumerate() {
        let bit_index = u32::try_from(index).expect("active set length prevalidated as u32");
        if vote.aggregation_bits.get(bit_index).unwrap_or(false) {
            public_keys.push(
                neutrin0_crypto::bls::PublicKey::from_bytes(&validator.pubkey)
                    .map_err(|_| BftError::InvalidAggregateSignature)?,
            );
        }
    }
    let public_key_refs: Vec<&neutrin0_crypto::bls::PublicKey> = public_keys.iter().collect();
    let message = finality_vote_signed_message(domain, &vote.data);
    neutrin0_crypto::bls::fast_aggregate_verify(&public_key_refs, &message, &signature)
        .map_err(|_| BftError::InvalidAggregateSignature)
}

#[cfg(not(feature = "std"))]
pub(crate) fn verify_vote_signature(
    _chain_id: ConsensusDomain,
    _active_set: &[Validator],
    _vote: &FinalityVote,
) -> Result<(), BftError> {
    Err(BftError::SignatureAggregationUnavailable)
}
