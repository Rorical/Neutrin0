//! Authenticated proposal, explicit nil and pacemaker validation.

use alloc::collections::BTreeSet;
use neutrin0_consensus_types::{
    BftProposal, NilVote, RoundChange, RoundChangeCertificate, bft::bft_leader_with_root,
};
use neutrin0_primitives::{
    ConsensusDomain, Hash, Seed, Validator, quorum_fraction_valid, quorum_reached,
};

use crate::{
    bls::Verifier,
    finality::{FinalityError, active_stake_total, is_active, signers},
    slashing::{VerifiedQuorums, verify_quorum_with},
};
use neutrin0_consensus_types::evidence::commitment;

/// Verify a designated leader and its exact proposal/earlier valid quorum.
/// `seed` is the proposal chunk's incoming seed, which draws its leaders.
pub fn verify_proposal(
    domain: ConsensusDomain,
    validators: &[Validator],
    seed: &Seed,
    proposal: &BftProposal,
    fraction: (u64, u64),
) -> Result<(), FinalityError> {
    verify_proposal_using(
        domain,
        validators,
        seed,
        proposal,
        fraction,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verify a proposal with shared immediate signatures or recursively proven facts.
pub fn verify_proposal_using(
    domain: ConsensusDomain,
    validators: &[Validator],
    seed: &Seed,
    proposal: &BftProposal,
    fraction: (u64, u64),
    verifier: &mut impl Verifier,
) -> Result<(), FinalityError> {
    verify_proposal_with(
        domain,
        validators,
        commitment(validators),
        seed,
        proposal,
        fraction,
        verifier,
        &mut VerifiedQuorums::new(fraction),
    )
}

/// [`verify_proposal_using`] for a caller already holding
/// `root == commitment(validators)`, sharing already verified QCs.
#[allow(
    clippy::too_many_arguments,
    reason = "The proposal's exact chunk context: domain, set, its root and seed."
)]
pub(crate) fn verify_proposal_with<'a>(
    domain: ConsensusDomain,
    validators: &[Validator],
    root: Hash,
    seed: &Seed,
    proposal: &'a BftProposal,
    fraction: (u64, u64),
    verifier: &mut impl Verifier,
    quorums: &mut VerifiedQuorums<'a>,
) -> Result<(), FinalityError> {
    if bft_leader_with_root(
        domain.chain_id,
        proposal.chunk.chunk_id,
        proposal.round,
        seed,
        validators,
        root,
    ) != Some(proposal.proposer_index)
        || proposal.chunk.active_validator_set_root != root
    {
        return Err(FinalityError::Target);
    }
    let validator = validators
        .get(proposal.proposer_index as usize)
        .ok_or(FinalityError::Membership)?;
    if !verifier.verify(
        &validator.pubkey,
        &proposal.signing_message(domain),
        &proposal.signature,
    ) {
        return Err(FinalityError::Signature);
    }
    match (proposal.round, &proposal.round_change_certificate) {
        (0, None) => {}
        (0, Some(_)) | (_, None) => return Err(FinalityError::Target),
        (_, Some(certificate)) => {
            if certificate.chunk_id != proposal.chunk.chunk_id
                || certificate.round != proposal.round
            {
                return Err(FinalityError::Target);
            }
            verify_round_change_certificate_with(
                domain,
                validators,
                certificate,
                fraction,
                verifier,
                quorums,
            )?;
            if certificate.highest_quorum().is_some_and(|highest| {
                proposal.valid_quorum.as_ref().is_none_or(|valid| {
                    valid.data.round < highest.data.round
                        || (valid.data.round == highest.data.round
                            && !valid.data.same_value(&highest.data))
                })
            }) {
                return Err(FinalityError::Target);
            }
        }
    }
    if let Some(quorum) = &proposal.valid_quorum {
        if quorum.data.chunk_id != proposal.chunk.chunk_id
            || quorum.data.chunk_hash != proposal.chunk.hash()
            || quorum.data.selection != proposal.selection()
            || quorum.data.round >= proposal.round
        {
            return Err(FinalityError::Target);
        }
        verify_quorum_with(domain, validators, quorum, fraction, verifier, quorums)
            .map_err(|_| FinalityError::Quorum)?;
    }
    Ok(())
}

/// Authenticate a nil aggregate and every individually retained signature.
pub fn verify_nil_vote(
    domain: ConsensusDomain,
    validators: &[Validator],
    vote: &NilVote,
) -> Result<(), FinalityError> {
    verify_nil_vote_using(
        domain,
        validators,
        vote,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Nil authentication with cached equations or a recursively authenticated fact set.
pub fn verify_nil_vote_using(
    domain: ConsensusDomain,
    validators: &[Validator],
    vote: &NilVote,
    verifier: &mut impl Verifier,
) -> Result<(), FinalityError> {
    if usize::try_from(vote.aggregation_bits.bit_len()).ok() != Some(validators.len()) {
        return Err(FinalityError::Membership);
    }
    let Some((keys, _)) = signers(validators, &vote.aggregation_bits) else {
        return Err(FinalityError::Membership);
    };
    // Every claim signs `vote.data`, as does the aggregate.
    let message = vote.data.signing_message(domain);
    let mut seen = BTreeSet::new();
    for claim in &vote.attestations {
        if claim.vote != vote.data
            || !seen.insert(claim.validator_index)
            || vote.aggregation_bits.get(claim.validator_index) != Some(true)
        {
            return Err(FinalityError::Membership);
        }
        let validator = validators
            .get(claim.validator_index as usize)
            .ok_or(FinalityError::Membership)?;
        if !verifier.verify(&validator.pubkey, &message, &claim.vote_signature)
            || !verifier.verify(
                &validator.pubkey,
                &claim.signing_message(domain),
                &claim.signature,
            )
        {
            return Err(FinalityError::Signature);
        }
    }
    if keys.is_empty() || seen.len() != keys.len() {
        return Err(FinalityError::Membership);
    }
    if !verifier.aggregate(&keys, &message, &vote.signature) {
        return Err(FinalityError::Signature);
    }
    Ok(())
}

/// Verify one signed round-change report and its independently authenticated QC.
pub fn verify_round_change(
    domain: ConsensusDomain,
    validators: &[Validator],
    report: &RoundChange,
    fraction: (u64, u64),
) -> Result<(), FinalityError> {
    verify_round_change_using(
        domain,
        validators,
        report,
        fraction,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Round-change verification using shared keys/facts.
pub fn verify_round_change_using(
    domain: ConsensusDomain,
    validators: &[Validator],
    report: &RoundChange,
    fraction: (u64, u64),
    verifier: &mut impl Verifier,
) -> Result<(), FinalityError> {
    verify_round_change_with(
        domain,
        validators,
        report,
        fraction,
        verifier,
        &mut VerifiedQuorums::new(fraction),
    )
}

fn verify_round_change_with<'a>(
    domain: ConsensusDomain,
    validators: &[Validator],
    report: &'a RoundChange,
    fraction: (u64, u64),
    verifier: &mut impl Verifier,
    quorums: &mut VerifiedQuorums<'a>,
) -> Result<(), FinalityError> {
    let validator = validators
        .get(report.validator_index as usize)
        .filter(|validator| is_active(validator))
        .ok_or(FinalityError::Membership)?;
    if report.round == 0 {
        return Err(FinalityError::Target);
    }
    if !verifier.verify(
        &validator.pubkey,
        &report.signing_message(domain),
        &report.signature,
    ) {
        return Err(FinalityError::Signature);
    }
    if let Some(quorum) = &report.highest_quorum {
        if quorum.data.chunk_id != report.chunk_id || quorum.data.round >= report.round {
            return Err(FinalityError::Target);
        }
        verify_quorum_with(domain, validators, quorum, fraction, verifier, quorums)
            .map_err(|_| FinalityError::Quorum)?;
    }
    Ok(())
}

/// Authenticate a bounded unique active-stake quorum before advancing rounds.
pub fn verify_round_change_certificate(
    domain: ConsensusDomain,
    validators: &[Validator],
    certificate: &RoundChangeCertificate,
    fraction: (u64, u64),
) -> Result<(), FinalityError> {
    verify_round_change_certificate_using(
        domain,
        validators,
        certificate,
        fraction,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Authenticate a pacemaker certificate through a shared verifier.
pub fn verify_round_change_certificate_using(
    domain: ConsensusDomain,
    validators: &[Validator],
    certificate: &RoundChangeCertificate,
    fraction: (u64, u64),
    verifier: &mut impl Verifier,
) -> Result<(), FinalityError> {
    verify_round_change_certificate_with(
        domain,
        validators,
        certificate,
        fraction,
        verifier,
        &mut VerifiedQuorums::new(fraction),
    )
}

fn verify_round_change_certificate_with<'a>(
    domain: ConsensusDomain,
    validators: &[Validator],
    certificate: &'a RoundChangeCertificate,
    (numerator, denominator): (u64, u64),
    verifier: &mut impl Verifier,
    quorums: &mut VerifiedQuorums<'a>,
) -> Result<(), FinalityError> {
    if certificate.reports.is_empty()
        || certificate.reports.len() > validators.len()
        || !quorum_fraction_valid(numerator, denominator)
    {
        return Err(FinalityError::Membership);
    }
    let mut seen = BTreeSet::new();
    let mut stake = 0_u128;
    let total = active_stake_total(validators).ok_or(FinalityError::Membership)?;
    for report in &certificate.reports {
        if report.chunk_id != certificate.chunk_id
            || report.round != certificate.round
            || !seen.insert(report.validator_index)
        {
            return Err(FinalityError::Target);
        }
        verify_round_change_with(
            domain,
            validators,
            report,
            (numerator, denominator),
            verifier,
            quorums,
        )?;
        stake = stake
            .checked_add(validators[report.validator_index as usize].effective_stake)
            .ok_or(FinalityError::Membership)?;
    }
    if !quorum_reached(stake, total, numerator, denominator) {
        return Err(FinalityError::Quorum);
    }
    Ok(())
}
