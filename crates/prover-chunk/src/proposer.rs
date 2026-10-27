//! Guest-compatible proposer signature and VRF validation.

use neutrin0_consensus_types::Header;
use neutrin0_primitives::{DOMAIN_PROPOSER_SIG, FixedU128, Hash, Seed, Validator};
use neutrin0_vrf::{is_eligible, vrf_message};
use sha2::{Digest, Sha256};

use crate::finality::{active_stake_total, is_active};

/// Proposer authentication or stake-weighted eligibility failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposerError {
    /// Unknown, slashed or zero-stake validator; empty or overflowing stake.
    Validator,
    /// Header signature is invalid.
    Signature,
    /// VRF signature is invalid for the chain, seed and slot.
    Vrf,
    /// Valid VRF output falls outside the stake-weighted threshold.
    Ineligible,
}

/// Eligibility inputs shared by every header checked against one validator set.
#[derive(Clone, Copy)]
pub(crate) struct Proposers<'a> {
    /// Authenticated validator set.
    pub(crate) validators: &'a [Validator],
    /// `active_stake_total(validators)`, computed once for the whole set.
    pub(crate) total: Option<u128>,
    /// Finalized randomness the VRF is evaluated over.
    pub(crate) seed: &'a Seed,
    /// Expected proposers per slot.
    pub(crate) expected: FixedU128,
}

impl<'a> Proposers<'a> {
    /// Precompute the active stake of `validators`.
    pub(crate) fn new(validators: &'a [Validator], seed: &'a Seed, expected: FixedU128) -> Self {
        Self {
            validators,
            total: active_stake_total(validators),
            seed,
            expected,
        }
    }
}

/// Verify the proposer signature and the BLS-VRF claim inside a guest.
pub fn verify_proposer(
    header: &Header,
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    seed: &Seed,
    expected_proposers: FixedU128,
) -> Result<(), ProposerError> {
    verify_proposer_using(
        header,
        domain,
        validators,
        seed,
        expected_proposers,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_proposer_using(
    header: &Header,
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    seed: &Seed,
    expected_proposers: FixedU128,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), ProposerError> {
    verify_proposer_with(
        header,
        &header.hash(),
        domain,
        Proposers::new(validators, seed, expected_proposers),
        verifier,
    )
}

/// [`verify_proposer_using`] with `header_hash == header.hash()` and the set's
/// active stake already computed. A missing total is reported where the
/// per-header computation reported it.
pub(crate) fn verify_proposer_with(
    header: &Header,
    header_hash: &Hash,
    domain: neutrin0_primitives::ConsensusDomain,
    proposers: Proposers<'_>,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), ProposerError> {
    let validators = proposers.validators;
    verify_header_signature_with(header, header_hash, domain, validators, verifier)?;
    let validator = usize::try_from(header.proposer_index)
        .ok()
        .and_then(|index| validators.get(index))
        .filter(|validator| is_active(validator))
        .ok_or(ProposerError::Validator)?;
    let total = proposers.total.ok_or(ProposerError::Validator)?;
    let vrf_message = vrf_message(domain, proposers.seed, header.slot);
    if !verifier.verify(&validator.pubkey, &vrf_message, &header.vrf_proof) {
        return Err(ProposerError::Vrf);
    }
    let output = Sha256::digest(header.vrf_proof).into();
    if !is_eligible(
        &output,
        validator.effective_stake,
        total,
        proposers.expected,
    ) {
        return Err(ProposerError::Ineligible);
    }
    Ok(())
}

/// Authenticate a header without assuming its VRF claim is valid.
pub fn verify_header_signature(
    header: &Header,
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
) -> Result<(), ProposerError> {
    verify_header_signature_using(
        header,
        domain,
        validators,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_header_signature_using(
    header: &Header,
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), ProposerError> {
    verify_header_signature_with(header, &header.hash(), domain, validators, verifier)
}

/// [`verify_header_signature_using`] with `header_hash == header.hash()`.
pub(crate) fn verify_header_signature_with(
    header: &Header,
    header_hash: &Hash,
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), ProposerError> {
    let validator = validators
        .get(header.proposer_index as usize)
        .filter(|validator| is_active(validator))
        .ok_or(ProposerError::Validator)?;
    // A header cited from before a hard fork verifies under its own domain.
    let message = domain
        .at_height(header.height)
        .signing_message(DOMAIN_PROPOSER_SIG, header_hash);
    if !verifier.verify(&validator.pubkey, &message, &header.signature) {
        return Err(ProposerError::Signature);
    }
    Ok(())
}
