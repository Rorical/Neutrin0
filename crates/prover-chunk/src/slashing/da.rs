//! DA commitment fraud: a signed publication contradicting the header's root.

use neutrin0_primitives::Validator;

use super::EvidenceError;

/// Message authenticating publication of an exact DA bundle for one header.
pub fn da_publication_message(
    domain: neutrin0_primitives::ConsensusDomain,
    header_hash: &[u8; 32],
    bundle_hash: &[u8; 32],
) -> alloc::vec::Vec<u8> {
    let mut payload = alloc::vec::Vec::from(*header_hash);
    payload.extend_from_slice(bundle_hash);
    domain.signing_message(neutrin0_primitives::DOMAIN_DA_PUBLICATION, &payload)
}

/// Authenticate a mismatching full-body DA publication by the header signer.
/// This proves commitment fraud, not data availability or censorship.
pub fn verify_da_fraud(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    header: &neutrin0_consensus_types::Header,
    fraud: &neutrin0_consensus_types::DaFraudProof,
) -> Result<(), EvidenceError> {
    verify_da_fraud_using(
        domain,
        validators,
        header,
        fraud,
        &mut crate::bls::DirectVerifier::default(),
    )
}

/// Verification with a shared key cache or an authenticated fact source.
pub fn verify_da_fraud_using(
    domain: neutrin0_primitives::ConsensusDomain,
    validators: &[Validator],
    header: &neutrin0_consensus_types::Header,
    fraud: &neutrin0_consensus_types::DaFraudProof,
    verifier: &mut impl crate::bls::Verifier,
) -> Result<(), EvidenceError> {
    let header_hash = header.hash();
    crate::proposer::verify_header_signature_with(
        header,
        &header_hash,
        domain,
        validators,
        verifier,
    )
    .map_err(|_| EvidenceError::Signature)?;
    let validator = validators
        .get(header.proposer_index as usize)
        .ok_or(EvidenceError::Binding)?;
    let hash = neutrin0_primitives::blake3_256(&fraud.offending_bundle);
    if hash != fraud.bundle_hash || fraud.expected_da_root != header.da_root {
        return Err(EvidenceError::Binding);
    }
    if !verifier.verify(
        &validator.pubkey,
        &da_publication_message(domain.at_height(header.height), &header_hash, &hash),
        &fraud.publication_signature,
    ) {
        return Err(EvidenceError::Signature);
    }
    let body: neutrin0_consensus_types::Body =
        borsh::from_slice(&fraud.offending_bundle).map_err(|_| EvidenceError::Binding)?;
    let actual = crate::consensus::body_da_root(&body);
    if actual != fraud.computed_da_root || actual == header.da_root {
        return Err(EvidenceError::Binding);
    }
    Ok(())
}
