//! BLS-VRF message construction, evaluation, and verification.

use alloc::vec::Vec;

#[cfg(feature = "std")]
use neutrin0_crypto::{
    CryptoError,
    bls::{PublicKey, SecretKey, Signature},
    sha256,
};
use neutrin0_primitives::{ConsensusDomain, DOMAIN_VRF, Seed, Slot};

/// 32-byte VRF output, defined as `SHA-256(proof_bytes)`.
pub type VrfOutput = [u8; 32];

/// VRF proof: a deterministic BLS12-381 signature over [`vrf_message`].
#[cfg(feature = "std")]
pub type VrfProof = Signature;

/// Build the canonical BLS-VRF input bytes for a given `(chain, seed, slot)`.
///
/// Layout (little-endian for fixed-width integers):
///
/// ```text
/// DOMAIN_VRF (16) || chain_id (8) || chain_spec_hash (32) || finalized_seed (32) || slot (8)
/// ```
///
/// The tag, chain ID and complete chain-spec hash prevent cross-spec replay, the
/// `finalized_seed` binds eligibility to the latest finalized fork, and
/// `slot` makes each `(validator, slot)` tuple have exactly one output
/// per finalized-seed epoch.
pub fn vrf_message(domain: ConsensusDomain, finalized_seed: &Seed, slot: Slot) -> Vec<u8> {
    let mut payload = [0_u8; 32 + 8];
    payload[..32].copy_from_slice(finalized_seed);
    payload[32..].copy_from_slice(&slot.to_le_bytes());
    domain.signing_message(DOMAIN_VRF, &payload)
}

/// Evaluate the VRF for `(domain, finalized_seed, slot)` under `secret_key`.
///
/// Returns the proof (a deterministic 96-byte BLS signature) and the
/// 32-byte VRF output. The output is the value that
/// [`crate::is_eligible`] checks against the stake-weighted threshold.
#[cfg(feature = "std")]
pub fn eval(
    secret_key: &SecretKey,
    domain: ConsensusDomain,
    finalized_seed: &Seed,
    slot: Slot,
) -> (VrfProof, VrfOutput) {
    let message = vrf_message(domain, finalized_seed, slot);
    let proof = secret_key.sign(&message);
    let output = sha256(&proof.to_bytes());
    (proof, output)
}

/// Verify `proof` against `public_key` for `(domain, finalized_seed, slot)`.
///
/// On success returns the same 32-byte VRF output [`eval`] would have
/// produced, so the verifier can feed it directly into
/// [`crate::is_eligible`] without trusting any value the prover sent over
/// the wire.
#[cfg(feature = "std")]
pub fn verify(
    public_key: &PublicKey,
    domain: ConsensusDomain,
    finalized_seed: &Seed,
    slot: Slot,
    proof: &VrfProof,
) -> Result<VrfOutput, CryptoError> {
    let message = vrf_message(domain, finalized_seed, slot);
    public_key.verify(&message, proof)?;
    Ok(sha256(&proof.to_bytes()))
}

#[cfg(test)]
mod tests;
