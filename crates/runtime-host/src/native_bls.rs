//! Immediate BLST verdicts for host Fact recording; Guests keep portable BLS.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Crate-visible adapter of a private module; `pub` would be unreachable."
)]

use neutrin0_crypto::bls::{PublicKey, Signature, fast_aggregate_verify};
use neutrin0_primitives::{BlsPublicKey, BlsSignature};
use neutrin0_prover_chunk::bls::Verifier;

/// No deferred decisions or host-supplied validity flags cross this adapter.
#[derive(Default)]
pub(super) struct NativeBlstVerifier;

fn checked_key(bytes: &BlsPublicKey) -> Option<PublicKey> {
    let point = PublicKey::from_bytes(bytes).ok()?;
    (point.to_bytes() == *bytes).then_some(point)
}

fn checked_signature(bytes: &BlsSignature) -> Option<Signature> {
    let point = Signature::from_bytes(bytes).ok()?;
    (point.to_bytes() == *bytes).then_some(point)
}

impl Verifier for NativeBlstVerifier {
    fn verify(&mut self, key: &BlsPublicKey, message: &[u8], signature: &BlsSignature) -> bool {
        let (Some(key), Some(signature)) = (checked_key(key), checked_signature(signature)) else {
            return false;
        };
        key.verify(message, &signature).is_ok()
    }

    fn aggregate(
        &mut self,
        keys: &[BlsPublicKey],
        message: &[u8],
        signature: &BlsSignature,
    ) -> bool {
        if keys.is_empty() {
            return false;
        }
        let Some(signature) = checked_signature(signature) else {
            return false;
        };
        let Some(keys) = keys.iter().map(checked_key).collect::<Option<Vec<_>>>() else {
            return false;
        };
        let keys: Vec<_> = keys.iter().collect();
        fast_aggregate_verify(&keys, message, &signature).is_ok()
    }

    fn pop(&mut self, key: &BlsPublicKey, signature: &BlsSignature) -> bool {
        let (Some(key), Some(signature)) = (checked_key(key), checked_signature(signature)) else {
            return false;
        };
        key.verify_pop(&signature).is_ok()
    }
}

#[cfg(test)]
mod tests;
