//! Portable BLS12-381 min-pk POP verification for SP1 guests.
//!
//! Uses the same cipher-suite domains as `neutrin0-crypto::bls`.
//! Checked decompression enforces curve and subgroup membership; identity
//! keys/signatures and identity aggregates are rejected explicitly.

use bls12_381::{
    G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt,
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    multi_miller_loop,
};
use neutrin0_primitives::{BlsPublicKey, BlsSignature};
use sha2_10::Sha256;

mod batch;
#[cfg(test)]
mod batch_tests;
mod caches;
#[cfg(test)]
mod tests;

pub use batch::BatchVerifier;
pub use caches::CheckedKeys;
use caches::{CheckedSignatures, PreparedMessages};

/// Signature cipher-suite domain for min-pk POP.
pub const SIG_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// Proof-of-possession cipher-suite domain.
pub const POP_DST: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

pub(super) fn public_key(bytes: &BlsPublicKey) -> Option<G1Affine> {
    let point = Option::<G1Affine>::from(G1Affine::from_compressed(bytes))?;
    (!bool::from(point.is_identity())).then_some(point)
}

fn verify_point(key: G1Affine, message: &[u8], signature: &BlsSignature, dst: &[u8]) -> bool {
    let Some(signature) = Option::<G2Affine>::from(G2Affine::from_compressed(signature)) else {
        return false;
    };
    if bool::from(key.is_identity()) || bool::from(signature.is_identity()) {
        return false;
    }
    verify_checked_points(key, message, signature, dst)
}

fn verify_checked_points(key: G1Affine, message: &[u8], signature: G2Affine, dst: &[u8]) -> bool {
    let message_point =
        <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([message], dst);
    // One final exponentiation for the pairing-product identity saves guest
    // work without changing either subgroup checks or the signature equation.
    multi_miller_loop(&[
        (&key, &G2Prepared::from(G2Affine::from(message_point))),
        (&-G1Affine::generator(), &G2Prepared::from(signature)),
    ])
    .final_exponentiation()
        == Gt::identity()
}

/// Verify one signature, rejecting malformed, non-subgroup or identity points.
#[must_use]
pub fn verify(key: &BlsPublicKey, message: &[u8], signature: &BlsSignature) -> bool {
    public_key(key).is_some_and(|point| verify_point(point, message, signature, SIG_DST))
}

/// Verify possession of a validator key before admitting it to an aggregate.
#[must_use]
pub fn verify_pop(key: &BlsPublicKey, proof: &BlsSignature) -> bool {
    public_key(key).is_some_and(|point| verify_point(point, key, proof, POP_DST))
}

/// Verify a registration's proof of possession for the registering `address`.
///
/// The proof signs [`neutrin0_primitives::registration_pop_message`], so a
/// proof copied from another registration fails for any other address.
#[must_use]
pub fn verify_registration_pop(
    key: &BlsPublicKey,
    address: &neutrin0_primitives::Hash,
    proof: &BlsSignature,
) -> bool {
    let message = neutrin0_primitives::registration_pop_message(key, address);
    public_key(key).is_some_and(|point| verify_point(point, &message, proof, POP_DST))
}

/// Verify a same-message aggregate over a nonempty set of authenticated keys.
///
/// Callers must authenticate key membership and prior possession checks;
/// aggregate verification by itself does not establish either property.
#[must_use]
pub fn fast_aggregate_verify(
    keys: &[BlsPublicKey],
    message: &[u8],
    signature: &BlsSignature,
) -> bool {
    if keys.is_empty() {
        return false;
    }
    let mut aggregate = G1Projective::identity();
    for key in keys {
        let Some(point) = public_key(key) else {
            return false;
        };
        aggregate += point;
    }
    verify_point(G1Affine::from(aggregate), message, signature, SIG_DST)
}

/// Signature checks used by consensus and by recursively authenticated facts.
/// A deferred verifier must be finished before its enclosing statement is accepted.
pub trait Verifier {
    /// Check a signature under the signature cipher suite.
    fn verify(&mut self, key: &BlsPublicKey, message: &[u8], signature: &BlsSignature) -> bool;
    /// Check a same-message aggregate; callers authenticate membership and POP.
    fn aggregate(
        &mut self,
        keys: &[BlsPublicKey],
        message: &[u8],
        signature: &BlsSignature,
    ) -> bool;
    /// Check proof of possession under its separate cipher-suite domain.
    fn pop(&mut self, key: &BlsPublicKey, signature: &BlsSignature) -> bool;
}

pub(super) fn verify_cached_points(
    key: G1Affine,
    signature: G2Affine,
    message: &G2Prepared,
) -> bool {
    multi_miller_loop(&[
        (&key, message),
        (&-G1Affine::generator(), &G2Prepared::from(signature)),
    ])
    .final_exponentiation()
        == Gt::identity()
}

/// Immediate verification for decisions that depend on a negative verdict.
#[derive(Default)]
pub struct DirectVerifier {
    keys: CheckedKeys,
    signatures: CheckedSignatures,
    messages: PreparedMessages,
}

impl DirectVerifier {
    fn check(
        &mut self,
        key: Option<G1Affine>,
        message: &[u8],
        signature: &BlsSignature,
        dst: &'static [u8],
    ) -> bool {
        let Some(key) = key else {
            return false;
        };
        let Some(signature) = self.signatures.get(signature) else {
            return false;
        };
        verify_cached_points(key, signature, self.messages.get(message, dst).as_ref())
    }
}

impl Verifier for DirectVerifier {
    fn verify(&mut self, key: &BlsPublicKey, message: &[u8], signature: &BlsSignature) -> bool {
        let point = self.keys.get(key);
        self.check(point, message, signature, SIG_DST)
    }
    fn aggregate(
        &mut self,
        keys: &[BlsPublicKey],
        message: &[u8],
        signature: &BlsSignature,
    ) -> bool {
        let point = self.keys.aggregate(keys);
        self.check(point, message, signature, SIG_DST)
    }
    fn pop(&mut self, key: &BlsPublicKey, signature: &BlsSignature) -> bool {
        let point = self.keys.get(key);
        self.check(point, key, signature, POP_DST)
    }
}
