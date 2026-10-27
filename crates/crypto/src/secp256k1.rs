//! secp256k1 ECDSA via `k256`.
//!
//! Provides 65-byte recoverable signatures (`r || s || v`) so a verifier can
//! identify the signer from the signature alone, matching Ethereum
//! conventions.
//!
//! The hash function used internally during signing/verification is
//! SHA-256, per the k256 crate's default. Callers that want a different
//! pre-hash should hash externally and call into the crate's hazmat API
//! (not exposed here).

use core::fmt;

use k256::ecdsa::{
    RecoveryId, Signature as K256Sig, SigningKey, VerifyingKey, signature::Verifier,
};
use k256::elliptic_curve::Generate;
use rand_core::CryptoRng;
use zeroize::ZeroizeOnDrop;

use crate::error::CryptoError;
use neutrin0_primitives::{Secp256k1PublicKey, Secp256k1Signature};

/// secp256k1 secret key. Zeroized on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey(SigningKey);

/// secp256k1 public key in SEC1 compressed form (33 bytes).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(VerifyingKey);

impl SecretKey {
    /// Sample a fresh secret key from a CSPRNG.
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        Self(SigningKey::generate_from_rng(rng))
    }

    /// Construct from a 32-byte big-endian scalar. Returns an error if
    /// the scalar is zero or outside the group order.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        SigningKey::from_bytes(bytes.into())
            .map(Self)
            .map_err(|_| CryptoError::InvalidSecretKey)
    }

    /// Serialize as 32 bytes big-endian.
    pub fn to_bytes(&self) -> [u8; 32] {
        let bytes = self.0.to_bytes();
        let mut out = [0_u8; 32];
        out.copy_from_slice(bytes.as_ref());
        out
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(*self.0.verifying_key())
    }

    /// Compute a 65-byte recoverable signature: `r (32) || s (32) || v (1)`.
    ///
    /// The signature is normalised to low-`s` per BIP-62 / RFC 6979 to
    /// avoid malleability.
    pub fn sign(&self, message: &[u8]) -> Secp256k1Signature {
        let (sig, recovery_id) = self.0.sign_recoverable(message);
        let mut out = [0_u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = recovery_id.to_byte();
        out
    }
}

impl PublicKey {
    /// Decode a 33-byte SEC1 compressed public key.
    pub fn from_bytes(bytes: &Secp256k1PublicKey) -> Result<Self, CryptoError> {
        VerifyingKey::from_sec1_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidPublicKey)
    }

    /// Encode as 33 bytes SEC1 compressed.
    pub fn to_bytes(&self) -> Secp256k1PublicKey {
        let encoded = self.0.to_sec1_point(true);
        let bytes = encoded.as_bytes();
        // The compressed encoding of an affine point is always 33 bytes
        // (1-byte tag + 32-byte x-coordinate); the underlying crate
        // guarantees this for VerifyingKey.
        debug_assert_eq!(bytes.len(), 33, "SEC1 compressed must be 33 bytes");
        let mut out = [0_u8; 33];
        out.copy_from_slice(bytes);
        out
    }

    /// Ethereum address: the final 20 bytes of Keccak(uncompressed x || y).
    pub fn ethereum_address(&self) -> [u8; 20] {
        let encoded = self.0.to_sec1_point(false);
        let hash = crate::keccak256(&encoded.as_bytes()[1..]);
        let mut address = [0; 20];
        address.copy_from_slice(&hash[12..]);
        address
    }

    /// Verify a 65-byte recoverable signature against `message`.
    ///
    /// The recovery byte is validated as part of the signature encoding,
    /// but it is not used to recover the signer. Callers that want to
    /// recover the signer from the signature alone should use [`recover`].
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Secp256k1Signature,
    ) -> Result<(), CryptoError> {
        RecoveryId::from_byte(signature[64]).ok_or(CryptoError::InvalidSignature)?;
        let sig =
            K256Sig::from_slice(&signature[..64]).map_err(|_| CryptoError::InvalidSignature)?;
        self.0
            .verify(message, &sig)
            .map_err(|_| CryptoError::Verification)
    }
}

/// Recover the signing public key from `message` and `signature`.
///
/// Returns an error if the signature is malformed or no valid public key
/// could be recovered. This is the standard ECDSA-with-recovery flow.
pub fn recover(message: &[u8], signature: &Secp256k1Signature) -> Result<PublicKey, CryptoError> {
    let sig = K256Sig::from_slice(&signature[..64]).map_err(|_| CryptoError::InvalidSignature)?;
    let recovery_id = RecoveryId::from_byte(signature[64]).ok_or(CryptoError::InvalidSignature)?;
    VerifyingKey::recover_from_msg(message, &sig, recovery_id)
        .map(PublicKey)
        .map_err(|_| CryptoError::Verification)
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("secp256k1::SecretKey")
            .field("pubkey", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("secp256k1::PublicKey")
            .field(&hex::encode(self.to_bytes()))
            .finish()
    }
}

#[cfg(test)]
mod tests;
