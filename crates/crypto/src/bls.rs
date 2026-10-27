//! BLS12-381 signature scheme via `blst`.
//!
//! # Variant and cipher suite
//!
//! Neutrin0 uses **min-pk** (public key on G1, signature on G2) with the
//! **POP scheme** (Proof of Possession):
//!
//! * `SIG_DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"`
//! * `POP_DST = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"`
//!
//! This follows the IRTF BLS POP cipher suite.
//! The POP scheme makes finality-vote aggregation safe against rogue-key
//! attacks without requiring per-message augmentation, at the cost of
//! requiring every validator to publish a one-shot proof-of-possession at
//! registration.
//!
//! # Domain-tagged plaintexts
//!
//! Consensus callers derive `ConsensusDomain` from the authenticated chain
//! specification and prepend a 16-byte `DOMAIN_*` tag, chain ID and complete
//! chain-specification hash *before* calling [`SecretKey::sign`]; the BLS
//! cipher suite DST handles only the per-curve subgroup binding. The two
//! layers of separation cannot collide because they apply to different
//! inputs of the hash-to-curve.
//!
//! # API summary
//!
//! * Single-signer: [`SecretKey::sign`] / [`PublicKey::verify`].
//! * Proof of possession: [`SecretKey::prove_possession`] /
//!   [`PublicKey::verify_pop`].
//! * Aggregation: [`aggregate_signatures`], [`aggregate_public_keys`].
//! * Verification of aggregates:
//!   - [`fast_aggregate_verify`]: many signers, one shared message — the
//!     hot path for finality-vote certificates.
//!   - [`aggregate_verify`]: signer `i` signed message `i`.

use core::fmt;

use blst::{
    BLST_ERROR,
    min_pk::{
        AggregatePublicKey, AggregateSignature, PublicKey as BlstPk, SecretKey as BlstSk,
        Signature as BlstSig,
    },
};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;
use neutrin0_primitives::{BlsPublicKey, BlsSignature};

/// Cipher-suite DST for `sign` / `verify` (POP scheme).
pub const SIG_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Cipher-suite DST for proof-of-possession operations.
pub const POP_DST: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// BLS12-381 secret key (32-byte big-endian scalar). Zeroized on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey(BlstSk);

/// BLS12-381 public key on G1 (48 bytes compressed).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(BlstPk);

/// BLS12-381 signature on G2 (96 bytes compressed).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(BlstSig);

impl SecretKey {
    /// Sample a fresh secret key from a CSPRNG.
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let mut ikm = [0_u8; 32];
        rng.fill_bytes(&mut ikm);
        let key = Self::key_gen(&ikm, &[]).expect("32-byte CSPRNG IKM is always sufficient");
        ikm.zeroize();
        key
    }

    /// IRTF-draft `KeyGen` from input key material.
    ///
    /// `ikm` MUST be at least 32 bytes of cryptographically uniform entropy.
    /// `key_info` is an optional domain separator (empty by default).
    pub fn key_gen(ikm: &[u8], key_info: &[u8]) -> Result<Self, CryptoError> {
        if ikm.len() < 32 {
            return Err(CryptoError::UnexpectedLength {
                actual: ikm.len(),
                expected: 32,
            });
        }
        BlstSk::key_gen(ikm, key_info)
            .map(Self)
            .map_err(|_| CryptoError::InvalidSecretKey)
    }

    /// Deserialize a 32-byte big-endian scalar. Rejects out-of-range
    /// (including zero) values.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        BlstSk::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::InvalidSecretKey)
    }

    /// Serialize as 32 bytes big-endian.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.sk_to_pk())
    }

    /// Sign `message` with this key under the cipher-suite [`SIG_DST`].
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.0.sign(message, SIG_DST, &[]))
    }

    /// Produce a proof-of-possession of this secret key.
    ///
    /// The signed payload is the secret key's own 48-byte compressed
    /// public key; the cipher-suite DST is [`POP_DST`]. Verified with
    /// [`PublicKey::verify_pop`].
    pub fn prove_possession(&self) -> Signature {
        let pk_bytes = self.public_key().to_bytes();
        Signature(self.0.sign(&pk_bytes, POP_DST, &[]))
    }

    /// Produce the proof of possession a validator registration carries.
    ///
    /// Signs [`neutrin0_primitives::registration_pop_message`] under
    /// [`POP_DST`], binding the key to the registering `address` so the proof
    /// cannot seat the key at any other address. Verified with
    /// [`PublicKey::verify_registration`].
    pub fn prove_registration(&self, address: &[u8; 32]) -> Signature {
        let message =
            neutrin0_primitives::registration_pop_message(&self.public_key().to_bytes(), address);
        Signature(self.0.sign(&message, POP_DST, &[]))
    }
}

impl PublicKey {
    /// Decode a 48-byte compressed G1 point and validate subgroup membership.
    pub fn from_bytes(bytes: &BlsPublicKey) -> Result<Self, CryptoError> {
        let pk = BlstPk::from_bytes(bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
        pk.validate().map_err(|_| CryptoError::InvalidPublicKey)?;
        Ok(Self(pk))
    }

    /// Encode as 48 bytes compressed.
    pub fn to_bytes(&self) -> BlsPublicKey {
        self.0.to_bytes()
    }

    /// Verify `signature` over `message`.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), CryptoError> {
        // `sig_groupcheck = true`, `pk_validate = true` — defensive even
        // though `from_bytes` already validates.
        match signature
            .0
            .verify(true, message, SIG_DST, &[], &self.0, true)
        {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            _ => Err(CryptoError::Verification),
        }
    }

    /// Verify a proof-of-possession produced by [`SecretKey::prove_possession`].
    pub fn verify_pop(&self, pop: &Signature) -> Result<(), CryptoError> {
        let pk_bytes = self.to_bytes();
        match pop.0.verify(true, &pk_bytes, POP_DST, &[], &self.0, true) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            _ => Err(CryptoError::Verification),
        }
    }

    /// Verify a registration proof produced by
    /// [`SecretKey::prove_registration`] for `address`.
    pub fn verify_registration(
        &self,
        address: &[u8; 32],
        pop: &Signature,
    ) -> Result<(), CryptoError> {
        let message = neutrin0_primitives::registration_pop_message(&self.to_bytes(), address);
        match pop.0.verify(true, &message, POP_DST, &[], &self.0, true) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            _ => Err(CryptoError::Verification),
        }
    }
}

impl Signature {
    /// Decode a 96-byte compressed G2 point, validate subgroup membership,
    /// and reject the identity element.
    pub fn from_bytes(bytes: &BlsSignature) -> Result<Self, CryptoError> {
        let sig = BlstSig::from_bytes(bytes).map_err(|_| CryptoError::InvalidSignature)?;
        sig.validate(true)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(Self(sig))
    }

    /// Encode as 96 bytes compressed.
    pub fn to_bytes(&self) -> BlsSignature {
        self.0.to_bytes()
    }
}

/// Aggregate a non-empty slice of signatures into one.
///
/// All inputs are subgroup-checked.
pub fn aggregate_signatures(signatures: &[&Signature]) -> Result<Signature, CryptoError> {
    if signatures.is_empty() {
        return Err(CryptoError::EmptyInput);
    }
    let sig_refs: Vec<&BlstSig> = signatures.iter().map(|s| &s.0).collect();
    let agg = AggregateSignature::aggregate(&sig_refs, true)
        .map_err(|_| CryptoError::InvalidSignature)?;
    Ok(Signature(agg.to_signature()))
}

/// Aggregate a non-empty slice of public keys into one.
///
/// All inputs are subgroup-checked.
pub fn aggregate_public_keys(public_keys: &[&PublicKey]) -> Result<PublicKey, CryptoError> {
    if public_keys.is_empty() {
        return Err(CryptoError::EmptyInput);
    }
    let pk_refs: Vec<&BlstPk> = public_keys.iter().map(|p| &p.0).collect();
    let agg =
        AggregatePublicKey::aggregate(&pk_refs, true).map_err(|_| CryptoError::InvalidPublicKey)?;
    Ok(PublicKey(agg.to_public_key()))
}

/// Verify that `signature` is the aggregate of every signer in
/// `public_keys` over the *same* `message`.
///
/// Hot path for chunk-BFT finality vote certificates: every prevote (or
/// every precommit) over a given `(chunk_id, round, chunk_hash)` is the
/// same message, so we collapse N pairings to 2.
pub fn fast_aggregate_verify(
    public_keys: &[&PublicKey],
    message: &[u8],
    signature: &Signature,
) -> Result<(), CryptoError> {
    if public_keys.is_empty() {
        return Err(CryptoError::EmptyInput);
    }
    let pk_refs: Vec<&BlstPk> = public_keys.iter().map(|p| &p.0).collect();
    match signature
        .0
        .fast_aggregate_verify(true, message, SIG_DST, &pk_refs)
    {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(CryptoError::Verification),
    }
}

/// Verify that `signature` is the aggregate of `public_keys[i]` signing
/// `messages[i]` for each `i`.
///
/// For distinct signers over distinct payloads.
pub fn aggregate_verify(
    public_keys: &[&PublicKey],
    messages: &[&[u8]],
    signature: &Signature,
) -> Result<(), CryptoError> {
    if public_keys.is_empty() {
        return Err(CryptoError::EmptyInput);
    }
    if public_keys.len() != messages.len() {
        return Err(CryptoError::UnexpectedLength {
            actual: messages.len(),
            expected: public_keys.len(),
        });
    }
    let pk_refs: Vec<&BlstPk> = public_keys.iter().map(|p| &p.0).collect();
    match signature
        .0
        .aggregate_verify(true, messages, SIG_DST, &pk_refs, true)
    {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(CryptoError::Verification),
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("bls::SecretKey")
            .field("pubkey", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("bls::PublicKey")
            .field(&hex::encode(self.to_bytes()))
            .finish()
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("bls::Signature")
            .field(&hex::encode(self.to_bytes()))
            .finish()
    }
}

#[cfg(test)]
mod tests;
