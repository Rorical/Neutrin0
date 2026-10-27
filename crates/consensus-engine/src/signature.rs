//! Header-signature verification.
//!
//! The proposer signs its own header under [`DOMAIN_PROPOSER_SIG`] through
//! [`crate::ProposerKey::sign`]. Followers re-derive
//! the same message and verify against the proposer's BLS public key
//! looked up in the active validator set.
//!
//! The message bound by the signature is
//! `DOMAIN_PROPOSER_SIG || chain_id (u64 LE) || chain_spec_hash (32) || header_hash (32)`.

use neutrin0_consensus_types::Header;
use neutrin0_crypto::bls::{PublicKey, Signature};
use neutrin0_primitives::{BlsPublicKey, ConsensusDomain, DOMAIN_PROPOSER_SIG, Hash, Validator};

extern crate alloc;
use alloc::vec::Vec;

/// Failures while verifying a header proposer signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    /// Header references a validator index outside the active set.
    ValidatorIndexOutOfBounds {
        /// Referenced validator index.
        index: u32,
        /// Active-set length.
        len: usize,
    },
    /// Validator's stored BLS public key bytes do not decode.
    InvalidPublicKey {
        /// Validator index whose public key bytes were invalid.
        index: u32,
    },
    /// Signature bytes do not decode under the BLS scheme.
    InvalidSignatureBytes,
    /// Signature was well-formed but did not verify against the
    /// canonical signed message.
    BadSignature,
}

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ValidatorIndexOutOfBounds { index, len } => write!(
                f,
                "header proposer index {index} is outside active set of length {len}"
            ),
            Self::InvalidPublicKey { index } => write!(
                f,
                "validator {index} has malformed BLS public-key bytes in the active set"
            ),
            Self::InvalidSignatureBytes => f.write_str("header signature bytes are malformed"),
            Self::BadSignature => f.write_str("header signature failed BLS verification"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignatureError {}

/// Build the canonical message bound by the proposer signature.
///
/// This is the exact byte sequence the proposer's BLS signature covers.
/// Followers reconstruct the same bytes to verify.
#[must_use]
pub fn proposer_signed_message(domain: ConsensusDomain, header_hash: &Hash) -> Vec<u8> {
    domain.signing_message(DOMAIN_PROPOSER_SIG, header_hash)
}

/// Verify the proposer signature carried by `header` against the
/// validator's BLS public key in `active_set`.
///
/// On success returns the validator entry whose key matched. Returns
/// [`SignatureError`] for every failure mode: out-of-range validator
/// index, malformed key, malformed signature, or signature that does
/// not verify against the canonical signed message.
///
/// # Errors
///
/// See [`SignatureError`] variants.
pub fn verify_header_signature<'a>(
    header: &Header,
    active_set: &'a [Validator],
    domain: ConsensusDomain,
) -> Result<&'a Validator, SignatureError> {
    let index = header.proposer_index;
    let position = usize::try_from(index).expect("u32 fits usize on supported targets");
    let validator = active_set
        .get(position)
        .ok_or(SignatureError::ValidatorIndexOutOfBounds {
            index,
            len: active_set.len(),
        })?;

    let public_key = parse_public_key(&validator.pubkey, index)?;
    let signature = Signature::from_bytes(&header.signature)
        .map_err(|_| SignatureError::InvalidSignatureBytes)?;
    let header_hash = header.hash();
    // A header from before a hard fork was signed under its own domain.
    let message = proposer_signed_message(domain.at_height(header.height), &header_hash);
    public_key
        .verify(&message, &signature)
        .map_err(|_| SignatureError::BadSignature)?;
    Ok(validator)
}

fn parse_public_key(bytes: &BlsPublicKey, index: u32) -> Result<PublicKey, SignatureError> {
    PublicKey::from_bytes(bytes).map_err(|_| SignatureError::InvalidPublicKey { index })
}

#[cfg(test)]
mod tests;
