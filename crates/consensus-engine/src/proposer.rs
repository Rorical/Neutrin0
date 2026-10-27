//! Proposer key material and message signing.
//!
//! [`ProposerKey`] bundles a validator's BLS key, the canonical 48-byte
//! public-key bytes, and the validator index in the active set. The key is
//! held here or by a remote signer; production signs every message through
//! [`ProposerKey::sign`], so the key never leaks elsewhere.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

#[cfg(any(test, feature = "test-signing"))]
use neutrin0_consensus_types::FinalityVoteData;
use neutrin0_crypto::bls::{SecretKey, Signature};
use neutrin0_primitives::{BlsPublicKey, BlsSignature, ConsensusDomain, ValidatorIndex};
#[cfg(any(test, feature = "test-signing"))]
use neutrin0_primitives::{DOMAIN_PROPOSER_SIG, Hash, Seed, Slot};

use crate::sign_request::{RemoteSigner, SignRequest};

extern crate alloc;

/// Validator BLS key used to sign block headers and finality votes.
///
/// Cloning duplicates the underlying BLS secret-key material, or shares
/// the remote signer; local clones zeroise on drop. The chain backend and
/// engine each hold their own clone so the BFT-loop driver can sign votes
/// independently of the synchronous engine mutex. Production signs only
/// through [`ProposerKey::sign`]; the single-message helpers bypass the
/// journal, exist only for tests (`test-signing`), sign with a local key and
/// panic on a remote one.
#[derive(Clone, Debug)]
pub struct ProposerKey {
    signer: KeySigner,
    public_key_bytes: BlsPublicKey,
    validator_index: ValidatorIndex,
}

/// Where the secret key is.
#[derive(Clone, Debug)]
enum KeySigner {
    Local(SecretKey),
    Remote(Arc<dyn RemoteSigner>),
}

/// A request the validator's signer did not sign.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerError(pub String);

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "validator signer: {}", self.0)
    }
}

/// Errors when constructing a [`ProposerKey`] from raw bytes.
#[derive(Debug, Eq, PartialEq)]
pub enum ProposerKeyError {
    /// The IKM was too short for BLS `KeyGen`.
    InvalidKeyMaterial,
}

impl fmt::Display for ProposerKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyMaterial => f.write_str("BLS key derivation rejected the input IKM"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProposerKeyError {}

impl ProposerKey {
    /// Sign explicit vote, proof acceptance and the exact optional unlock claim.
    /// Bypasses the signing journal; tests only.
    #[must_use]
    #[cfg(any(test, feature = "test-signing"))]
    pub fn attest_vote(
        &self,
        domain: ConsensusDomain,
        vote: FinalityVoteData,
        proof_hashes: Vec<Hash>,
        unlock_quorum: Option<neutrin0_consensus_types::QuorumCertificate>,
    ) -> neutrin0_consensus_types::VoteAttestation {
        let proof_acceptance = (vote.phase
            == neutrin0_consensus_types::FinalityVotePhase::Precommit
            || !proof_hashes.is_empty())
        .then(|| neutrin0_consensus_types::ProofManifest { proof_hashes }.commitment());
        let mut attestation = neutrin0_consensus_types::VoteAttestation {
            validator_index: self.validator_index,
            vote_signature: self.sign_finality_vote(domain, &vote),
            vote,
            proof_acceptance,
            unlock_quorum,
            signature: [0; 96],
        };
        attestation.signature = self
            .sign_raw(&attestation.signing_message(domain))
            .to_bytes();
        attestation
    }
    /// Build a proposer from an existing BLS secret key.
    #[must_use]
    pub fn new(secret_key: SecretKey, validator_index: ValidatorIndex) -> Self {
        let public_key_bytes = secret_key.public_key().to_bytes();
        Self {
            signer: KeySigner::Local(secret_key),
            public_key_bytes,
            validator_index,
        }
    }

    /// A proposer whose key `public_key` a remote `signer` holds.
    #[must_use]
    pub fn remote(
        public_key: BlsPublicKey,
        signer: Arc<dyn RemoteSigner>,
        validator_index: ValidatorIndex,
    ) -> Self {
        Self {
            signer: KeySigner::Remote(signer),
            public_key_bytes: public_key,
            validator_index,
        }
    }

    /// Sign `request` under `domain`, in [`SignRequest::sign_with`] order.
    /// A remote signer's answer is used only once it verifies, so a signer
    /// configured for another chain signs nothing usable.
    ///
    /// # Errors
    /// Returns a refusal, an unreachable signer or signatures that do not
    /// verify.
    pub fn sign(
        &self,
        domain: ConsensusDomain,
        request: &SignRequest,
    ) -> Result<Vec<BlsSignature>, SignerError> {
        match &self.signer {
            KeySigner::Local(secret_key) => {
                Ok(request.sign_with(domain, |message| secret_key.sign(message).to_bytes()))
            }
            KeySigner::Remote(signer) => {
                let signatures = signer
                    .sign(&self.public_key_bytes, request)
                    .map_err(SignerError)?;
                if !request.verify(domain, &self.public_key_bytes, &signatures) {
                    return Err(SignerError(
                        "the signatures do not verify for this chain and key".into(),
                    ));
                }
                Ok(signatures)
            }
        }
    }

    /// The local secret key.
    ///
    /// # Panics
    /// Panics for a remote key, which signs only through [`Self::sign`].
    const fn local_key(&self) -> &SecretKey {
        match &self.signer {
            KeySigner::Local(secret_key) => secret_key,
            KeySigner::Remote(_) => panic!("a remote validator key signs only through sign()"),
        }
    }

    /// Derive a proposer deterministically from BLS-spec IKM bytes.
    ///
    /// Per BLS-12-381, IKM must be at least 32 bytes long.
    pub fn from_ikm(ikm: &[u8], validator_index: ValidatorIndex) -> Result<Self, ProposerKeyError> {
        let secret_key =
            SecretKey::key_gen(ikm, &[]).map_err(|_| ProposerKeyError::InvalidKeyMaterial)?;
        Ok(Self::new(secret_key, validator_index))
    }

    /// Validator index of this proposer in the active set.
    #[must_use]
    pub const fn validator_index(&self) -> ValidatorIndex {
        self.validator_index
    }

    /// Keep this BLS identity while binding it to its authenticated active-set
    /// position. Consensus rotation can change the position without changing
    /// either the secret key or its durable anti-equivocation identity.
    #[must_use]
    pub fn with_validator_index(&self, validator_index: ValidatorIndex) -> Self {
        Self {
            validator_index,
            ..self.clone()
        }
    }

    /// Canonical 48-byte BLS public-key bytes.
    #[must_use]
    pub const fn public_key_bytes(&self) -> &BlsPublicKey {
        &self.public_key_bytes
    }

    /// Sign raw bytes with the validator's BLS key. The engine
    /// always passes a *domain-tagged* message; this helper does not
    /// add any prefix itself.
    #[must_use]
    #[cfg(any(test, feature = "test-signing"))]
    pub fn sign_raw(&self, message: &[u8]) -> Signature {
        self.local_key().sign(message)
    }

    /// Produce the BLS proof-of-possession over this key's own
    /// public key under the `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO
    /// _POP_` DST. The signed payload is exactly
    /// `self.public_key_bytes()`, matching what
    /// [`PublicKey::verify_pop`](neutrin0_crypto::bls::PublicKey::verify_pop)
    /// expects.
    #[must_use]
    pub fn prove_possession(&self) -> Signature {
        self.local_key().prove_possession()
    }

    /// Proof of possession for a validator registration that
    /// registers this key at `address`, the validator's runtime address.
    /// Consensus seats the key only at the address the proof binds.
    #[must_use]
    pub fn prove_registration(&self, address: &[u8; 32]) -> Signature {
        self.local_key().prove_registration(address)
    }

    /// Borrow the underlying BLS secret key. Crate-internal so
    /// modules that need to call into `neutrin0-vrf::eval` (which
    /// requires the raw key) can do so without re-deriving it.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn secret_key(&self) -> &SecretKey {
        self.local_key()
    }

    /// Evaluate the proposer VRF for `(consensus_domain, seed, slot)` and
    /// return the 96-byte BLS signature ready to be assigned to
    /// [`neutrin0_consensus_types::Header::vrf_proof`].
    ///
    /// This is the public-key-encapsulated counterpart to
    /// [`neutrin0_vrf::eval`]; the raw `SecretKey` stays inside the
    /// crate. Callers that also need the deterministic VRF output
    /// (e.g. for fork choice randomness) can re-derive it via
    /// [`neutrin0_vrf::verify`] against the returned proof.
    #[must_use]
    #[cfg(any(test, feature = "test-signing"))]
    pub fn vrf_eval(&self, domain: ConsensusDomain, seed: &Seed, slot: Slot) -> BlsSignature {
        let (signature, _output) = neutrin0_vrf::eval(self.local_key(), domain, seed, slot);
        signature.to_bytes()
    }

    /// Sign a header hash under the proposer-signature domain.
    ///
    /// Returns the 96-byte BLS signature ready to be assigned to
    /// [`neutrin0_consensus_types::Header::signature`].
    #[must_use]
    #[cfg(any(test, feature = "test-signing"))]
    pub fn sign_proposer_message(
        &self,
        domain: ConsensusDomain,
        header_hash: &Hash,
    ) -> BlsSignature {
        self.sign_raw(&domain.signing_message(DOMAIN_PROPOSER_SIG, header_hash))
            .to_bytes()
    }

    /// Sign a finality-vote payload.
    ///
    /// Domain tag is [`neutrin0_primitives::DOMAIN_PREVOTE`] for prevotes and
    /// [`neutrin0_primitives::DOMAIN_PRECOMMIT`] for precommits; the rest of the message is
    /// `chain_id (LE u64) || chain_spec_hash (32) || borsh(FinalityVoteData)`.
    #[cfg(any(test, feature = "test-signing"))]
    pub fn sign_finality_vote(
        &self,
        domain: ConsensusDomain,
        vote_data: &FinalityVoteData,
    ) -> BlsSignature {
        self.sign_raw(&vote_data.signing_message(domain)).to_bytes()
    }
}

#[cfg(test)]
mod tests;
