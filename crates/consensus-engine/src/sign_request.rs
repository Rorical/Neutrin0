//! Typed signing requests.
//!
//! Everything a validator key signs is one of these, so a signer holding the
//! key in another process (`neutrin0-signer`) rebuilds each exact message
//! itself and can refuse one that conflicts with a message it already signed.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::{
    BftProposal, Header, NilVoteAttestation, RoundChange, VoteAttestation,
};
use neutrin0_crypto::bls::{PublicKey, Signature};
use neutrin0_primitives::{
    BlsPublicKey, BlsSignature, ConsensusDomain, DOMAIN_PROPOSER_SIG, Seed, Slot,
};

extern crate alloc;

/// Something a validator key signs.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub enum SignRequest {
    /// A block header, signed over its hash.
    Header(Header),
    /// The proposer VRF of `slot` under the finalized `seed`.
    Vrf {
        /// Finalized seed the slot's eligibility is drawn from.
        seed: Seed,
        /// Slot whose eligibility is evaluated.
        slot: Slot,
    },
    /// A finality vote and the attestation over it, both signatures unset.
    Vote(VoteAttestation),
    /// A nil vote and the attestation over it, both signatures unset.
    NilVote(NilVoteAttestation),
    /// A round leader's proposal, its signature unset.
    Proposal(Box<BftProposal>),
    /// A round change, its signature unset.
    RoundChange(RoundChange),
}

impl SignRequest {
    /// Sign each message of this request under `domain` with `sign`: a vote,
    /// then its attestation, which carries the vote's signature, for votes;
    /// the single message otherwise.
    pub fn sign_with(
        &self,
        domain: ConsensusDomain,
        mut sign: impl FnMut(&[u8]) -> BlsSignature,
    ) -> Vec<BlsSignature> {
        match self {
            Self::Header(header) => {
                vec![sign(
                    &domain.signing_message(DOMAIN_PROPOSER_SIG, &header.hash()),
                )]
            }
            Self::Vrf { seed, slot } => vec![sign(&neutrin0_vrf::vrf_message(domain, seed, *slot))],
            Self::Vote(claim) => {
                let mut claim = claim.clone();
                claim.vote_signature = sign(&claim.vote.signing_message(domain));
                vec![claim.vote_signature, sign(&claim.signing_message(domain))]
            }
            Self::NilVote(claim) => {
                let mut claim = claim.clone();
                claim.vote_signature = sign(&claim.vote.signing_message(domain));
                vec![claim.vote_signature, sign(&claim.signing_message(domain))]
            }
            Self::Proposal(proposal) => vec![sign(&proposal.signing_message(domain))],
            Self::RoundChange(report) => vec![sign(&report.signing_message(domain))],
        }
    }

    /// Whether `signatures` are exactly `identity`'s signatures of this
    /// request under `domain`, in [`Self::sign_with`] order.
    #[must_use]
    pub fn verify(
        &self,
        domain: ConsensusDomain,
        identity: &BlsPublicKey,
        signatures: &[BlsSignature],
    ) -> bool {
        let Ok(key) = PublicKey::from_bytes(identity) else {
            return false;
        };
        // Replay the signing order, feeding each given signature in place of
        // signing, so a later message is built over the earlier signature.
        let mut given = signatures.iter();
        let mut valid = true;
        let replayed = self.sign_with(domain, |message| {
            let Some(signature) = given.next() else {
                valid = false;
                return [0; 96];
            };
            valid &= Signature::from_bytes(signature)
                .is_ok_and(|parsed| key.verify(message, &parsed).is_ok());
            *signature
        });
        valid && replayed.len() == signatures.len()
    }
}

/// A validator key held by another process.
pub trait RemoteSigner: Send + Sync + core::fmt::Debug {
    /// `identity`'s signatures of `request`, in [`SignRequest::sign_with`]
    /// order, or why there are none.
    ///
    /// # Errors
    /// Returns the signer's refusal or an unreachable signer.
    fn sign(
        &self,
        identity: &BlsPublicKey,
        request: &SignRequest,
    ) -> Result<Vec<BlsSignature>, String>;
}
