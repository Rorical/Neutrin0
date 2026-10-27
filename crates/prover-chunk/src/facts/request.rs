//! Exact inputs to deterministic cryptographic checks and their identities.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::BlockProof;
use neutrin0_primitives::{BlsPublicKey, BlsSignature, Hash};

use super::block_is_valid;
use crate::{
    bls::{self, Verifier},
    history::HistoryError,
};

/// Maximum independent assertions in one fact receipt.
pub const MAX_FACTS: usize = 64;

/// Exact input to a deterministic cryptographic check.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
#[allow(clippy::large_enum_variant)]
pub enum FactRequest {
    /// Signature or possession check with explicit cipher-suite separation.
    Signature {
        /// Public key.
        key: BlsPublicKey,
        /// Domain-tagged plaintext.
        message: Vec<u8>,
        /// Signature bytes.
        signature: BlsSignature,
        /// True only for POP (message must equal key).
        possession: bool,
    },
    /// Same-message aggregate; evidence separately authenticates key membership.
    Aggregate {
        /// Complete ordered signer keys.
        keys: Vec<BlsPublicKey>,
        /// Domain-tagged plaintext.
        message: Vec<u8>,
        /// Aggregate bytes.
        signature: BlsSignature,
    },
    /// Exact block envelope and accepted program identity.
    Block {
        /// Accepted runtime program.
        key: [u32; 8],
        /// Signed envelope, including proof bytes.
        proof: BlockProof,
    },
}

impl FactRequest {
    /// Content identity binds variant, lengths, domains, keys and exact bytes.
    pub fn id(&self) -> Hash {
        self.borrowed().id()
    }

    pub(super) const fn borrowed(&self) -> FactRequestRef<'_> {
        match self {
            Self::Signature {
                key,
                message,
                signature,
                possession,
            } => FactRequestRef::Signature {
                key,
                message: message.as_slice(),
                signature,
                possession: *possession,
            },
            Self::Aggregate {
                keys,
                message,
                signature,
            } => FactRequestRef::Aggregate {
                keys: keys.as_slice(),
                message: message.as_slice(),
                signature,
            },
            Self::Block { key, proof } => FactRequestRef::Block { key, proof },
        }
    }

    pub(super) fn verify(&self, verifier: &mut impl Verifier) -> Result<bool, HistoryError> {
        self.borrowed().verify(verifier)
    }

    pub(super) const fn scheduling_key(&self) -> (u8, &[u8], &[u8]) {
        match self {
            Self::Signature {
                message,
                possession,
                ..
            } => (
                0,
                if *possession {
                    bls::POP_DST
                } else {
                    bls::SIG_DST
                },
                message.as_slice(),
            ),
            Self::Aggregate { message, .. } => (1, bls::SIG_DST, message.as_slice()),
            Self::Block { .. } => (2, &[], &[]),
        }
    }
}

/// Deterministically pack unique requests by kind, cipher suite and message.
///
/// Full request ids break ties. Each at-most-64-item batch is then restored to
/// ascending id order, preserving canonical statement ordering and exact ids;
/// this changes only which requests share a proof. Callers bound the total work.
///
/// # Errors
/// Rejects repeated ids, including conflicting proposed verdicts for one input.
pub fn pack_requests(
    requests: Vec<(FactRequest, bool)>,
) -> Result<Vec<Vec<(FactRequest, bool)>>, HistoryError> {
    let mut seen = alloc::collections::BTreeSet::new();
    let mut requests = requests
        .into_iter()
        .map(|(request, valid)| (request.id(), request, valid))
        .collect::<Vec<_>>();
    if requests.iter().any(|(id, _, _)| !seen.insert(*id)) {
        return Err(HistoryError::Evidence);
    }
    requests.sort_unstable_by(|(left_id, left, _), (right_id, right, _)| {
        left.scheduling_key()
            .cmp(&right.scheduling_key())
            .then_with(|| left_id.cmp(right_id))
    });
    let mut batches = Vec::with_capacity(requests.len().div_ceil(MAX_FACTS));
    let mut pending = Vec::with_capacity(MAX_FACTS);
    for request in requests {
        pending.push(request);
        if pending.len() == MAX_FACTS {
            pending.sort_unstable_by_key(|(id, _, _)| *id);
            batches.push(
                pending
                    .into_iter()
                    .map(|(_, request, valid)| (request, valid))
                    .collect(),
            );
            pending = Vec::with_capacity(MAX_FACTS);
        }
    }
    if !pending.is_empty() {
        pending.sort_unstable_by_key(|(id, _, _)| *id);
        batches.push(
            pending
                .into_iter()
                .map(|(_, request, valid)| (request, valid))
                .collect(),
        );
    }
    Ok(batches)
}

/// Borrowed [`FactRequest`] with an identical Borsh encoding: the same variant
/// order, and `&[u8]`/`&[BlsPublicKey]` encode exactly like the owned vectors.
/// Verifiers derive ids from it without cloning messages, keys or proofs.
#[derive(BorshSerialize, Clone, Copy)]
pub(super) enum FactRequestRef<'a> {
    Signature {
        key: &'a BlsPublicKey,
        message: &'a [u8],
        signature: &'a BlsSignature,
        possession: bool,
    },
    Aggregate {
        keys: &'a [BlsPublicKey],
        message: &'a [u8],
        signature: &'a BlsSignature,
    },
    Block {
        key: &'a [u32; 8],
        proof: &'a BlockProof,
    },
}

impl FactRequestRef<'_> {
    /// Equal to [`FactRequest::id`] of the owned request.
    pub(super) fn id(self) -> Hash {
        neutrin0_consensus_types::tagged_commitment(b"neutrin0-cryptographic-fact", &self)
    }

    pub(super) fn verify(self, verifier: &mut impl Verifier) -> Result<bool, HistoryError> {
        match self {
            Self::Signature {
                key,
                message,
                signature,
                possession,
            } => Ok(if possession {
                message == key.as_slice() && verifier.pop(key, signature)
            } else {
                verifier.verify(key, message, signature)
            }),
            Self::Aggregate {
                keys,
                message,
                signature,
            } => Ok(verifier.aggregate(keys, message, signature)),
            Self::Block { key, proof } => block_is_valid(proof, key),
        }
    }

    pub(super) fn to_request(self) -> FactRequest {
        match self {
            Self::Signature {
                key,
                message,
                signature,
                possession,
            } => FactRequest::Signature {
                key: *key,
                message: message.to_vec(),
                signature: *signature,
                possession,
            },
            Self::Aggregate {
                keys,
                message,
                signature,
            } => FactRequest::Aggregate {
                keys: keys.to_vec(),
                message: message.to_vec(),
                signature: *signature,
            },
            Self::Block { key, proof } => FactRequest::Block {
                key: *key,
                proof: proof.clone(),
            },
        }
    }
}
