//! Union aggregation of individually signed value and nil votes.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Crate-visible helpers of a private module; `pub` would be unreachable."
)]

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};

use neutrin0_consensus_types::{
    AggregatedVote, FinalityVote, FinalityVoteData, FinalityVotePhase, NilVote,
};
use neutrin0_primitives::{BitVec, BlsSignature, Validator};

use crate::BftError;
use crate::stake::bitmap_stake;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VoteAccumulator {
    pub(crate) phase: FinalityVotePhase,
    pub(crate) aggregate: Option<AggregatedVote>,
    pub(crate) aggregate_stake: u128,
    pub(crate) attestations: Vec<neutrin0_consensus_types::VoteAttestation>,
    pub(crate) proof_manifests: BTreeMap<
        neutrin0_consensus_types::ProofAcceptanceCommitment,
        Arc<neutrin0_consensus_types::ProofManifest>,
    >,
}

impl VoteAccumulator {
    pub(crate) const fn new(phase: FinalityVotePhase) -> Self {
        Self {
            phase,
            aggregate: None,
            aggregate_stake: 0,
            attestations: Vec::new(),
            proof_manifests: BTreeMap::new(),
        }
    }

    pub(crate) fn record(
        &mut self,
        vote: FinalityVote,
        stake: u128,
        validators: &[Validator],
        manifest_roots: Vec<neutrin0_consensus_types::ProofAcceptanceCommitment>,
    ) -> Result<(), BftError> {
        let Some(existing) = &self.aggregate else {
            self.proof_manifests = manifest_roots
                .into_iter()
                .zip(vote.proof_manifests)
                .map(|(root, manifest)| (root, Arc::new(manifest)))
                .collect();
            self.attestations = vote.attestations;
            self.aggregate = Some(AggregatedVote {
                aggregation_bits: vote.aggregation_bits,
                signature: vote.signature,
            });
            self.aggregate_stake = stake;
            return Ok(());
        };
        let claims = merge_signed_claims(&self.attestations, vote.attestations, |claim| {
            (claim.validator_index, claim.vote_signature)
        })?;
        let retained = self.attestations.len();
        if claims.len() == retained {
            return Ok(());
        }
        let signature = extend_vote_aggregate(&existing.signature, &claims, retained, |claim| {
            claim.vote_signature
        })?;
        let aggregation_bits = union_bit_vecs(&existing.aggregation_bits, &vote.aggregation_bits);
        let combined_stake = bitmap_stake(validators, &aggregation_bits)?;
        let required: BTreeSet<_> = claims
            .iter()
            .filter_map(|claim| claim.proof_acceptance)
            .collect();
        let mut manifests = self.proof_manifests.clone();
        for (root, manifest) in manifest_roots.into_iter().zip(vote.proof_manifests) {
            if !required.contains(&root) {
                continue;
            }
            if let Some(prior) = manifests.get(&root) {
                if prior.as_ref() != &manifest {
                    return Err(BftError::InvalidAggregateSignature);
                }
            } else {
                manifests.insert(root, Arc::new(manifest));
            }
        }
        manifests.retain(|root, _| required.contains(root));
        let hashes = manifests
            .keys()
            .try_fold(0_u64, |sum, root| sum.checked_add(root.count));
        if manifests.len() != required.len()
            || manifests.len() > neutrin0_primitives::MAX_CONSENSUS_VALIDATORS
            || hashes
                .is_none_or(|hashes| hashes > neutrin0_primitives::MAX_CONSENSUS_COMMITTEE_BLOCKS)
        {
            return Err(BftError::InvalidAggregateSignature);
        }
        self.proof_manifests = manifests;
        self.attestations = claims;
        self.aggregate = Some(AggregatedVote {
            aggregation_bits,
            signature,
        });
        self.aggregate_stake = combined_stake;
        Ok(())
    }

    pub(crate) fn aggregate(&self) -> Option<AggregatedVote> {
        self.aggregate.clone()
    }

    /// The retained aggregate as a vote for `data`, if any vote was recorded.
    pub(crate) fn vote(&self, data: FinalityVoteData) -> Option<FinalityVote> {
        let aggregate = self.aggregate.as_ref()?;
        Some(FinalityVote {
            proof_manifests: self
                .proof_manifests
                .values()
                .map(|manifest| manifest.as_ref().clone())
                .collect(),
            aggregation_bits: aggregate.aggregation_bits.clone(),
            signature: aggregate.signature,
            data,
            attestations: self.attestations.clone(),
        })
    }

    /// Whether every signer bit and every claim of `vote` is already retained.
    /// Such a replay changes nothing, so its signatures need not be verified
    /// again; retained claims were verified when first accepted.
    pub(crate) fn already_covers(&self, vote: &FinalityVote) -> bool {
        let Some(existing) = &self.aggregate else {
            return false;
        };
        if vote.attestations.is_empty() {
            return false;
        }
        let retained: BTreeSet<_> = self
            .attestations
            .iter()
            .map(|claim| (claim.validator_index, claim.vote_signature))
            .collect();
        (0..vote.aggregation_bits.bit_len()).all(|index| {
            vote.aggregation_bits.get(index) != Some(true)
                || existing.aggregation_bits.get(index) == Some(true)
        }) && vote
            .attestations
            .iter()
            .all(|claim| retained.contains(&(claim.validator_index, claim.vote_signature)))
    }
}

/// [`VoteAccumulator::already_covers`] for a retained nil aggregate.
pub(crate) fn nil_already_covers(known: &NilVote, vote: &NilVote) -> bool {
    if vote.attestations.is_empty() {
        return false;
    }
    let retained: BTreeSet<_> = known
        .attestations
        .iter()
        .map(|claim| (claim.validator_index, claim.vote_signature))
        .collect();
    (0..vote.aggregation_bits.bit_len()).all(|index| {
        vote.aggregation_bits.get(index) != Some(true)
            || known.aggregation_bits.get(index) == Some(true)
    }) && vote
        .attestations
        .iter()
        .all(|claim| retained.contains(&(claim.validator_index, claim.vote_signature)))
}

pub(crate) fn merge_signed_claims<T: Clone>(
    retained: &[T],
    incoming: Vec<T>,
    signer: impl Fn(&T) -> (u32, BlsSignature),
) -> Result<Vec<T>, BftError> {
    use alloc::collections::btree_map::Entry;
    let mut signatures: alloc::collections::BTreeMap<_, _> = retained.iter().map(&signer).collect();
    let mut claims = retained.to_vec();
    for claim in incoming {
        let (index, signature) = signer(&claim);
        match signatures.entry(index) {
            Entry::Occupied(prior) if *prior.get() != signature => {
                return Err(BftError::InvalidAggregateSignature);
            }
            Entry::Occupied(_) => {}
            Entry::Vacant(entry) => {
                entry.insert(signature);
                claims.push(claim);
            }
        }
    }
    Ok(claims)
}

pub(crate) fn union_bit_vecs(left: &BitVec, right: &BitVec) -> BitVec {
    debug_assert_eq!(left.bit_len(), right.bit_len());
    let mut out = BitVec::default();
    for index in 0..left.bit_len() {
        out.push(left.get(index).unwrap_or(false) || right.get(index).unwrap_or(false));
    }
    out
}

#[cfg(feature = "std")]
pub(crate) fn aggregate_vote_signatures(
    signatures: &[BlsSignature],
) -> Result<BlsSignature, BftError> {
    let signatures = signatures
        .iter()
        .map(neutrin0_crypto::bls::Signature::from_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| BftError::InvalidAggregateSignature)?;
    let refs: Vec<_> = signatures.iter().collect();
    neutrin0_crypto::bls::aggregate_signatures(&refs)
        .map(|signature| signature.to_bytes())
        .map_err(|_| BftError::InvalidAggregateSignature)
}

/// Aggregate the vote signatures of `claims[retained..]` onto `existing`, the
/// aggregate of exactly `claims[..retained]`.
///
/// Every retained aggregate was verified with exact signer coverage against
/// individually verified, subgroup-checked claim signatures. BLS signatures are
/// unique per key and message, so a verified aggregate is the group sum of its
/// claims; group addition is associative and commutative and the compressed
/// encoding is canonical, so the result equals aggregating every claim afresh.
/// The identity, reachable only when retained signatures cancel, does not
/// decode and falls back to that full aggregation.
#[cfg(feature = "std")]
pub(crate) fn extend_vote_aggregate<T>(
    existing: &BlsSignature,
    claims: &[T],
    retained: usize,
    vote_signature: impl Fn(&T) -> BlsSignature,
) -> Result<BlsSignature, BftError> {
    let Ok(existing) = neutrin0_crypto::bls::Signature::from_bytes(existing) else {
        let signatures: Vec<_> = claims.iter().map(&vote_signature).collect();
        return aggregate_vote_signatures(&signatures);
    };
    let added = claims[retained..]
        .iter()
        .map(|claim| neutrin0_crypto::bls::Signature::from_bytes(&vote_signature(claim)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| BftError::InvalidAggregateSignature)?;
    let refs: Vec<_> = core::iter::once(&existing).chain(&added).collect();
    neutrin0_crypto::bls::aggregate_signatures(&refs)
        .map(|signature| signature.to_bytes())
        .map_err(|_| BftError::InvalidAggregateSignature)
}

#[cfg(not(feature = "std"))]
pub(crate) fn extend_vote_aggregate<T>(
    _existing: &BlsSignature,
    _claims: &[T],
    _retained: usize,
    _vote_signature: impl Fn(&T) -> BlsSignature,
) -> Result<BlsSignature, BftError> {
    Err(BftError::SignatureAggregationUnavailable)
}
