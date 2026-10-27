#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Consensus-level VRF integration.
//!
//! This crate sits above the low-level `neutrin0-vrf` primitive. It understands
//! validator-set indexing, header proposer claims and public chunk-aggregator
//! selection. The cryptographic construction and threshold math are implemented
//! in `neutrin0-vrf`; this crate wires those primitives to the consensus wire
//! types from designs 09 and 15.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use neutrin0_consensus_types::Header;
use neutrin0_crypto::{bls::PublicKey, bls::Signature, sha256};
use neutrin0_primitives::{
    BlsPublicKey, BlsSignature, ChunkId, ConsensusDomain, DOMAIN_AGG_PROOF, FixedU128, Hash, Seed,
    Slot, Validator, ValidatorIndex,
};
use neutrin0_vrf::{VrfOutput, is_eligible, verify};

/// Number of swap-or-not rounds used for public committee shuffling.
pub(crate) const SHUFFLE_ROUND_COUNT: u8 = 90;

/// Per-round swap-or-not pivots, which depend only on the seed.
type ShufflePivots = [u64; SHUFFLE_ROUND_COUNT as usize];

/// Result of a successful proposer VRF verification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProposerEligibility {
    /// Proposer index in the active validator set.
    pub validator_index: ValidatorIndex,
    /// Recomputed VRF output used for the stake-weighted threshold check.
    pub vrf_output: VrfOutput,
}

/// Public chunk-aggregator selection result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AggregatorSelection {
    /// Validator index in the active validator set.
    pub validator_index: ValidatorIndex,
    /// Public pseudo-random output used for the stake-weighted threshold check.
    pub selection_output: VrfOutput,
}

/// Inputs required to verify one proposer VRF claim.
#[derive(Clone, Copy, Debug)]
pub struct ProposerClaim<'a> {
    /// Validator BLS public key bytes.
    pub public_key: &'a BlsPublicKey,
    /// Validator effective stake, in wei.
    pub stake: u128,
    /// Total active stake for the validator set, in wei.
    pub total_stake: u128,
    /// Complete chain-spec signing domain bound into the VRF message.
    pub domain: ConsensusDomain,
    /// Latest finalized public seed.
    pub finalized_seed: &'a Seed,
    /// Slot being proposed for.
    pub slot: Slot,
    /// Proposer VRF proof from the header.
    pub vrf_proof: &'a BlsSignature,
    /// Expected proposer count per slot as `Q64.64`.
    pub expected_proposers_per_slot: FixedU128,
}

/// Errors returned by consensus-level VRF checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VrfError {
    /// The active validator set has no unslashed positive stake.
    ZeroTotalStake,
    /// The selected validator has zero effective stake.
    ZeroValidatorStake,
    /// Summing active stake overflowed `u128`.
    StakeOverflow,
    /// A validator index could not fit in the wire type.
    ValidatorIndexOverflow {
        /// Active-set length that could not be represented.
        len: usize,
    },
    /// A header referenced a validator index outside the active set.
    ValidatorIndexOutOfBounds {
        /// Referenced validator index.
        index: ValidatorIndex,
        /// Active-set length.
        len: usize,
    },
    /// The validator public key bytes were invalid.
    InvalidPublicKey,
    /// The VRF proof bytes were invalid or failed verification.
    InvalidProof,
    /// The VRF proof verified, but its output missed the stake-weighted threshold.
    NotEligible,
}

impl fmt::Display for VrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTotalStake => f.write_str("active validator set has zero total stake"),
            Self::ZeroValidatorStake => f.write_str("validator has zero effective stake"),
            Self::StakeOverflow => f.write_str("active validator stake overflowed u128"),
            Self::ValidatorIndexOverflow { len } => {
                write!(f, "active validator set length {len} exceeds u32::MAX")
            }
            Self::ValidatorIndexOutOfBounds { index, len } => {
                write!(
                    f,
                    "validator index {index} is outside active set length {len}"
                )
            }
            Self::InvalidPublicKey => f.write_str("invalid validator BLS public key"),
            Self::InvalidProof => f.write_str("invalid validator VRF proof"),
            Self::NotEligible => {
                f.write_str("validator VRF output missed the eligibility threshold")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VrfError {}

/// Computes total stake for all unslashed validators with positive stake.
pub fn total_active_stake(active_set: &[Validator]) -> Result<u128, VrfError> {
    let mut total = 0_u128;
    for validator in active_set {
        if validator.effective_stake == 0 {
            continue;
        }
        total = total
            .checked_add(validator.effective_stake)
            .ok_or(VrfError::StakeOverflow)?;
    }

    if total == 0 {
        return Err(VrfError::ZeroTotalStake);
    }

    Ok(total)
}

/// Verifies a raw proposer VRF claim against a public key and stake weight.
pub fn verify_proposer(claim: ProposerClaim<'_>) -> Result<VrfOutput, VrfError> {
    if claim.stake == 0 {
        return Err(VrfError::ZeroValidatorStake);
    }
    if claim.total_stake == 0 {
        return Err(VrfError::ZeroTotalStake);
    }

    let public_key = parse_public_key(claim.public_key)?;
    let proof = parse_proof(claim.vrf_proof)?;
    let output = verify(
        &public_key,
        claim.domain,
        claim.finalized_seed,
        claim.slot,
        &proof,
    )
    .map_err(|_| VrfError::InvalidProof)?;

    if !is_eligible(
        &output,
        claim.stake,
        claim.total_stake,
        claim.expected_proposers_per_slot,
    ) {
        return Err(VrfError::NotEligible);
    }

    Ok(output)
}

/// Verifies the proposer VRF claim carried by a block header.
pub fn verify_header_proposer(
    header: &Header,
    active_set: &[Validator],
    domain: ConsensusDomain,
    finalized_seed: &Seed,
    expected_proposers_per_slot: FixedU128,
) -> Result<ProposerEligibility, VrfError> {
    let validator = active_validator(active_set, header.proposer_index)?;
    let total_stake = total_active_stake(active_set)?;
    let vrf_output = verify_proposer(ProposerClaim {
        public_key: &validator.pubkey,
        stake: validator.effective_stake,
        total_stake,
        domain,
        finalized_seed,
        slot: header.slot,
        vrf_proof: &header.vrf_proof,
        expected_proposers_per_slot,
    })?;

    Ok(ProposerEligibility {
        validator_index: header.proposer_index,
        vrf_output,
    })
}

/// Computes the public pseudo-random output used for aggregator selection.
pub(crate) fn aggregator_selection_output(
    seed: &Seed,
    chunk_id: ChunkId,
    round: u32,
    validator_index: ValidatorIndex,
) -> VrfOutput {
    let mut message = Vec::with_capacity(DOMAIN_AGG_PROOF.len() + seed.len() + 8 + 4 + 4);
    message.extend_from_slice(&DOMAIN_AGG_PROOF);
    message.extend_from_slice(seed);
    message.extend_from_slice(&chunk_id.to_le_bytes());
    message.extend_from_slice(&round.to_le_bytes());
    message.extend_from_slice(&validator_index.to_le_bytes());
    sha256(&message)
}

/// Computes Ethereum-style swap-or-not shuffling for one validator index.
///
/// `pivots` must be [`shuffle_pivots`] of the same `seed`; computing them once
/// lets a whole committee share the 90 per-round pivot hashes.
///
/// Returns `None` when `validator_count == 0` or `index >= validator_count`.
/// For valid inputs this is a permutation over `0..validator_count`, so callers
/// can iterate source positions and map them into shuffled validator indices
/// without allocating the whole shuffled list.
pub(crate) fn compute_shuffled_index(
    index: ValidatorIndex,
    validator_count: ValidatorIndex,
    seed: &Seed,
    pivots: &ShufflePivots,
) -> Option<ValidatorIndex> {
    if validator_count == 0 || index >= validator_count {
        return None;
    }

    let mut index = u64::from(index);
    let count = u64::from(validator_count);
    for (round, pivot) in (0..SHUFFLE_ROUND_COUNT).zip(pivots) {
        let pivot = pivot % count;
        let flip = (pivot + count - index) % count;
        let position = index.max(flip);
        let source = shuffle_source(seed, round, position / 256);
        let byte = source[usize::try_from((position % 256) / 8).expect("byte index fits usize")];
        let bit = (byte >> (position % 8)) & 1;
        if bit == 1 {
            index = flip;
        }
    }

    Some(ValidatorIndex::try_from(index).expect("shuffled index remains below u32 count"))
}

/// Selects public chunk aggregators with the same stake-weighted threshold math.
///
/// Unlike proposer election, this selection is public: the shared finalized
/// seed plus `(chunk_id, round, validator_index)` gives every node the same
/// pseudo-random output for every active validator. Slashed and zero-stake
/// validators are ignored.
pub fn aggregator_committee(
    active_set: &[Validator],
    seed: &Seed,
    chunk_id: ChunkId,
    round: u32,
    expected_aggregators_per_round: FixedU128,
) -> Result<Vec<AggregatorSelection>, VrfError> {
    let total_stake = total_active_stake(active_set)?;
    let validator_count = indexed_validator_count(active_set)?;
    let pivots = shuffle_pivots(seed);
    let mut selected = Vec::new();

    for source_index in 0..validator_count {
        let validator_index = compute_shuffled_index(source_index, validator_count, seed, &pivots)
            .expect("source index is within validator count");
        let validator = &active_set
            [usize::try_from(validator_index).expect("u32 fits usize on supported targets")];
        if validator.effective_stake == 0 {
            continue;
        }
        let selection_output = aggregator_selection_output(seed, chunk_id, round, validator_index);
        if is_eligible(
            &selection_output,
            validator.effective_stake,
            total_stake,
            expected_aggregators_per_round,
        ) {
            selected.push(AggregatorSelection {
                validator_index,
                selection_output,
            });
        }
    }

    Ok(selected)
}

/// Whether `validator_index` is a member of [`aggregator_committee`] for the
/// same inputs, without building the committee.
///
/// The committee shuffle only permutes visiting order, so a validator is a
/// member exactly when it is active and its own selection output passes the
/// stake-weighted threshold. Errors match [`aggregator_committee`]; an index
/// outside the active set is not a member.
pub fn is_aggregator(
    active_set: &[Validator],
    seed: &Seed,
    chunk_id: ChunkId,
    round: u32,
    validator_index: ValidatorIndex,
    expected_aggregators_per_round: FixedU128,
) -> Result<bool, VrfError> {
    let total_stake = total_active_stake(active_set)?;
    indexed_validator_count(active_set)?;
    let position = usize::try_from(validator_index).expect("u32 fits usize on supported targets");
    let Some(validator) = active_set.get(position) else {
        return Ok(false);
    };
    if validator.effective_stake == 0 {
        return Ok(false);
    }
    Ok(is_eligible(
        &aggregator_selection_output(seed, chunk_id, round, validator_index),
        validator.effective_stake,
        total_stake,
        expected_aggregators_per_round,
    ))
}

fn indexed_validator_count(active_set: &[Validator]) -> Result<ValidatorIndex, VrfError> {
    let len = active_set.len();
    ValidatorIndex::try_from(len).map_err(|_| VrfError::ValidatorIndexOverflow { len })
}

/// Every round's swap-or-not pivot for `seed`, in round order.
fn shuffle_pivots(seed: &Seed) -> ShufflePivots {
    core::array::from_fn(|round| {
        shuffle_pivot(seed, u8::try_from(round).expect("shuffle round fits u8"))
    })
}

fn shuffle_pivot(seed: &Seed, round: u8) -> u64 {
    let digest = shuffle_digest(seed, round, None);
    u64::from_le_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 digest has at least 8 bytes"),
    )
}

fn shuffle_source(seed: &Seed, round: u8, position_window: u64) -> Hash {
    let window =
        u32::try_from(position_window).expect("validator_count is u32, so position/256 fits u32");
    shuffle_digest(seed, round, Some(window))
}

fn shuffle_digest(seed: &Seed, round: u8, position_window: Option<u32>) -> Hash {
    let mut message = [0_u8; 32 + 1 + 4];
    message[..32].copy_from_slice(seed);
    message[32] = round;
    let len = position_window.map_or(33, |window| {
        message[33..].copy_from_slice(&window.to_le_bytes());
        message.len()
    });
    sha256(&message[..len])
}

fn active_validator(
    active_set: &[Validator],
    index: ValidatorIndex,
) -> Result<&Validator, VrfError> {
    let position = usize::try_from(index).expect("u32 fits usize on supported targets");
    active_set
        .get(position)
        .ok_or(VrfError::ValidatorIndexOutOfBounds {
            index,
            len: active_set.len(),
        })
}

fn parse_public_key(public_key: &BlsPublicKey) -> Result<PublicKey, VrfError> {
    PublicKey::from_bytes(public_key).map_err(|_| VrfError::InvalidPublicKey)
}

fn parse_proof(vrf_proof: &BlsSignature) -> Result<Signature, VrfError> {
    Signature::from_bytes(vrf_proof).map_err(|_| VrfError::InvalidProof)
}

#[cfg(test)]
mod tests;
