#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Chunk-level Tendermint-style finality.
//!
//! Signed fair round leaders, explicit nil phases and quorum-certified round
//! changes drive the live protocol. A round certifies a chunk once it holds an
//! authenticated proposal, both configured value quorums and an active
//! validator-set root matching its incoming finalized context; the engine
//! finalizes the certified chunk only with its complete chunk proof.

extern crate alloc;

mod accumulator;
mod pacemaker;
mod proposal;
mod rounds;
mod stake;
#[cfg(test)]
mod tests;
mod verify;
mod votes;

pub use pacemaker::{Pacemaker, RoundStep, TimeoutAction};

use alloc::{collections::BTreeMap, vec::Vec};
use core::fmt;

use neutrin0_consensus_types::{BftProposal, Chunk, NilVote};
use neutrin0_primitives::{ConsensusDomain, Hash, Seed, Validator};

use accumulator::VoteAccumulator;

/// Result of attempting to finalize a chunk round.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FinalizationStatus {
    /// More votes are required.
    Pending,
    /// Chunk finalized.
    Finalized,
}

/// Errors returned by chunk-BFT vote handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BftError {
    /// The active validator set is empty or has no positive unslashed stake.
    ZeroTotalStake,
    /// Summing active validator stake overflowed `u128`.
    StakeOverflow,
    /// The active validator set is too large for the aggregation bit vector.
    ValidatorSetTooLarge,
    /// The configured quorum fraction is invalid.
    InvalidQuorum,
    /// The vote phase did not match the method being called.
    WrongPhase,
    /// The vote names a different chunk, round, or chunk hash.
    WrongVoteTarget,
    /// The vote precedes the round's proposal and every held selection
    /// outweighs it; it can still count once the proposal arrives.
    PendingSelectionsFull,
    /// The aggregation bit vector length differs from the active validator set.
    InvalidAggregationBits,
    /// No unslashed positive stake was represented by the vote bits.
    EmptyVote,
    /// Aggregating unique individually signed votes failed.
    InvalidAggregateSignature,
    /// Signature aggregation is unavailable without the `std` feature.
    SignatureAggregationUnavailable,
    /// The chunk's active validator-set root does not match the previous checkpoint.
    ValidatorSetRootMismatch,
    /// `advance_to_round` was called with a round equal to or below
    /// the current one. Round advancement is strictly monotonic so
    /// late timeout signals cannot rewind the BFT state.
    RoundNotIncreased {
        /// Current round before the failed advance.
        current: u32,
        /// Round the caller requested.
        requested: u32,
    },
}

impl fmt::Display for BftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTotalStake => f.write_str("active validator set has zero total stake"),
            Self::StakeOverflow => f.write_str("active validator stake overflowed u128"),
            Self::ValidatorSetTooLarge => f.write_str("active validator set exceeds u32::MAX"),
            Self::InvalidQuorum => f.write_str("invalid quorum fraction"),
            Self::WrongPhase => f.write_str("finality vote has the wrong phase"),
            Self::WrongVoteTarget => f.write_str("finality vote targets a different tuple"),
            Self::PendingSelectionsFull => {
                f.write_str("held pre-proposal selections outweigh the finality vote")
            }
            Self::InvalidAggregationBits => {
                f.write_str("aggregation bits do not match active validator set")
            }
            Self::EmptyVote => f.write_str("finality vote carries no active stake"),
            Self::InvalidAggregateSignature => f.write_str("invalid aggregate vote signature"),
            Self::SignatureAggregationUnavailable => {
                f.write_str("signature aggregation requires the std feature")
            }
            Self::ValidatorSetRootMismatch => {
                f.write_str("active validator-set root does not match previous checkpoint")
            }
            Self::RoundNotIncreased { current, requested } => write!(
                f,
                "advance_to_round({requested}) does not exceed current round {current}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BftError {}

/// Distinct payment selections whose value votes are held before the round's
/// proposal arrives, per phase.
///
/// Honest voters sign only the proposal's. A full set yields its weakest
/// selection to a verified vote that outweighs it, so a few colluding signers
/// cannot fill it ahead of the honest selection; one signer behind several
/// selections double-votes, which is slashable.
pub const MAX_PENDING_SELECTIONS: usize = 4;

/// Chunk-BFT state for one chunk and round.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkBft {
    domain: ConsensusDomain,
    chunk: Chunk,
    round: u32,
    active_set: Vec<Validator>,
    active_validator_set_root: Hash,
    /// The chunk's incoming seed, which draws its round leaders.
    seed: Seed,
    total_stake: u128,
    prevote_quorum: (u64, u64),
    precommit_quorum: (u64, u64),
    prevotes: VoteAccumulator,
    precommits: VoteAccumulator,
    /// Authenticated value votes that arrived before the round's proposal,
    /// per phase and payment selection (design 08). The proposal's selection
    /// becomes the counted accumulator and the others are discarded, so no
    /// vote counts for a selection the proposal does not name.
    pending_prevotes: BTreeMap<Hash, VoteAccumulator>,
    pending_precommits: BTreeMap<Hash, VoteAccumulator>,
    proposal: Option<BftProposal>,
    nil_prevotes: Option<NilVote>,
    nil_precommits: Option<NilVote>,
}
