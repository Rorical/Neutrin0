#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Vote-weighted heaviest-proven-chain fork choice.
//!
//! The rule follows design 09: blocks must descend from the last finalized
//! block, unproven blocks count tentatively, a stale block excludes itself and
//! every descendant, and latest votes are weighted by stake. Candidates rank by
//! vote score, then proven prefix, then height.

extern crate alloc;

mod blocks;
mod finality;
mod scoring;
#[cfg(test)]
mod tests;

use alloc::collections::BTreeMap;
use core::fmt;

use neutrin0_consensus_types::FinalityVoteData;
use neutrin0_primitives::{BlockHash, ChunkHash, Hash, Height, Slot, ValidatorIndex, ZERO_HASH};
use sha2::{Digest, Sha256};

/// Proof state tracked by fork choice.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProofStatus {
    /// Block proof has not arrived yet.
    PendingProof,
    /// Block proof verified.
    Proven,
    /// Unproven past the exclusive window (design 08): excluded from head
    /// selection together with its descendants, and deleted one window later.
    Stale,
    /// Block is covered by finalized recursive history.
    Finalized,
}

/// Latest vote from one validator used by fork choice scoring.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkVote {
    /// Vote payload naming the target chunk.
    pub data: FinalityVoteData,
    /// Validator stake weight for this latest vote, in wei.
    pub weight: u128,
}

/// Stored fork-choice view of one block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockNode {
    /// Canonical header hash.
    pub hash: BlockHash,
    /// Parent header hash.
    pub parent_hash: BlockHash,
    /// Block height.
    pub height: Height,
    /// Slot copied from the header.
    pub slot: Slot,
    /// Slot the stale rule measures the exclusive window from: the earliest
    /// slot among this block and the unproven siblings sharing its parent.
    /// A proposer that withholds a receipt cannot buy a fresh window by
    /// signing another child of the same parent.
    pub stale_clock: Slot,
    /// Proposer index copied from the header.
    pub proposer_index: ValidatorIndex,
    /// Current proof state.
    pub proof_status: ProofStatus,
    /// Header VRF proof hash used as deterministic same-score tie-breaker.
    pub vrf_tie_breaker: Hash,
}

/// Errors returned by fork-choice state transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ForkChoiceError {
    /// A block's parent is neither known nor the finalized anchor.
    UnknownParent(BlockHash),
    /// The requested block is unknown.
    UnknownBlock(BlockHash),
    /// A chunk certificate did not match the supplied chunk.
    InvalidFinalityCertificate,
    /// Score arithmetic overflowed `u128`.
    ScoreOverflow,
}

impl fmt::Display for ForkChoiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownParent(parent) => write!(f, "unknown block parent {parent:?}"),
            Self::UnknownBlock(hash) => write!(f, "unknown block {hash:?}"),
            Self::InvalidFinalityCertificate => {
                f.write_str("finality certificate does not match chunk")
            }
            Self::ScoreOverflow => f.write_str("fork-choice score overflowed u128"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ForkChoiceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChunkRef {
    end_block_hash: BlockHash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CandidateScore {
    hash: BlockHash,
    score: u128,
    /// Height of the highest block on the candidate's branch whose whole
    /// ancestry above finality is proven: unproven blocks never outrank a
    /// proven branch of the same vote weight.
    proven_height: Height,
    height: Height,
    vrf_tie_breaker: Hash,
}

/// Fork-choice state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForkChoice {
    blocks: BTreeMap<BlockHash, BlockNode>,
    chunks: BTreeMap<ChunkHash, ChunkRef>,
    votes: BTreeMap<ValidatorIndex, ChunkVote>,
    finalized: BlockHash,
}

impl ForkChoice {
    /// Creates fork choice anchored at the last finalized block hash.
    pub const fn new(finalized: BlockHash) -> Self {
        Self {
            blocks: BTreeMap::new(),
            chunks: BTreeMap::new(),
            votes: BTreeMap::new(),
            finalized,
        }
    }

    /// Returns the current finalized anchor block hash.
    pub const fn finalized(&self) -> BlockHash {
        self.finalized
    }

    /// Returns a known block node.
    pub fn block(&self, hash: &BlockHash) -> Option<&BlockNode> {
        self.blocks.get(hash)
    }
}

impl Default for ForkChoice {
    fn default() -> Self {
        Self::new(ZERO_HASH)
    }
}

fn vrf_tie_breaker(proof: &[u8; 96]) -> Hash {
    Sha256::digest(proof).into()
}
