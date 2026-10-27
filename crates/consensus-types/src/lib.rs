#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Consensus wire types shared by engine, network, and proof crates.

extern crate alloc;

pub mod bft;
pub mod bootstrap;
pub use bft::{
    BftMessage, BftProposal, BftVote, IndexedNilVote, NilVote, NilVoteAttestation, NilVoteData,
    PaymentSelection, RoundChange, RoundChangeCertificate, bft_leader,
};
pub mod candidate;
pub use candidate::BftCandidate;
pub mod evidence;
pub mod hashing;
pub mod history;
pub mod history_proof;
pub mod participation;
pub mod proof_acceptance;
pub mod proving;
mod quorum_dictionary;
pub use proof_acceptance::{
    ProofAcceptanceCommitment, ProofAcceptanceOpening, ProofManifest, ProofManifestIndex,
    proof_manifest_for, proof_manifests_for, proof_manifests_valid,
};
pub mod runtime;
pub mod signed_artifacts;
pub mod state_diff;
pub use history_proof::{AnchorOpening, Checkpoint, HistoryProof};
pub use state_diff::{BlockReceipt, BlockStateDiff, CandidateBlock, ProvenBlock, StateWrite};
mod block;
mod block_proof;
mod chunk;
mod finality;
mod program_lane;
mod slashing_evidence;
#[cfg(test)]
mod tests;
pub use block::{Block, Body, Header};
pub use block_proof::{BlockProof, BlockProofPublicInputs};
pub use chunk::{Chunk, ChunkProof, ChunkProofPublicInputs};
pub use finality::{
    AggregatedVote, FinalityCert, FinalityVote, FinalityVoteData, FinalityVotePhase, IndexedVote,
    QuorumCertificate, VoteAttestation, attestation_coverage_valid,
};
pub use program_lane::{
    MAX_PROGRAM_BYTES, MAX_PROGRAM_PIECE_BYTES, MAX_PROGRAM_PIECES_PER_BLOCK, ProgramPiece,
    ProgramPieceDescriptor, ProgramPieceRef, program_content_hash, program_piece_count,
    program_piece_refs, program_pieces_commitment,
};
pub use slashing_evidence::{DaFraudProof, LockEvidence, ProofRejectionReason, SlashingEvidence};

use alloc::vec::Vec;

use borsh::BorshSerialize;
use neutrin0_primitives::{Hash, blake3_256};

/// BLAKE3 of `tag || borsh(value)`, serializing the value straight after the tag.
#[must_use]
pub fn tagged_commitment<T: BorshSerialize + ?Sized>(tag: &[u8], value: &T) -> Hash {
    let mut bytes = Vec::from(tag);
    value
        .serialize(&mut bytes)
        .expect("canonical tagged commitment encoding");
    blake3_256(&bytes)
}
