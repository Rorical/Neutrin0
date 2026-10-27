//! The proven chunk commitment and its proof artifact.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{BlockHash, ChunkHash, ChunkId, Hash, Height, StateRoot};

use crate::FinalityCert;

/// Proven chunk commitment.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Chunk {
    /// Sequential chunk number, starting at zero.
    pub chunk_id: ChunkId,
    /// First canonical block height in the chunk.
    pub start_height: Height,
    /// Last canonical block height in the chunk.
    pub end_height: Height,
    /// State root before `start_height` executes.
    pub start_state_root: StateRoot,
    /// State root after `end_height` executes.
    pub end_state_root: StateRoot,
    /// First block hash in the chunk.
    pub start_block_hash: BlockHash,
    /// Last block hash in the chunk.
    pub end_block_hash: BlockHash,
    /// Merkle root over block hashes in height order.
    pub block_hash_root: Hash,
    /// Merkle root over block proof commitments.
    pub block_proof_root: Hash,
    /// Merkle root over VRF proofs in slot order.
    pub vrf_proof_root: Hash,
    /// Active validator set used for this chunk.
    pub active_validator_set_root: Hash,
    /// Validator set that becomes active after this chunk checkpoints.
    pub next_validator_set_root: Hash,
    /// Consensus-owned permanent identity-sanctions trie after this chunk.
    pub next_identity_sanctions_root: Hash,
    /// Data-availability root over all block DA roots.
    pub da_root: Hash,
}

impl Chunk {
    /// Computes `BLAKE3(DOMAIN_CHUNK || borsh(self))`, the canonical chunk hash.
    pub fn hash(&self) -> ChunkHash {
        crate::hashing::borsh_commitment(&neutrin0_primitives::DOMAIN_CHUNK, self)
    }
}

/// Public inputs committed by a single chunk proof.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ChunkProofPublicInputs {
    /// Chunk identifier, monotonic across the canonical chain.
    pub chunk_id: ChunkId,
    /// First block height covered by this chunk.
    pub start_height: Height,
    /// Last block height covered by this chunk.
    pub end_height: Height,
    /// State root before `start_height` executes.
    pub start_state_root: StateRoot,
    /// State root after `end_height` executes.
    pub end_state_root: StateRoot,
    /// Block hash at `start_height`.
    pub start_block_hash: BlockHash,
    /// Block hash at `end_height`.
    pub end_block_hash: BlockHash,
    /// Merkle root over the included block hashes.
    pub block_hash_root: Hash,
    /// Merkle root over the included block proofs.
    pub block_proof_root: Hash,
    /// Merkle root over the included VRF proofs.
    pub vrf_proof_root: Hash,
    /// Validator set active for `start_height`.
    pub active_validator_set_root: Hash,
    /// Validator set that becomes active after `end_height`.
    pub next_validator_set_root: Hash,
    /// Consensus-owned permanent identity-sanctions trie after this chunk.
    pub next_identity_sanctions_root: Hash,
    /// Aggregated data-availability commitment for the chunk.
    pub da_root: Hash,
}

/// Opaque chunk proof artifact gossiped once a chunk is proven.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ChunkProof {
    /// Certificate proven by complete consensus aggregation.
    pub finality_cert: FinalityCert,
    /// Chunk identifier proven by this artifact.
    pub chunk_id: ChunkId,
    /// Chunk hash proven by this artifact.
    pub chunk_hash: ChunkHash,
    /// Public inputs the backend proof binds.
    pub public_inputs: ChunkProofPublicInputs,
    /// Account the proof credits, committed outside the consensus statement
    /// (design 08).
    pub prover_address: Hash,
    /// Backend-defined proof bytes.
    pub proof_bytes: Vec<u8>,
}
