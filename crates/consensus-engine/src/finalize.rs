//! Complete chunk proof and BFT finalization of proven blocks.

use crate::block_state::BlockState;
use crate::engine::Engine;
use crate::error::EngineError;
use crate::merkle::{hash_leaf, merkle_root_of_hashes};
use crate::proposer::ProposerKey;
use alloc::vec::Vec;
use neutrin0_consensus_types::{
    BlockProof as WireBlockProof, Chunk, ChunkProof as WireChunkProof, ChunkProofPublicInputs,
    FinalityCert, Header,
};
use neutrin0_primitives::{BlockHash, ChunkHash, ChunkId, Hash, ZERO_HASH};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;

extern crate alloc;

mod error;

pub use error::FinalizeError;

/// Successful outcome of [`Engine::finalize_chunk`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizeOutcome {
    /// The chunk that was assembled and finalized.
    pub chunk: Chunk,
    /// Canonical chunk hash (also equal to `chunk.hash()`).
    pub chunk_hash: ChunkHash,
    /// Wire chunk proof persisted in the store.
    pub chunk_proof: WireChunkProof,
    /// Public inputs the backend bound for the chunk proof.
    pub public_inputs: ChunkProofPublicInputs,
    /// Finality certificate persisted in the store.
    pub finality_cert: FinalityCert,
}

impl<DB: Database> Engine<DB> {
    /// Prove and finalize complete execution and consensus for a chunk.
    /// This convenience path commits an already-materialized canonical branch.
    /// A saved BFT target on another branch requires
    /// [`Self::commit_bft_consensus_chunk`] with a configured replay executor.
    pub fn finalize_chunk<PS: ProofSystem>(
        &mut self,
        chunk_id: ChunkId,
        proof_system: &PS,
        voter: &ProposerKey,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        let mut prepared = self.prepare_bft_consensus_chunk(chunk_id, proof_system)?;
        let validated = self.certify_validated_consensus_chunk(&mut prepared, voter)?;
        let chunk_prover = self
            .prover_address
            .or_else(|| {
                self.active_validator_set()
                    .iter()
                    .find(|validator| validator.pubkey == *voter.public_key_bytes())
                    .map(|validator| validator.withdrawal_credentials)
            })
            .unwrap_or(neutrin0_primitives::ZERO_HASH);
        if let Some((chunk_id, statement_key)) = prepared.missing_ratified_proof() {
            return Err(FinalizeError::MissingChunkProof {
                chunk_id,
                statement_key,
            });
        }
        let proof = proof_system.prove_consensus_chunk(
            &prepared.proofs,
            &prepared.ratified,
            &prepared.witness,
            chunk_prover,
        )?;
        // Proving reads the certified witness without changing it.
        self.commit_validated_consensus_chunk(&prepared.witness, &proof, proof_system, validated)
    }

    pub(crate) fn validate_chunk_id_sequence(
        &self,
        chunk_id: ChunkId,
    ) -> Result<(), FinalizeError<DB::Error>> {
        let latest = self.latest_finalized_chunk_id();
        let expected_next = match latest {
            Some(latest) => latest
                .checked_add(1)
                .ok_or(FinalizeError::HeightRangeOverflow)?,
            None => 0,
        };
        if chunk_id != expected_next {
            return Err(FinalizeError::NonContiguousChunkId {
                latest,
                requested: chunk_id,
            });
        }
        Ok(())
    }

    /// Drive the chunk-BFT module through one round, either by
    /// consuming a live BFT session or obtaining a local certificate when
    /// the local signer alone meets the configured quorum.
    pub(crate) fn run_chunk_bft(
        &mut self,
        chunk: &Chunk,
        chunk_hash: ChunkHash,
        voter: &ProposerKey,
        active_validator_set_root: Hash,
    ) -> Result<FinalityCert, FinalizeError<DB::Error>> {
        if self
            .local_voter
            .as_ref()
            .is_some_and(|local| local.public_key_bytes() != voter.public_key_bytes())
        {
            return Err(EngineError::Signing(crate::signing::SigningViolation::Conflict).into());
        }
        let previous = self.local_voter.clone();
        self.set_local_voter(voter.clone());
        let driven = if self.bft_sessions.contains_key(&chunk.chunk_id) {
            self.resume_bft_session(chunk.chunk_id)
        } else {
            self.open_bft_session(chunk.clone())
        };
        self.local_voter = previous;
        driven.map_err(|error| match error {
            crate::BftLoopError::Bft(error) => FinalizeError::Bft(error),
            crate::BftLoopError::Engine(error) => FinalizeError::Engine(error),
            _ => FinalizeError::FinalizationStalled,
        })?;
        let session = self
            .bft_sessions
            .get(&chunk.chunk_id)
            .ok_or(FinalizeError::FinalizationStalled)?;
        finalize_from_session(session, chunk_hash, active_validator_set_root)
    }

    /// Attempt to assemble the canonical [`Chunk`] for `chunk_id` from
    /// already-persisted block headers and proofs. Used by the live
    /// BFT loop ([`crate::bft_loop`]) to decide when a chunk is ready
    /// to vote on without paying the cost of generating the chunk
    /// proof or re-verifying every block proof.
    ///
    /// Returns `Ok(None)` if any block in the range is missing, not
    /// yet in [`BlockState::Proven`] or beyond, or has no persisted
    /// block proof — i.e. the chunk is not yet proof-ready and no
    /// BFT session should be opened.
    ///
    /// # Errors
    ///
    /// Returns [`FinalizeError::HeightRangeOverflow`] if `chunk_id`
    /// is too large to address; [`FinalizeError::ParentHashMismatch`]
    /// if a block's `parent_hash` does not extend the previous block
    /// in the chunk; or the engine's storage / chain-spec errors.
    pub fn assemble_chunk(
        &self,
        chunk_id: ChunkId,
    ) -> Result<Option<Chunk>, FinalizeError<DB::Error>> {
        let (start_height, end_height) = self
            .chunk_heights(chunk_id)
            .ok_or(FinalizeError::HeightRangeOverflow)?;

        let mut headers: Vec<Header> = Vec::new();
        let mut block_hashes: Vec<BlockHash> = Vec::new();
        let mut block_proof_leaves: Vec<Hash> = Vec::new();
        let mut vrf_leaves: Vec<Hash> = Vec::new();
        let mut da_leaves: Vec<Hash> = Vec::new();
        let mut expected_parent: Option<BlockHash> = None;

        for height in start_height..=end_height {
            let Some(header) = self.store().get_header_by_height(height)? else {
                return Ok(None);
            };
            let hash = header.hash();
            if let Some(expected) = expected_parent
                && header.parent_hash != expected
            {
                return Err(FinalizeError::ParentHashMismatch {
                    height,
                    expected,
                    actual: header.parent_hash,
                });
            }
            let Some(state) = self.store().get_block_state(&hash)? else {
                return Ok(None);
            };
            if !matches!(state, BlockState::Proven | BlockState::Finalized) {
                return Ok(None);
            }
            let Some(wire_proof) = self.store().get_block_proof(&hash)? else {
                return Ok(None);
            };

            block_proof_leaves.push(hash_leaf(&wire_proof_leaf_bytes(&wire_proof)));
            vrf_leaves.push(hash_leaf(&header.vrf_proof));
            da_leaves.push(hash_leaf(&header.da_root));
            block_hashes.push(hash);
            headers.push(header);
            expected_parent = Some(hash);
        }

        let first_header = headers.first().expect("at least one header in chunk range");
        let last_header = headers.last().expect("at least one header in chunk range");
        let Some(start_state_root) = self.state_root_before(first_header)? else {
            return Err(FinalizeError::MissingParentHeader {
                parent_hash: first_header.parent_hash,
            });
        };
        let start_block_hash = *block_hashes.first().expect("non-empty block hashes");
        let end_block_hash = *block_hashes.last().expect("non-empty block hashes");

        let active_validator_set_root = crate::validator_set_root(self.active_validator_set());
        let next_validator_set_root = if last_header.runtime_extra == ZERO_HASH {
            active_validator_set_root
        } else {
            last_header.runtime_extra
        };

        Ok(Some(Chunk {
            next_identity_sanctions_root: self.identity_sanctions.root(),

            chunk_id,
            start_height,
            end_height,
            start_state_root,
            end_state_root: last_header.state_root,
            start_block_hash,
            end_block_hash,
            block_hash_root: merkle_root_of_hashes(&block_hashes),
            block_proof_root: merkle_root_of_hashes(&block_proof_leaves),
            vrf_proof_root: merkle_root_of_hashes(&vrf_leaves),
            active_validator_set_root,
            next_validator_set_root,
            da_root: merkle_root_of_hashes(&da_leaves),
        }))
    }
}

/// Read the accumulated cert from a live BFT session that has
/// already reached its precommit quorum. The caller has already
/// removed the session from the engine's session map; this function
/// only borrows it.
fn finalize_from_session<E>(
    session: &crate::bft_loop::BftSession,
    chunk_hash: ChunkHash,
    active_validator_set_root: Hash,
) -> Result<FinalityCert, FinalizeError<E>> {
    if session.chunk_hash() != chunk_hash {
        return Err(FinalizeError::FinalizationStalled);
    }
    let cert = session
        .chunk_bft()
        .try_finalize(active_validator_set_root)?
        .ok_or(FinalizeError::FinalizationStalled)?;
    Ok(cert)
}

/// Canonical leaf bytes for a wire block proof: the borsh-encoded
/// public inputs, which the chunk Guest hashes into `block_proof_root`
/// the same way.
fn wire_proof_leaf_bytes(wire_proof: &WireBlockProof) -> Vec<u8> {
    borsh::to_vec(&wire_proof.public_inputs)
        .expect("borsh encode of BlockProofPublicInputs is infallible")
}
