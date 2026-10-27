//! Durable bounded accountability sources; capacity never evicts live references.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::signed_artifacts::{SignedArtifact, SignedArtifactKind};
use neutrin0_primitives::{ChunkId, Hash};
use neutrin0_storage::{Batch, Column};

mod admission;
mod lookup;

#[cfg(test)]
mod tests;

/// Records received from peers, refused once full.
const MAX_PEER_SIGNED_ARTIFACTS: usize = 3840;
const MAX_PEER_SIGNED_ARTIFACT_BYTES: usize = 384 * 1024 * 1024;
/// This node's own signatures and the sources its own votes name. They are
/// counted apart, so peer records can never starve local publication, and the
/// budget is large enough that named receipts that are not this node's
/// preferred ones are stored in full.
const MAX_LOCAL_SIGNED_ARTIFACTS: usize = 4096;
const MAX_LOCAL_SIGNED_ARTIFACT_BYTES: usize = 512 * 1024 * 1024;
const PRUNED_FLOOR_KEY: &[u8] = b"signed_artifact_pruned_floor";
/// `SignedArtifactIndex` tag of metadata rows keyed by source identity.
const METADATA_BY_ID: u8 = 0;
/// `SignedArtifactIndex` tag of metadata rows keyed by source chunk, then identity.
const METADATA_BY_CHUNK: u8 = 1;

fn metadata_id_key(id: Hash) -> [u8; 33] {
    let mut key = [0; 33];
    key[0] = METADATA_BY_ID;
    key[1..].copy_from_slice(&id);
    key
}

fn metadata_chunk_prefix(chunk: ChunkId) -> [u8; 9] {
    let mut key = [0; 9];
    key[0] = METADATA_BY_CHUNK;
    key[1..].copy_from_slice(&chunk.to_be_bytes());
    key
}

fn metadata_chunk_key(chunk: ChunkId, id: Hash) -> [u8; 41] {
    let mut key = [0; 41];
    key[..9].copy_from_slice(&metadata_chunk_prefix(chunk));
    key[9..].copy_from_slice(&id);
    key
}

fn put_metadata(batch: &mut Batch, metadata: &SignedArtifactMetadata) -> borsh::io::Result<()> {
    let bytes = borsh::to_vec(metadata)?;
    batch.put(
        Column::SignedArtifactIndex,
        metadata_id_key(metadata.id),
        bytes.as_slice(),
    );
    batch.put(
        Column::SignedArtifactIndex,
        metadata_chunk_key(metadata.chunk_id, metadata.id),
        bytes,
    );
    Ok(())
}

fn delete_metadata(batch: &mut Batch, chunk: ChunkId, id: Hash) {
    batch.delete(Column::SignedArtifactIndex, metadata_id_key(id));
    batch.delete(Column::SignedArtifactIndex, metadata_chunk_key(chunk, id));
}

#[derive(BorshSerialize, BorshDeserialize)]
struct StoredArtifact {
    chunk_id: ChunkId,
    payload: StoredPayload,
}
#[derive(BorshSerialize, BorshDeserialize)]
enum StoredPayload {
    Source(Box<SignedArtifact>),
    // Accepted receipt bytes live in BlockProofs while it holds them; a
    // preferred receipt replacing them expands this row back to the source.
    AcceptedBlockProof(Hash),
}

/// Small dependency metadata; raw receipts are resolved only for relevant observations.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct SignedArtifactMetadata {
    /// Authenticated source chunk.
    pub chunk_id: ChunkId,
    /// Exact immutable artifact identity.
    pub id: Hash,
    /// Signed source category.
    pub kind: SignedArtifactKind,
    /// Protocol round, absent for a block receipt.
    pub round: Option<u32>,
    /// Individual accountable signers.
    pub signers: Vec<u32>,
    /// Exact signed proof-envelope dependencies.
    pub proof_hashes: Vec<Hash>,
    /// Encoded retained source size, excluding referenced accepted receipt bytes.
    pub storage_bytes: u64,
    /// This node published the source under its durable signing journal.
    pub local: bool,
    /// Value-vote phase, needed to retain an earlier actual locked precommit.
    pub phase: Option<neutrin0_consensus_types::FinalityVotePhase>,
    /// Signed value target, absent for nil and pure pacemaker declarations.
    pub target: Option<Hash>,
}

impl SignedArtifactMetadata {
    /// Metadata for `artifact`, whose identity the caller already computed as `id`.
    fn for_artifact(
        chunk_id: ChunkId,
        id: Hash,
        artifact: &SignedArtifact,
    ) -> borsh::io::Result<Self> {
        let (round, signers, mut proof_hashes) = match artifact {
            SignedArtifact::Vote(vote) => (
                Some(vote.data.round),
                vote.attestations
                    .iter()
                    .map(|claim| claim.validator_index)
                    .collect(),
                {
                    let index =
                        neutrin0_consensus_types::ProofManifestIndex::new(&vote.proof_manifests)
                            .filter(|index| index.covers_exact(&vote.attestations))
                            .ok_or_else(|| {
                                borsh::io::Error::new(
                                    borsh::io::ErrorKind::InvalidData,
                                    "invalid proof manifest dictionary",
                                )
                            })?;
                    index
                        .commitments()
                        .flat_map(|commitment| {
                            index
                                .get(&commitment)
                                .into_iter()
                                .flat_map(|manifest| manifest.proof_hashes.iter().copied())
                        })
                        .collect()
                },
            ),
            SignedArtifact::Quorum(quorum) => (Some(quorum.data.round), Vec::new(), Vec::new()),
            SignedArtifact::BlockProof(_) => (None, Vec::new(), Vec::new()),
            SignedArtifact::Proposal(value) => {
                (Some(value.round), vec![value.proposer_index], Vec::new())
            }
            SignedArtifact::NilVote(value) => (
                Some(value.data.round),
                value
                    .attestations
                    .iter()
                    .map(|claim| claim.validator_index)
                    .collect(),
                Vec::new(),
            ),
            SignedArtifact::RoundChange(value) => {
                (Some(value.round), vec![value.validator_index], Vec::new())
            }
            SignedArtifact::RoundChangeCertificate(value) => (
                Some(value.round),
                value
                    .reports
                    .iter()
                    .map(|report| report.validator_index)
                    .collect(),
                Vec::new(),
            ),
        };
        proof_hashes.sort_unstable();
        proof_hashes.dedup();
        Ok(Self {
            chunk_id,
            id,
            kind: artifact.kind(),
            round,
            signers,
            proof_hashes,
            storage_bytes: 0,
            local: false,
            phase: match artifact {
                SignedArtifact::Vote(value) => Some(value.data.phase),
                SignedArtifact::NilVote(value) => Some(value.data.phase),
                _ => None,
            },
            target: match artifact {
                SignedArtifact::Vote(value) => Some(value.data.chunk_hash),
                SignedArtifact::Quorum(value) => Some(value.data.chunk_hash),
                SignedArtifact::Proposal(value) => Some(value.chunk.hash()),
                _ => None,
            },
        })
    }
}
