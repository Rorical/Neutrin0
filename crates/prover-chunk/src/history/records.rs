//! Historical records: full source records, certificate-independent
//! contexts and the read-only view offence rules share.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize, io};
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::{Chunk, FinalityCert};
use neutrin0_primitives::{Hash, Seed, Validator};

/// A previously proven finalization, including the set effective at that time.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct HistoricalChunk {
    /// Canonical finalized chunk.
    pub chunk: Chunk,
    /// Validator indices resolve against this historical set.
    pub validators: Vec<Validator>,
    /// Randomness used to verify this chunk's proposer claims.
    pub seed: Seed,
    /// Block Guest authenticated at this chunk's start boundary.
    pub block_guest_vk_digest: [u32; 8],
    /// Runtime artifact authenticated at this chunk's start boundary.
    pub runtime_code_hash: Hash,
    /// Commitment of this chunk's start boundary.
    pub start_boundary: Hash,
    /// Retained complete finality metadata and source signatures. Participation
    /// is selected separately in the following chunk's committed precommit QC.
    pub finality: FinalityCert,
}

/// Canonical history commitment, independent of the collected quorum subset.
///
/// Certificates are reverified when used for inactivity authorization;
/// their non-unique encodings must never split the next consensus boundary.
pub fn history_commitment(chunks: &[HistoricalChunk]) -> Hash {
    neutrin0_consensus_types::history::history_root(
        &chunks
            .iter()
            .map(|record| commitment(&record.evidence_context()))
            .collect::<Vec<_>>(),
    )
}

/// Certificate-independent historical execution and validator context.
///
/// Its membership is authenticated by an incoming history root whose leaves
/// were appended by complete Chunk verification. Source signatures remain in
/// [`HistoricalChunk`], separately from this proving-time context.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize)]
pub struct HistoricalContext {
    /// Canonical finalized chunk.
    pub chunk: Chunk,
    /// Validator indices resolve against this historical set.
    pub validators: Vec<Validator>,
    /// Randomness used to verify this chunk's proposer claims.
    pub seed: Seed,
    /// Block Guest authenticated at this chunk's start boundary.
    pub block_guest_vk_digest: [u32; 8],
    /// Runtime artifact authenticated at this chunk's start boundary.
    pub runtime_code_hash: Hash,
    /// Commitment of this chunk's start boundary.
    pub start_boundary: Hash,
}

impl BorshDeserialize for HistoricalContext {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let chunk = Chunk::deserialize_reader(reader)?;
        let count = u32::deserialize_reader(reader)? as usize;
        if count == 0 || count > neutrin0_primitives::MAX_CONSENSUS_VALIDATORS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "historical validator count",
            ));
        }
        let validators = (0..count)
            .map(|_| Validator::deserialize_reader(reader))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self {
            chunk,
            validators,
            seed: Seed::deserialize_reader(reader)?,
            block_guest_vk_digest: <[u32; 8]>::deserialize_reader(reader)?,
            runtime_code_hash: Hash::deserialize_reader(reader)?,
            start_boundary: Hash::deserialize_reader(reader)?,
        })
    }
}

impl From<&HistoricalChunk> for HistoricalContext {
    fn from(record: &HistoricalChunk) -> Self {
        Self {
            chunk: record.chunk.clone(),
            validators: record.validators.clone(),
            seed: record.seed,
            block_guest_vk_digest: record.block_guest_vk_digest,
            runtime_code_hash: record.runtime_code_hash,
            start_boundary: record.start_boundary,
        }
    }
}

/// Read-only validator context shared by full sources and slim history reads.
/// Implementing this trait does not authenticate a record's membership.
pub trait HistoricalSource {
    /// Canonical chunk metadata.
    fn chunk(&self) -> &Chunk;
    /// Validator vector effective for the source chunk.
    fn validators(&self) -> &[Validator];
    /// Proposer-election seed effective for the source chunk.
    fn seed(&self) -> &Seed;
}

impl HistoricalSource for HistoricalChunk {
    fn chunk(&self) -> &Chunk {
        &self.chunk
    }
    fn validators(&self) -> &[Validator] {
        &self.validators
    }
    fn seed(&self) -> &Seed {
        &self.seed
    }
}

impl HistoricalSource for HistoricalContext {
    fn chunk(&self) -> &Chunk {
        &self.chunk
    }
    fn validators(&self) -> &[Validator] {
        &self.validators
    }
    fn seed(&self) -> &Seed {
        &self.seed
    }
}

#[derive(Clone, Copy)]
pub(super) struct HistoricalView<'a> {
    pub(super) chunk: &'a Chunk,
    pub(super) validators: &'a [Validator],
    pub(super) seed: &'a Seed,
}

impl HistoricalContext {
    /// Certificate-independent context authenticated by the history root.
    pub fn evidence_context(&self) -> neutrin0_consensus_types::evidence::EvidenceContext {
        evidence_context(
            &self.chunk,
            &self.validators,
            self.seed,
            self.block_guest_vk_digest,
            self.runtime_code_hash,
            self.start_boundary,
        )
    }
}

impl HistoricalChunk {
    /// Certificate-independent context authenticated by the history root.
    pub fn evidence_context(&self) -> neutrin0_consensus_types::evidence::EvidenceContext {
        evidence_context(
            &self.chunk,
            &self.validators,
            self.seed,
            self.block_guest_vk_digest,
            self.runtime_code_hash,
            self.start_boundary,
        )
    }
}

fn evidence_context(
    chunk: &Chunk,
    validators: &[Validator],
    seed: Seed,
    block_guest_vk_digest: [u32; 8],
    runtime_code_hash: Hash,
    start_boundary: Hash,
) -> neutrin0_consensus_types::evidence::EvidenceContext {
    neutrin0_consensus_types::evidence::EvidenceContext {
        chunk_id: chunk.chunk_id,
        chunk_hash: chunk.hash(),
        end_height: chunk.end_height,
        validators_root: commitment(validators),
        seed,
        source_block_guest_vk_digest: block_guest_vk_digest,
        source_runtime_code_hash: runtime_code_hash,
        start_boundary,
    }
}
