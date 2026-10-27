//! Chunk statements, the History proofs they form and anchor openings.
//!
//! Every chunk Guest after the first recursively verifies the proof of the
//! chunk before it and the first chunk starts at the boundary its chain
//! specification pins (genesis, or a hard fork's start), so one valid chunk
//! receipt proves the whole chain from that start to its end boundary
//! (design 13).

use crate::ChunkProofPublicInputs;
use crate::evidence::EvidenceContext;
use crate::history::HistoryPath;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{BoundedBytes, ChainSpec, DOMAIN_CHECKPOINT, Hash};

/// SP1 verification-key digest, obtained with `hash_u32()`.
pub type VkDigest = [u32; 8];
/// Maximum encoded chunk receipt carried by a History proof, excluding the
/// outer framing.
pub const MAX_HISTORY_RECEIPT_BYTES: usize = 8 * 1024 * 1024;

pub use neutrin0_primitives::{
    ChainBinding, ConsensusBoundary, ExecutionPrograms, PinnedPrograms, ProgramSet, ScheduledFork,
};

/// The four Guest identities a proof backend embeds.
///
/// A node binary contributes these. The execution Guests bound to the
/// specification's runtime artifact form the genesis boundary's program set;
/// the chunk Guest belongs to the chain binding and never changes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct GuestPrograms {
    /// Inner execution programs recursively verified by the chunk Guest.
    pub execution: ExecutionPrograms,
    /// Pinned chunk Guest.
    pub chunk: VkDigest,
}

impl GuestPrograms {
    /// `true` when no identity is zero.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.execution.is_complete() && self.chunk != [0; 8]
    }

    /// Bind the execution Guests to a runtime artifact.
    #[must_use]
    pub const fn with_runtime(self, runtime_code_hash: Hash) -> ProgramSet {
        ProgramSet {
            runtime_code_hash,
            execution: self.execution,
        }
    }
}

/// BLAKE3 content hashes of the artifacts a program set is built from.
///
/// They are distributed through the block body's program lane (design 20).
/// A zero hash means the artifact is not distributed on chain.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ProgramArtifacts {
    /// Runtime WASM whose hash is `ProgramSet::runtime_code_hash`.
    pub runtime: Hash,
    /// ELF of the immutable Fact Guest; distribution never authorizes replacement.
    pub fact: Hash,
    /// Evidence Guest ELF.
    pub evidence: Hash,
    /// Block Guest ELF.
    pub block: Hash,
}

impl ProgramArtifacts {
    /// Every nonzero content hash.
    pub fn named(&self) -> impl Iterator<Item = Hash> {
        [self.runtime, self.fact, self.evidence, self.block]
            .into_iter()
            .filter(|hash| *hash != [0; 32])
    }
}

/// A program switch scheduled in runtime state and executed by the chunk Guest at
/// the boundary entering `activate_at_chunk`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ScheduledUpgrade {
    /// First chunk executed under `programs`.
    pub activate_at_chunk: u64,
    /// Program set that boundary adopts.
    pub programs: ProgramSet,
    /// Content hashes nodes fetch from the program lane and install.
    pub artifacts: ProgramArtifacts,
    /// Whether every named artifact was completely published in the program
    /// lane. The runtime sets it from the authenticated lane descriptors; the
    /// chunk Guest switches only an available schedule, so an unavailable one
    /// is void at its activation boundary.
    pub available: bool,
}

/// Trusted chain identity, the chunk Guest it pins and the program set trusted
/// at an anchor. Never selected by a peer; statements carry program sets in
/// their boundaries.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ProofDomain {
    /// Immutable chain identity.
    pub chain: ChainBinding,
    /// The specification's chunk Guest, every History receipt's verifying key.
    pub chunk: VkDigest,
    /// Program set trusted at the anchor (the genesis set for a fresh node).
    pub programs: ProgramSet,
}

impl ProofDomain {
    /// The boundary `spec`'s History starts from: genesis, or a hard fork's
    /// pinned start.
    #[must_use]
    pub fn genesis_boundary(&self, spec: &ChainSpec) -> ConsensusBoundary {
        ConsensusBoundary::first(spec)
    }

    /// `true` when this is `spec`'s identity and chunk Guest and `spec`
    /// accepts the program set.
    #[must_use]
    pub fn is_valid(&self, spec: &ChainSpec) -> bool {
        self.chain == ChainBinding::new(spec)
            && self.chunk == spec.genesis_chunk
            && spec.accepts_programs(&self.programs)
    }
}

/// Exact compact public values of the complete Chunk Guest.
#[derive(Clone, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ConsensusStatement {
    /// Immutable chain identity.
    pub chain: ChainBinding,
    /// Incoming authenticated boundary; its program set verified this chunk.
    pub start: ConsensusBoundary,
    /// Derived outgoing authenticated boundary; its program set rules the next chunk.
    pub end: ConsensusBoundary,
    /// Existing canonical chunk commitment.
    pub chunk: ChunkProofPublicInputs,
    /// Exact finality certificate commitment.
    pub finality_cert_hash: Hash,
}

/// Exact public values a Chunk Guest receipt commits (design 08).
///
/// The consensus statement and, outside it, the account the chunk proof
/// credits. Two receipts of one certificate with different provers finalize
/// the same chunk and prove the same History.
#[derive(Clone, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ChunkReceiptStatement {
    /// The chunk's consensus statement.
    pub statement: ConsensusStatement,
    /// Account the chunk proof credits.
    pub chunk_prover_address: Hash,
}

impl ChunkReceiptStatement {
    /// Commitment of the complete public values, the chunk proof's statement
    /// key (design 08).
    #[must_use]
    pub fn statement_key(&self) -> Hash {
        crate::evidence::commitment(self)
    }
}

/// A recursive proof of the whole chain from the specification's start to
/// `statement.end`.
///
/// It is a finalized chunk receipt without its certificate: the chunk Guest of
/// every chunk after the first verified the previous chunk's receipt, and the
/// first chunk started at the start boundary of the bound specification
/// (genesis, or a hard fork's start), so a valid receipt under a trusted chain
/// binding authenticates every boundary back to that start. Its end is a
/// rules-valid history, not a latestness or long-range claim; a verifier
/// anchored after the start also needs an [`AnchorOpening`].
#[derive(Clone, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct HistoryProof {
    /// Public values the receipt commits.
    pub statement: ChunkReceiptStatement,
    /// Compressed STARK chunk receipt, checked independently by the backend.
    pub receipt: BoundedBytes<MAX_HISTORY_RECEIPT_BYTES>,
}

impl HistoryProof {
    /// Boundary the proven chain ends in.
    #[must_use]
    pub const fn end(&self) -> &ConsensusBoundary {
        &self.statement.statement.end
    }

    /// Immutable chain identity the receipt claims.
    #[must_use]
    pub const fn chain(&self) -> &ChainBinding {
        &self.statement.statement.chain
    }

    /// Derived endpoint; proving it does not by itself make it canonical.
    #[must_use]
    pub const fn end_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            chain: self.statement.statement.chain,
            boundary: self.statement.statement.end,
        }
    }
}

/// Places an earlier boundary on the chain a later boundary ends.
///
/// The History leaf of chunk `m` commits that chunk's start boundary, so an
/// opening of leaf `m` under the history root of a later boundary `B_n`
/// authenticates `B_m` as an ancestor of `B_n`. Every leaf was appended by a
/// complete chunk Guest, so the opening is as strong as the receipt that
/// proves `B_n`.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct AnchorOpening {
    /// Context committed by leaf `m`.
    pub context: EvidenceContext,
    /// Membership of leaf `m` under the later boundary's history root.
    pub path: HistoryPath,
}

/// How an optional [`AnchorOpening`] relates `anchor` to the chain ending in
/// `end`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorCheck {
    /// `anchor` lies on the chain: it is the History's start, `end` itself, or
    /// a verified opening places it there.
    Extends,
    /// `anchor` needs an opening and none was supplied.
    Unopened,
    /// The opening does not authenticate the anchor's leaf under `end`'s
    /// history root, or it was supplied where none belongs: a provider fault
    /// that says nothing about the chain.
    Invalid,
    /// The proven chain does not contain `anchor`: `end` is a different
    /// boundary at the same count, or the authenticated leaf at the anchor's
    /// index started from a different boundary.
    Conflicts,
}

/// Whether relating the boundary at `anchor` chunks to an endpoint at `end`
/// chunks takes an [`AnchorOpening`].
///
/// The History's start at `first` chunks (genesis or a fork's start) and the
/// endpoint take none, and [`check_anchor`] refuses one for them, so a
/// provider sends exactly what this says.
#[must_use]
pub const fn needs_opening(first: u64, anchor: u64, end: u64) -> bool {
    anchor != first && anchor != end
}

/// Relate `anchor` to the chain that ends in `end` through `opening`.
///
/// `end` must itself be authenticated, normally as the end of a verified
/// [`HistoryProof`] of the chain whose History starts at `start`
/// ([`ConsensusBoundary::first`] of the trusted specification). The start precedes every
/// such end and needs no opening; `end` itself needs none either. Any other
/// anchor needs the opening of its own chunk's leaf; nothing below the start
/// belongs to this specification.
#[must_use]
pub fn check_anchor(
    start: &ConsensusBoundary,
    anchor: &ConsensusBoundary,
    end: &ConsensusBoundary,
    opening: Option<&AnchorOpening>,
) -> AnchorCheck {
    if anchor.next_chunk_id > end.next_chunk_id || anchor.next_chunk_id < start.next_chunk_id {
        return AnchorCheck::Invalid;
    }
    if anchor.next_chunk_id == end.next_chunk_id {
        return match (opening, anchor == end) {
            (Some(_), _) => AnchorCheck::Invalid,
            (None, true) => AnchorCheck::Extends,
            (None, false) => AnchorCheck::Conflicts,
        };
    }
    if anchor.next_chunk_id == start.next_chunk_id {
        return if opening.is_none() && anchor == start {
            AnchorCheck::Extends
        } else {
            AnchorCheck::Invalid
        };
    }
    let Some(AnchorOpening { context, path }) = opening else {
        return AnchorCheck::Unopened;
    };
    if context.chunk_id != anchor.next_chunk_id
        || path.index != anchor.next_chunk_id
        || path.count != end.next_chunk_id
        || !path.verify(crate::evidence::commitment(context), end.history_root)
    {
        return AnchorCheck::Invalid;
    }
    if context.start_boundary == anchor.commitment() {
        AnchorCheck::Extends
    } else {
        AnchorCheck::Conflicts
    }
}

/// Whether `anchor` lies on the chain that ends in `end`; see [`check_anchor`].
#[must_use]
pub fn anchors(
    start: &ConsensusBoundary,
    anchor: &ConsensusBoundary,
    end: &ConsensusBoundary,
    opening: Option<&AnchorOpening>,
) -> bool {
    check_anchor(start, anchor, end, opening) == AnchorCheck::Extends
}

/// A boundary with its chain identity: a light client's or bootstrap's trust
/// anchor, or the endpoint a History proof ends in.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Checkpoint {
    /// Immutable chain identity.
    pub chain: ChainBinding,
    /// Authenticated boundary, including the program set active after it.
    pub boundary: ConsensusBoundary,
}
impl Checkpoint {
    /// Domain-separated endpoint identity.
    #[must_use]
    pub fn hash(&self) -> Hash {
        crate::tagged_commitment(&DOMAIN_CHECKPOINT, self)
    }
}

/// Vector whose declared length is checked before allocating or decoding elements.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize)]
pub struct BoundedVec<T, const N: usize>(Vec<T>);
impl<T, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self(Vec::new())
    }
}
impl<T, const N: usize> BoundedVec<T, N> {
    /// Reject values exceeding the protocol bound.
    pub fn new(values: Vec<T>) -> Result<Self, neutrin0_primitives::BoundsError> {
        if values.len() > N {
            return Err(neutrin0_primitives::BoundsError {
                actual: values.len(),
                max: N,
            });
        }
        Ok(Self(values))
    }
}
impl<T, const N: usize> core::ops::Deref for BoundedVec<T, N> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T: BorshDeserialize, const N: usize> BorshDeserialize for BoundedVec<T, N> {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let len = u32::deserialize_reader(reader)? as usize;
        if len > N {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "vector exceeds bound",
            ));
        }
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(T::deserialize_reader(reader)?);
        }
        Ok(Self(values))
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // Small fixture indices become byte patterns.
mod tests;
