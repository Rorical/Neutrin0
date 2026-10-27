//! Bounded, content-addressed sources for objective accountability.
//!
//! An inventory is an availability hint. Its source chunk and every returned
//! signature/proof binding must be authenticated by the receiving host.

extern crate alloc;
use crate::{
    BftProposal, BlockProof, FinalityVote, NilVote, QuorumCertificate, RoundChange,
    RoundChangeCertificate, tagged_commitment,
};
use alloc::{boxed::Box, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{ChunkId, Hash};

/// Maximum encoded source artifact, independent of chain age.
pub const MAX_SIGNED_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
/// Maximum references in one inventory page or gossip notice.
pub const MAX_ARTIFACT_INVENTORY: usize = 32;

/// Source category; a hint does not establish validity.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SignedArtifactKind {
    /// Original aggregate and all individual signed declarations.
    Vote,
    /// Independently verifiable historical prevote quorum.
    Quorum,
    /// Exact accepted or rejected block-proof envelope.
    BlockProof,
    /// Signed designated-leader proposal.
    Proposal,
    /// Explicit nil vote and accountable signer declarations.
    NilVote,
    /// Signed readiness report preserving its highest quorum.
    RoundChange,
    /// Independently verifiable signed pacemaker quorum.
    RoundChangeCertificate,
}

/// Immutable sources retained for delayed evidence detection.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "Short-lived transport value; the receipt variant carries its attribution inline."
)]
pub enum SignedArtifact {
    /// Vote signatures and mandatory attestations.
    Vote(FinalityVote),
    /// Historical locking or unlocking quorum.
    Quorum(QuorumCertificate),
    /// Exact bytes named by a precommit declaration.
    BlockProof(BlockProof),
    /// Signed designated-leader proposal.
    Proposal(Box<BftProposal>),
    /// Explicit nil vote and accountable signer declarations.
    NilVote(NilVote),
    /// Signed readiness report preserving its highest quorum.
    RoundChange(RoundChange),
    /// Independently verifiable signed pacemaker quorum.
    RoundChangeCertificate(RoundChangeCertificate),
}

#[derive(BorshSerialize, BorshDeserialize)]
#[allow(
    clippy::large_enum_variant,
    reason = "Decoding scratch value mirroring `SignedArtifact`."
)]
enum Payload {
    Vote(FinalityVote),
    Quorum(QuorumCertificate),
    BlockProof(BlockProof),
    Proposal(Box<BftProposal>),
    NilVote(NilVote),
    RoundChange(RoundChange),
    RoundChangeCertificate(RoundChangeCertificate),
}

impl SignedArtifact {
    /// Category advertised by its provider.
    #[must_use]
    pub const fn kind(&self) -> SignedArtifactKind {
        match self {
            Self::Vote(_) => SignedArtifactKind::Vote,
            Self::Quorum(_) => SignedArtifactKind::Quorum,
            Self::BlockProof(_) => SignedArtifactKind::BlockProof,
            Self::Proposal(_) => SignedArtifactKind::Proposal,
            Self::NilVote(_) => SignedArtifactKind::NilVote,
            Self::RoundChange(_) => SignedArtifactKind::RoundChange,
            Self::RoundChangeCertificate(_) => SignedArtifactKind::RoundChangeCertificate,
        }
    }

    /// Exact content identity. Proof identities match existing signed envelope hashes.
    #[must_use]
    pub fn id(&self) -> Hash {
        match self {
            Self::Vote(vote) => tagged_commitment(b"neutrin0/artifact/vote", vote),
            Self::Quorum(quorum) => tagged_commitment(b"neutrin0/artifact/quorum", quorum),
            Self::BlockProof(proof) => crate::evidence::commitment(proof),
            Self::Proposal(value) => tagged_commitment(b"neutrin0/artifact/proposal", value),
            Self::NilVote(value) => tagged_commitment(b"neutrin0/artifact/nilvote", value),
            Self::RoundChange(value) => tagged_commitment(b"neutrin0/artifact/roundchange", value),
            Self::RoundChangeCertificate(value) => {
                tagged_commitment(b"neutrin0/artifact/roundchangecertificate", value)
            }
        }
    }

    /// Source chunk computed from the protocol block range, with overflow rejection.
    #[must_use]
    pub fn chunk_id(&self, chunk_size: u64) -> Option<ChunkId> {
        match self {
            Self::Vote(vote) => Some(vote.data.chunk_id),
            Self::Quorum(quorum) => Some(quorum.data.chunk_id),
            Self::Proposal(value) => Some(value.chunk.chunk_id),
            Self::NilVote(value) => Some(value.data.chunk_id),
            Self::RoundChange(value) => Some(value.chunk_id),
            Self::RoundChangeCertificate(value) => Some(value.chunk_id),
            Self::BlockProof(proof) => proof.height.checked_sub(1)?.checked_div(chunk_size),
        }
    }

    /// Compact inventory reference for this exact immutable artifact.
    #[must_use]
    pub fn reference(&self) -> SignedArtifactRef {
        SignedArtifactRef {
            id: self.id(),
            kind: self.kind(),
        }
    }
}

impl BorshSerialize for SignedArtifact {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        let payload = match self {
            Self::Vote(value) => Payload::Vote(value.clone()),
            Self::Quorum(value) => Payload::Quorum(value.clone()),
            Self::BlockProof(value) => Payload::BlockProof(value.clone()),
            Self::Proposal(value) => Payload::Proposal(value.clone()),
            Self::NilVote(value) => Payload::NilVote(value.clone()),
            Self::RoundChange(value) => Payload::RoundChange(value.clone()),
            Self::RoundChangeCertificate(value) => Payload::RoundChangeCertificate(value.clone()),
        };
        let bytes = borsh::to_vec(&payload)?;
        if bytes.len() > MAX_SIGNED_ARTIFACT_BYTES {
            return Err(invalid("artifact too large"));
        }
        bytes.serialize(writer)
    }
}

impl BorshDeserialize for SignedArtifact {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let length = usize::try_from(u32::deserialize_reader(reader)?)
            .map_err(|_| invalid("artifact length"))?;
        if length > MAX_SIGNED_ARTIFACT_BYTES {
            return Err(invalid("artifact too large"));
        }
        let mut bytes = alloc::vec![0; length];
        reader.read_exact(&mut bytes)?;
        let mut payload = bytes.as_slice();
        let artifact = match u8::deserialize_reader(&mut payload)? {
            0 => Self::Vote(crate::bft::read_value(&mut payload)?),
            1 => Self::Quorum(crate::bft::read_quorum(&mut payload)?),
            2 => Self::BlockProof(BlockProof::deserialize_reader(&mut payload)?),
            3 => Self::Proposal(Box::new(crate::bft::read_proposal(&mut payload)?)),
            4 => Self::NilVote(crate::bft::read_nil(&mut payload)?),
            5 => Self::RoundChange(crate::bft::read_round_change(&mut payload)?),
            6 => Self::RoundChangeCertificate(crate::bft::read_round_change_certificate(
                &mut payload,
            )?),
            _ => return Err(invalid("source artifact tag")),
        };
        if !payload.is_empty() {
            return Err(invalid("trailing source artifact bytes"));
        }
        Ok(artifact)
    }
}

/// Exact identity and advisory source category.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SignedArtifactRef {
    /// Canonical immutable content hash.
    pub id: Hash,
    /// Provider-advertised category; checked against returned bytes.
    pub kind: SignedArtifactKind,
}

/// Bounded inventory page, also used as gossip availability notices.
#[derive(BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct SignedArtifactInventory {
    /// Host-authenticated current or historical source chunk.
    pub chunk_id: ChunkId,
    /// At most 32 exact references, in increasing content-hash order.
    pub entries: Vec<SignedArtifactRef>,
    /// Last returned identity when another page remains.
    pub next: Option<Hash>,
}

impl BorshDeserialize for SignedArtifactInventory {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let chunk_id = ChunkId::deserialize_reader(reader)?;
        let count = usize::try_from(u32::deserialize_reader(reader)?)
            .map_err(|_| invalid("inventory length"))?;
        if count > MAX_ARTIFACT_INVENTORY {
            return Err(invalid("inventory too large"));
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(SignedArtifactRef::deserialize_reader(reader)?);
        }
        if entries.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err(invalid("inventory order"));
        }
        let next = Option::<Hash>::deserialize_reader(reader)?;
        if next.is_some() && next != entries.last().map(|item| item.id) {
            return Err(invalid("inventory cursor"));
        }
        Ok(Self {
            chunk_id,
            entries,
            next,
        })
    }
}

fn invalid(message: &'static str) -> borsh::io::Error {
    borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unbounded_outer_payload_before_allocation() {
        let bytes = u32::try_from(MAX_SIGNED_ARTIFACT_BYTES + 1)
            .unwrap()
            .to_le_bytes();
        assert!(borsh::from_slice::<SignedArtifact>(&bytes).is_err());
    }
    #[test]
    fn rejects_unbounded_inventory_and_duplicate_ids() {
        let mut bytes = 0_u64.to_le_bytes().to_vec();
        bytes.extend(33_u32.to_le_bytes());
        assert!(borsh::from_slice::<SignedArtifactInventory>(&bytes).is_err());
        let inventory = SignedArtifactInventory {
            chunk_id: 0,
            entries: alloc::vec![SignedArtifactRef { id: [1; 32], kind: SignedArtifactKind::Vote }; 2],
            next: None,
        };
        assert!(
            borsh::from_slice::<SignedArtifactInventory>(&borsh::to_vec(&inventory).unwrap())
                .is_err()
        );
    }
}
