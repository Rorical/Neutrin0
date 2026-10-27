//! Explicit value/nil voting, fair round leaders and signed pacemaker reports.

mod leader;
mod messages;
#[cfg(test)]
mod tests;
mod wire;

pub use leader::{bft_leader, bft_leader_with_root};
pub use messages::{
    BftMessage, BftVote, IndexedNilVote, NilVote, NilVoteAttestation, NilVoteData, RoundChange,
    RoundChangeCertificate,
};
pub use wire::{
    read_nil, read_proposal, read_round_change, read_round_change_certificate, read_value,
};

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{BitVec, BlsSignature, ConsensusDomain, DOMAIN_BFT_PROPOSAL, Hash};

use crate::{AggregatedVote, Chunk, FinalityVoteData, QuorumCertificate};

/// Independently signed proposal from the designated leader of this round.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BftProposal {
    /// Complete compact candidate; its block proofs are fetched separately.
    pub chunk: Chunk,
    /// Round for which the candidate is proposed.
    pub round: u32,
    /// Index in the authenticated active validator set.
    pub proposer_index: u32,
    /// Highest earlier prevote quorum known for this exact candidate.
    pub valid_quorum: Option<QuorumCertificate>,
    /// Authenticated entry into this nonzero round; absent only for round zero.
    pub round_change_certificate: Option<RoundChangeCertificate>,
    /// Slot at which the leader proposed; the exclusive-window rule is
    /// evaluated against it (design 08).
    pub proposal_slot: u64,
    /// The receipt named for each height of the chunk, in height order
    /// (design 08).
    pub receipts: Vec<ReceiptChoice>,
    /// Chunk proofs this proposal ratifies for payment: the previous chunk's,
    /// or nothing for a chain's first chunk (design 08).
    pub ratified_chunk_proofs: Vec<ChunkRatification>,
    /// Signature binding all fields under the chain's proposal domain.
    pub signature: BlsSignature,
}

/// One height's selected block receipt: its attribution and statement key
/// (design 08). The key commits the prover address; the pair travels so a
/// later chunk can attribute the block without the receipt.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ReceiptChoice {
    /// Account the receipt credits.
    pub prover_address: Hash,
    /// Commitment of the receipt's complete public values.
    pub statement_key: Hash,
}

/// One ratified chunk proof (design 08).
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ChunkRatification {
    /// Chunk the proof finalizes.
    pub chunk_id: u64,
    /// Account the chunk proof credits.
    pub prover_address: Hash,
    /// Commitment of the finality certificate the proof's statement names.
    /// Nodes may finalize a chunk under different valid certificates; with it
    /// every node rebuilds the exact statement from its boundaries.
    pub finality_cert_hash: Hash,
    /// Commitment of the chunk proof's complete public values.
    pub statement_key: Hash,
}

/// A certificate's leader proposal in the compact form a later block carries.
///
/// The chunk is omitted and the valid quorum and round-change certificate are
/// replaced by the commitments its signature covers. It verifies against the
/// chunk a History record supplies and lets the consuming chunk derive the
/// proving report (design 08).
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct CompactProposal {
    /// Round the proposal was made in.
    pub round: u32,
    /// Index of the round's designated leader.
    pub proposer_index: u32,
    /// Commitment of the proposal's valid quorum, if any.
    pub valid_quorum: Option<Hash>,
    /// Commitment of the proposal's round-change certificate, if any.
    pub round_change_certificate: Option<Hash>,
    /// The leader's signed slot.
    pub proposal_slot: u64,
    /// The selected receipt of every height.
    pub receipts: Vec<ReceiptChoice>,
    /// The ratified chunk proofs.
    pub ratified_chunk_proofs: Vec<ChunkRatification>,
    /// The leader's signature.
    pub signature: BlsSignature,
}

/// Canonical proposal signing bytes shared by the full and compact forms.
#[allow(clippy::too_many_arguments)] // Every signed field, in signing order.
fn proposal_signing_message(
    domain: ConsensusDomain,
    chunk: &Chunk,
    round: u32,
    proposer_index: u32,
    valid_quorum: Option<Hash>,
    round_change_certificate: Option<Hash>,
    proposal_slot: u64,
    receipts: &[ReceiptChoice],
    ratified_chunk_proofs: &[ChunkRatification],
) -> Vec<u8> {
    domain.at_chunk(chunk.chunk_id).signing_message_borsh(
        DOMAIN_BFT_PROPOSAL,
        &(
            chunk,
            round,
            proposer_index,
            valid_quorum,
            round_change_certificate,
            proposal_slot,
            receipts,
            ratified_chunk_proofs,
        ),
    )
}

/// A proposal's payment selection (design 08).
///
/// Its signed slot, the receipt chosen for every height and the ratified chunk
/// proof. A BFT value is a chunk with one selection; a leader re-proposing a
/// valid value reproduces the selection its quorum signed.
#[derive(BorshSerialize, Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct PaymentSelection {
    /// The leader's signed slot.
    pub proposal_slot: u64,
    /// The selected receipt of every height.
    pub receipts: Vec<ReceiptChoice>,
    /// The ratified chunk proof.
    pub ratified_chunk_proofs: Vec<ChunkRatification>,
}

impl PaymentSelection {
    /// The commitment value votes sign.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        selection_commitment(
            self.proposal_slot,
            &self.receipts,
            &self.ratified_chunk_proofs,
        )
    }
}

impl BorshDeserialize for PaymentSelection {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let proposal_slot = u64::deserialize_reader(reader)?;
        let receipts = Vec::<ReceiptChoice>::deserialize_reader(reader)?;
        if receipts.len() > MAX_BFT_PROPOSAL_RECEIPTS {
            return Err(invalid_wire("selection names too many receipts"));
        }
        let ratified_chunk_proofs = Vec::<ChunkRatification>::deserialize_reader(reader)?;
        if ratified_chunk_proofs.len() > MAX_BFT_PROPOSAL_RATIFICATIONS {
            return Err(invalid_wire("selection ratifies too many chunk proofs"));
        }
        Ok(Self {
            proposal_slot,
            receipts,
            ratified_chunk_proofs,
        })
    }
}

/// Commitment of a proposal's payment selection: its signed slot, the
/// receipt chosen for every height and the ratification list (design 08).
/// Every value vote signs it next to the chunk hash.
#[must_use]
pub fn selection_commitment(
    proposal_slot: u64,
    receipts: &[ReceiptChoice],
    ratified_chunk_proofs: &[ChunkRatification],
) -> Hash {
    crate::tagged_commitment(
        &neutrin0_primitives::DOMAIN_SELECTION,
        &(proposal_slot, receipts, ratified_chunk_proofs),
    )
}

impl CompactProposal {
    /// Commitment of the payment selection every vote of the certificate
    /// signs.
    #[must_use]
    pub fn selection(&self) -> Hash {
        selection_commitment(
            self.proposal_slot,
            &self.receipts,
            &self.ratified_chunk_proofs,
        )
    }

    /// Signing bytes of the full proposal this compact form came from, for
    /// `chunk`.
    #[must_use]
    pub fn signing_message(&self, domain: ConsensusDomain, chunk: &Chunk) -> Vec<u8> {
        proposal_signing_message(
            domain,
            chunk,
            self.round,
            self.proposer_index,
            self.valid_quorum,
            self.round_change_certificate,
            self.proposal_slot,
            &self.receipts,
            &self.ratified_chunk_proofs,
        )
    }
}

impl BftProposal {
    /// Canonical chain-bound signing bytes.
    ///
    /// # Panics
    /// Panics if an in-memory round-entry certificate exceeds encoding bounds.
    #[must_use]
    pub fn signing_message(&self, domain: ConsensusDomain) -> Vec<u8> {
        proposal_signing_message(
            domain,
            &self.chunk,
            self.round,
            self.proposer_index,
            self.valid_quorum
                .as_ref()
                .map(QuorumCertificate::commitment),
            self.round_change_certificate
                .as_ref()
                .map(RoundChangeCertificate::commitment),
            self.proposal_slot,
            &self.receipts,
            &self.ratified_chunk_proofs,
        )
    }

    /// Commitment of the payment selection every value vote of this round
    /// signs (design 08).
    #[must_use]
    pub fn selection(&self) -> Hash {
        selection_commitment(
            self.proposal_slot,
            &self.receipts,
            &self.ratified_chunk_proofs,
        )
    }

    /// The payment selection this proposal names.
    #[must_use]
    pub fn payment_selection(&self) -> PaymentSelection {
        PaymentSelection {
            proposal_slot: self.proposal_slot,
            receipts: self.receipts.clone(),
            ratified_chunk_proofs: self.ratified_chunk_proofs.clone(),
        }
    }

    /// Statement keys of the named receipts, in height order.
    #[must_use]
    pub fn receipt_keys(&self) -> Vec<Hash> {
        self.receipts
            .iter()
            .map(|choice| choice.statement_key)
            .collect()
    }

    /// The compact form carried by the chunk that consumes this proposal's
    /// certificate (design 08).
    #[must_use]
    pub fn compact(&self) -> CompactProposal {
        CompactProposal {
            round: self.round,
            proposer_index: self.proposer_index,
            valid_quorum: self
                .valid_quorum
                .as_ref()
                .map(QuorumCertificate::commitment),
            round_change_certificate: self
                .round_change_certificate
                .as_ref()
                .map(RoundChangeCertificate::commitment),
            proposal_slot: self.proposal_slot,
            receipts: self.receipts.clone(),
            ratified_chunk_proofs: self.ratified_chunk_proofs.clone(),
            signature: self.signature,
        }
    }
}

/// Local transport bound, matching candidate retrieval rather than consensus membership.
pub const MAX_BFT_SIGNERS: u32 = crate::candidate::MAX_CANDIDATE_SIGNERS;
/// Most receipts one proposal names: one per height of the largest chunk.
#[allow(
    clippy::cast_possible_truncation,
    reason = "The committee block bound is 16,384, far below any pointer width."
)]
pub const MAX_BFT_PROPOSAL_RECEIPTS: usize =
    neutrin0_primitives::MAX_CONSENSUS_COMMITTEE_BLOCKS as usize;
/// Wire bound on the chunk proofs one proposal ratifies.
pub const MAX_BFT_PROPOSAL_RATIFICATIONS: usize =
    neutrin0_primitives::MAX_CHUNK_RATIFICATIONS as usize;

fn read_bounded_vec<T: BorshDeserialize, R: borsh::io::Read>(
    reader: &mut R,
    max: u32,
) -> borsh::io::Result<Vec<T>> {
    let count = u32::deserialize_reader(reader)?;
    if count > max {
        return Err(invalid_wire("BFT vector exceeds transport bound"));
    }
    let mut values = Vec::new();
    for _ in 0..count {
        values.push(T::deserialize_reader(reader)?);
    }
    Ok(values)
}

pub(crate) fn read_bitmap<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<BitVec> {
    let bit_len = u32::deserialize_reader(reader)?;
    let byte_len = u32::deserialize_reader(reader)?;
    if bit_len > MAX_BFT_SIGNERS || byte_len != bit_len.div_ceil(8) {
        return Err(invalid_wire("BFT bitmap exceeds transport bound"));
    }
    let mut bytes = Vec::new();
    for _ in 0..byte_len {
        bytes.push(u8::deserialize_reader(reader)?);
    }
    BitVec::from_bytes(bit_len, bytes).map_err(|_| invalid_wire("noncanonical BFT bitmap"))
}

fn invalid_wire(message: &str) -> borsh::io::Error {
    borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, message)
}

/// Decode an aggregate while bounding its bitmap before allocation.
pub(crate) fn read_aggregate<R: borsh::io::Read>(
    reader: &mut R,
) -> borsh::io::Result<AggregatedVote> {
    Ok(AggregatedVote {
        aggregation_bits: read_bitmap(reader)?,
        signature: BlsSignature::deserialize_reader(reader)?,
    })
}

/// Decode a value quorum with local transport bitmap bounds.
pub fn read_quorum<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<QuorumCertificate> {
    Ok(QuorumCertificate {
        data: FinalityVoteData::deserialize_reader(reader)?,
        aggregate: read_aggregate(reader)?,
    })
}

pub(crate) fn read_optional_quorum<R: borsh::io::Read>(
    reader: &mut R,
) -> borsh::io::Result<Option<QuorumCertificate>> {
    match u8::deserialize_reader(reader)? {
        0 => Ok(None),
        1 => Ok(Some(read_quorum(reader)?)),
        _ => Err(invalid_wire("invalid BFT quorum option")),
    }
}
