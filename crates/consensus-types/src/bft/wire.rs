//! Transport decoders of the BFT envelopes, bounded before allocation.

use alloc::boxed::Box;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::BlsSignature;

use super::{
    BftMessage, BftProposal, BftVote, MAX_BFT_SIGNERS, NilVote, NilVoteData, RoundChange,
    RoundChangeCertificate, invalid_wire, read_bitmap, read_bounded_vec, read_optional_quorum,
};
use crate::FinalityVote;

/// Decode a value vote with local transport bitmap and attestation bounds.
pub fn read_value<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<FinalityVote> {
    crate::quorum_dictionary::read_value(reader)
}

/// Decode an explicit nil vote with local transport allocation bounds.
pub fn read_nil<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<NilVote> {
    Ok(NilVote {
        data: NilVoteData::deserialize_reader(reader)?,
        aggregation_bits: read_bitmap(reader)?,
        signature: BlsSignature::deserialize_reader(reader)?,
        attestations: read_bounded_vec(reader, MAX_BFT_SIGNERS)?,
    })
}

/// Decode a round-leader proposal with local transport allocation bounds.
/// Core proposal decoding remains the canonical protocol codec.
pub fn read_proposal<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<BftProposal> {
    crate::quorum_dictionary::read_proposal(reader)
}

/// Decode a signed round-change report with local transport quorum bounds.
pub fn read_round_change<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<RoundChange> {
    Ok(RoundChange {
        chunk_id: u64::deserialize_reader(reader)?,
        round: u32::deserialize_reader(reader)?,
        validator_index: u32::deserialize_reader(reader)?,
        highest_quorum: read_optional_quorum(reader)?,
        signature: BlsSignature::deserialize_reader(reader)?,
    })
}

/// Decode a pacemaker certificate with local transport allocation bounds.
pub fn read_round_change_certificate<R: borsh::io::Read>(
    reader: &mut R,
) -> borsh::io::Result<RoundChangeCertificate> {
    crate::quorum_dictionary::read_round_change_certificate(reader)
}

impl BorshSerialize for BftProposal {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        crate::quorum_dictionary::write_proposal(self, writer)
    }
}

impl BorshDeserialize for BftProposal {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        read_proposal(reader)
    }
}

impl BorshSerialize for RoundChangeCertificate {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        crate::quorum_dictionary::write_round_change_certificate(self, writer)
    }
}

impl BorshDeserialize for RoundChangeCertificate {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        read_round_change_certificate(reader)
    }
}

impl BorshDeserialize for BftVote {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        match u8::deserialize_reader(reader)? {
            0 => Ok(Self::Value(read_value(reader)?)),
            1 => Ok(Self::Nil(read_nil(reader)?)),
            _ => Err(invalid_wire("invalid BFT vote target")),
        }
    }
}

impl BorshDeserialize for BftMessage {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        match u8::deserialize_reader(reader)? {
            0 => Ok(Self::Proposal(Box::new(read_proposal(reader)?))),
            1 => Ok(Self::Vote(BftVote::deserialize_reader(reader)?)),
            2 => Ok(Self::RoundChange(read_round_change(reader)?)),
            3 => Ok(Self::RoundChangeCertificate(read_round_change_certificate(
                reader,
            )?)),
            _ => Err(invalid_wire("invalid BFT message")),
        }
    }
}
