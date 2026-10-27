//! Field-level encoders of the envelopes that share one quorum dictionary.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize, io};
use neutrin0_primitives::BlsSignature;

use super::{DictionaryReader, invalid};
use crate::{
    BftProposal, Chunk, FinalityVoteData, QuorumCertificate, RoundChange, RoundChangeCertificate,
    VoteAttestation, bft,
};

pub(super) fn claim_quorums(
    claims: &[VoteAttestation],
) -> impl Iterator<Item = &QuorumCertificate> {
    claims
        .iter()
        .filter_map(|claim| claim.unlock_quorum.as_ref())
}

pub(super) fn report_quorums(
    certificate: &RoundChangeCertificate,
) -> impl Iterator<Item = &QuorumCertificate> {
    certificate
        .reports
        .iter()
        .filter_map(|report| report.highest_quorum.as_ref())
}

pub(super) fn proposal_quorums(proposal: &BftProposal) -> impl Iterator<Item = &QuorumCertificate> {
    proposal.valid_quorum.iter().chain(
        proposal
            .round_change_certificate
            .iter()
            .flat_map(report_quorums),
    )
}

pub(super) fn write_claims<W: io::Write>(
    claims: &[VoteAttestation],
    writer: &mut W,
) -> io::Result<()> {
    u32::try_from(claims.len())
        .map_err(|_| invalid("BFT claim count overflow"))?
        .serialize(writer)?;
    for claim in claims {
        claim.vote_signature.serialize(writer)?;
        claim.validator_index.serialize(writer)?;
        claim.vote.serialize(writer)?;
        claim.proof_acceptance.serialize(writer)?;
        claim
            .unlock_quorum
            .as_ref()
            .map(QuorumCertificate::commitment)
            .serialize(writer)?;
        claim.signature.serialize(writer)?;
    }
    Ok(())
}

pub(super) fn read_claims<R: io::Read>(
    reader: &mut R,
    dictionary: &mut DictionaryReader,
) -> io::Result<Vec<VoteAttestation>> {
    let count = u32::deserialize_reader(reader)?;
    if count > bft::MAX_BFT_SIGNERS {
        return Err(invalid("BFT value attestations exceed transport bound"));
    }
    let mut claims = Vec::new();
    for _ in 0..count {
        claims.push(VoteAttestation {
            vote_signature: BlsSignature::deserialize_reader(reader)?,
            validator_index: u32::deserialize_reader(reader)?,
            vote: FinalityVoteData::deserialize_reader(reader)?,
            proof_acceptance: Option::<crate::ProofAcceptanceCommitment>::deserialize_reader(
                reader,
            )?,
            unlock_quorum: dictionary.optional(reader)?,
            signature: BlsSignature::deserialize_reader(reader)?,
        });
    }
    Ok(claims)
}

pub(super) fn write_reports<W: io::Write>(
    certificate: &RoundChangeCertificate,
    writer: &mut W,
) -> io::Result<()> {
    certificate.chunk_id.serialize(writer)?;
    certificate.round.serialize(writer)?;
    u32::try_from(certificate.reports.len())
        .map_err(|_| invalid("BFT report count overflow"))?
        .serialize(writer)?;
    for report in &certificate.reports {
        report.chunk_id.serialize(writer)?;
        report.round.serialize(writer)?;
        report.validator_index.serialize(writer)?;
        report
            .highest_quorum
            .as_ref()
            .map(QuorumCertificate::commitment)
            .serialize(writer)?;
        report.signature.serialize(writer)?;
    }
    Ok(())
}

pub(super) fn read_reports<R: io::Read>(
    reader: &mut R,
    dictionary: &mut DictionaryReader,
) -> io::Result<RoundChangeCertificate> {
    let chunk_id = u64::deserialize_reader(reader)?;
    let round = u32::deserialize_reader(reader)?;
    let count = u32::deserialize_reader(reader)?;
    if count > bft::MAX_BFT_SIGNERS {
        return Err(invalid("BFT reports exceed transport bound"));
    }
    let mut reports = Vec::new();
    for _ in 0..count {
        reports.push(RoundChange {
            chunk_id: u64::deserialize_reader(reader)?,
            round: u32::deserialize_reader(reader)?,
            validator_index: u32::deserialize_reader(reader)?,
            highest_quorum: dictionary.optional(reader)?,
            signature: BlsSignature::deserialize_reader(reader)?,
        });
    }
    Ok(RoundChangeCertificate {
        chunk_id,
        round,
        reports,
    })
}

pub(super) fn write_proposal_fields<W: io::Write>(
    proposal: &BftProposal,
    writer: &mut W,
) -> io::Result<()> {
    proposal.chunk.serialize(writer)?;
    proposal.round.serialize(writer)?;
    proposal.proposer_index.serialize(writer)?;
    proposal
        .valid_quorum
        .as_ref()
        .map(QuorumCertificate::commitment)
        .serialize(writer)?;
    match &proposal.round_change_certificate {
        None => 0_u8.serialize(writer)?,
        Some(certificate) => {
            1_u8.serialize(writer)?;
            write_reports(certificate, writer)?;
        }
    }
    proposal.proposal_slot.serialize(writer)?;
    proposal.receipts.serialize(writer)?;
    proposal.ratified_chunk_proofs.serialize(writer)?;
    proposal.signature.serialize(writer)
}

pub(super) fn read_proposal_fields<R: io::Read>(
    reader: &mut R,
    dictionary: &mut DictionaryReader,
) -> io::Result<BftProposal> {
    let chunk = Chunk::deserialize_reader(reader)?;
    let round = u32::deserialize_reader(reader)?;
    let proposer_index = u32::deserialize_reader(reader)?;
    let valid_quorum = dictionary.optional(reader)?;
    let round_change_certificate = match u8::deserialize_reader(reader)? {
        0 => None,
        1 => Some(read_reports(reader, dictionary)?),
        _ => return Err(invalid("invalid BFT round-entry option")),
    };
    let proposal_slot = u64::deserialize_reader(reader)?;
    let receipts = Vec::<bft::ReceiptChoice>::deserialize_reader(reader)?;
    if receipts.len() > bft::MAX_BFT_PROPOSAL_RECEIPTS {
        return Err(invalid("BFT proposal names too many receipts"));
    }
    let ratified_chunk_proofs = Vec::<bft::ChunkRatification>::deserialize_reader(reader)?;
    if ratified_chunk_proofs.len() > bft::MAX_BFT_PROPOSAL_RATIFICATIONS {
        return Err(invalid("BFT proposal ratifies too many chunk proofs"));
    }
    Ok(BftProposal {
        chunk,
        round,
        proposer_index,
        valid_quorum,
        round_change_certificate,
        proposal_slot,
        receipts,
        ratified_chunk_proofs,
        signature: BlsSignature::deserialize_reader(reader)?,
    })
}
