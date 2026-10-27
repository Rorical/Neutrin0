//! Canonical shared quorum carriers for signed BFT envelopes.
//!
//! Public semantic types retain complete certificates. Larger envelopes encode
//! each exact certificate once, followed by explicit optional content hashes.
//! Signatures bind those hashes, never a host-selected dictionary position.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Crate-visible codec entry points of a private module; `pub` would be unreachable."
)]

mod fields;
#[cfg(test)]
mod tests;

use alloc::collections::{BTreeMap, BTreeSet};
use borsh::{BorshDeserialize, BorshSerialize, io};
use neutrin0_primitives::{BlsSignature, Hash};

use crate::{
    BftProposal, FinalityCert, FinalityVote, FinalityVoteData, QuorumCertificate,
    RoundChangeCertificate, bft,
};
use fields::{
    claim_quorums, proposal_quorums, read_claims, read_proposal_fields, read_reports,
    report_quorums, write_claims, write_proposal_fields, write_reports,
};

const MAX_CERTIFICATE_QUORUMS: u32 = 3 * bft::MAX_BFT_SIGNERS + 1;
const MAX_PROPOSAL_QUORUMS: u32 = bft::MAX_BFT_SIGNERS + 1;
const MAX_DICTIONARY_BYTES: usize = crate::signed_artifacts::MAX_SIGNED_ARTIFACT_BYTES;
// Fixed vote fields, bitmap framing and signature; even an empty bitmap needs
// these bytes. Reject impossible table declarations before reading entries.
const MIN_QUORUM_BYTES: usize = 8 + 4 + 1 + 32 + 4 + 4 + 96;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct DictionaryWriter<'a>(BTreeMap<Hash, &'a QuorumCertificate>);

impl<'a> DictionaryWriter<'a> {
    fn collect(
        quorums: impl IntoIterator<Item = &'a QuorumCertificate>,
        maximum: u32,
    ) -> io::Result<Self> {
        let mut entries = BTreeMap::new();
        let mut expanded_bytes = 0_usize;
        for quorum in quorums {
            expanded_bytes = expanded_bytes
                .checked_add(borsh::object_length(quorum)?)
                .filter(|bytes| *bytes <= MAX_DICTIONARY_BYTES)
                .ok_or_else(|| invalid("expanded quorum carriers exceed byte bound"))?;
            let commitment = quorum.commitment();
            if let Some(prior) = entries.insert(commitment, quorum)
                && prior != quorum
            {
                return Err(invalid("conflicting shared quorum commitment"));
            }
            if u32::try_from(entries.len())
                .ok()
                .is_none_or(|count| count > maximum)
            {
                return Err(invalid("shared quorum dictionary exceeds count bound"));
            }
        }
        Ok(Self(entries))
    }

    fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        u32::try_from(self.0.len())
            .map_err(|_| invalid("shared quorum count overflow"))?
            .serialize(writer)?;
        let mut bounded = ByteBudgetWriter {
            writer,
            remaining: MAX_DICTIONARY_BYTES,
        };
        for quorum in self.0.values() {
            quorum.serialize(&mut bounded)?;
        }
        Ok(())
    }
}

struct ByteBudgetWriter<'a, W> {
    writer: &'a mut W,
    remaining: usize,
}

impl<W: io::Write> io::Write for ByteBudgetWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(invalid("shared quorum dictionary exceeds byte bound"));
        }
        let written = self.writer.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

struct ByteBudgetReader<'a, R> {
    reader: &'a mut R,
    remaining: usize,
}

impl<R: io::Read> io::Read for ByteBudgetReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(invalid("shared quorum dictionary exceeds byte bound"));
        }
        let read = self.reader.read(bytes)?;
        self.remaining -= read;
        Ok(read)
    }
}

struct DictionaryReader {
    entries: BTreeMap<Hash, (QuorumCertificate, usize)>,
    used: BTreeSet<Hash>,
    expanded_remaining: usize,
}

impl DictionaryReader {
    fn read<R: io::Read>(reader: &mut R, maximum: u32) -> io::Result<Self> {
        let count = u32::deserialize_reader(reader)?;
        if count > maximum {
            return Err(invalid("shared quorum dictionary exceeds count bound"));
        }
        if usize::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(MIN_QUORUM_BYTES))
            .is_none_or(|bytes| bytes > MAX_DICTIONARY_BYTES)
        {
            return Err(invalid("shared quorum dictionary exceeds byte bound"));
        }
        let mut entries = BTreeMap::new();
        let mut previous = None;
        let mut bounded = ByteBudgetReader {
            reader,
            remaining: MAX_DICTIONARY_BYTES,
        };
        for _ in 0..count {
            let quorum = bft::read_quorum(&mut bounded)?;
            let commitment = quorum.commitment();
            if previous.is_some_and(|previous| previous >= commitment) {
                return Err(invalid("shared quorum dictionary is not sorted and unique"));
            }
            let encoded_length = borsh::object_length(&quorum)?;
            let _ = entries.insert(commitment, (quorum, encoded_length));
            previous = Some(commitment);
        }
        Ok(Self {
            entries,
            used: BTreeSet::new(),
            expanded_remaining: MAX_DICTIONARY_BYTES,
        })
    }

    fn optional<R: io::Read>(&mut self, reader: &mut R) -> io::Result<Option<QuorumCertificate>> {
        let Some(commitment) = Option::<Hash>::deserialize_reader(reader)? else {
            return Ok(None);
        };
        let (quorum, encoded_length) = self
            .entries
            .get(&commitment)
            .ok_or_else(|| invalid("missing shared quorum certificate"))?;
        self.expanded_remaining = self
            .expanded_remaining
            .checked_sub(*encoded_length)
            .ok_or_else(|| invalid("expanded quorum carriers exceed byte bound"))?;
        self.used.insert(commitment);
        Ok(Some(quorum.clone()))
    }

    fn finish(self) -> io::Result<()> {
        if self.used.len() != self.entries.len() {
            return Err(invalid("unused shared quorum certificate"));
        }
        Ok(())
    }
}

pub(super) fn write_value<W: io::Write>(vote: &FinalityVote, writer: &mut W) -> io::Result<()> {
    DictionaryWriter::collect(claim_quorums(&vote.attestations), bft::MAX_BFT_SIGNERS)?
        .write(writer)?;
    vote.aggregation_bits.serialize(writer)?;
    vote.data.serialize(writer)?;
    vote.signature.serialize(writer)?;
    write_claims(&vote.attestations, writer)?;
    vote.proof_manifests.serialize(writer)
}

pub(super) fn read_value<R: io::Read>(reader: &mut R) -> io::Result<FinalityVote> {
    let mut dictionary = DictionaryReader::read(reader, bft::MAX_BFT_SIGNERS)?;
    let aggregation_bits = bft::read_bitmap(reader)?;
    let data = FinalityVoteData::deserialize_reader(reader)?;
    let signature = BlsSignature::deserialize_reader(reader)?;
    let attestations = read_claims(reader, &mut dictionary)?;
    let proof_manifests = crate::proof_acceptance::read_manifests(reader)?;
    dictionary.finish()?;
    Ok(FinalityVote {
        aggregation_bits,
        data,
        signature,
        attestations,
        proof_manifests,
    })
}

pub(super) fn write_proposal<W: io::Write>(
    proposal: &BftProposal,
    writer: &mut W,
) -> io::Result<()> {
    DictionaryWriter::collect(proposal_quorums(proposal), MAX_PROPOSAL_QUORUMS)?.write(writer)?;
    write_proposal_fields(proposal, writer)
}

pub(super) fn read_proposal<R: io::Read>(reader: &mut R) -> io::Result<BftProposal> {
    let mut dictionary = DictionaryReader::read(reader, MAX_PROPOSAL_QUORUMS)?;
    let proposal = read_proposal_fields(reader, &mut dictionary)?;
    dictionary.finish()?;
    Ok(proposal)
}

pub(super) fn write_round_change_certificate<W: io::Write>(
    certificate: &RoundChangeCertificate,
    writer: &mut W,
) -> io::Result<()> {
    DictionaryWriter::collect(report_quorums(certificate), bft::MAX_BFT_SIGNERS)?.write(writer)?;
    write_reports(certificate, writer)
}

pub(super) fn read_round_change_certificate<R: io::Read>(
    reader: &mut R,
) -> io::Result<RoundChangeCertificate> {
    let mut dictionary = DictionaryReader::read(reader, bft::MAX_BFT_SIGNERS)?;
    let certificate = read_reports(reader, &mut dictionary)?;
    dictionary.finish()?;
    Ok(certificate)
}

pub(super) fn write_certificate<W: io::Write>(
    certificate: &FinalityCert,
    writer: &mut W,
) -> io::Result<()> {
    DictionaryWriter::collect(
        proposal_quorums(&certificate.proposal)
            .chain(claim_quorums(&certificate.prevote_attestations))
            .chain(claim_quorums(&certificate.precommit_attestations)),
        MAX_CERTIFICATE_QUORUMS,
    )?
    .write(writer)?;
    write_proposal_fields(&certificate.proposal, writer)?;
    write_claims(&certificate.prevote_attestations, writer)?;
    write_claims(&certificate.precommit_attestations, writer)?;
    certificate.proof_manifests.serialize(writer)?;
    certificate.chunk_id.serialize(writer)?;
    certificate.round.serialize(writer)?;
    certificate.chunk_hash.serialize(writer)?;
    certificate.prevote.serialize(writer)?;
    certificate.precommit.serialize(writer)?;
    certificate.active_validator_set_root.serialize(writer)
}

pub(super) fn read_certificate<R: io::Read>(reader: &mut R) -> io::Result<FinalityCert> {
    let mut dictionary = DictionaryReader::read(reader, MAX_CERTIFICATE_QUORUMS)?;
    let proposal = read_proposal_fields(reader, &mut dictionary)?;
    let prevote_attestations = read_claims(reader, &mut dictionary)?;
    let precommit_attestations = read_claims(reader, &mut dictionary)?;
    let proof_manifests = crate::proof_acceptance::read_manifests(reader)?;
    let certificate = FinalityCert {
        proposal,
        prevote_attestations,
        precommit_attestations,
        proof_manifests,
        chunk_id: u64::deserialize_reader(reader)?,
        round: u32::deserialize_reader(reader)?,
        chunk_hash: Hash::deserialize_reader(reader)?,
        prevote: bft::read_aggregate(reader)?,
        precommit: bft::read_aggregate(reader)?,
        active_validator_set_root: Hash::deserialize_reader(reader)?,
    };
    dictionary.finish()?;
    Ok(certificate)
}
