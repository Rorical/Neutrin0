//! The proving report a chunk derives from the previous chunk's carried
//! certificate (design 08).

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{DOMAIN_PROVING, Hash, Validator};

use crate::bft::{ChunkRatification, CompactProposal};
use crate::{Chunk, QuorumCertificate};

/// Commitment of "no proving report consumed yet": the boundary value at
/// genesis and until a chunk consumes a carried certificate.
pub const NO_PROVING: Hash = [0; 32];

/// The previous chunk's certificate as a later block carries it: the
/// precommit quorum and the leader proposal it retains, in compact form.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct CarriedCertificate {
    /// The compact precommit quorum the participation report derives from.
    pub quorum: QuorumCertificate,
    /// The certificate's leader proposal, verified against the History
    /// record's chunk.
    pub proposal: CompactProposal,
}

/// One height of a proving report.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ProvingEntry {
    /// Block height.
    pub height: u64,
    /// Account the selected receipt credits.
    pub prover: Hash,
}

/// Attribution of one certified chunk: who proved each block, the committee
/// that shares the chunk share by weight, and which chunk proofs the
/// certificate ratified.
///
/// Every field is a function of the finalized chunk alone. The receipt
/// choices and the ratification list are part of the voted value, so every
/// certificate of the chunk carries the same ones, and the committee is the
/// chunk's whole recorded validator set rather than whichever quorum subset a
/// carrier attaches (design 08).
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct ProvingReport {
    /// Certified chunk.
    pub chunk_id: u64,
    /// One entry per height, in order.
    pub entries: Vec<ProvingEntry>,
    /// Withdrawal accounts and effective stakes of the chunk's unslashed,
    /// positively weighted validators, in validator-set order.
    pub committee: Vec<(Hash, u128)>,
    /// Chunk proofs the certificate ratified, in order; for a hard fork's
    /// first chunk, which ratifies none, the predecessor's endpoint prover
    /// the specification pins (design 20).
    pub chunk_provers: Vec<(u64, Hash)>,
}

impl ProvingReport {
    /// Derive the report of `chunk` from its carried certificate and its
    /// recorded committee; `None` when the certificate does not cover the
    /// chunk exactly or its quorum did not sign the carried selection.
    /// Callers authenticate the quorum and proposal signatures first.
    #[must_use]
    pub fn from_certificate(
        chunk: &Chunk,
        validators: &[Validator],
        carried: &CarriedCertificate,
    ) -> Option<Self> {
        let heights = chunk.start_height..=chunk.end_height;
        let span = usize::try_from(chunk.end_height.checked_sub(chunk.start_height)?)
            .ok()?
            .checked_add(1)?;
        if carried.proposal.receipts.len() != span
            || carried.quorum.data.selection != carried.proposal.selection()
            || carried.quorum.data.chunk_hash != chunk.hash()
        {
            return None;
        }
        let committee = validators
            .iter()
            .filter(|validator| validator.effective_stake > 0)
            .map(|validator| (validator.withdrawal_credentials, validator.effective_stake))
            .collect();
        Some(Self {
            chunk_id: chunk.chunk_id,
            entries: heights
                .zip(&carried.proposal.receipts)
                .map(|(height, choice)| ProvingEntry {
                    height,
                    prover: choice.prover_address,
                })
                .collect(),
            committee,
            chunk_provers: carried
                .proposal
                .ratified_chunk_proofs
                .iter()
                .map(|entry| (entry.chunk_id, entry.prover_address))
                .collect(),
        })
    }

    /// Domain-separated commitment of the exact report.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        crate::tagged_commitment(&DOMAIN_PROVING, self)
    }
}

/// Whether `list` is the ratification a certificate signs, given the chunk
/// `previous` whose proof that certificate's chunk ratifies
/// (`ChainSpec::previous_chunk`).
///
/// That is exactly the previous chunk's proof, and nothing for a chain's first
/// chunk (design 08): genesis, or a hard fork's pinned start (design 20),
/// where `previous` is `None`. The chunk Guest of the certificate's chunk
/// verifies the named proof recursively, and that proof verified its own
/// predecessor's, so no boundary needs to count ratified chunks.
#[must_use]
pub const fn ratifies_previous(list: &[ChunkRatification], previous: Option<u64>) -> bool {
    match (previous, list) {
        (None, []) => true,
        (Some(previous), [entry]) => entry.chunk_id == previous,
        _ => false,
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // Small fixture indices become byte patterns.
mod tests;
