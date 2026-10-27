//! Nil votes, round-change reports, certificates and the gossip envelope.

use alloc::{boxed::Box, vec::Vec};

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{
    BitVec, BlsSignature, ConsensusDomain, DOMAIN_BFT_NIL, DOMAIN_BFT_NIL_ATTESTATION,
    DOMAIN_BFT_ROUND_CHANGE, Hash,
};

use super::BftProposal;
use crate::{FinalityVote, FinalityVotePhase, QuorumCertificate};

/// An explicit vote for no value. A nil vote cannot finalize or erase a lock.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct NilVoteData {
    /// Chunk whose round is being advanced.
    pub chunk_id: u64,
    /// Round in which the validator did not select a value.
    pub round: u32,
    /// Prevote or precommit step; both sign this field.
    pub phase: FinalityVotePhase,
}

impl NilVoteData {
    /// Canonical chain-bound signing bytes, distinct from every value vote.
    #[must_use]
    pub fn signing_message(&self, domain: ConsensusDomain) -> Vec<u8> {
        domain
            .at_chunk(self.chunk_id)
            .signing_message_borsh(DOMAIN_BFT_NIL, self)
    }
}

/// Individual signatures retained when a nil vote is aggregated.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct NilVoteAttestation {
    /// Index of the accountable signer.
    pub validator_index: u32,
    /// Exact nil vote.
    pub vote: NilVoteData,
    /// Individual signature of that nil vote.
    pub vote_signature: BlsSignature,
    /// Additional signature binding signer identity and retained vote signature.
    pub signature: BlsSignature,
}

impl NilVoteAttestation {
    /// Canonical chain-bound accountability signature bytes.
    #[must_use]
    pub fn signing_message(&self, domain: ConsensusDomain) -> Vec<u8> {
        domain.at_chunk(self.vote.chunk_id).signing_message_borsh(
            DOMAIN_BFT_NIL_ATTESTATION,
            &(self.validator_index, &self.vote, &self.vote_signature),
        )
    }
}

/// Aggregate nil vote with complete individual signer coverage.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct NilVote {
    /// Signed nil payload.
    pub data: NilVoteData,
    /// Exact signers in the aggregate.
    pub aggregation_bits: BitVec,
    /// Aggregate signature of the nil payload.
    pub signature: BlsSignature,
    /// Individually signed accountable statements for every included signer.
    pub attestations: Vec<NilVoteAttestation>,
}

/// An independently signed nil vote used in objective equivocation evidence.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct IndexedNilVote {
    /// Exact nil payload.
    pub data: NilVoteData,
    /// The accused validator's individual signature.
    pub signature: BlsSignature,
}

/// BFT vote wire format with disjoint explicit nil and value targets.
#[derive(BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub enum BftVote {
    /// Vote for a particular proven chunk.
    Value(FinalityVote),
    /// Vote for no value during this phase.
    Nil(NilVote),
}

/// Signed readiness to enter a round, preserving the highest observed value QC.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct RoundChange {
    /// Chunk whose consensus session is advancing.
    pub chunk_id: u64,
    /// New round requested by this report.
    pub round: u32,
    /// Accountable active validator index.
    pub validator_index: u32,
    /// Highest earlier value prevote QC known to the signer.
    pub highest_quorum: Option<QuorumCertificate>,
    /// Chain-bound signature of the exact report and carried quorum.
    pub signature: BlsSignature,
}

impl RoundChange {
    /// Canonical chain-bound signing bytes.
    #[must_use]
    pub fn signing_message(&self, domain: ConsensusDomain) -> Vec<u8> {
        domain.at_chunk(self.chunk_id).signing_message_borsh(
            DOMAIN_BFT_ROUND_CHANGE,
            &(
                self.chunk_id,
                self.round,
                self.validator_index,
                self.highest_quorum
                    .as_ref()
                    .map(QuorumCertificate::commitment),
            ),
        )
    }
}

/// Unique signed reports with a quorum of authenticated active stake.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RoundChangeCertificate {
    /// Chunk receiving a pacemaker certificate.
    pub chunk_id: u64,
    /// Exact new round shared by all reports.
    pub round: u32,
    /// Unique per-validator reports; the signatures may carry different QCs.
    pub reports: Vec<RoundChange>,
}

impl RoundChangeCertificate {
    /// Commit the complete canonical certificate and all original reports.
    ///
    /// # Panics
    /// Panics if an in-memory certificate exceeds the envelope encoding bounds.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        crate::hashing::borsh_commitment(b"NEU_BFT_RC_REF__", self)
    }

    /// The highest independently verified value QC carried by the certificate.
    /// Equal-round certificates are selected deterministically by target hash.
    #[must_use]
    pub fn highest_quorum(&self) -> Option<&QuorumCertificate> {
        self.reports
            .iter()
            .filter_map(|report| report.highest_quorum.as_ref())
            .max_by_key(|quorum| {
                (
                    quorum.data.round,
                    quorum.data.chunk_hash,
                    quorum.data.selection,
                )
            })
    }
}

/// Bounded gossip envelope used by the live round protocol.
#[derive(BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub enum BftMessage {
    /// Signed leader proposal.
    Proposal(Box<BftProposal>),
    /// Explicit value or nil vote.
    Vote(BftVote),
    /// Signed pacemaker report.
    RoundChange(RoundChange),
    /// Quorum-certified catchup to a later round.
    RoundChangeCertificate(RoundChangeCertificate),
}
