//! Finality votes, signer attestations, quorum certificates and finality certificates.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{
    BitVec, BlsSignature, ChunkHash, ChunkId, ConsensusDomain, Hash, ValidatorIndex,
};

use crate::{
    BftProposal, ProofAcceptanceCommitment, ProofManifest, bft, hashing, proving, quorum_dictionary,
};

/// Finality vote phase.
#[derive(
    BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum FinalityVotePhase {
    /// Tendermint prevote.
    Prevote,
    /// Tendermint precommit.
    Precommit,
}

/// Finality vote message payload.
///
/// The voted value is the chunk together with the payment selection of the
/// round's leader proposal (design 08): votes for one chunk with different
/// selections are votes for different values, so a lock, a quorum and a
/// certificate fix the selection as firmly as the chunk.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct FinalityVoteData {
    /// Chunk being voted on.
    pub chunk_id: u64,
    /// BFT round.
    pub round: u32,
    /// Chunk commitment hash.
    pub chunk_hash: ChunkHash,
    /// Commitment of the proposal's proposal slot, receipt choices and
    /// ratification list ([`crate::bft::selection_commitment`]).
    pub selection: Hash,
    /// Vote phase.
    pub phase: FinalityVotePhase,
}

impl FinalityVoteData {
    /// Whether `other` votes for the same value: the same chunk with the same
    /// payment selection.
    #[must_use]
    pub fn same_value(&self, other: &Self) -> bool {
        self.chunk_hash == other.chunk_hash && self.selection == other.selection
    }

    /// Canonical phase-specific signature bytes bound to the complete chain spec.
    #[must_use]
    pub fn signing_message(&self, domain: ConsensusDomain) -> Vec<u8> {
        let tag = match self.phase {
            FinalityVotePhase::Prevote => neutrin0_primitives::DOMAIN_PREVOTE,
            FinalityVotePhase::Precommit => neutrin0_primitives::DOMAIN_PRECOMMIT,
        };
        domain
            .at_chunk(self.chunk_id)
            .signing_message_borsh(tag, self)
    }
}

/// Aggregated finality vote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalityVote {
    /// Validators whose signatures are included.
    pub aggregation_bits: BitVec,
    /// Signed vote payload.
    pub data: FinalityVoteData,
    /// Aggregate BLS signature.
    pub signature: BlsSignature,
    /// Mandatory individual signer attestations for both phases. Prevotes sign
    /// unlock declarations; precommits additionally bind exact proof bytes.
    pub attestations: Vec<VoteAttestation>,
    /// Sorted, unique exact proof lists required by these precommit signers.
    pub proof_manifests: Vec<ProofManifest>,
}

/// Explicit, independently signed statement accompanying a finality vote.
///
/// The signature covers the vote and its individual signature, ordered hashes of `BlockProof`
/// envelopes through a counted Merkle commitment, and the exact optional unlock certificate. Removing a certificate
/// or substituting proof bytes therefore invalidates the signature. Prevotes
/// carry no proof acceptance and explicitly sign their unlock declaration.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct VoteAttestation {
    /// Individual vote signature, retained for evidence after aggregation.
    pub vote_signature: BlsSignature,
    /// Index in the authenticated validator set for this chunk.
    pub validator_index: ValidatorIndex,
    /// Exact vote covered by this attestation.
    pub vote: FinalityVoteData,
    /// Counted commitment to exact proof bytes in canonical height order;
    /// present only on precommits. Full lists travel once per distinct commitment.
    pub proof_acceptance: Option<ProofAcceptanceCommitment>,
    /// The signer's claimed unlock justification, including an explicit `None`.
    /// Its exact content hash is signed; shared envelope dictionaries retain
    /// the full carrier for verification and objective evidence.
    pub unlock_quorum: Option<QuorumCertificate>,
    /// Signature binding `DOMAIN_VOTE_ATTESTATION`, chain ID and complete chain-spec hash.
    pub signature: BlsSignature,
}

impl VoteAttestation {
    /// Canonical bytes signed by the validator (excluding the signature itself).
    #[must_use]
    pub fn signing_message(&self, domain: ConsensusDomain) -> Vec<u8> {
        domain.at_chunk(self.vote.chunk_id).signing_message_borsh(
            neutrin0_primitives::DOMAIN_VOTE_ATTESTATION,
            &(
                self.validator_index,
                &self.vote,
                &self.vote_signature,
                &self.proof_acceptance,
                self.unlock_quorum
                    .as_ref()
                    .map(QuorumCertificate::commitment),
            ),
        )
    }
}

/// Check exact signer coverage and the phase's proof-list requirements.
/// Cryptographic verification and expected validator bitmap length are caller duties.
#[must_use]
pub fn attestation_coverage_valid(
    vote: &FinalityVoteData,
    bits: &BitVec,
    claims: &[VoteAttestation],
    block_count: u64,
) -> bool {
    if block_count == 0 || claims.is_empty() {
        return false;
    }
    let mut seen = alloc::collections::BTreeSet::new();
    for claim in claims {
        if claim.vote != *vote
            || bits.get(claim.validator_index) != Some(true)
            || !seen.insert(claim.validator_index)
            || match vote.phase {
                FinalityVotePhase::Prevote => claim.proof_acceptance.is_some(),
                FinalityVotePhase::Precommit => claim.proof_acceptance.is_none_or(|acceptance| {
                    acceptance.count != block_count
                        || acceptance.count > neutrin0_primitives::MAX_CONSENSUS_COMMITTEE_BLOCKS
                }),
            }
        {
            return false;
        }
    }
    (0..bits.bit_len())
        .filter(|index| bits.get(*index) == Some(true))
        .count()
        == seen.len()
}

impl VoteAttestation {
    /// Recover the independently signed vote for objective evidence.
    #[must_use]
    pub fn indexed_vote(&self) -> IndexedVote {
        IndexedVote {
            data: self.vote.clone(),
            signature: self.vote_signature,
        }
    }
}

impl FinalityCert {
    /// Exact vote payload this certificate's `phase` signs.
    #[must_use]
    pub fn vote_data(&self, phase: FinalityVotePhase) -> FinalityVoteData {
        FinalityVoteData {
            chunk_id: self.chunk_id,
            round: self.round,
            chunk_hash: self.chunk_hash,
            selection: self.proposal.selection(),
            phase,
        }
    }

    /// Recover the accountable envelope of `phase`, including every individual
    /// signature and signed unlock claim.
    #[must_use]
    pub fn vote(&self, phase: FinalityVotePhase) -> FinalityVote {
        let (aggregate, attestations) = match phase {
            FinalityVotePhase::Prevote => (&self.prevote, &self.prevote_attestations),
            FinalityVotePhase::Precommit => (&self.precommit, &self.precommit_attestations),
        };
        FinalityVote {
            data: self.vote_data(phase),
            aggregation_bits: aggregate.aggregation_bits.clone(),
            signature: aggregate.signature,
            attestations: attestations.clone(),
            proof_manifests: if phase == FinalityVotePhase::Precommit {
                self.proof_manifests.clone()
            } else {
                Vec::new()
            },
        }
    }

    /// Recover the accountable prevote envelope, including signed unlock claims.
    #[must_use]
    pub fn prevote_vote(&self) -> FinalityVote {
        self.vote(FinalityVotePhase::Prevote)
    }

    /// Recover the accountable precommit envelope without losing individual signatures.
    #[must_use]
    pub fn precommit_vote(&self) -> FinalityVote {
        self.vote(FinalityVotePhase::Precommit)
    }

    /// Compact precommit quorum for participation in this finalized target.
    /// It never authorizes finalization or unlocks a validator's voting lock.
    #[must_use]
    pub fn participation_certificate(&self) -> QuorumCertificate {
        QuorumCertificate {
            data: self.vote_data(FinalityVotePhase::Precommit),
            aggregate: self.precommit.clone(),
        }
    }

    /// The certificate as the consuming chunk carries it: the precommit
    /// quorum and the compact leader proposal (design 08).
    #[must_use]
    pub fn carried_certificate(&self) -> proving::CarriedCertificate {
        proving::CarriedCertificate {
            quorum: self.participation_certificate(),
            proposal: self.proposal.compact(),
        }
    }
}

/// Aggregated vote signature and signer bitmap.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct AggregatedVote {
    /// Validators whose signatures are included.
    pub aggregation_bits: BitVec,
    /// Aggregate BLS signature.
    pub signature: BlsSignature,
}

/// Quorum certificate for one finality vote payload.
#[derive(BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct QuorumCertificate {
    /// Signed vote payload.
    pub data: FinalityVoteData,
    /// Aggregate signature and signer bitmap.
    pub aggregate: AggregatedVote,
}

impl QuorumCertificate {
    /// Bind the exact vote, aggregate signature and signer bitmap independently
    /// of a containing envelope's dictionary positions.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        hashing::borsh_commitment(b"NEU_BFT_QC_REF__", self)
    }
}

impl BorshDeserialize for QuorumCertificate {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        bft::read_quorum(reader)
    }
}

/// Finality certificate proving prevote and precommit quorum for one chunk.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FinalityCert {
    /// Exact authenticated round-leader proposal selected by both vote phases.
    pub proposal: BftProposal,
    /// Complete per-signer prevote accountability statements.
    pub prevote_attestations: Vec<VoteAttestation>,
    /// Complete per-signer precommit accountability statements.
    pub precommit_attestations: Vec<VoteAttestation>,
    /// Canonical shared dictionary required by every precommit attestation.
    pub proof_manifests: Vec<ProofManifest>,
    /// Finalized chunk identifier.
    pub chunk_id: ChunkId,
    /// BFT round that finalized the chunk.
    pub round: u32,
    /// Finalized chunk hash.
    pub chunk_hash: ChunkHash,
    /// Aggregated prevote signature meeting quorum.
    pub prevote: AggregatedVote,
    /// Aggregated precommit signature meeting quorum.
    pub precommit: AggregatedVote,
    /// Active validator-set root used for quorum weighting.
    pub active_validator_set_root: Hash,
}

impl BorshSerialize for FinalityVote {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        quorum_dictionary::write_value(self, writer)
    }
}

impl BorshSerialize for FinalityCert {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        quorum_dictionary::write_certificate(self, writer)
    }
}

impl BorshDeserialize for FinalityVote {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        bft::read_value(reader)
    }
}

impl BorshDeserialize for FinalityCert {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        quorum_dictionary::read_certificate(reader)
    }
}

/// A finality vote with signer identity carried separately.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct IndexedVote {
    /// Signed vote payload.
    pub data: FinalityVoteData,
    /// Individual validator BLS signature.
    pub signature: BlsSignature,
}
