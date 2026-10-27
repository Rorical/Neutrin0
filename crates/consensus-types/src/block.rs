//! Engine-canonical block header, block and body.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{BlockHash, BlsSignature, Hash, Height, Slot, StateRoot, ValidatorIndex};

use crate::program_lane::{MAX_PROGRAM_PIECES_PER_BLOCK, ProgramPiece};
use crate::{evidence, participation, proving, runtime};

/// Engine-canonical block header.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct Header {
    /// Monotonic block height.
    pub height: Height,
    /// Slot at which the block was produced.
    pub slot: Slot,
    /// Parent header hash.
    pub parent_hash: BlockHash,
    /// Proposer index in the active validator set.
    pub proposer_index: ValidatorIndex,
    /// Proposer BLS-VRF proof.
    pub vrf_proof: BlsSignature,
    /// Post-execution state root.
    pub state_root: StateRoot,
    /// Transactions root.
    pub transactions_root: [u8; 32],
    /// Merkle root of the block's compact participation acknowledgements.
    pub votes_root: [u8; 32],
    /// Data-availability commitment root.
    pub da_root: [u8; 32],
    /// Runtime-defined commitment.
    pub runtime_extra: [u8; 32],
    /// Commitment of the execution inputs the block consumed: its context,
    /// participation, acknowledgements, proving report and evidence anchor
    /// (design 08). Every receipt's output must reproduce it.
    pub inputs_root: [u8; 32],
    /// Runtime-emitted per-block receipts commitment. The runtime
    /// computes this over its runtime-defined transaction receipts; the
    /// SP1 proof's `BlockProofPublicInputs.receipt_root` must match
    /// this field exactly.
    pub receipts_root: [u8; 32],
    /// Gas consumed by the block.
    pub gas_used: u64,
    /// Block gas limit.
    pub gas_limit: u64,
    /// Slot timestamp in seconds since UNIX epoch.
    pub timestamp: u64,
    /// Proposer BLS signature.
    pub signature: BlsSignature,
}

impl Header {
    /// Computes the canonical block-header hash.
    ///
    /// The proposer signature is excluded, matching design 05's
    /// `BLAKE3(DOMAIN_HEADER || borsh(header_without_signature))` rule. This hash is also the
    /// payload signed by the proposer under `DOMAIN_PROPOSER_SIG`.
    pub fn hash(&self) -> BlockHash {
        crate::hashing::borsh_commitment(
            &neutrin0_primitives::DOMAIN_HEADER,
            &HeaderHashPayload::from(self),
        )
    }
}

#[derive(BorshSerialize)]
struct HeaderHashPayload {
    height: Height,
    slot: Slot,
    parent_hash: BlockHash,
    proposer_index: ValidatorIndex,
    vrf_proof: BlsSignature,
    state_root: StateRoot,
    transactions_root: Hash,
    votes_root: Hash,
    da_root: Hash,
    runtime_extra: Hash,
    inputs_root: Hash,
    receipts_root: Hash,
    gas_used: u64,
    gas_limit: u64,
    timestamp: u64,
}

impl From<&Header> for HeaderHashPayload {
    fn from(header: &Header) -> Self {
        Self {
            height: header.height,
            slot: header.slot,
            parent_hash: header.parent_hash,
            proposer_index: header.proposer_index,
            vrf_proof: header.vrf_proof,
            state_root: header.state_root,
            transactions_root: header.transactions_root,
            votes_root: header.votes_root,
            da_root: header.da_root,
            runtime_extra: header.runtime_extra,
            inputs_root: header.inputs_root,
            receipts_root: header.receipts_root,
            gas_used: header.gas_used,
            gas_limit: header.gas_limit,
            timestamp: header.timestamp,
        }
    }
}

/// Engine-canonical block.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct Block {
    /// Signed header authenticated by `Header::hash`.
    pub header: Header,
    /// Runtime-interpretable body committed by the header roots.
    pub body: Body,
}

impl Block {
    /// Computes the canonical block hash, equal to the header hash.
    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }
}

/// Canonical transaction and embedded finality-vote body.
/// Validator operations and proven evidence admissions are runtime transactions.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct Body {
    /// Opaque execution data authenticated by the header's receipt commitment.
    /// Transported and persisted atomically with this block.
    pub artifacts: runtime::ExecutionArtifacts,
    /// Runtime-defined transaction blobs.
    pub transactions: Vec<Vec<u8>>,
    /// Compact positive participation signatures in the vote DA lane.
    #[borsh(deserialize_with = "participation::read_participation_votes")]
    pub participation_acks: Vec<participation::ParticipationVote>,
    /// Previous-chunk certificate, present only in the chunk's carrier: the
    /// first block its proposer produced while holding the certificate, with
    /// the precommit quorum and the compact leader proposal (design 08). Its
    /// exact bytes form a header-committed DA lane. Later blocks inherit the
    /// selected reports along their ancestry and carry no certificate.
    pub participation: Option<proving::CarriedCertificate>,
    /// Ordered EvidenceProof attachments, one per evidence admission. These
    /// witnesses are transported and archived with the body, outside header
    /// transaction/vote/DA commitments; alternate valid proofs are interchangeable.
    pub evidence_proofs: Vec<evidence::EvidenceArtifact>,
    /// Program-artifact pieces of the data-availability lane (design 20):
    /// upgrade runtime and Guest bytes travelling with ordinary block sync,
    /// committed by the header's DA root, never read by the STF.
    pub programs: Vec<ProgramPiece>,
}

impl Body {
    /// Compare the header-committed lanes independently of proof attachments.
    #[must_use]
    pub fn same_consensus_content(&self, other: &Self) -> bool {
        self.transactions == other.transactions
            && self.participation_acks == other.participation_acks
            && self.participation == other.participation
            && self.programs == other.programs
            && self.artifacts == other.artifacts
    }

    /// `true` when the program lane respects every bound and every piece
    /// authenticates against its artifact.
    #[must_use]
    pub fn programs_well_formed(&self) -> bool {
        self.programs.len() <= MAX_PROGRAM_PIECES_PER_BLOCK
            && self.programs.iter().all(ProgramPiece::authenticates)
    }
}
