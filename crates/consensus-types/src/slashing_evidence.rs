//! Objective slashing evidence carried in block bodies.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{BlsSignature, Hash, ValidatorIndex};

use crate::{
    BftProposal, BlockProof, Header, IndexedNilVote, IndexedVote, ProofAcceptanceOpening,
    QuorumCertificate, VoteAttestation,
};

/// Reason a proof artifact was rejected by a verifier.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProofRejectionReason {
    /// Proof bytes were malformed for the selected backend.
    MalformedProof,
    /// Proof public inputs did not match the canonical block or chunk data.
    PublicInputsMismatch,
    /// Backend verifier rejected the proof.
    VerifierRejected,
}

/// Evidence for a Tendermint lock violation.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct LockEvidence {
    /// Earlier prevote quorum that locked the validator.
    pub locked_prevote_quorum: QuorumCertificate,
    /// The later prevote or precommit signer's authenticated unlock claim.
    /// Absence of a locally observed certificate is never evidence of absence.
    pub attestation: VoteAttestation,
}

/// Evidence that a published DA bundle does not match its committed root.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct DaFraudProof {
    /// Proposer signature authenticating publication of these exact bytes.
    /// Header commitment alone cannot attribute an arbitrary bad peer bundle.
    pub publication_signature: BlsSignature,
    /// DA root committed by the signed header.
    pub expected_da_root: Hash,
    /// DA root recomputed from the offending bundle.
    pub computed_da_root: Hash,
    /// Hash of the published bundle.
    pub bundle_hash: Hash,
    /// Offending DA bundle bytes.
    pub offending_bundle: Vec<u8>,
}

/// Objective slashing evidence carried in a block body.
#[allow(clippy::large_enum_variant)]
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub enum SlashingEvidence {
    /// A designated round leader signed distinct proposals for one chunk/round.
    DoubleBftProposal {
        /// Authenticated round leader index.
        proposer_index: ValidatorIndex,
        /// First independently signed proposal.
        proposal_a: BftProposal,
        /// Conflicting independently signed proposal.
        proposal_b: BftProposal,
    },
    /// A value and an explicit nil vote signed for the same phase and round.
    ConflictingNilVote {
        /// Accountable signer in the authenticated source set.
        validator_index: ValidatorIndex,
        /// Independently signed value vote.
        value_vote: IndexedVote,
        /// Independently signed nil vote.
        nil_vote: IndexedNilVote,
    },
    /// Two distinct headers signed by the same proposer at the same slot.
    DoubleProposal {
        /// Offending proposer index.
        proposer_index: ValidatorIndex,
        /// First signed header.
        header_a: Header,
        /// Conflicting signed header.
        header_b: Header,
    },
    /// Two distinct prevotes for one validator, chunk, and round.
    DoublePrevote {
        /// Offending validator index.
        validator_index: ValidatorIndex,
        /// First prevote.
        vote_a: IndexedVote,
        /// Conflicting prevote.
        vote_b: IndexedVote,
    },
    /// Two distinct precommits for one validator, chunk, and round.
    DoublePrecommit {
        /// Offending validator index.
        validator_index: ValidatorIndex,
        /// First precommit.
        vote_a: IndexedVote,
        /// Conflicting precommit.
        vote_b: IndexedVote,
    },
    /// A validator violated an earlier Tendermint lock.
    LockViolation {
        /// Offending validator index.
        validator_index: ValidatorIndex,
        /// Vote that established the lock.
        vote_a: IndexedVote,
        /// Conflicting later vote.
        vote_b: IndexedVote,
        /// Lock and unlock evidence.
        lock_evidence: LockEvidence,
    },
    /// A validator explicitly accepted a specific proof envelope that fails
    /// the protocol verifier. A precommit alone is insufficient: the evidence
    /// must carry the offender's domain-separated attestation of the complete
    /// proof bytes and metadata. Verifiers independently establish rejection.
    InvalidProofSigning {
        /// Offending validator index.
        validator_index: ValidatorIndex,
        /// Per-validator precommit the offender signed. The vote's
        /// chunk_id must cover the height of `rejected_proof`.
        vote: IndexedVote,
        /// Explicit acceptance of this exact proof envelope by the offender.
        attestation: VoteAttestation,
        /// Exact block proof envelope bound by the attestation. Any
        /// verifier re-runs `proof_system.verify_block` on this and
        /// expects rejection.
        rejected_proof: BlockProof,
        /// Position-bound opening of the exact rejected envelope in the signed root.
        proof_opening: ProofAcceptanceOpening,
        /// Reason the emitting node's verifier rejected
        /// `rejected_proof`. Carried as a diagnostic; verifiers
        /// re-derive their own classification while re-verifying.
        reason: ProofRejectionReason,
    },
    /// A header claimed execution results that its block's correct execution
    /// does not produce (design 08). A valid receipt for the same block and
    /// declared inputs shows the claim false.
    InvalidExecutionClaim {
        /// Offending proposer index.
        proposer_index: ValidatorIndex,
        /// The offending signed header.
        header: Header,
        /// Its parent header, binding the claimed pre-state root. `None`
        /// exactly when the parent is the specification's first boundary
        /// (genesis or a hard fork's start), which has no header and binds
        /// the pre-state root itself.
        parent: Option<Header>,
        /// A valid receipt of the block whose result fields differ from the
        /// header's.
        receipt: BlockProof,
    },
    /// A proposer committed to DA bytes that do not match the signed root.
    DaCommitmentFraud {
        /// Offending proposer index.
        proposer_index: ValidatorIndex,
        /// Header with the fraudulent DA commitment.
        header: Header,
        /// Fraud proof over the offending bundle.
        fraud_proof: DaFraudProof,
    },
}

impl SlashingEvidence {
    /// Index of the validator this evidence accuses inside its source chunk's
    /// validator set. Structural only: the Evidence Guest authenticates the
    /// signatures, this merely names whose identity the claim is about.
    #[must_use]
    pub const fn offender_index(&self) -> ValidatorIndex {
        match self {
            Self::DoubleBftProposal { proposer_index, .. }
            | Self::DoubleProposal { proposer_index, .. }
            | Self::DaCommitmentFraud { proposer_index, .. }
            | Self::InvalidExecutionClaim { proposer_index, .. } => *proposer_index,
            Self::ConflictingNilVote {
                validator_index, ..
            }
            | Self::DoublePrevote {
                validator_index, ..
            }
            | Self::DoublePrecommit {
                validator_index, ..
            }
            | Self::LockViolation {
                validator_index, ..
            }
            | Self::InvalidProofSigning {
                validator_index, ..
            } => *validator_index,
        }
    }
}
