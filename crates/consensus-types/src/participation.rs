//! Certified precommit participation handed from consensus to the runtime.
//!
//! One block of each chunk after chunk 0, the carrier, selects a valid
//! previous-chunk certificate in its header-committed participation lane. The
//! carrier and the blocks after it on that branch consume the resulting report. The Chunk Guest authenticates the source membership and
//! certificate, and commits the consumed report into the outgoing boundary.
//! Alternative certificates used to finalize the current chunk cannot change
//! that boundary. The runtime receives only the report, never certificates.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{BitVec, DOMAIN_PARTICIPATION, Hash, Validator};

/// Economic participation proof using an individual bare precommit signature.
///
/// Source membership, target and timing come from authenticated historical data;
/// complete proof-acceptance attestations remain separate safety sources.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ParticipationVote {
    /// Exact chain-domain precommit payload signed by the validator.
    pub data: crate::FinalityVoteData,
    /// Position in the authenticated historical source committee.
    pub validator_index: u32,
    /// Individual signature of `data`, never an aggregate shortcut.
    pub vote_signature: neutrin0_primitives::BlsSignature,
}

impl ParticipationVote {
    /// The source seat this vote acknowledges: its source chunk and signer
    /// index. Each seat appears at most once across one chunk's vote lanes; a
    /// precommit of the same seat in another round or with another selection
    /// adds no acknowledgement, only signature work.
    #[must_use]
    pub const fn source_seat(&self) -> (u64, u32) {
        (self.data.chunk_id, self.validator_index)
    }

    /// Extract a bare precommit without changing the separately retained source.
    #[must_use]
    pub fn from_attestation(claim: &crate::VoteAttestation) -> Option<Self> {
        (claim.vote.phase == crate::FinalityVotePhase::Precommit).then(|| Self {
            data: claim.vote.clone(),
            validator_index: claim.validator_index,
            vote_signature: claim.vote_signature,
        })
    }
}

/// Decode a bounded compact acknowledgement lane before allocating its items.
///
/// # Errors
/// Rejects excessive counts, non-precommit payloads and malformed wire inputs.
pub fn read_participation_votes<R: borsh::io::Read>(
    reader: &mut R,
) -> borsh::io::Result<Vec<ParticipationVote>> {
    let count = u32::deserialize_reader(reader)?;
    if count as usize > MAX_PARTICIPATION_ACKS {
        return Err(borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "participation acknowledgements exceed lane bound",
        ));
    }
    let mut votes = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let vote = ParticipationVote::deserialize_reader(reader)?;
        if vote.data.phase != crate::FinalityVotePhase::Precommit {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "participation acknowledgement is not a precommit",
            ));
        }
        votes.push(vote);
    }
    Ok(votes)
}

/// Count of entries in the participation-acknowledgement DA lane.
///
/// # Panics
/// Panics only when the in-memory vector exceeds the Borsh wire count range.
#[must_use]
pub fn vote_lane_count(acks: &[ParticipationVote]) -> u32 {
    u32::try_from(acks.len()).expect("Borsh vote lane count")
}

/// Merkle root of the compact acknowledgements in lane order.
#[must_use]
pub fn vote_lane_root(acks: &[ParticipationVote]) -> Hash {
    neutrin0_primitives::merkle_root_from_hashes(
        acks.iter().map(crate::evidence::commitment).collect(),
    )
}

/// Encoded bytes of the acknowledgement lane, including its count.
///
/// # Errors
/// Returns an encoding/count error rather than accepting an unmeasured lane.
pub fn vote_lane_bytes(acks: &[ParticipationVote]) -> borsh::io::Result<usize> {
    borsh::object_length(acks)
}

/// Commitment of "no certified chunk yet": the boundary value at genesis and
/// the runtime's commitment when it receives no report.
pub const NO_PARTICIPATION: Hash = [0; 32];

/// Complete following chunks reserved for publishing omitted precommit signatures.
pub const PARTICIPATION_CHALLENGE_CHUNKS: u64 = 2;
/// At most two bounded committees can supply acknowledgements in one block.
pub const MAX_PARTICIPATION_ACKS: usize = 512;
/// Encoded historical vote lane budget, including positive acknowledgements.
pub const MAX_PARTICIPATION_VOTE_BYTES: usize = 2 * 1024 * 1024;

/// Bound signature and historical-source work independently of user gas.
#[must_use]
pub fn vote_lane_is_bounded(acks: &[ParticipationVote]) -> bool {
    acks.len() <= MAX_PARTICIPATION_ACKS
        && vote_lane_bytes(acks).is_ok_and(|bytes| bytes <= MAX_PARTICIPATION_VOTE_BYTES)
}

/// Positive participation derived from an authenticated historical precommit.
/// The containing Chunk Guest verifies its signed source in the existing vote lane.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, BorshSerialize, BorshDeserialize)]
pub struct ParticipationAcknowledgement {
    /// Finalized source chunk.
    pub chunk_id: u64,
    /// Historical BLS identity, independent of its current runtime account.
    pub identity: neutrin0_primitives::BlsPublicKey,
    /// Withdrawal account authenticated in the source committee.
    pub address: Hash,
}

/// Commit the canonical sorted positive participation records.
#[must_use]
pub fn acknowledgement_commitment(acks: &[ParticipationAcknowledgement]) -> Hash {
    if acks.is_empty() {
        return [0; 32];
    }
    crate::hashing::borsh_commitment(b"NTRO/participation-acks", acks)
}

/// Derive one record from an individually signature-verified historical precommit.
/// Claims for another target, inactive member or outside the grace window fail.
#[must_use]
pub fn acknowledgement_from_participation_vote(
    incoming_chunk: u64,
    canonical_chunk_hash: Hash,
    validators: &[Validator],
    vote: &ParticipationVote,
) -> Option<ParticipationAcknowledgement> {
    if vote.data.phase != crate::FinalityVotePhase::Precommit
        || vote.data.chunk_hash != canonical_chunk_hash
        || vote
            .data
            .chunk_id
            .checked_add(PARTICIPATION_CHALLENGE_CHUNKS)
            .is_none_or(|deadline| incoming_chunk > deadline)
        || vote.data.chunk_id >= incoming_chunk
    {
        return None;
    }
    let validator = validators.get(usize::try_from(vote.validator_index).ok()?)?;
    (validator.effective_stake > 0).then_some(ParticipationAcknowledgement {
        chunk_id: vote.data.chunk_id,
        identity: validator.pubkey,
        address: validator.withdrawal_credentials,
    })
}

/// Signers of the previous-chunk precommit selected in consensus data, by address.
///
/// `present` lists every signer of the certificate; `absent` lists the
/// validators that were active and unslashed but were not in the selected subset.
/// Non-inclusion does not establish that no vote was published.
/// Inactive seats are in neither list.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ParticipationReport {
    /// Finalized chunk the certificate covers.
    pub chunk_id: u64,
    /// Withdrawal credentials of the signers, in validator-set order.
    pub present: Vec<Hash>,
    /// Withdrawal credentials of the active non-signers, in validator-set order.
    pub absent: Vec<Hash>,
    /// Historical identities of the omitted signers, aligned with `absent`.
    pub absent_identities: Vec<neutrin0_primitives::BlsPublicKey>,
}

impl ParticipationReport {
    /// Resolve a precommit signer bitmap against the chunk's active set.
    ///
    /// Returns `None` when the bitmap does not cover the set exactly.
    #[must_use]
    pub fn from_certificate(
        chunk_id: u64,
        validators: &[Validator],
        precommit: &BitVec,
    ) -> Option<Self> {
        if usize::try_from(precommit.bit_len()).ok()? != validators.len() {
            return None;
        }
        let mut present = Vec::new();
        let mut absent = Vec::new();
        let mut absent_identities = Vec::new();
        for (index, validator) in validators.iter().enumerate() {
            let signed = precommit.get(u32::try_from(index).ok()?)?;
            if signed {
                present.push(validator.withdrawal_credentials);
            } else if validator.effective_stake > 0 {
                absent.push(validator.withdrawal_credentials);
                absent_identities.push(validator.pubkey);
            }
        }
        Some(Self {
            chunk_id,
            present,
            absent,
            absent_identities,
        })
    }

    /// Domain-separated commitment of the exact report.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        crate::tagged_commitment(&DOMAIN_PARTICIPATION, self)
    }
}

/// Commitment of an optional report; `None` commits [`NO_PARTICIPATION`].
#[must_use]
pub fn participation_commitment(report: Option<&ParticipationReport>) -> Hash {
    report.map_or(NO_PARTICIPATION, ParticipationReport::commitment)
}

#[cfg(test)]
mod compact_ack_tests;
