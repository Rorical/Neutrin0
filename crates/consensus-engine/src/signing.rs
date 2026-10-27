//! Durable local signing reservations and monotonic anti-equivocation watermarks.
//!
//! A reservation is synchronized before accessing the secret key. Repeating the
//! exact reservation is safe because BLS signatures are deterministic. Conflicting
//! messages, earlier rounds and already-finalized chunks are rejected. Entries use
//! the public key rather than its mutable validator-set position as identity.
//! Every signature also binds the complete chain-spec hash in its 56-byte
//! consensus prefix; raw proposal/report reservations accept only that exact
//! current domain during recovery.

use alloc::boxed::Box;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;
use neutrin0_consensus_types::{
    BftProposal, FinalityVoteData, FinalityVotePhase, NilVoteData, ProofAcceptanceCommitment,
    QuorumCertificate, RoundChange,
};
use neutrin0_primitives::{BitVec, BlsPublicKey, DomainTag, Hash, Slot};
use neutrin0_storage::{Batch, Column, ColumnSnapshot};

use crate::{EngineError, StoreError};

extern crate alloc;

mod headers;
mod manifests;
mod messages;
mod nil_votes;
mod ownership;
mod votes;
mod watermark;

pub(crate) use ownership::{Ownership, Seen};

// Journal key tags. Every tag except the proposer watermark is followed by the
// BLS identity and the big-endian chunk id, then any round/phase suffix.
/// Per-identity, per-chunk value-vote watermark.
const VOTE_WATERMARK_TAG: u8 = 0;
/// Per-identity proposer slot watermark; never expires with finality.
const PROPOSER_WATERMARK_TAG: u8 = 1;
/// Exact value-vote intent at one round and phase.
const VOTE_INTENT_TAG: u8 = 2;
/// Exact nil-vote intent at one round and phase.
const NIL_INTENT_TAG: u8 = 3;
/// Exact leader-proposal signing message at one round.
const PROPOSAL_MESSAGE_TAG: u8 = 4;
/// Exact round-change report signing message at one round.
const ROUND_CHANGE_MESSAGE_TAG: u8 = 5;
/// A message kind's watermark tag follows its message tag by this distance.
const MESSAGE_WATERMARK_OFFSET: u8 = 2;
/// Exact full proof list, stored once per identity/chunk/commitment.
const PROOF_MANIFEST_TAG: u8 = 8;
/// Highest chunk-scoped journal tag.
const LAST_CHUNK_TAG: u8 = PROOF_MANIFEST_TAG;
/// Tag byte plus BLS identity; a chunk-scoped key's chunk id starts here.
const IDENTITY_KEY_LEN: usize = 1 + size_of::<BlsPublicKey>();
/// Tag, identity and big-endian chunk id.
const CHUNK_KEY_LEN: usize = IDENTITY_KEY_LEN + size_of::<u64>();

/// Offset of the little-endian chain id in a consensus signing message,
/// after its domain tag.
const CHAIN_ID_OFFSET: usize = size_of::<DomainTag>();
/// Offset of the chain-spec hash in a consensus signing message.
const SPEC_HASH_OFFSET: usize = CHAIN_ID_OFFSET + size_of::<u64>();
/// Length of the `tag || chain_id LE8 || chain_spec_hash` signing prefix.
const DOMAIN_PREFIX_LEN: usize = SPEC_HASH_OFFSET + size_of::<Hash>();

/// A requested signature would violate local signing safety.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningViolation {
    /// Local operator policy or shutdown forbids signatures.
    Paused,
    /// Another message was reserved at this signing position.
    Conflict,
    /// A newer round or proposer slot was already reserved.
    Regression,
    /// Finalized history must never be signed again.
    FinalizedChunk,
    /// The signing key does not match its authenticated validator-set position.
    KeyNotActive,
    /// The chunk precedes this specification's hard fork and belongs to a
    /// predecessor's signing domain.
    PriorDomain,
    /// The chunk lies at or beyond the count of the hard fork that ends this
    /// chain.
    Halted,
    /// The doppelganger quiet period after startup has not passed.
    Quiet,
}

impl fmt::Display for SigningViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Paused => "local consensus signing is paused",
            Self::Conflict => "conflicting local signing reservation",
            Self::Regression => "local signing position regressed",
            Self::FinalizedChunk => "refusing to sign finalized history",
            Self::KeyNotActive => "local signing key is not an active validator",
            Self::PriorDomain => "refusing to sign a chunk of a predecessor specification",
            Self::Halted => "refusing to sign at or beyond the hard fork that ends this chain",
            Self::Quiet => "refusing to sign during the doppelganger quiet period",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
struct VoteIntent {
    data: FinalityVoteData,
    validator_index: u32,
    proof_acceptance: Option<ProofAcceptanceCommitment>,
    unlock_quorum: Option<QuorumCertificate>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct VoteWatermark {
    spec: Hash,
    identity: BlsPublicKey,
    chunk_id: u64,
    round: u32,
    prevote: Option<VoteIntent>,
    precommit: Option<VoteIntent>,
    locked: Option<QuorumCertificate>,
}

impl VoteWatermark {
    /// Move to `round`, clearing superseded phase intents; earlier rounds are refused.
    /// The retained lock is unaffected.
    fn advance(&mut self, round: u32) -> Result<(), SigningViolation> {
        if round < self.round {
            return Err(SigningViolation::Regression);
        }
        if round > self.round {
            self.round = round;
            self.prevote = None;
            self.precommit = None;
        }
        Ok(())
    }
}

/// The proposer slot watermarks of `journal`, signed under the
/// specification `from`, rebound to its hard-fork successor `to`. Slots run
/// on across a fork, so a validator never proposes again at a slot it used.
/// Every other entry is a vote or message at a chunk the successor signs only
/// under its own domain, or never, so none carries over.
///
/// # Errors
/// Refuses a watermark of another specification or one that does not decode.
pub(crate) fn successor_journal(
    journal: &[(Vec<u8>, Vec<u8>)],
    from: Hash,
    to: Hash,
) -> Result<ColumnSnapshot, String> {
    let mut carried = Vec::new();
    for (key, value) in journal {
        if key.first() != Some(&PROPOSER_WATERMARK_TAG) {
            continue;
        }
        let mut watermark: ProposalWatermark =
            borsh::from_slice(value).map_err(|error| alloc::format!("{error}"))?;
        if watermark.spec != from {
            return Err("signing journal belongs to another specification".into());
        }
        watermark.spec = to;
        carried.push((
            key.clone(),
            borsh::to_vec(&watermark).map_err(|error| alloc::format!("{error}"))?,
        ));
    }
    Ok(carried)
}

#[derive(BorshSerialize, BorshDeserialize)]
struct ProposalWatermark {
    spec: Hash,
    identity: BlsPublicKey,
    slot: Slot,
    hash: Hash,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct NilIntent {
    spec: Hash,
    identity: BlsPublicKey,
    data: NilVoteData,
    validator_index: u32,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct MessageIntent {
    spec: Hash,
    identity: BlsPublicKey,
    message: Vec<u8>,
    carrier: MessageCarrier,
}

/// Retain exact unsigned source material before signing its compact commitment.
/// Recovery never substitutes a newly discovered certificate for this carrier.
#[derive(BorshSerialize, BorshDeserialize)]
enum MessageCarrier {
    Proposal(Box<BftProposal>),
    RoundChange(Box<RoundChange>),
}

#[derive(BorshSerialize, BorshDeserialize)]
struct MessageWatermark {
    spec: Hash,
    identity: BlsPublicKey,
    chunk_id: u64,
    round: u32,
}

fn nil_key(identity: &BlsPublicKey, data: &NilVoteData) -> Vec<u8> {
    let mut key = vote_key(identity, data.chunk_id);
    key[0] = NIL_INTENT_TAG;
    key.extend_from_slice(&data.round.to_be_bytes());
    key.push(u8::from(data.phase == FinalityVotePhase::Precommit));
    key
}

fn round_message_key(tag: u8, identity: &BlsPublicKey, chunk_id: u64, round: u32) -> Vec<u8> {
    let mut key = vote_key(identity, chunk_id);
    key[0] = tag;
    key.extend_from_slice(&round.to_be_bytes());
    key
}

fn message_watermark_key(tag: u8, identity: &BlsPublicKey, chunk_id: u64) -> Vec<u8> {
    let mut key = vote_key(identity, chunk_id);
    key[0] = tag + MESSAGE_WATERMARK_OFFSET;
    key
}

/// Durable position used to identify an interrupted local signing operation.
pub(crate) struct SigningProgress {
    /// Highest round reserved for this chunk and identity.
    pub round: u32,
    /// A prevote intent is present at the highest round.
    pub prevoted: bool,
    /// A complete precommit attestation intent is present at that round.
    pub precommitted: bool,
    /// Lock retained from the original precommit establishing it.
    pub locked: Option<QuorumCertificate>,
    /// Value intents reserved at `round`, prevote first.
    intents: [Option<VoteIntent>; 2],
}

fn vote_key(identity: &BlsPublicKey, chunk_id: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(CHUNK_KEY_LEN);
    key.push(VOTE_WATERMARK_TAG);
    key.extend_from_slice(identity);
    key.extend_from_slice(&chunk_id.to_be_bytes());
    key
}

fn manifest_key(
    identity: &BlsPublicKey,
    chunk_id: u64,
    acceptance: &ProofAcceptanceCommitment,
) -> Vec<u8> {
    let mut key = vote_key(identity, chunk_id);
    key[0] = PROOF_MANIFEST_TAG;
    key.extend_from_slice(&acceptance.count.to_be_bytes());
    key.extend_from_slice(&acceptance.root);
    key
}

fn proposal_key(identity: &BlsPublicKey) -> Vec<u8> {
    let mut key = Vec::with_capacity(IDENTITY_KEY_LEN);
    key.push(PROPOSER_WATERMARK_TAG);
    key.extend_from_slice(identity);
    key
}

fn intent_key(identity: &BlsPublicKey, data: &FinalityVoteData) -> Vec<u8> {
    let mut key = vote_key(identity, data.chunk_id);
    key[0] = VOTE_INTENT_TAG;
    key.extend_from_slice(&data.round.to_be_bytes());
    key.push(u8::from(data.phase == FinalityVotePhase::Precommit));
    key
}

/// Remove only positions rendered unsignable by the same atomic watermark
/// update. The retained lock's original precommit intent remains recoverable.
fn compact_round_intents(
    batch: &mut Batch,
    identity: &BlsPublicKey,
    chunk_id: u64,
    old_round: u32,
    new_round: u32,
    lock: Option<&QuorumCertificate>,
) {
    if new_round <= old_round {
        return;
    }
    for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
        let data = FinalityVoteData {
            chunk_id,
            round: old_round,
            phase,
            chunk_hash: [0; 32],
            selection: [0; 32],
        };
        if phase != FinalityVotePhase::Precommit
            || lock.is_none_or(|lock| lock.data.round != old_round)
        {
            batch.delete(Column::SigningJournal, intent_key(identity, &data));
        }
        batch.delete(
            Column::SigningJournal,
            nil_key(
                identity,
                &NilVoteData {
                    chunk_id,
                    round: old_round,
                    phase,
                },
            ),
        );
    }
    batch.delete(
        Column::SigningJournal,
        round_message_key(PROPOSAL_MESSAGE_TAG, identity, chunk_id, old_round),
    );
    batch.delete(
        Column::SigningJournal,
        round_message_key(ROUND_CHANGE_MESSAGE_TAG, identity, chunk_id, old_round),
    );
    if let Some(reported) = old_round.checked_add(1).filter(|round| *round < new_round) {
        batch.delete(
            Column::SigningJournal,
            round_message_key(ROUND_CHANGE_MESSAGE_TAG, identity, chunk_id, reported),
        );
    }
}

/// Aggregation bits naming exactly `signer` within an active set of `len`.
fn single_signer_bits(len: usize, signer: u32) -> BitVec {
    let signer = usize::try_from(signer).expect("u32 fits usize");
    let mut bits = BitVec::default();
    for index in 0..len {
        bits.push(index == signer);
    }
    bits
}

impl<E> From<borsh::io::Error> for EngineError<E> {
    fn from(error: borsh::io::Error) -> Self {
        Self::Store(StoreError::Codec(error))
    }
}

#[cfg(test)]
mod tests;
