//! External effects of the BFT loop and its error type.

use core::fmt;

use neutrin0_consensus_chunk_bft::BftError;
use neutrin0_consensus_types::{
    BftProposal, FinalityVote, FinalityVotePhase, NilVote, RoundChange, RoundChangeCertificate,
};
use neutrin0_primitives::{BlockHash, ChunkHash, ChunkId, Hash};

use crate::error::EngineError;
use crate::store::StoreError;

/// Immutable identity used to fence asynchronous proof work against BFT changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BftQuorumIdentity {
    /// Sequential chunk identifier.
    pub chunk_id: ChunkId,
    /// Candidate commitment signed by this quorum.
    pub chunk_hash: ChunkHash,
    /// Round that produced the quorum.
    pub round: u32,
    /// Exact finality certificate commitment.
    pub certificate_hash: Hash,
}

impl BftQuorumIdentity {
    /// Identify an exact authenticated certificate snapshot.
    #[must_use]
    pub fn from_certificate(certificate: &neutrin0_consensus_types::FinalityCert) -> Self {
        Self {
            chunk_id: certificate.chunk_id,
            chunk_hash: certificate.chunk_hash,
            round: certificate.round,
            certificate_hash: neutrin0_consensus_types::evidence::commitment(certificate),
        }
    }
}

/// External effect the engine wants the caller to perform after a
/// BFT-loop ingest.
///
/// The caller is the node-level chain backend / sync driver. It owns
/// the network handle and is responsible for borsh-encoding the vote
/// and publishing on the matching gossip topic, or invoking
/// [`Engine::finalize_chunk`](crate::Engine::finalize_chunk) on the
/// quorum signal.
#[derive(Clone, Debug)]
pub enum BftAction {
    /// Publish the carried finality vote on
    /// `Topic::FinalityVotesPrevote`.
    BroadcastPrevote(FinalityVote),
    /// Publish the designated round leader's signed proven candidate.
    BroadcastProposal(Box<BftProposal>),
    /// Publish an explicit nil prevote or precommit.
    BroadcastNilVote(NilVote),
    /// Publish an individually signed report requesting a later round.
    BroadcastRoundChange(RoundChange),
    /// Publish authenticated quorum evidence for entering a later round.
    BroadcastRoundChangeCertificate(RoundChangeCertificate),
    /// Publish the carried finality vote on
    /// `Topic::FinalityVotesPrecommit`.
    BroadcastPrecommit(FinalityVote),
    /// The local validator was elected as an aggregator for this
    /// chunk and round and its locally-accumulated aggregate
    /// prevote has grown since the last publish. Caller should
    /// gossip on `Topic::AggregateFinalityVotes(subnet)`.
    PublishAggregatePrevote {
        /// Subnet topic suffix derived from the chunk id.
        subnet: u8,
        /// Union-aggregated vote covering every partial prevote
        /// recorded locally so far.
        vote: FinalityVote,
    },
    /// Same as [`BftAction::PublishAggregatePrevote`] for precommits.
    PublishAggregatePrecommit {
        /// Subnet topic suffix derived from the chunk id.
        subnet: u8,
        /// Union-aggregated vote covering every partial precommit
        /// recorded locally so far.
        vote: FinalityVote,
    },
    /// The 2/3 precommit quorum has been reached for this chunk.
    /// Caller should invoke
    /// [`Engine::finalize_chunk`](crate::Engine::finalize_chunk).
    QuorumReached(BftQuorumIdentity),
}

impl BftAction {
    /// Publication of one local value vote on its phase topic.
    pub(super) fn local_vote(vote: &FinalityVote) -> Self {
        match vote.data.phase {
            FinalityVotePhase::Prevote => Self::BroadcastPrevote(vote.clone()),
            FinalityVotePhase::Precommit => Self::BroadcastPrecommit(vote.clone()),
        }
    }
}

/// Failures while driving the live BFT loop.
#[derive(Debug)]
pub enum BftLoopError<E> {
    /// The underlying chunk-BFT accumulator rejected the vote.
    Bft(BftError),
    /// Engine storage / bookkeeping failure.
    Engine(EngineError<E>),
    /// `open_bft_session` was called twice for the same chunk id.
    SessionAlreadyOpen {
        /// Chunk id that already has a live session.
        chunk_id: ChunkId,
    },
    /// `observe_finality_vote` was called for a chunk that has no
    /// session and is not in scope to open one.
    NoSessionForChunk {
        /// Chunk id named by the orphan vote.
        chunk_id: ChunkId,
    },
    /// The active validator set has no positive unslashed stake.
    EmptyActiveSet,
    /// The proposed branch failed complete current-backend candidate validation.
    Candidate(crate::FinalizeError<E>),
    /// The proposal ratifies a chunk proof this node does not hold yet
    /// (design 08); the proposal is retried once the proof arrives.
    ChunkProofUnavailable {
        /// Chunk the proof finalizes.
        chunk_id: u64,
        /// Statement key of the named proof.
        statement_key: Hash,
    },
    /// The proposal names a receipt this node does not hold yet (design 08);
    /// the proposal is retried once the receipt arrives.
    ReceiptUnavailable {
        /// Block whose receipt is named.
        block_hash: BlockHash,
        /// Statement key of the named receipt.
        statement_key: Hash,
    },
}

impl<E: fmt::Debug + fmt::Display> fmt::Display for BftLoopError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bft(err) => write!(f, "chunk-BFT: {err}"),
            Self::Engine(err) => write!(f, "engine error: {err}"),
            Self::SessionAlreadyOpen { chunk_id } => {
                write!(f, "BFT session for chunk {chunk_id} already open")
            }
            Self::NoSessionForChunk { chunk_id } => {
                write!(f, "no BFT session for chunk {chunk_id}")
            }
            Self::EmptyActiveSet => {
                f.write_str("active validator set has no positive unslashed stake")
            }
            Self::Candidate(error) => write!(f, "invalid BFT candidate: {error}"),
            Self::ChunkProofUnavailable {
                chunk_id,
                statement_key,
            } => write!(
                f,
                "chunk proof {statement_key:?} of chunk {chunk_id} is not held locally"
            ),
            Self::ReceiptUnavailable {
                block_hash,
                statement_key,
            } => write!(
                f,
                "receipt {statement_key:?} of block {block_hash:?} is not held locally"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for BftLoopError<E> {}

impl<E> BftLoopError<E> {
    /// Whether the vote was refused only because it precedes the round's
    /// proposal; the caller holds it and retries once the proposal is accepted.
    #[must_use]
    pub const fn awaits_proposal(&self) -> bool {
        matches!(self, Self::Bft(BftError::PendingSelectionsFull))
    }
}

impl<E> From<BftError> for BftLoopError<E> {
    fn from(value: BftError) -> Self {
        Self::Bft(value)
    }
}

impl<E> From<EngineError<E>> for BftLoopError<E> {
    fn from(value: EngineError<E>) -> Self {
        Self::Engine(value)
    }
}

impl<E> From<StoreError<E>> for BftLoopError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Engine(EngineError::Store(value))
    }
}
