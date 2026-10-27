//! Failures while finalizing a chunk.

use core::fmt;

use neutrin0_consensus_chunk_bft::BftError;
use neutrin0_primitives::{BlockHash, ChunkId, Hash, Height};
use neutrin0_proof_system::ProofError;

use crate::block_state::BlockState;
use crate::error::EngineError;
use crate::store::StoreError;

/// Failures while finalizing a chunk.
#[derive(Debug)]
pub enum FinalizeError<E> {
    /// Engine bookkeeping or storage failure.
    Engine(EngineError<E>),
    /// Staging the proven branch's materialized state failed.
    Replay(crate::ImportError<E>),
    /// `chunk_id` did not advance by exactly one from the latest
    /// finalized chunk (or was non-zero with no prior finalization).
    NonContiguousChunkId {
        /// Latest finalized chunk id; `None` means chunk 0 has not
        /// finalized yet.
        latest: Option<ChunkId>,
        /// Chunk id the caller asked for.
        requested: ChunkId,
    },
    /// One of the blocks covered by the chunk is missing.
    MissingBlock {
        /// Height the engine looked up.
        height: Height,
    },
    /// A covered block's FSM state is not [`BlockState::Proven`].
    BlockNotProven {
        /// Block hash whose state was wrong.
        hash: BlockHash,
        /// State the FSM reported.
        state: BlockState,
    },
    /// A covered block has no persisted block proof.
    MissingBlockProof {
        /// Block hash whose proof was missing.
        hash: BlockHash,
    },
    /// The receipt a certificate or proposal names for a covered block is not
    /// held locally (design 08).
    MissingBlockReceipt {
        /// Block hash whose receipt is named.
        hash: BlockHash,
        /// Statement key of the named receipt.
        statement_key: Hash,
    },
    /// The chunk proof a certificate ratifies is not held locally (design 08).
    MissingChunkProof {
        /// Chunk the named proof finalizes.
        chunk_id: ChunkId,
        /// Statement key of the named proof.
        statement_key: Hash,
    },
    /// A parent header could not be loaded.
    MissingParentHeader {
        /// Parent hash that should have been present.
        parent_hash: BlockHash,
    },
    /// A covered block does not extend the previous covered block.
    ParentHashMismatch {
        /// Height whose parent link was invalid.
        height: Height,
        /// Parent hash required by the previous block in the chunk.
        expected: BlockHash,
        /// Parent hash carried by the header at `height`.
        actual: BlockHash,
    },
    /// A persisted block proof does not bind the canonical header data.
    BlockProofPublicInputsMismatch {
        /// Block hash whose proof inputs did not match the header.
        hash: BlockHash,
    },
    /// Chunk size from the chain spec overflowed when computing the
    /// covered height range.
    HeightRangeOverflow,
    /// The configured validator set has no positive unslashed stake.
    EmptyActiveSet,
    /// Backend chunk-proof generation failed.
    Backend(ProofError),
    /// Chunk-BFT bookkeeping rejected a signed vote.
    Bft(BftError),
    /// The BFT layer accepted votes but still reports `Pending`. Only
    /// possible when the available valid votes do not form a quorum.
    FinalizationStalled,
    /// Borsh-serialising the backend chunk proof for storage failed.
    Codec(borsh::io::Error),
}

impl<E: fmt::Debug + fmt::Display> fmt::Display for FinalizeError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(e) => write!(f, "engine error: {e}"),
            Self::Replay(e) => write!(f, "branch replay failed: {e}"),
            Self::NonContiguousChunkId { latest, requested } => match latest {
                Some(latest) => write!(
                    f,
                    "chunk {requested} cannot be finalized: latest finalized chunk is {latest}"
                ),
                None => write!(
                    f,
                    "chunk {requested} cannot be finalized: no chunk has finalized yet"
                ),
            },
            Self::MissingBlock { height } => write!(f, "no header persisted at height {height}"),
            Self::BlockNotProven { hash, state } => write!(
                f,
                "block {hash:?} is in state {state}, must be Proven before chunk finalization"
            ),
            Self::MissingBlockProof { hash } => {
                write!(f, "block {hash:?} has no persisted block proof")
            }
            Self::MissingBlockReceipt {
                hash,
                statement_key,
            } => write!(
                f,
                "receipt {statement_key:?} of block {hash:?} is not held locally"
            ),
            Self::MissingChunkProof {
                chunk_id,
                statement_key,
            } => write!(
                f,
                "chunk proof {statement_key:?} of chunk {chunk_id} is not held locally"
            ),
            Self::MissingParentHeader { parent_hash } => {
                write!(f, "parent header {parent_hash:?} is missing")
            }
            Self::ParentHashMismatch {
                height,
                expected,
                actual,
            } => write!(
                f,
                "block at height {height} has parent {actual:?}, expected {expected:?}"
            ),
            Self::BlockProofPublicInputsMismatch { hash } => write!(
                f,
                "block proof for {hash:?} does not match canonical header public inputs"
            ),
            Self::HeightRangeOverflow => f.write_str("chunk height range overflowed u64"),
            Self::EmptyActiveSet => {
                f.write_str("active validator set has no positive unslashed stake")
            }
            Self::Backend(err) => write!(f, "proof backend error: {err:?}"),
            Self::Bft(err) => write!(f, "chunk-BFT error: {err}"),
            Self::FinalizationStalled => f.write_str("chunk-BFT did not reach finalization"),
            Self::Codec(err) => write!(f, "borsh encode of backend chunk proof failed: {err}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for FinalizeError<E> {}

impl<E> From<EngineError<E>> for FinalizeError<E> {
    fn from(value: EngineError<E>) -> Self {
        Self::Engine(value)
    }
}

impl<E> From<StoreError<E>> for FinalizeError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Engine(EngineError::Store(value))
    }
}

impl<E> From<ProofError> for FinalizeError<E> {
    fn from(value: ProofError) -> Self {
        Self::Backend(value)
    }
}

impl<E> From<BftError> for FinalizeError<E> {
    fn from(value: BftError) -> Self {
        Self::Bft(value)
    }
}

impl<E> From<borsh::io::Error> for FinalizeError<E> {
    fn from(value: borsh::io::Error) -> Self {
        Self::Codec(value)
    }
}
