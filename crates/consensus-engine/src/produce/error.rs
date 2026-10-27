//! Failures while producing a single block.

extern crate alloc;

use alloc::string::String;
use core::fmt;

use neutrin0_consensus_vrf::VrfError;
use neutrin0_primitives::Slot;

use crate::error::EngineError;
use crate::store::StoreError;

/// Failures while producing a single block.
#[derive(Debug)]
pub enum ProductionError<E> {
    /// Engine bookkeeping or storage failure.
    Engine(EngineError<E>),
    /// Validator key cannot propose: missing index, slashed, etc.
    NotEligible(VrfError),
    /// Block height counter would overflow `u64`.
    HeightOverflow,
    /// Persisted proving input exceeds the chain's allocation ceiling.
    WitnessTooLarge {
        /// Encoded witness bytes emitted by the executor.
        actual: usize,
        /// Genesis-pinned maximum bytes.
        limit: u64,
    },
    /// Unsigned produced block cannot fit the local gossip envelope.
    BodyTooLarge {
        /// Full encoded header and body, including receipts and attachments.
        actual: usize,
        /// Current transport ceiling.
        limit: usize,
    },
    /// The block's state diff exceeds the transport ceiling proof-following
    /// nodes accept. Production retries with fewer user candidates.
    StateDiffTooLarge {
        /// Serialized diff size in bytes.
        actual: usize,
        /// Transport ceiling in bytes.
        limit: usize,
    },
    /// The dynamic runtime ([`BlockExecutor`](neutrin0_proof_system::BlockExecutor)) failed during the
    /// dry-run path.
    Executor(String),
    /// The requested slot does not advance past the current head slot.
    NonMonotonicSlot {
        /// Slot of the current head block, or genesis slot 0.
        parent_slot: Slot,
        /// Slot requested for the new block.
        requested: Slot,
    },
}

impl<E: fmt::Display + fmt::Debug> fmt::Display for ProductionError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(e) => write!(f, "engine error: {e}"),
            Self::NotEligible(e) => write!(f, "validator cannot propose: {e}"),
            Self::HeightOverflow => f.write_str("block height counter overflowed"),
            Self::WitnessTooLarge { actual, limit } => {
                write!(f, "block proving input {actual} exceeds {limit} bytes")
            }
            Self::BodyTooLarge { actual, limit } => {
                write!(f, "produced block envelope {actual} exceeds {limit} bytes")
            }
            Self::StateDiffTooLarge { actual, limit } => {
                write!(f, "state diff {actual} bytes exceeds limit {limit}")
            }
            Self::Executor(msg) => write!(f, "block executor failed: {msg}"),
            Self::NonMonotonicSlot {
                parent_slot,
                requested,
            } => write!(
                f,
                "slot {requested} must be greater than current head slot {parent_slot}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Debug + fmt::Display> std::error::Error for ProductionError<E> {}

impl<E> From<EngineError<E>> for ProductionError<E> {
    fn from(value: EngineError<E>) -> Self {
        Self::Engine(value)
    }
}

impl<E> From<StoreError<E>> for ProductionError<E> {
    fn from(value: StoreError<E>) -> Self {
        Self::Engine(EngineError::Store(value))
    }
}
