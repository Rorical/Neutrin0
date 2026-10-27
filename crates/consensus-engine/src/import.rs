//! Verify and archive peer blocks and proofs, replay selected branches, and
//! publish complete chunk finality with its canonical head and state atomically.
//!
//! Executor-equipped production imports check runtime commitments before storage.

use alloc::vec::Vec;

use neutrin0_primitives::{BlockHash, ChunkHash, ChunkId, Height, Slot, StateRoot};
use neutrin0_storage::{Batch, Column};
use neutrin0_trie::Trie;

extern crate alloc;

mod admission;
mod block;
mod block_proof;
mod block_receipt;
mod candidates;
mod chunk_proof;
mod diffs;
mod error;
mod execution;
mod follow;
mod replay;

pub use block_receipt::ReceiptOutcome;
pub use error::ImportError;

pub use diffs::apply_state_diff;

/// How far a slot may start after the local wall clock, in seconds.
///
/// Sized to swallow modest NTP drift between honest operators plus network
/// jitter. A header's own timestamp carries no tolerance: it must equal its
/// slot's start, so a proposer cannot move chain time at all.
pub const MAX_CLOCK_DRIFT_SECS: u64 = 60;

/// Dry-run failure text when the program set of the block's chunk cannot be
/// derived yet.
pub const PROGRAMS_UNAVAILABLE: &str = "program set of the block's chunk is unavailable";
/// The previous chunk's certificate, which every block of this chunk reports
/// to the runtime, is not finalized locally yet.
pub const PARTICIPATION_UNAVAILABLE: &str =
    "participation report of the block's chunk is unavailable";
/// The history root of the block's chunk is not finalized locally yet.
pub const HISTORY_UNAVAILABLE: &str = "unavailable historical boundary";

/// Successful outcome of [`Engine::import_block`](crate::Engine::import_block).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportBlockOutcome {
    /// Hash of the imported block, which need not be the head: a sibling or
    /// an already archived ancestor leaves the head where it was.
    pub block_hash: BlockHash,
    /// New local head hash.
    pub new_head_hash: BlockHash,
    /// New local head height.
    pub new_head_height: Height,
    /// New local head slot.
    pub new_head_slot: Slot,
}

/// Successful outcome of [`Engine::import_block_proof`](crate::Engine::import_block_proof).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportBlockProofOutcome {
    /// Hash of the proven block.
    pub block_hash: BlockHash,
    /// Height of the proven block.
    pub height: Height,
}

/// Successful outcome of [`Engine::import_chunk_proof`](crate::Engine::import_chunk_proof).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportChunkProofOutcome {
    /// Chunk id covered by the imported proof.
    pub chunk_id: ChunkId,
    /// Last block height covered by the chunk.
    pub end_height: Height,
    /// Hash of the imported chunk envelope.
    pub chunk_hash: ChunkHash,
}

pub(crate) struct ReplayedHead {
    pub(crate) height: Height,
    pub(crate) hash: BlockHash,
    pub(crate) state_root: StateRoot,
    pub(crate) state: Trie,
    /// Execution artifacts of replayed blocks that had none retained.
    pub(crate) artifacts: Vec<(BlockHash, CheckedExecution)>,
}

impl ReplayedHead {
    /// Publish replay-generated witnesses and diffs with the selected state
    /// and ancestry.
    pub(crate) fn stage_witnesses(&mut self, batch: &mut Batch) -> Result<(), borsh::io::Error> {
        for (hash, checked) in self.artifacts.drain(..) {
            batch.put(Column::Witnesses, hash, checked.witness);
            batch.put(Column::StateDiffs, hash, borsh::to_vec(&checked.diff)?);
        }
        Ok(())
    }
}

/// Artifacts one checked execution leaves beside the block: the proving
/// witness and the state diff served to proof-following nodes.
pub(crate) struct CheckedExecution {
    /// Opaque proving input for the matching proof system.
    pub(crate) witness: Vec<u8>,
    /// Final value of every key the block wrote.
    pub(crate) diff: neutrin0_consensus_types::BlockStateDiff,
}

/// The post-state, witness and diff an admitted publication yields once its
/// writes are judged: a receipt-following node has no witness.
type JudgedWrites = (
    Option<Trie>,
    Option<Vec<u8>>,
    neutrin0_consensus_types::BlockStateDiff,
);

/// Header and body checks shared by every block import path.
pub(crate) struct AdmittedBlock {
    /// Parent header hash.
    pub(crate) parent_hash: BlockHash,
    /// State root the block executes over.
    pub(crate) parent_state_root: StateRoot,
    /// `true` when the parent is the currently materialized head.
    pub(crate) extends_materialised_head: bool,
}

#[cfg(test)]
mod tests;
