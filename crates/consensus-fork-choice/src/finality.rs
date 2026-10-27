//! Finalized-chunk admission and pruning below the finalized anchor.

use neutrin0_consensus_types::{Chunk, FinalityCert};
use neutrin0_primitives::BlockHash;

use crate::{ForkChoice, ForkChoiceError, ProofStatus};

impl ForkChoice {
    /// Registers a finalized chunk and moves the finalized anchor to its end block.
    pub fn add_finalized_chunk(
        &mut self,
        chunk: &Chunk,
        cert: &FinalityCert,
    ) -> Result<(), ForkChoiceError> {
        let chunk_hash = self.add_chunk(chunk);
        if cert.chunk_id != chunk.chunk_id || cert.chunk_hash != chunk_hash {
            return Err(ForkChoiceError::InvalidFinalityCertificate);
        }
        if chunk.end_block_hash != self.finalized
            && !self.block_extends(chunk.end_block_hash, self.finalized)
        {
            return Err(ForkChoiceError::UnknownBlock(chunk.end_block_hash));
        }

        let previous = self.finalized;
        self.finalized = chunk.end_block_hash;
        self.mark_finalized_ancestors(chunk.end_block_hash, previous);
        Ok(())
    }

    /// Remove finalized ancestors and detached forks while preserving descendant votes.
    pub fn retain_finalized_subtree(&mut self) {
        let retained: alloc::collections::BTreeSet<_> = self
            .blocks
            .keys()
            .copied()
            .filter(|hash| *hash != self.finalized && self.block_extends(*hash, self.finalized))
            .collect();
        self.blocks.retain(|hash, _| retained.contains(hash));
        self.chunks
            .retain(|_, chunk| retained.contains(&chunk.end_block_hash));
        self.votes
            .retain(|_, vote| self.chunks.contains_key(&vote.data.chunk_hash));
    }

    /// Mark the newly finalized segment: `hash` and its ancestors down to, but
    /// excluding, the previous anchor `previous`.
    ///
    /// Every ancestor of `previous` was marked when it became final, so the
    /// walk is bounded by the new segment rather than the retained history.
    /// It also stops at an unknown block or a self-parented node.
    fn mark_finalized_ancestors(&mut self, mut hash: BlockHash, previous: BlockHash) {
        while hash != previous {
            let Some(node) = self.blocks.get_mut(&hash) else {
                break;
            };
            node.proof_status = ProofStatus::Finalized;
            if node.parent_hash == hash {
                break;
            }
            hash = node.parent_hash;
        }
    }
}
