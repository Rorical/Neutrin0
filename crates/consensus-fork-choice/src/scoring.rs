//! Chunk votes and vote-weighted head selection.

use alloc::collections::BTreeMap;
#[cfg(test)]
use alloc::vec::Vec;
use core::cmp::Ordering;

use neutrin0_consensus_types::Chunk;
use neutrin0_primitives::{BlockHash, ChunkHash, ValidatorIndex};

#[cfg(test)]
use crate::ForkChoiceError;
use crate::{BlockNode, CandidateScore, ChunkRef, ChunkVote, ForkChoice, ProofStatus};

impl ForkChoice {
    /// Registers a chunk so votes for its hash can score descendant blocks.
    pub fn add_chunk(&mut self, chunk: &Chunk) -> ChunkHash {
        let chunk_hash = chunk.hash();
        self.chunks.insert(
            chunk_hash,
            ChunkRef {
                end_block_hash: chunk.end_block_hash,
            },
        );
        chunk_hash
    }

    /// Records the latest chunk vote from `validator`.
    pub fn add_vote(&mut self, validator: ValidatorIndex, vote: ChunkVote) {
        self.votes.insert(validator, vote);
    }

    /// Number of distinct validators with at least one recorded
    /// vote in this fork-choice instance. Diagnostic helper used
    /// by integration tests / operator probes to verify that the
    /// vote ingestion pipeline is feeding fork-choice in
    /// production.
    #[must_use]
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    /// Lookup the latest recorded vote from `validator`, if any.
    /// `#[doc(hidden)]` because production callers should drive
    /// fork-choice through the typed API (`add_vote`, `head`,
    /// `add_finalized_chunk`); this exists for tests that need
    /// to assert which chunk a particular validator has voted on.
    #[doc(hidden)]
    #[must_use]
    pub fn vote_for_validator(&self, validator: ValidatorIndex) -> Option<&ChunkVote> {
        self.votes.get(&validator)
    }

    /// Returns the current fork-choice head.
    ///
    /// Latest-vote weight is summed once per voted chunk end block, then each
    /// candidate is scored by a single walk over its ancestry.
    pub fn head(&self) -> BlockHash {
        self.head_descending_from(self.finalized)
    }

    /// Select descendants of an authenticated execution dependency without advancing finality.
    /// The caller must independently authenticate the anchor and retain its sources.
    #[must_use]
    pub fn head_descending_from(&self, anchor: BlockHash) -> BlockHash {
        // `None` marks a block whose vote total exceeds `u128`.
        let mut weights = BTreeMap::<BlockHash, Option<u128>>::new();
        for vote in self.votes.values() {
            if let Some(chunk) = self.chunks.get(&vote.data.chunk_hash) {
                let entry = weights.entry(chunk.end_block_hash).or_insert(Some(0));
                *entry = entry.and_then(|weight| weight.checked_add(vote.weight));
            }
        }
        self.blocks
            .iter()
            .filter(|(hash, _)| anchor == self.finalized || self.block_extends(**hash, anchor))
            .filter_map(|(hash, node)| self.walk_candidate(*hash, node, &weights))
            .max_by(compare_candidates)
            .map_or(anchor, |score| score.hash)
    }

    /// Score one candidate from a single walk over the blocks [`Self::block_extends`]
    /// visits: the candidate, then parents until a block is unknown or its own parent.
    ///
    /// The candidate must extend the finalized block with no `Stale` block
    /// before it on the walk; the finalized candidate itself checks every known
    /// block it walks through. Every vote target on the walk adds its weight. A
    /// candidate whose total exceeds `u128` is dropped exactly as a checked sum
    /// of non-negative weights would fail.
    fn walk_candidate(
        &self,
        candidate: BlockHash,
        node: &BlockNode,
        weights: &BTreeMap<BlockHash, Option<u128>>,
    ) -> Option<CandidateScore> {
        let mut extends_finalized = false;
        let mut stale = false;
        let mut weight = 0_u128;
        // Walking down, the highest block from which every ancestor is
        // proven: reset at each unproven block.
        let mut proven_height = None;
        let mut hash = candidate;
        loop {
            if hash == self.finalized {
                extends_finalized = true;
            }
            if let Some(block_weight) = weights.get(&hash) {
                weight = weight.checked_add((*block_weight)?)?;
            }
            let Some(visited) = self.blocks.get(&hash) else {
                break;
            };
            if !extends_finalized {
                if is_proven(visited.proof_status) {
                    proven_height.get_or_insert(visited.height);
                } else {
                    proven_height = None;
                }
            }
            stale |= visited.proof_status == ProofStatus::Stale
                && (!extends_finalized || candidate == self.finalized);
            if visited.parent_hash == hash {
                break;
            }
            hash = visited.parent_hash;
        }
        if !extends_finalized || stale {
            return None;
        }
        Some(CandidateScore {
            hash: candidate,
            score: weight,
            proven_height: proven_height.unwrap_or(0),
            height: node.height,
            vrf_tie_breaker: node.vrf_tie_breaker,
        })
    }

    /// Reference scoring with one ancestor walk per vote, which
    /// [`Self::head`] must match.
    #[cfg(test)]
    pub(super) fn head_reference(&self) -> BlockHash {
        self.blocks
            .keys()
            .filter_map(|hash| self.score_candidate(*hash).ok().flatten())
            .max_by(compare_candidates)
            .map_or(self.finalized, |score| score.hash)
    }

    #[cfg(test)]
    pub(super) fn score_candidate(
        &self,
        candidate: BlockHash,
    ) -> Result<Option<CandidateScore>, ForkChoiceError> {
        let node = self
            .blocks
            .get(&candidate)
            .ok_or(ForkChoiceError::UnknownBlock(candidate))?;
        if !self.block_extends(candidate, self.finalized) || self.has_stale_ancestor(candidate) {
            return Ok(None);
        }

        let mut score = 0_u128;
        for vote in self.votes.values() {
            if self.vote_applies_to_candidate(vote, candidate) {
                score = score
                    .checked_add(vote.weight)
                    .ok_or(ForkChoiceError::ScoreOverflow)?;
            }
        }

        Ok(Some(CandidateScore {
            hash: candidate,
            score,
            proven_height: self.proven_height_reference(candidate),
            height: node.height,
            vrf_tie_breaker: node.vrf_tie_breaker,
        }))
    }

    #[cfg(test)]
    fn vote_applies_to_candidate(&self, vote: &ChunkVote, candidate: BlockHash) -> bool {
        self.chunks
            .get(&vote.data.chunk_hash)
            .is_some_and(|chunk_ref| self.block_extends(candidate, chunk_ref.end_block_hash))
    }

    /// Reference proven-prefix height: the highest block on the branch whose
    /// every ancestor down to finality is proven.
    #[cfg(test)]
    fn proven_height_reference(&self, candidate: BlockHash) -> neutrin0_primitives::Height {
        let mut path = Vec::new();
        let mut hash = candidate;
        while hash != self.finalized
            && let Some(node) = self.blocks.get(&hash)
        {
            path.push(node);
            if node.parent_hash == hash {
                break;
            }
            hash = node.parent_hash;
        }
        path.iter()
            .rev()
            .take_while(|node| is_proven(node.proof_status))
            .last()
            .map_or(0, |node| node.height)
    }

    #[cfg(test)]
    fn has_stale_ancestor(&self, mut hash: BlockHash) -> bool {
        while let Some(node) = self.blocks.get(&hash) {
            if node.proof_status == ProofStatus::Stale {
                return true;
            }
            if node.parent_hash == self.finalized {
                return false;
            }
            hash = node.parent_hash;
        }
        false
    }
}

fn compare_candidates(left: &CandidateScore, right: &CandidateScore) -> Ordering {
    left.score
        .cmp(&right.score)
        .then_with(|| left.proven_height.cmp(&right.proven_height))
        .then_with(|| left.height.cmp(&right.height))
        .then_with(|| right.vrf_tie_breaker.cmp(&left.vrf_tie_breaker))
        .then_with(|| right.hash.cmp(&left.hash))
}

const fn is_proven(status: ProofStatus) -> bool {
    matches!(status, ProofStatus::Proven | ProofStatus::Finalized)
}
