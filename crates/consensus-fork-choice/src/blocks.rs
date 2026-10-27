//! Block bookkeeping: insertion, proof status, staleness, removal and ancestry.

use neutrin0_consensus_types::Header;
use neutrin0_primitives::{BlockHash, Slot, ValidatorIndex};

use crate::{BlockNode, ForkChoice, ForkChoiceError, ProofStatus, vrf_tie_breaker};

impl ForkChoice {
    /// Adds a block with `PendingProof` status and returns its canonical hash.
    pub fn add_block(&mut self, header: &Header) -> Result<BlockHash, ForkChoiceError> {
        let hash = header.hash();
        let parent_hash = header.parent_hash;
        if parent_hash != self.finalized && !self.blocks.contains_key(&parent_hash) {
            return Err(ForkChoiceError::UnknownParent(parent_hash));
        }

        // Unproven children of one parent share the earliest window.
        let stale_clock = self
            .blocks
            .values()
            .filter(|node| {
                node.parent_hash == parent_hash && node.proof_status == ProofStatus::PendingProof
            })
            .map(|node| node.stale_clock)
            .fold(header.slot, Slot::min);
        for node in self.blocks.values_mut() {
            if node.parent_hash == parent_hash && node.proof_status == ProofStatus::PendingProof {
                node.stale_clock = node.stale_clock.min(stale_clock);
            }
        }
        let node = BlockNode {
            hash,
            parent_hash,
            height: header.height,
            slot: header.slot,
            stale_clock,
            proposer_index: header.proposer_index,
            proof_status: ProofStatus::PendingProof,
            vrf_tie_breaker: vrf_tie_breaker(&header.vrf_proof),
        };
        self.blocks.insert(hash, node);
        Ok(hash)
    }

    /// Mark every block still awaiting its proof whose stale clock is at or
    /// before `cutoff_slot` as [`ProofStatus::Stale`] and return how many
    /// changed.
    /// The engine never restores a stale block: a later receipt is verified
    /// for accountability and dropped (design 08).
    pub fn mark_stale(&mut self, cutoff_slot: Slot) -> usize {
        let mut changed = 0;
        for node in self.blocks.values_mut() {
            if node.proof_status == ProofStatus::PendingProof && node.stale_clock <= cutoff_slot {
                node.proof_status = ProofStatus::Stale;
                changed += 1;
            }
        }
        changed
    }

    /// The block `proposer_index` signed for `slot`, if one is known. Signed
    /// headers make a second one a double proposal.
    #[must_use]
    pub fn block_at_slot(&self, slot: Slot, proposer_index: ValidatorIndex) -> Option<BlockHash> {
        self.blocks
            .values()
            .find(|node| node.slot == slot && node.proposer_index == proposer_index)
            .map(|node| node.hash)
    }

    /// Whether `hash` or one of its ancestors above finality is stale.
    #[must_use]
    pub fn on_stale_branch(&self, mut hash: BlockHash) -> bool {
        while hash != self.finalized
            && let Some(node) = self.blocks.get(&hash)
        {
            if node.proof_status == ProofStatus::Stale {
                return true;
            }
            if node.parent_hash == hash {
                return false;
            }
            hash = node.parent_hash;
        }
        false
    }

    /// Blocks above finality that no receipt proves, stale ones included.
    #[must_use]
    pub fn unproven_count(&self) -> usize {
        self.blocks
            .values()
            .filter(|node| {
                matches!(
                    node.proof_status,
                    ProofStatus::PendingProof | ProofStatus::Stale
                )
            })
            .count()
    }

    /// Stale blocks whose slot is at or before `cutoff_slot`, with every
    /// known descendant.
    #[must_use]
    pub fn stale_subtrees(&self, cutoff_slot: Slot) -> alloc::collections::BTreeSet<BlockHash> {
        let mut ordered: alloc::vec::Vec<_> = self.blocks.values().collect();
        ordered.sort_by_key(|node| (node.height, node.hash));
        let mut removed = alloc::collections::BTreeSet::new();
        // A parent is lower than its child, so one ascending pass reaches
        // every descendant after its ancestor.
        for node in ordered {
            if (node.proof_status == ProofStatus::Stale && node.stale_clock <= cutoff_slot)
                || removed.contains(&node.parent_hash)
            {
                removed.insert(node.hash);
            }
        }
        removed
    }

    /// Forget `hashes`.
    pub fn remove_blocks(&mut self, hashes: &alloc::collections::BTreeSet<BlockHash>) {
        self.blocks.retain(|hash, _| !hashes.contains(hash));
    }

    /// Updates a known block's proof status.
    pub fn on_block_proof(
        &mut self,
        hash: BlockHash,
        status: ProofStatus,
    ) -> Result<(), ForkChoiceError> {
        let node = self
            .blocks
            .get_mut(&hash)
            .ok_or(ForkChoiceError::UnknownBlock(hash))?;
        node.proof_status = status;
        Ok(())
    }

    pub(super) fn block_extends(&self, mut descendant: BlockHash, ancestor: BlockHash) -> bool {
        if descendant == ancestor {
            return true;
        }
        while let Some(node) = self.blocks.get(&descendant) {
            if node.parent_hash == ancestor {
                return true;
            }
            if node.parent_hash == descendant {
                return false;
            }
            descendant = node.parent_hash;
        }
        false
    }
}
