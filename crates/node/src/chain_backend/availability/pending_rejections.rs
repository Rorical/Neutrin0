//! Rejected proof envelopes held until a retained vote names them.

use neutrin0_consensus_types::BlockProof;
use neutrin0_primitives::Hash;

use super::Rejection;

/// Rejected envelopes kept before any vote names them.
const MAX_PENDING_REJECTIONS: usize = 64;
/// Byte budget of [`PendingRejections`].
const MAX_PENDING_REJECTION_BYTES: usize = 32 * 1024 * 1024;

/// Rejected envelopes no retained vote names yet, by exact identity. Anyone
/// can mint these for a known header, so they are bounded in count and bytes,
/// never relayed and never stored durably; they are kept only so a precommit
/// that later accepts the exact bytes is still detected. Entries are never
/// overwritten, and they cannot touch the engine's import-path cache.
#[derive(Default)]
#[allow(clippy::redundant_pub_crate)] // Stored by the parent backend.
pub(in crate::chain_backend) struct PendingRejections {
    entries: std::collections::VecDeque<(Hash, BlockProof, Rejection)>,
    bytes: usize,
}

impl PendingRejections {
    pub(super) fn insert(&mut self, id: Hash, proof: BlockProof, reason: Rejection) {
        let size = proof.proof_bytes.len();
        if size > MAX_PENDING_REJECTION_BYTES || self.entries.iter().any(|(held, _, _)| *held == id)
        {
            return;
        }
        while self.entries.len() >= MAX_PENDING_REJECTIONS
            || self.bytes.saturating_add(size) > MAX_PENDING_REJECTION_BYTES
        {
            let Some((_, oldest, _)) = self.entries.pop_front() else {
                break;
            };
            self.bytes -= oldest.proof_bytes.len();
        }
        self.bytes += size;
        self.entries.push_back((id, proof, reason));
    }

    pub(super) fn get(&self, id: &Hash) -> Option<(BlockProof, Rejection)> {
        self.entries
            .iter()
            .find(|(held, _, _)| held == id)
            .map(|(_, proof, reason)| (proof.clone(), *reason))
    }
}
