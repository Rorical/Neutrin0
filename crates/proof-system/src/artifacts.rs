//! Bounded reads of locally authenticated execution programs.

use alloc::sync::Arc;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::history_proof::VkDigest;
use neutrin0_primitives::Hash;

/// Locally authenticated execution-artifact identity, independent of its transport hash.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ArtifactIdentity {
    /// BLAKE3 of exact WASM bytes.
    Runtime(Hash),
    /// Locally derived SP1 verifying-key digest.
    Guest(VkDigest),
}

/// Local resource retention selected from authenticated chain records.
/// Source identities may remain reloadable without keeping compiled code or CUDA sessions.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ProgramRetention {
    /// Authenticated sources still available to historical queries and artifact serving.
    pub sources: Vec<ArtifactIdentity>,
    /// Current, scheduled and bounded proposal identities to keep warm.
    pub warm: Vec<ArtifactIdentity>,
}

/// Bounded single-artifact disk reader. Implementations must authenticate content bytes.
pub type ProgramArtifactLoader = Arc<dyn Fn(ArtifactIdentity) -> Option<Vec<u8>> + Send + Sync>;

/// Explicit ownership of program resources for queued and running proof jobs.
pub type ProgramLease = Arc<dyn Send + Sync>;

/// Maximum payload copied for one execution-program fragment.
pub const MAX_ARTIFACT_FRAGMENT_BYTES: usize = 64 * 1024;

/// Copy a bounded fragment and return the complete artifact's byte length.
///
/// Zero-sized requests, offsets outside the artifact and unrepresentable offsets
/// return `None`. The caller's requested size is capped at 64 KiB.
#[must_use]
pub fn artifact_fragment(bytes: &[u8], offset: u64, max_bytes: usize) -> Option<(u64, Vec<u8>)> {
    let total = u64::try_from(bytes.len()).ok()?;
    let start = usize::try_from(offset).ok()?;
    let available = bytes.get(start..)?;
    let count = available
        .len()
        .min(max_bytes)
        .min(MAX_ARTIFACT_FRAGMENT_BYTES);
    if count == 0 {
        return None;
    }
    Some((total, available[..count].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::{MAX_ARTIFACT_FRAGMENT_BYTES, artifact_fragment};

    #[test]
    fn bounded_reads_cover_the_last_fragment_without_wrapping_offsets() {
        let bytes = alloc::vec![3; MAX_ARTIFACT_FRAGMENT_BYTES + 7];
        let total = u64::try_from(bytes.len()).unwrap();
        let (length, first) = artifact_fragment(&bytes, 0, usize::MAX).unwrap();
        assert_eq!(length, total);
        assert_eq!(first.len(), MAX_ARTIFACT_FRAGMENT_BYTES);
        let (_, last) = artifact_fragment(
            &bytes,
            u64::try_from(MAX_ARTIFACT_FRAGMENT_BYTES).unwrap(),
            MAX_ARTIFACT_FRAGMENT_BYTES,
        )
        .unwrap();
        assert_eq!(last, alloc::vec![3; 7]);
        assert!(artifact_fragment(&bytes, total, 1).is_none());
        assert!(artifact_fragment(&bytes, u64::MAX, 1).is_none());
        assert!(artifact_fragment(&bytes, 0, 0).is_none());
    }
}
