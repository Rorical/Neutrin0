//! Reassembly of program-lane pieces into complete, verified artifacts.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use neutrin0_consensus_types::ProgramPiece;
use neutrin0_primitives::Hash;

use super::{MAX_PARTIAL_BYTES, Partial, ProgramStore, content_hash};

impl ProgramStore {
    /// Absorb the program lane of an imported block, keeping only pieces of
    /// artifacts in `wanted` that authenticate against their content hash.
    /// Returns the content hashes of artifacts completed by these pieces.
    pub fn absorb(&self, pieces: &[ProgramPiece], wanted: &BTreeSet<Hash>) -> Vec<Hash> {
        let mut completed = Vec::new();
        let mut partial = self
            .partial
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Reservations follow governance: an artifact no longer named frees
        // its share immediately, so a stale proposal cannot starve a live one.
        partial.retain(|hash, _| wanted.contains(hash));
        for piece in pieces {
            let hash = piece.content_hash();
            if !wanted.contains(&hash) || !piece.authenticates() {
                continue;
            }
            if self
                .complete
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .artifacts
                .contains_key(&hash)
                || self.is_persisted(&hash)
            {
                continue;
            }
            if !partial.contains_key(&hash) {
                let reserved: u64 = partial
                    .values()
                    .map(|entry| u64::from(entry.total_len))
                    .sum();
                if reserved + u64::from(piece.total_len) > MAX_PARTIAL_BYTES {
                    continue;
                }
                partial.insert(
                    hash,
                    Partial {
                        total_len: piece.total_len,
                        received: BTreeMap::new(),
                        bytes: 0,
                    },
                );
            }
            let entry = partial.get_mut(&hash).expect("inserted above");
            if entry.received.contains_key(&piece.offset) {
                continue;
            }
            entry.bytes += piece.bytes.len();
            entry.received.insert(piece.offset, piece.bytes.clone());
            if let Some(bytes) = Self::assembled(entry) {
                partial.remove(&hash);
                // Every piece authenticated against the root, so the whole
                // artifact does too; recomputing is a cheap final check.
                if content_hash(&bytes) == Some(hash) && self.accept(hash, bytes, &completed) {
                    completed.push(hash);
                }
            }
        }
        drop(partial);
        completed
    }

    /// Concatenate contiguous pieces once they cover the whole artifact.
    fn assembled(entry: &Partial) -> Option<Vec<u8>> {
        if entry.bytes != entry.total_len as usize {
            return None;
        }
        let mut bytes = Vec::with_capacity(entry.total_len as usize);
        for (offset, chunk) in &entry.received {
            if *offset as usize != bytes.len() {
                return None;
            }
            bytes.extend_from_slice(chunk);
        }
        (bytes.len() == entry.total_len as usize).then_some(bytes)
    }

    /// Keep a verified artifact in memory until the installer decides.
    /// `reported` lists artifacts this absorption already completed; they
    /// keep their bytes. Returns `false` when the artifact was not kept.
    fn accept(&self, hash: Hash, bytes: Vec<u8>, reported: &[Hash]) -> bool {
        let mut complete = self
            .complete
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let kept = complete.insert(hash, bytes, reported);
        drop(complete);
        kept
    }

    fn is_persisted(&self, hash: &Hash) -> bool {
        self.dir
            .as_ref()
            .is_some_and(|dir| Self::artifact_path(dir, hash).exists())
    }

    /// Complete artifacts awaiting installation.
    #[must_use]
    pub fn complete(&self) -> Vec<(Hash, Arc<Vec<u8>>)> {
        self.complete
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .artifacts
            .iter()
            .map(|(hash, bytes)| (*hash, Arc::clone(bytes)))
            .collect()
    }

    /// Forget an artifact once installed or rejected.
    pub fn mark_installed(&self, hash: &Hash) {
        self.complete
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(hash);
    }
}
