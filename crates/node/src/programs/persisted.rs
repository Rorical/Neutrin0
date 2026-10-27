//! Reading, indexing and pruning the artifacts a store persists.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use neutrin0_consensus_types::MAX_PROGRAM_BYTES;
use neutrin0_primitives::{Hash, blake3_256};
use neutrin0_proof_system::artifacts::ArtifactIdentity;

use super::{ArtifactKind, ProgramStore, content_hash, parse_hex_hash};

impl ProgramStore {
    /// Read exactly one bounded content-authenticated artifact from disk or memory.
    #[must_use]
    pub fn read_persisted(&self, hash: &Hash) -> Option<Vec<u8>> {
        let Some(dir) = self.dir.as_ref() else {
            return self
                .memory_sources
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .artifacts
                .get(hash)
                .map(|bytes| bytes.as_ref().clone());
        };
        let path = Self::artifact_path(dir, hash);
        let metadata = fs::metadata(&path).ok()?;
        if metadata.len() == 0 || metadata.len() > u64::from(MAX_PROGRAM_BYTES) {
            return None;
        }
        let bytes = fs::read(path).ok()?;
        (content_hash(&bytes).as_ref() == Some(hash)).then_some(bytes)
    }

    /// Reload a locally authenticated identity without allocating all archived programs.
    #[must_use]
    pub fn read_identity(&self, identity: ArtifactIdentity) -> Option<Vec<u8>> {
        let hash = self.identity_content_hash(identity)?;
        let bytes = self.read_persisted(&hash)?;
        match identity {
            ArtifactIdentity::Runtime(expected)
                if ArtifactKind::of(&bytes) == ArtifactKind::Wasm
                    && blake3_256(&bytes) == expected =>
            {
                Some(bytes)
            }
            ArtifactIdentity::Guest(_) if ArtifactKind::of(&bytes) == ArtifactKind::Elf => {
                Some(bytes)
            }
            _ => None,
        }
    }

    /// Cheap exact index lookup; source content is reauthenticated when read.
    #[must_use]
    pub fn identity_content_hash(&self, identity: ArtifactIdentity) -> Option<Hash> {
        let Some(dir) = self.dir.as_ref() else {
            return self
                .memory_sources
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .identities
                .get(&identity)
                .copied();
        };
        let path = Self::identity_path(dir, identity);
        if fs::metadata(&path).ok()?.len() != 32 {
            return None;
        }
        <Hash>::try_from(fs::read(path).ok()?.as_slice()).ok()
    }

    /// Whether a bounded completed source exists locally; this never authenticates it for use.
    #[must_use]
    pub fn has_persisted(&self, hash: &Hash) -> bool {
        if self.dir.is_none() {
            return self
                .memory_sources
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .artifacts
                .contains_key(hash);
        }
        self.dir
            .as_ref()
            .and_then(|dir| fs::metadata(Self::artifact_path(dir, hash)).ok())
            .is_some_and(|metadata| {
                metadata.len() > 0 && metadata.len() <= u64::from(MAX_PROGRAM_BYTES)
            })
    }

    /// Prune abandoned proposal material and stale indices, keeping authenticated sources.
    pub fn retain_sources(&self, identities: &BTreeSet<ArtifactIdentity>, wanted: &BTreeSet<Hash>) {
        self.partial
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|hash, _| wanted.contains(hash));
        let mut complete = self
            .complete
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let abandoned: Vec<_> = complete
            .artifacts
            .keys()
            .filter(|hash| !wanted.contains(*hash))
            .copied()
            .collect();
        for hash in abandoned {
            complete.remove(&hash);
        }
        drop(complete);
        let _persistence = self
            .persistence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(dir) = &self.dir else {
            self.retain_memory_sources(identities, wanted);
            return;
        };
        let mut retained = wanted.clone();
        for identity in identities {
            if let Some(hash) = self.identity_content_hash(*identity) {
                retained.insert(hash);
            }
        }
        Self::prune_persisted_sources(dir, identities, &retained);
    }

    /// Memory-only counterpart of the disk sweep: drop identities no longer
    /// named and artifacts nothing retains.
    fn retain_memory_sources(
        &self,
        identities: &BTreeSet<ArtifactIdentity>,
        wanted: &BTreeSet<Hash>,
    ) {
        let mut sources = self
            .memory_sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sources
            .identities
            .retain(|identity, _| identities.contains(identity));
        let mut retained = wanted.clone();
        retained.extend(sources.identities.values().copied());
        let obsolete: Vec<_> = sources
            .artifacts
            .keys()
            .filter(|hash| !retained.contains(*hash))
            .copied()
            .collect();
        for hash in obsolete {
            sources.remove(&hash);
        }
        drop(sources);
    }

    /// Delete artifact files outside `retained` and identity indices outside
    /// `identities`.
    fn prune_persisted_sources(
        dir: &Path,
        identities: &BTreeSet<ArtifactIdentity>,
        retained: &BTreeSet<Hash>,
    ) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "bin") {
                if let Some(hash) = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .and_then(parse_hex_hash)
                    && !retained.contains(&hash)
                {
                    let _ = fs::remove_file(path);
                }
            } else if path.extension().is_some_and(|ext| ext == "idx") {
                let identity = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .and_then(|stem| stem.strip_prefix("identity-"))
                    .and_then(|encoded| hex::decode(encoded).ok())
                    .and_then(|bytes| borsh::from_slice::<ArtifactIdentity>(&bytes).ok());
                if identity.is_none_or(|identity| !identities.contains(&identity)) {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }

    /// Persisted artifacts whose bytes still hash to their file name.
    #[must_use]
    pub fn persisted(&self) -> Vec<(Hash, Vec<u8>)> {
        let _persistence = self
            .persistence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(dir) = &self.dir else {
            return Vec::new();
        };
        let Ok(entries) = fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "bin") {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            match content_hash(&bytes) {
                Some(hash) if Self::artifact_path(dir, &hash) == path => found.push((hash, bytes)),
                _ => {
                    let _ = fs::remove_file(path);
                }
            }
        }
        found.sort_by_key(|(hash, _)| *hash);
        found
    }

    /// Persisted artifacts by file name and leading bytes, without reading or
    /// hashing their contents; cheap enough for an unauthenticated status call.
    pub fn persisted_summary(&self) -> Vec<(Hash, ArtifactKind)> {
        use std::io::Read as _;
        let Some(dir) = &self.dir else {
            return Vec::new();
        };
        let Ok(entries) = fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(stem) = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".bin"))
            else {
                continue;
            };
            let Some(hash) = parse_hex_hash(stem) else {
                continue;
            };
            let mut magic = [0_u8; 4];
            let kind = fs::File::open(&path)
                .and_then(|mut file| file.read_exact(&mut magic))
                .map_or(ArtifactKind::Unknown, |()| ArtifactKind::of(&magic));
            found.push((hash, kind));
        }
        found.sort_by_key(|(hash, _)| *hash);
        found
    }

    /// Bytes of a complete or persisted artifact.
    #[must_use]
    pub fn artifact(&self, hash: &Hash) -> Option<Arc<Vec<u8>>> {
        if let Some(bytes) = self
            .complete
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .artifacts
            .get(hash)
        {
            return Some(Arc::clone(bytes));
        }
        let dir = self.dir.as_ref()?;
        let bytes = fs::read(Self::artifact_path(dir, hash)).ok()?;
        (content_hash(&bytes) == Some(*hash)).then(|| Arc::new(bytes))
    }
}
