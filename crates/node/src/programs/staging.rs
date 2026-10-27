//! Durable staging of content-authenticated artifacts.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use neutrin0_primitives::Hash;
use neutrin0_proof_system::artifacts::ArtifactIdentity;

use super::{
    MAX_MEMORY_SOURCE_BYTES, MAX_MEMORY_SOURCES, NEXT_TEMP_FILE, ProgramStore, content_hash,
};

/// Serialized durable staging of one artifact while its installation is checked.
///
/// Rejecting a stage removes only a new file owned by that stage; an existing
/// authenticated artifact remains available to previously installed programs.
pub struct ProgramStaging<'a> {
    store: &'a ProgramStore,
    hash: Hash,
    pub(super) created: bool,
    accepted: bool,
    _persistence: std::sync::MutexGuard<'a, ()>,
}

impl ProgramStaging<'_> {
    /// Persist the locally checked program identity before publishing the stage.
    /// # Errors
    /// Returns a disk error; callers retain the completed download for retry.
    pub fn accept_identity(mut self, identity: ArtifactIdentity) -> std::io::Result<()> {
        if let Some(dir) = &self.store.dir {
            let path = ProgramStore::identity_path(dir, identity);
            let temporary = path.with_extension("pending");
            fs::write(&temporary, self.hash)?;
            fs::File::open(&temporary)?.sync_all()?;
            fs::rename(temporary, path)?;
            fs::File::open(dir)?.sync_all()?;
        } else {
            self.store
                .memory_sources
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .identities
                .insert(identity, self.hash);
        }
        self.accepted = true;
        Ok(())
    }

    /// Keep the staged bytes after successful runtime or verifying-key checks.
    pub fn accept(mut self) {
        self.accepted = true;
    }
}

impl Drop for ProgramStaging<'_> {
    fn drop(&mut self) {
        if self.created && !self.accepted {
            if let Some(dir) = &self.store.dir {
                let _ = fs::remove_file(ProgramStore::artifact_path(dir, &self.hash));
                let _ = fs::File::open(dir).and_then(|directory| directory.sync_all());
            } else {
                self.store
                    .memory_sources
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&self.hash);
            }
        }
    }
}

impl ProgramStore {
    /// Register already authenticated retained source material without creating a session.
    /// # Errors
    /// Returns a disk error or rejects bytes whose content hash differs.
    pub fn remember_identity(
        &self,
        hash: &Hash,
        bytes: &[u8],
        identity: ArtifactIdentity,
    ) -> std::io::Result<()> {
        self.stage_authenticated(hash, bytes)?
            .accept_identity(identity)
    }

    /// Persist an artifact that governance named and the node installed, so
    /// a restart reinstalls exactly the approved set and nothing else.
    pub fn persist(&self, hash: &Hash, bytes: &[u8]) {
        let _ = self.persist_authenticated(hash, bytes);
    }

    /// Durably stage content-authenticated bytes before exposing their identity
    /// to execution/proof jobs or committing a snapshot which requires them.
    /// Guest key checks still precede registry insertion; a rejected program is
    /// removed by its installer. A memory-only store has no durable chain state.
    /// # Errors
    /// Rejects a content-hash mismatch or a failed write, sync or atomic rename.
    pub fn persist_authenticated(&self, hash: &Hash, bytes: &[u8]) -> std::io::Result<()> {
        self.stage_authenticated(hash, bytes)?.accept();
        Ok(())
    }

    /// Hold the store's persistence lock through the caller's installation
    /// decision. Dropping the returned guard rejects newly staged bytes without
    /// deleting a pre-existing or concurrently accepted artifact.
    /// # Errors
    /// Rejects content mismatches, unreadable existing files or failed durable writes.
    pub fn stage_authenticated(
        &self,
        hash: &Hash,
        bytes: &[u8],
    ) -> std::io::Result<ProgramStaging<'_>> {
        let persistence = self
            .persistence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if content_hash(bytes) != Some(*hash) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "program content hash mismatch",
            ));
        }
        let mut stage = ProgramStaging {
            store: self,
            hash: *hash,
            created: false,
            accepted: false,
            _persistence: persistence,
        };
        let Some(dir) = &self.dir else {
            self.stage_memory_source(&mut stage, hash, bytes)?;
            return Ok(stage);
        };
        let path = Self::artifact_path(dir, hash);
        match fs::read(&path) {
            Ok(existing) if existing == bytes => {
                fs::File::open(&path)?.sync_all()?;
                fs::File::open(dir)?.sync_all()?;
                return Ok(stage);
            }
            Ok(existing) if content_hash(&existing) == Some(*hash) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "existing authenticated program has different bytes",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        // From this point any file at the destination was absent or corrupt,
        // and all store mutations stay serialized until accept/drop.
        stage.created = true;
        write_artifact_durably(dir, &path, bytes)?;
        Ok(stage)
    }

    /// Keep the bytes in the bounded memory-only sources; the stage owns
    /// them only when this call inserted them.
    fn stage_memory_source(
        &self,
        stage: &mut ProgramStaging<'_>,
        hash: &Hash,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        let mut sources = self
            .memory_sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !sources.artifacts.contains_key(hash) {
            if sources.artifacts.len() >= MAX_MEMORY_SOURCES
                || sources.bytes.saturating_add(bytes.len()) > MAX_MEMORY_SOURCE_BYTES
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::OutOfMemory,
                    "bounded in-memory program sources are protected/full; configure a data directory",
                ));
            }
            sources.bytes += bytes.len();
            sources.artifacts.insert(*hash, Arc::new(bytes.to_vec()));
            stage.created = true;
        }
        drop(sources);
        Ok(())
    }

    /// Delete a persisted artifact the chain no longer names.
    pub fn forget_persisted(&self, hash: &Hash) {
        let _persistence = self
            .persistence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(dir) = &self.dir {
            let _ = fs::remove_file(Self::artifact_path(dir, hash));
        } else {
            self.memory_sources
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(hash);
        }
    }
}

/// Write `bytes` to a temporary file beside `path`, sync it and rename it
/// into place, syncing the directory; the temporary file never survives.
fn write_artifact_durably(dir: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let serial = NEXT_TEMP_FILE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("{}-{serial}.tmp", std::process::id()));
    let written = (|| {
        use std::io::Write as _;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        fs::File::open(dir)?.sync_all()
    })();
    let _ = fs::remove_file(tmp);
    written
}
