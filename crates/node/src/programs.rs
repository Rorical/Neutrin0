//! On-chain program distribution (design 20).
//!
//! Upgrade artifacts, the runtime WASM and the four Guest ELFs, travel in the
//! block body's program lane as bounded pieces committed by content hash.
//! This store reassembles pieces from imported blocks, accepts an artifact
//! only when its pieces reproduce the announced content hash (a commitment
//! to the artifact length and the Merkle root of its piece hashes), persists
//! accepted artifacts beside the database, and feeds locally published files
//! into produced blocks piece by piece.
//!
//! Nothing here decides what to trust: governance names content hashes and
//! Guest digests, the node installs an artifact only when governance named
//! it, and SP1 setup of an installed ELF is compared against the approved
//! digest before any proof is attempted under it.

use std::{
    collections::{BTreeMap, VecDeque},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use neutrin0_consensus_types::{
    MAX_PROGRAM_BYTES, MAX_PROGRAM_PIECE_BYTES, ProgramPiece, evidence::MerkleOpening,
    program_content_hash,
};
use neutrin0_primitives::{Hash, blake3_256, merkle_root_of_hashes};
use neutrin0_proof_system::artifacts::ArtifactIdentity;

mod assembly;
mod persisted;
mod publication;
mod staging;

pub use staging::ProgramStaging;

/// Lowercase hex of a content hash.
#[must_use]
pub fn hex_hash(hash: &Hash) -> String {
    hex::encode(hash)
}

/// Split an artifact into authenticated pieces. `None` when the artifact is
/// empty or over the protocol bound.
#[must_use]
pub fn split_into_pieces(bytes: &[u8]) -> Option<Vec<ProgramPiece>> {
    if bytes.is_empty() || bytes.len() > MAX_PROGRAM_BYTES as usize {
        return None;
    }
    let total_len = u32::try_from(bytes.len()).ok()?;
    let leaves: Vec<Hash> = bytes
        .chunks(MAX_PROGRAM_PIECE_BYTES)
        .map(blake3_256)
        .collect();
    let root = merkle_root_of_hashes(&leaves);
    bytes
        .chunks(MAX_PROGRAM_PIECE_BYTES)
        .enumerate()
        .map(|(index, chunk)| {
            Some(ProgramPiece {
                root,
                total_len,
                offset: u32::try_from(index * MAX_PROGRAM_PIECE_BYTES).ok()?,
                bytes: chunk.to_vec(),
                opening: MerkleOpening::build(&leaves, index)?,
            })
        })
        .collect()
}

/// Parse the lowercase hex produced by [`hex_hash`].
#[must_use]
pub fn parse_hex_hash(text: &str) -> Option<Hash> {
    hex::FromHex::from_hex(text).ok()
}

/// Content hash governance names for an artifact. `None` for an empty or
/// oversized artifact.
#[must_use]
pub fn content_hash(bytes: &[u8]) -> Option<Hash> {
    let total_len = u32::try_from(bytes.len()).ok()?;
    if bytes.is_empty() || total_len > MAX_PROGRAM_BYTES {
        return None;
    }
    let leaves: Vec<Hash> = bytes
        .chunks(MAX_PROGRAM_PIECE_BYTES)
        .map(blake3_256)
        .collect();
    Some(program_content_hash(
        total_len,
        merkle_root_of_hashes(&leaves),
    ))
}

/// Memory reserved for artifacts still being assembled, counted by their
/// declared lengths so a half-received artifact cannot exceed its share.
const MAX_PARTIAL_BYTES: u64 = 128 * 1024 * 1024;
/// Complete, verified artifacts kept in memory until installed.
const MAX_COMPLETE_ARTIFACTS: usize = 8;
/// Bytes of complete artifacts kept in memory until installed.
const MAX_COMPLETE_BYTES: usize = 64 * 1024 * 1024;
/// Cold source capacity for nodes deliberately running without a data directory.
const MAX_MEMORY_SOURCES: usize = 32;
const MAX_MEMORY_SOURCE_BYTES: usize = 256 * 1024 * 1024;
static NEXT_TEMP_FILE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// What an artifact's leading bytes say it is.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactKind {
    /// A `\0asm` WebAssembly module: a runtime.
    Wasm,
    /// A `\x7fELF` executable: an SP1 Guest.
    Elf,
    /// Neither; never installed.
    Unknown,
}

impl ArtifactKind {
    /// Classify by magic bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        if bytes.starts_with(b"\0asm") {
            Self::Wasm
        } else if bytes.starts_with(b"\x7fELF") {
            Self::Elf
        } else {
            Self::Unknown
        }
    }
}

struct Partial {
    total_len: u32,
    received: BTreeMap<u32, Vec<u8>>,
    bytes: usize,
}

/// A locally published file being streamed into produced blocks.
struct Publishing {
    path: PathBuf,
    content_hash: Hash,
    pieces: Vec<ProgramPiece>,
    next: usize,
}

/// Observable store state for operators.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProgramStoreStatus {
    /// `(content hash, bytes received, total bytes)` of artifacts in flight.
    pub assembling: Vec<(Hash, u32, u32)>,
    /// Complete, verified artifacts not yet installed.
    pub complete: Vec<Hash>,
    /// Artifacts persisted on disk, by content hash and kind.
    pub persisted: Vec<(Hash, ArtifactKind)>,
    /// `(content hash, pieces sent, total pieces)` of the file being published.
    pub publishing: Option<(Hash, u32, u32)>,
    /// Files queued for publication after the current one.
    pub publish_queue: Vec<String>,
}

/// Complete, verified artifacts awaiting installation, evicted in completion
/// order so a fresh artifact is never the first to go.
struct Completed {
    artifacts: BTreeMap<Hash, Arc<Vec<u8>>>,
    /// Content hashes in completion order, oldest first.
    order: VecDeque<Hash>,
    /// Total length of `artifacts`.
    bytes: usize,
}

struct MemorySources {
    artifacts: BTreeMap<Hash, Arc<Vec<u8>>>,
    identities: BTreeMap<ArtifactIdentity, Hash>,
    bytes: usize,
}

impl MemorySources {
    const fn empty() -> Self {
        Self {
            artifacts: BTreeMap::new(),
            identities: BTreeMap::new(),
            bytes: 0,
        }
    }

    fn remove(&mut self, hash: &Hash) {
        if let Some(bytes) = self.artifacts.remove(hash) {
            self.bytes -= bytes.len();
        }
        self.identities.retain(|_, content| content != hash);
    }
}

impl Completed {
    const fn empty() -> Self {
        Self {
            artifacts: BTreeMap::new(),
            order: VecDeque::new(),
            bytes: 0,
        }
    }

    fn remove(&mut self, hash: &Hash) {
        if let Some(bytes) = self.artifacts.remove(hash) {
            self.bytes -= bytes.len();
            self.order.retain(|entry| entry != hash);
        }
    }

    /// Keep a verified artifact, evicting the oldest completions until the
    /// memory bounds hold again. Artifacts in `reported` were completed by
    /// the same absorption, which hands them to the installer, so they are
    /// never evicted; when they alone fill the bounds the new artifact is
    /// refused instead and `false` is returned.
    fn insert(&mut self, hash: Hash, bytes: Vec<u8>, reported: &[Hash]) -> bool {
        if self.artifacts.contains_key(&hash) {
            return true;
        }
        self.bytes += bytes.len();
        self.artifacts.insert(hash, Arc::new(bytes));
        self.order.push_back(hash);
        while self.artifacts.len() > MAX_COMPLETE_ARTIFACTS || self.bytes > MAX_COMPLETE_BYTES {
            let victim = self
                .order
                .iter()
                .copied()
                .find(|entry| *entry != hash && !reported.contains(entry))
                .unwrap_or(hash);
            self.remove(&victim);
            if victim == hash {
                return false;
            }
        }
        true
    }
}

/// Reassembly, persistence and publication of program artifacts.
pub struct ProgramStore {
    dir: Option<PathBuf>,
    partial: Mutex<BTreeMap<Hash, Partial>>,
    complete: Mutex<Completed>,
    publishing: Mutex<Option<Publishing>>,
    persistence: Mutex<()>,
    memory_sources: Mutex<MemorySources>,
}

impl ProgramStore {
    /// Memory-only store with bounded cold sources; nothing survives process exit.
    #[must_use]
    pub const fn in_memory() -> Self {
        Self {
            dir: None,
            partial: Mutex::new(BTreeMap::new()),
            complete: Mutex::new(Completed::empty()),
            publishing: Mutex::new(None),
            persistence: Mutex::new(()),
            memory_sources: Mutex::new(MemorySources::empty()),
        }
    }

    /// Store rooted at `dir`: installed artifacts live in `dir`, files dropped
    /// into `dir/publish` are streamed into produced blocks and moved to
    /// `dir/published` once their last piece has been produced.
    ///
    /// Artifacts and identities are written to a temporary file that is
    /// renamed into place; a crash in between leaves the temporary file, which
    /// nothing reads, so opening removes it. The node holds its database lock
    /// first, so no other process writes here meanwhile.
    ///
    /// # Errors
    /// Returns the I/O error of creating the directories or removing a
    /// leftover temporary file.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        fs::create_dir_all(dir.join("publish"))?;
        fs::create_dir_all(dir.join("published"))?;
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if matches!(
                path.extension().and_then(std::ffi::OsStr::to_str),
                Some("tmp" | "pending")
            ) {
                fs::remove_file(&path)?;
            }
        }
        Ok(Self {
            dir: Some(dir.to_path_buf()),
            partial: Mutex::new(BTreeMap::new()),
            complete: Mutex::new(Completed::empty()),
            publishing: Mutex::new(None),
            persistence: Mutex::new(()),
            memory_sources: Mutex::new(MemorySources::empty()),
        })
    }

    fn artifact_path(dir: &Path, hash: &Hash) -> PathBuf {
        dir.join(format!("{}.bin", hex_hash(hash)))
    }

    fn identity_path(dir: &Path, identity: ArtifactIdentity) -> PathBuf {
        let encoded = borsh::to_vec(&identity).expect("fixed program identity serialization");
        dir.join(format!("identity-{}.idx", hex::encode(encoded)))
    }
}

#[cfg(test)]
mod tests;
