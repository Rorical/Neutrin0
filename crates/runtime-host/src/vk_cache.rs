//! On-disk verifying-key cache shared by every program, keyed by SP1 circuit
//! version and ELF hash, and the fact-receipt directories kept beside it.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Crate-visible helpers of a private module; `pub` would be unreachable."
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use sp1_sdk::{Elf, ProvingKey, SP1_CIRCUIT_VERSION, SP1ProvingKey, SP1VerifyingKey};

use crate::{ProgramProver, Sp1HostError, backend, guarded, sdk_err};

// All programs share the same circuit-version/ELF-addressed cache. Reconstruct
// the SDK key from its verification-key material without repeating ROM setup.
pub(super) fn cached_proving_key<P>(prover: &P, elf: Elf) -> Result<SP1ProvingKey, Sp1HostError>
where
    P: ProgramProver<ProvingKey = SP1ProvingKey>,
{
    // One bounded flight for local preprocessing. Recheck disk after acquiring
    // it so concurrent cold setup of the same ELF does not repeat ROM work.
    static SETUP: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _flight = SETUP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(vk) = load_cached_vk_for(&elf) {
        return Ok(SP1ProvingKey::new(vk, elf));
    }
    let pk = prover.submit(backend::SubmissionPriority::Normal, || {
        prover.setup(elf.clone()).map_err(sdk_err)
    })?;
    let _ = save_cached_vk_for(&elf, pk.verifying_key());
    Ok(pk)
}

/// Cache directory a node selected inside its own data directory.
static CACHE_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Verifying keys kept on disk, newest first; each is a few kilobytes.
const MAX_CACHED_VKS: usize = 64;

/// Fact-receipt directories kept, newest first; each holds at most the fact
/// cache's byte budget. Only one fact program is pinned per chain specification.
const MAX_FACT_DIRECTORIES: usize = 2;

/// Keep the verifying-key and fact-receipt caches under `dir`.
///
/// A node keeps them in its data directory instead of the build tree, and
/// this drops what earlier SP1 circuits or superseded keys left there. Only
/// the first call takes effect; a node calls it before proving.
pub fn set_cache_dir(dir: PathBuf) {
    if CACHE_DIR.set(dir).is_ok() {
        prune_cache(&cache_dir());
    }
}

/// Remove entries of other circuit versions and all but the newest bounded
/// sets of verifying keys and fact directories. Everything here is a cache.
fn prune_cache(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let current_vk = format!("vk-sp1-{SP1_CIRCUIT_VERSION}-");
    let current_facts = format!("facts-{SP1_CIRCUIT_VERSION}-");
    let mut vks = Vec::new();
    let mut facts = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok();
        let path = entry.path();
        if name.starts_with("vk-sp1-") {
            if name.starts_with(&current_vk) {
                vks.push((modified, path));
            } else {
                let _ = fs::remove_file(path);
            }
        } else if name.starts_with("facts-") {
            if name.starts_with(&current_facts) {
                facts.push((modified, path));
            } else {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
    for path in oldest_beyond(vks, MAX_CACHED_VKS) {
        let _ = fs::remove_file(path);
    }
    for path in oldest_beyond(facts, MAX_FACT_DIRECTORIES) {
        let _ = fs::remove_dir_all(path);
    }
}

/// The entries after the `keep` most recently modified ones.
fn oldest_beyond(
    mut entries: Vec<(Option<std::time::SystemTime>, PathBuf)>,
    keep: usize,
) -> impl Iterator<Item = PathBuf> {
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    entries.into_iter().skip(keep).map(|(_, path)| path)
}

pub(super) fn cache_dir() -> PathBuf {
    if let Some(dir) = CACHE_DIR.get() {
        return dir.clone();
    }
    if let Ok(env_dir) = std::env::var("NEUTRIN0_SP1_CACHE_DIR") {
        return PathBuf::from(env_dir);
    }
    let base = std::env::var("CARGO_TARGET_DIR").map_or_else(
        |_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"),
        PathBuf::from,
    );
    base.join("neutrin0-sp1-cache")
}

fn cache_path_for(elf: &Elf) -> PathBuf {
    let elf_hash = blake3::hash(elf).to_hex();
    let file = format!("vk-sp1-{SP1_CIRCUIT_VERSION}-{elf_hash}.bin");
    cache_dir().join(file)
}

/// The cached key for `elf`, or `None` when the file is missing or damaged.
///
/// A key that decodes but was altered on disk would otherwise be trusted for
/// proving and Guest authentication until an operator deleted the file; the
/// checksum turns that into one repeated setup.
pub(super) fn load_cached_vk_for(elf: &Elf) -> Option<SP1VerifyingKey> {
    let path = cache_path_for(elf);
    let file = fs::read(&path).ok()?;
    let bytes = open_sealed(&file)?;
    guarded(|| {
        neutrin0_prover_chunk::receipt_codec::decode::<SP1VerifyingKey, { 8 * 1024 * 1024 }>(bytes)
    })
    .ok()?
    .ok()
}

/// `bytes` prefixed with their BLAKE3 hash.
fn seal(bytes: &[u8]) -> Vec<u8> {
    let mut sealed = Vec::with_capacity(32 + bytes.len());
    sealed.extend_from_slice(blake3::hash(bytes).as_bytes());
    sealed.extend_from_slice(bytes);
    sealed
}

/// The payload of a [`seal`]ed file whose hash still matches.
fn open_sealed(file: &[u8]) -> Option<&[u8]> {
    let (checksum, bytes) = file.split_at_checked(32)?;
    (blake3::hash(bytes).as_bytes() == checksum).then_some(bytes)
}

fn save_cached_vk_for(elf: &Elf, vk: &SP1VerifyingKey) -> Result<(), std::io::Error> {
    let path = cache_path_for(elf);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = neutrin0_prover_chunk::receipt_codec::encode(vk)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    write_atomic(&path, &seal(&bytes))
}

/// Distinguishes this process's concurrent temporary files.
static TEMP_SERIAL: AtomicU64 = AtomicU64::new(0);

/// Replace `path` with `bytes` atomically. Each call writes its own
/// temporary file, named by process id and a per-process serial, then renames
/// it over `path`, so concurrent writers never share or truncate one another's
/// temporary file and readers only ever see a complete write.
pub(super) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let serial = TEMP_SERIAL.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("{}-{serial}.tmp", std::process::id()));
    let written = fs::write(&tmp, bytes).and_then(|()| fs::rename(&tmp, path));
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

#[cfg(test)]
mod tests;
