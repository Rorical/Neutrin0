//! [`BlockExecutor`] backed by the WASM dynamic runtime.
//!
//! Drives the embedded EVM runtime master cdylib through
//! wasmtime, mutates the engine's state trie in place with the
//! block's writes, and emits a persisted [`BlockWitness`] for proving.
//!
//! Exact `EvidenceProof` receipts are verified before WASM mutation. The emitted
//! witness bundle is replayed by the matching SP1 block Guest.
//!
//! [`BlockExecutor`]: neutrin0_proof_system::executor::BlockExecutor

use thiserror::Error;

use neutrin0_proof_system::artifacts::{ArtifactIdentity, ProgramArtifactLoader};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, RwLock};

use neutrin0_primitives::Hash;

use crate::wasm::{WasmError, WasmLimits, WasmRuntime};

mod block_executor;
mod runtime_cache;
mod witness;

pub use witness::{BlockWitness, decode_witness_bundle, encode_witness_bundle};

pub(crate) use witness::ProvingInputWriter;

use runtime_cache::{MAX_SINGLE_RUNTIME_BYTES, RuntimeCache, RuntimeEntry};

/// Errors produced by [`WasmExecutor::execute_block`].
///
/// [`WasmExecutor::execute_block`]: neutrin0_proof_system::executor::BlockExecutor::execute_block
#[derive(Debug, Error)]
pub enum ExecutorError {
    /// Wasmtime / WASM runtime failure during dry-run.
    #[error("WASM dry-run failed: {0}")]
    Wasm(String),
    /// Borsh failure encoding the prover stdin payload.
    #[error("borsh codec error: {0}")]
    Codec(String),
    /// The block names a runtime artifact this executor has not installed.
    #[error("runtime {} is not installed", hex_hash(.0))]
    UnknownRuntime(Hash),
}

/// Lowercase-hex rendering of a 32-byte hash for error messages.
const fn hex_hash(hash: &Hash) -> blake3::Hash {
    blake3::Hash::from_bytes(*hash)
}

impl From<WasmError> for ExecutorError {
    fn from(err: WasmError) -> Self {
        Self::Wasm(err.to_string())
    }
}

/// Production block executor: WASM dynamic runtimes + witness emission.
///
/// Holds one compiled [`WasmRuntime`] per runtime code hash. The embedded
/// EVM runtime master cdylib is installed at construction; upgrade
/// runtimes distributed on chain are installed later with
/// [`Self::install_runtime`] (design 20). Each call picks the runtime the
/// engine names for the block, so a program switch at a chunk boundary
/// needs no new process. `execute_block` creates a fresh wasmtime `Store`
/// per call so concurrent execution on different threads is safe.
pub struct WasmExecutor {
    runtimes: Mutex<RuntimeCache>,
    compilation: Mutex<()>,
    artifact_loader: RwLock<Option<ProgramArtifactLoader>>,
    limits: WasmLimits,
}

impl WasmExecutor {
    /// Wrap an explicit [`WasmRuntime`] under its code hash. Use
    /// [`Self::embedded`] for the embedded runtime cdylib.
    #[must_use]
    pub fn new(wasm: WasmRuntime) -> Self {
        let code_hash = wasm.code_hash();
        let limits = wasm.limits();
        let bytes = wasm.resident_program_bytes();
        Self {
            runtimes: Mutex::new(RuntimeCache {
                entries: HashMap::from([(
                    code_hash,
                    RuntimeEntry {
                        runtime: Arc::new(wasm),
                        touched: 0,
                        bytes,
                    },
                )]),
                warm: BTreeSet::from([code_hash]),
                sources: BTreeSet::from([code_hash]),
                ..RuntimeCache::default()
            }),
            compilation: Mutex::new(()),
            artifact_loader: RwLock::new(None),
            limits,
        }
    }

    /// Build with the embedded runtime master cdylib and default budgets.
    ///
    /// # Errors
    /// Surfaces [`WasmError`] if wasmtime fails to compile the embedded module.
    pub fn embedded() -> Result<Self, WasmError> {
        Self::embedded_with_limits(WasmLimits::default())
    }

    /// Build with the embedded runtime master cdylib and explicit per-call
    /// fuel and memory budgets.
    ///
    /// # Errors
    /// Surfaces [`WasmError`] if wasmtime fails to compile the embedded
    /// module or `limits` are invalid.
    pub fn embedded_with_limits(limits: WasmLimits) -> Result<Self, WasmError> {
        Ok(Self::new(WasmRuntime::embedded()?.with_limits(limits)?))
    }

    /// Compile and install a runtime artifact under its BLAKE3 code hash,
    /// with this executor's limits. Idempotent for an already installed hash.
    ///
    /// # Errors
    /// Surfaces [`WasmError`] when the bytes are not a loadable runtime.
    pub fn install_runtime(&self, wasm: &[u8]) -> Result<Hash, WasmError> {
        if wasm.is_empty() || wasm.len() > neutrin0_consensus_types::MAX_PROGRAM_BYTES as usize {
            return Err(WasmError::ResourceLimit(
                "runtime source exceeds protocol artifact limit".into(),
            ));
        }
        let _compilation = self
            .compilation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let code_hash = neutrin0_primitives::blake3_256(wasm);
        if self.has_runtime(&code_hash) {
            return Ok(code_hash);
        }
        self.runtimes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reserve(0)?;
        let runtime = WasmRuntime::new(wasm)?.with_limits(self.limits)?;
        let bytes = runtime.resident_program_bytes();
        if bytes > MAX_SINGLE_RUNTIME_BYTES {
            return Err(WasmError::ResourceLimit(
                "compiled runtime image exceeds 128 MiB".into(),
            ));
        }
        let mut cache = self
            .runtimes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.reserve(bytes)?;
        let touched = cache.clock;
        cache.entries.insert(
            code_hash,
            RuntimeEntry {
                runtime: Arc::new(runtime),
                touched,
                bytes,
            },
        );
        cache.sources.insert(code_hash);
        drop(cache);
        Ok(code_hash)
    }

    /// `true` when a runtime with this code hash is installed.
    #[must_use]
    pub fn has_runtime(&self, code_hash: &Hash) -> bool {
        let cache = self
            .runtimes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.entries.contains_key(code_hash)
            || cache
                .retired
                .iter()
                .filter_map(|(lease, _)| lease.upgrade())
                .any(|runtime| runtime.code_hash() == *code_hash)
    }

    /// Installed runtime code hashes.
    #[must_use]
    pub fn runtime_hashes(&self) -> Vec<Hash> {
        self.runtimes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .keys()
            .copied()
            .collect()
    }

    fn runtime(&self, code_hash: &Hash) -> Result<Arc<WasmRuntime>, ExecutorError> {
        {
            let mut cache = self
                .runtimes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cache.clock = cache.clock.saturating_add(1);
            let touched = cache.clock;
            if let Some(entry) = cache.entries.get_mut(code_hash) {
                entry.touched = touched;
                return Ok(Arc::clone(&entry.runtime));
            }
            if let Some(runtime) = cache
                .retired
                .iter()
                .filter_map(|(lease, _)| lease.upgrade())
                .find(|runtime| runtime.code_hash() == *code_hash)
            {
                return Ok(runtime);
            }
            if !cache.sources.contains(code_hash) {
                return Err(ExecutorError::UnknownRuntime(*code_hash));
            }
        }
        let loader = self
            .artifact_loader
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let bytes = loader
            .and_then(|reader| reader(ArtifactIdentity::Runtime(*code_hash)))
            .ok_or(ExecutorError::UnknownRuntime(*code_hash))?;
        if neutrin0_primitives::blake3_256(&bytes) != *code_hash {
            return Err(ExecutorError::UnknownRuntime(*code_hash));
        }
        self.install_runtime(&bytes)?;
        self.runtimes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .get(code_hash)
            .map(|entry| Arc::clone(&entry.runtime))
            .ok_or(ExecutorError::UnknownRuntime(*code_hash))
    }
}

#[cfg(test)]
mod tests;
