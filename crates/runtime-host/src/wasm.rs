//! WASM dynamic runtime host.
//!
//! Loads the `neutrin0-evm-runtime-master` cdylib in wasmtime,
//! drives `apply_block` against a borrowed state [`Trie`], and collects
//! the read / write set as a
//! [`StateWitness`](neutrin0_runtime_abi::StateWitness) (with on-path
//! trie nodes) that the SP1 Guest can replay.
//!
//! This is the non-proven execution path full nodes use for RPC,
//! mempool tx admission, and dry-run / witness generation. The proven
//! path (SP1) uses the same shared `apply_block` against
//! [`WitnessState`](neutrin0_runtime_core::WitnessState) so the two
//! paths cannot drift.
//!
//! [`Trie`]: neutrin0_trie::Trie

// FFI plumbing module — most lint allowances here cover the host-side
// cousins of those carried by `master::wasm_abi`.
#![allow(
    clippy::cast_possible_truncation, // usize <-> u32 conversions for wasm linear-memory addresses.
    clippy::cast_sign_loss,
    clippy::cast_lossless
)]

use neutrin0_runtime_abi::{
    ALLOCATE_ENTRYPOINT, APPLY_BLOCK_ENTRYPOINT, DEALLOCATE_ENTRYPOINT, MEMORY_EXPORT,
    QUERY_ENTRYPOINT, TxValidityDecodeError, VALIDATE_TX_ENTRYPOINT,
};
use wasmtime::{
    Config, Engine, ExternType, InstancePre, Linker, Module, Store, Trap, TypedFunc, ValType,
};

use crate::Sp1HostError;

mod calls;
mod host_imports;
mod host_state;
mod limits;

pub use limits::{DEFAULT_BLOCK_FUEL, WasmLimits};

use host_imports::register_host_imports;
use host_state::{HostState, guest_slice};

/// Embedded Osaka EVM runtime master cdylib, compiled in by `build.rs`.
pub const EVM_MASTER_WASM: &[u8] = include_bytes!(env!("NEUTRIN0_EVM_MASTER_WASM"));

/// Errors produced by the WASM dynamic runtime host.
#[derive(Debug, thiserror::Error)]
pub enum WasmError {
    /// Wasmtime reported an engine/module/instantiation/trap error.
    #[error("wasmtime error: {0}")]
    Wasmtime(String),
    /// Borsh codec error on the host side.
    #[error("borsh codec error: {0}")]
    Codec(String),
    /// The runtime returned a [`TxValidity`] blob the host could not
    /// decode (wrong length, unknown code, ...). Indicates a host /
    /// runtime ABI skew.
    ///
    /// [`TxValidity`]: neutrin0_runtime_abi::TxValidity
    #[error("invalid TxValidity from runtime: {0:?}")]
    InvalidTxValidity(TxValidityDecodeError),
    /// The call exhausted its fuel or memory budget from [`WasmLimits`].
    #[error("wasm resource limit exceeded: {0}")]
    ResourceLimit(String),
    /// The pre-state trie does not hold every node on an accessed path, so
    /// the run can neither be trusted nor witnessed.
    #[error("state unavailable: {0}")]
    State(String),
}

impl From<WasmError> for Sp1HostError {
    fn from(err: WasmError) -> Self {
        match err {
            WasmError::Wasmtime(msg)
            | WasmError::Codec(msg)
            | WasmError::ResourceLimit(msg)
            | WasmError::State(msg) => Self::Codec(msg),
            WasmError::InvalidTxValidity(decode_err) => Self::Codec(format!("{decode_err:?}")),
        }
    }
}

fn wt_err<E: std::fmt::Display>(err: E) -> WasmError {
    WasmError::Wasmtime(err.to_string())
}

/// Classify a trap raised while running a guest entrypoint.
fn trap_err(err: wasmtime::Error) -> WasmError {
    match err.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => WasmError::ResourceLimit("fuel exhausted".to_owned()),
        Some(Trap::MemoryOutOfBounds | Trap::UnreachableCodeReached) => {
            WasmError::ResourceLimit(format!("guest trapped: {err}"))
        }
        _ => wt_err(err),
    }
}

fn codec_err<E: std::fmt::Display>(err: E) -> WasmError {
    WasmError::Codec(err.to_string())
}

/// Check the complete ABI before accepting a runtime artifact for installation.
fn validate_runtime_exports(module: &Module) -> Result<(), WasmError> {
    match module.get_export(MEMORY_EXPORT) {
        Some(ExternType::Memory(memory)) if !memory.is_64() && !memory.is_shared() => {}
        _ => return Err(wt_err("runtime must export unshared 32-bit memory")),
    }
    let functions: [(&str, &[ValType], &[ValType]); 5] = [
        (ALLOCATE_ENTRYPOINT, &[ValType::I32], &[ValType::I32]),
        (DEALLOCATE_ENTRYPOINT, &[ValType::I32, ValType::I32], &[]),
        (
            APPLY_BLOCK_ENTRYPOINT,
            &[ValType::I32, ValType::I32],
            &[ValType::I64],
        ),
        (
            VALIDATE_TX_ENTRYPOINT,
            &[ValType::I32, ValType::I32],
            &[ValType::I64],
        ),
        (
            QUERY_ENTRYPOINT,
            &[ValType::I32, ValType::I32],
            &[ValType::I64],
        ),
    ];
    for (name, params, results) in functions {
        let Some(ExternType::Func(function)) = module.get_export(name) else {
            return Err(wt_err(format!("missing runtime function export `{name}`")));
        };
        if function.params().len() != params.len()
            || function.results().len() != results.len()
            || !function
                .params()
                .zip(params)
                .all(|(actual, expected)| ValType::eq(&actual, expected))
            || !function
                .results()
                .zip(results)
                .all(|(actual, expected)| ValType::eq(&actual, expected))
        {
            return Err(wt_err(format!(
                "invalid runtime function signature for `{name}`"
            )));
        }
    }
    Ok(())
}

/// Compiled WASM dynamic runtime. Hold one of these per process; it is
/// safe to share across threads (every call creates a fresh `Store`
/// from the pre-linked module).
pub struct WasmRuntime {
    artifact: std::sync::Arc<[u8]>,
    code_hash: neutrin0_primitives::Hash,
    engine: Engine,
    /// The module linked against the host imports once at construction.
    pre: InstancePre<HostState>,
    limits: WasmLimits,
}

impl WasmRuntime {
    /// Resident compiled image plus retained source bytes, excluding per-call stores.
    #[must_use]
    pub fn resident_program_bytes(&self) -> usize {
        let image = self.pre.module().image_range();
        image
            .end
            .addr()
            .saturating_sub(image.start.addr())
            .saturating_add(self.artifact.len())
    }

    /// Compile a runtime from raw wasm bytes (e.g. an on-chain runtime
    /// upgrade payload) and link it against the host imports. Use
    /// [`Self::embedded`] for the embedded [`EVM_MASTER_WASM`].
    ///
    /// # Errors
    /// Returns [`WasmError::Wasmtime`] if wasmtime cannot compile the
    /// module, resolve its imports or validate its required ABI exports.
    pub fn new(wasm: &[u8]) -> Result<Self, WasmError> {
        if wasm.is_empty() || wasm.len() > neutrin0_consensus_types::MAX_PROGRAM_BYTES as usize {
            return Err(WasmError::ResourceLimit(
                "runtime source exceeds protocol artifact limit".into(),
            ));
        }
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).map_err(wt_err)?;
        let module = Module::new(&engine, wasm).map_err(wt_err)?;
        let image = module.image_range();
        if image
            .end
            .addr()
            .saturating_sub(image.start.addr())
            .saturating_add(wasm.len())
            > 128 * 1024 * 1024
        {
            return Err(WasmError::ResourceLimit(
                "compiled runtime image exceeds 128 MiB".into(),
            ));
        }
        validate_runtime_exports(&module)?;
        let mut linker: Linker<HostState> = Linker::new(&engine);
        register_host_imports(&mut linker)?;
        let pre = linker.instantiate_pre(&module).map_err(wt_err)?;
        Ok(Self {
            artifact: std::sync::Arc::from(wasm),
            code_hash: neutrin0_primitives::blake3_256(wasm),
            engine,
            pre,
            limits: WasmLimits::default(),
        })
    }

    /// Exact artifact bytes whose BLAKE3 hash is this runtime's identity.
    #[must_use]
    pub fn artifact(&self) -> &[u8] {
        &self.artifact
    }

    /// Replace the per-call fuel and memory budgets.
    ///
    /// # Errors
    /// Returns [`WasmError::Codec`] when `limits` fails
    /// [`WasmLimits::validate`].
    pub fn with_limits(mut self, limits: WasmLimits) -> Result<Self, WasmError> {
        limits
            .validate()
            .map_err(|reason| WasmError::Codec(reason.to_owned()))?;
        self.limits = limits;
        Ok(self)
    }

    /// BLAKE3 content hash of the exact WASM artifact this runtime compiled.
    #[must_use]
    pub const fn code_hash(&self) -> neutrin0_primitives::Hash {
        self.code_hash
    }

    /// Budgets applied to every call.
    #[must_use]
    pub const fn limits(&self) -> WasmLimits {
        self.limits
    }

    /// Compile the embedded runtime master.
    ///
    /// # Errors
    /// See [`Self::new`].
    pub fn embedded() -> Result<Self, WasmError> {
        Self::new(EVM_MASTER_WASM)
    }

    /// Run one guest entrypoint in a fresh store whose memory and fuel
    /// are capped: copy `input` into a guest allocation, call `entry`,
    /// copy its packed `(ptr, len)` output back out and free both
    /// buffers. Returns the output bytes and the final host state.
    fn invoke(
        &self,
        entry: &str,
        input: &[u8],
        host: HostState,
        fuel: u64,
    ) -> Result<(Vec<u8>, HostState), WasmError> {
        let mut store = Store::new(&self.engine, host);
        store.limiter(|state| &mut state.limits);
        store.set_fuel(fuel).map_err(wt_err)?;

        let instance = self.pre.instantiate(&mut store).map_err(wt_err)?;
        let memory = instance
            .get_memory(&mut store, MEMORY_EXPORT)
            .ok_or_else(|| WasmError::Wasmtime("missing memory export".into()))?;

        let input_len = u32::try_from(input.len())
            .map_err(|_| WasmError::Codec("input exceeds the guest address space".to_owned()))?;
        let allocate: TypedFunc<u32, u32> = instance
            .get_typed_func(&mut store, ALLOCATE_ENTRYPOINT)
            .map_err(wt_err)?;
        let input_ptr = allocate.call(&mut store, input_len).map_err(trap_err)?;
        memory
            .write(&mut store, input_ptr as usize, input)
            .map_err(wt_err)?;

        let entry_fn: TypedFunc<(u32, u32), u64> =
            instance.get_typed_func(&mut store, entry).map_err(wt_err)?;
        let packed = entry_fn
            .call(&mut store, (input_ptr, input_len))
            .map_err(trap_err)?;
        let output_ptr = (packed >> 32) as u32;
        let output_len = (packed & 0xFFFF_FFFF) as u32;

        // Bound the guest-chosen range before copying, so a hostile length
        // cannot size a host allocation.
        let output = guest_slice(memory.data(&store), output_ptr, output_len)
            .ok_or_else(|| WasmError::Wasmtime("output range outside guest memory".to_owned()))?
            .to_vec();

        let deallocate = instance
            .get_typed_func::<(u32, u32), ()>(&mut store, DEALLOCATE_ENTRYPOINT)
            .map_err(wt_err)?;
        deallocate
            .call(&mut store, (input_ptr, input_len))
            .map_err(trap_err)?;
        deallocate
            .call(&mut store, (output_ptr, output_len))
            .map_err(trap_err)?;

        Ok((output, store.into_data()))
    }
}

#[cfg(test)]
mod tests;
