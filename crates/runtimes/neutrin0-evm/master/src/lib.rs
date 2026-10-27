#![cfg_attr(target_arch = "wasm32", no_std)]
#![allow(unsafe_code)] // WASM ABI exports use `#[unsafe(no_mangle)]` and raw FFI.

//! EVM runtime master binary.
//!
//! Two link targets:
//!
//! - `rlib` (native): used by host-side parity tests that exercise the
//!   shared STF against a pre-built [`StateWitness`](neutrin0_runtime_abi::StateWitness).
//! - `cdylib` for `wasm32-unknown-unknown`: loaded by the WASM dynamic
//!   runtime host. State access goes through host imports declared in
//!   the `neutrin0` import module.
//!
//! Both paths call the same `neutrin0_evm_runtime_core::apply_block`
//! function; only the [`StateBackend`](neutrin0_runtime_core::StateBackend) implementation differs.

extern crate alloc;

use alloc::vec::Vec;

use neutrin0_evm_runtime_core as runtime;
#[cfg(not(target_arch = "wasm32"))]
use neutrin0_runtime_abi::RuntimeBlockInput;
#[cfg(not(target_arch = "wasm32"))]
use neutrin0_runtime_abi::RuntimeBlockOutput;
#[cfg(not(target_arch = "wasm32"))]
use runtime::apply_block as core_apply_block;

/// Run the STF natively against a witness-backed state. Used by host-
/// side parity tests; the SP1 Guest is the production consumer of the
/// witness path.
///
/// Encoded input is `borsh((RuntimeBlockInput, StateWitness))`; encoded output
/// is `borsh(RuntimeBlockOutput)`.
#[cfg(not(target_arch = "wasm32"))]
pub fn apply_block_with_witness(input_bytes: &[u8]) -> Vec<u8> {
    use neutrin0_runtime_abi::StateWitness;
    use neutrin0_runtime_core::WitnessState;
    let (input, witness): (RuntimeBlockInput, StateWitness) =
        borsh::from_slice(input_bytes).expect("decode (RuntimeBlockInput, StateWitness)");
    let mut state = WitnessState::new(&witness).expect("witness must match claimed pre_state_root");
    let output: RuntimeBlockOutput = core_apply_block(&input, &mut state);
    borsh::to_vec(&output).expect("encode RuntimeBlockOutput")
}
// ---------------------------------------------------------------------------
// WASM dynamic runtime path.
// ---------------------------------------------------------------------------

/// WASM ABI exports. Compiled only into the `wasm32-unknown-unknown`
/// cdylib. State access is delegated to the WASM runtime host through
/// the `neutrin0` import module.
#[cfg(target_arch = "wasm32")]
#[allow(
    clippy::cast_possible_truncation, // usize == u32 on wasm32, casts are lossless here.
    clippy::cast_sign_loss,           // i32 returned by host imports is non-negative on the success path.
    clippy::cast_lossless,            // `as` is idiomatic for FFI plumbing.
    clippy::same_length_and_capacity, // `Vec::from_raw_parts` matches the leaking `vec!` pattern.
    clippy::wildcard_imports,         // FFI module is a closed surface; explicit imports add noise.
)]
mod wasm_abi {
    use super::*;
    use alloc::boxed::Box;
    use core::mem;
    use neutrin0_primitives::StateRoot;
    use neutrin0_runtime_core::StateBackend;

    #[link(wasm_import_module = "neutrin0")]
    unsafe extern "C" {
        /// Return the length of the value at `key`, or `-1` if absent.
        /// Records the read in the host's tracing set. The host stashes
        /// the value bytes pending a follow-up `state_read_into` call.
        fn state_read_len(key_ptr: u32, key_len: u32) -> i32;

        /// Copy the value stashed by the preceding `state_read_len`
        /// call into `value_ptr..value_ptr+len` in guest memory.
        fn state_read_into(value_ptr: u32);

        /// Write `value` at `key` in the host's overlay.
        fn state_write(key_ptr: u32, key_len: u32, value_ptr: u32, value_len: u32);

        /// Delete `key` from the host's overlay.
        fn state_delete(key_ptr: u32, key_len: u32);

        /// Write the live (pre-write) state root into `out_ptr..out_ptr+32`.
        fn pre_state_root(out_ptr: u32);

        /// Write the effective (post-write) state root into
        /// `out_ptr..out_ptr+32`.
        fn post_state_root(out_ptr: u32);
    }

    /// `StateBackend` that delegates to the WASM runtime host.
    struct WasmHostBackend;

    impl StateBackend for WasmHostBackend {
        fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
            unsafe {
                let len = state_read_len(key.as_ptr() as u32, key.len() as u32);
                if len < 0 {
                    return None;
                }
                let mut buf = alloc::vec![0u8; len as usize];
                state_read_into(buf.as_mut_ptr() as u32);
                Some(buf)
            }
        }

        fn write(&mut self, key: &[u8], value: Vec<u8>) {
            unsafe {
                state_write(
                    key.as_ptr() as u32,
                    key.len() as u32,
                    value.as_ptr() as u32,
                    value.len() as u32,
                );
            }
        }

        fn delete(&mut self, key: &[u8]) {
            unsafe {
                state_delete(key.as_ptr() as u32, key.len() as u32);
            }
        }

        fn pre_state_root(&self) -> StateRoot {
            let mut out = [0u8; 32];
            unsafe { pre_state_root(out.as_mut_ptr() as u32) };
            out
        }

        fn post_state_root(&self) -> StateRoot {
            let mut out = [0u8; 32];
            unsafe { post_state_root(out.as_mut_ptr() as u32) };
            out
        }
    }

    /// Allocate `len` bytes of zeroed memory and return a pointer.
    /// The host calls this before writing `RuntimeBlockInput` bytes into linear
    /// memory so the wasm side can later read them by pointer.
    #[unsafe(no_mangle)]
    extern "C" fn neutrin0_allocate(len: u32) -> u32 {
        let mut buf = alloc::vec![0u8; len as usize];
        let ptr = buf.as_mut_ptr() as u32;
        mem::forget(buf);
        ptr
    }

    /// Drop a buffer previously returned by `neutrin0_allocate` or by an
    /// entrypoint's packed result. Both allocate exactly `len` bytes, so
    /// rebuilding the allocation with capacity `len` matches its layout.
    #[unsafe(no_mangle)]
    extern "C" fn neutrin0_deallocate(ptr: u32, len: u32) {
        unsafe {
            let _ = Vec::from_raw_parts(ptr as *mut u8, len as usize, len as usize);
        }
    }

    /// Leak `bytes` as an exact-size allocation and pack it as
    /// `ptr << 32 | len` for the host.
    ///
    /// `into_boxed_slice` drops any spare capacity, so the host's later
    /// `neutrin0_deallocate(ptr, len)` frees the allocation with the layout
    /// it was made with.
    fn leak_packed(bytes: Vec<u8>) -> u64 {
        let bytes: &'static mut [u8] = Box::leak(bytes.into_boxed_slice());
        let ptr = bytes.as_ptr() as u32;
        let len = bytes.len() as u32;
        ((ptr as u64) << 32) | (len as u64)
    }

    /// Apply a block. The host writes a borsh-encoded `RuntimeBlockInput` into
    /// linear memory at `input_ptr..input_ptr+input_len`, then calls
    /// this function. Returns a packed `u64`: high 32 bits = output
    /// pointer, low 32 bits = output length.
    #[unsafe(no_mangle)]
    extern "C" fn apply_block(input_ptr: u32, input_len: u32) -> u64 {
        let input_bytes =
            unsafe { core::slice::from_raw_parts(input_ptr as *const u8, input_len as usize) };
        let input: neutrin0_runtime_abi::RuntimeCallInput =
            borsh::from_slice(input_bytes).expect("decode RuntimeCallInput");
        let mut backend = WasmHostBackend;
        let output = match input {
            neutrin0_runtime_abi::RuntimeCallInput::Block(input) => {
                neutrin0_runtime_abi::RuntimeCallOutput::Block(
                    runtime::execute_block(&input, &mut backend).into(),
                )
            }
            neutrin0_runtime_abi::RuntimeCallInput::Genesis(input) => {
                neutrin0_runtime_abi::RuntimeCallOutput::Genesis(
                    runtime::init_genesis(&input, &mut backend).into(),
                )
            }
        };

        leak_packed(borsh::to_vec(&output).expect("encode RuntimeBlockOutput"))
    }

    /// Header length of the `_neutrin0_validate_tx` envelope:
    /// 8 (`chain_id`) + 8 (`block_gas_limit`). The fee rate is runtime state.
    const VALIDATE_TX_HEADER_LEN: usize = 8 + 8;

    /// Transaction-admission entrypoint. Exposed under the ABI-defined
    /// symbol [`neutrin0_runtime_abi::VALIDATE_TX_ENTRYPOINT`].
    ///
    /// The host writes a flat byte string at `in_ptr..in_ptr+in_len`:
    ///
    /// ```text
    ///    8B  chain_id (little-endian u64)
    ///    8B  block_gas_limit (little-endian u64)
    ///   N    borsh-encoded Transaction bytes
    /// ```
    ///
    /// The runtime decodes the prefix, runs the runtime's
    /// [`neutrin0_evm_runtime_core::validate_tx`] against a
    /// [`WasmHostBackend`] (the host pins itself to read-only mode
    /// for admission), and writes the canonical dependency-bearing
    /// [`neutrin0_runtime_abi::TxValidity`] encoding into a new
    /// allocation. Returns a packed `u64`: high 32 bits = output
    /// pointer, low 32 bits = output length (at least
    /// [`neutrin0_runtime_abi::TX_VALIDITY_ENCODED_LEN`]).
    #[unsafe(no_mangle)]
    extern "C" fn _neutrin0_validate_tx(in_ptr: u32, in_len: u32) -> u64 {
        use neutrin0_runtime_abi::{TxValidationCode, TxValidity};
        use runtime::validate_tx as core_validate_tx;

        let bytes = unsafe { core::slice::from_raw_parts(in_ptr as *const u8, in_len as usize) };
        let validity = if bytes.len() < VALIDATE_TX_HEADER_LEN {
            TxValidity::invalid(TxValidationCode::Malformed)
        } else {
            let mut chain_id_buf = [0u8; 8];
            chain_id_buf.copy_from_slice(&bytes[0..8]);
            let chain_id = u64::from_le_bytes(chain_id_buf);
            let mut gas_buf = [0u8; 8];
            gas_buf.copy_from_slice(&bytes[8..16]);
            let block_gas_limit = u64::from_le_bytes(gas_buf);
            let tx_bytes = &bytes[VALIDATE_TX_HEADER_LEN..];
            let mut backend = WasmHostBackend;
            core_validate_tx(tx_bytes, &mut backend, chain_id, block_gas_limit)
        };

        leak_packed(validity.encode().to_vec())
    }

    /// Read-only query entrypoint. Exposed under the ABI-defined
    /// symbol [`neutrin0_runtime_abi::QUERY_ENTRYPOINT`].
    ///
    /// The host writes a borsh-encoded
    /// [`neutrin0_runtime_abi::QueryRequest`] into linear memory at
    /// `req_ptr..req_ptr+req_len`, then calls this function. The
    /// returned `u64` is packed: high 32 bits = output pointer, low
    /// 32 bits = output length. The payload at the output pointer
    /// is a borsh-encoded [`neutrin0_runtime_abi::QueryResponse`].
    ///
    /// State writes attempted by the runtime are intercepted by the
    /// host (`state_write` and `state_delete` no-op in query mode and
    /// the host overrides the response with
    /// [`neutrin0_runtime_abi::QueryStatus::PermissionDenied`]); this
    /// entrypoint trusts the host to enforce that invariant and does
    /// not gate writes itself.
    #[unsafe(no_mangle)]
    extern "C" fn _neutrin0_query(req_ptr: u32, req_len: u32) -> u64 {
        use neutrin0_runtime_abi::{QueryRequest, QueryResponse, QueryStatus};
        use runtime::query as core_query;

        let req_bytes =
            unsafe { core::slice::from_raw_parts(req_ptr as *const u8, req_len as usize) };
        let response = borsh::from_slice::<QueryRequest>(req_bytes).map_or_else(
            |_| QueryResponse::err(QueryStatus::InvalidArguments, alloc::vec![]),
            |req| {
                let mut backend = WasmHostBackend;
                core_query(&req, &mut backend)
            },
        );

        leak_packed(borsh::to_vec(&response).expect("encode QueryResponse"))
    }

    // -----------------------------------------------------------------
    // Allocator + panic handler for `wasm32-unknown-unknown`.
    // -----------------------------------------------------------------

    #[global_allocator]
    static ALLOCATOR: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

    #[panic_handler]
    fn on_panic(_info: &core::panic::PanicInfo<'_>) -> ! {
        core::arch::wasm32::unreachable()
    }
}

#[cfg(test)]
mod tests;
