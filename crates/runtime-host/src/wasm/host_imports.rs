//! The `neutrin0` host import module: bounded guest-memory access and the six
//! state operations the runtime cdylib imports.

use neutrin0_runtime_abi::{HOST_IMPORT_MODULE, MEMORY_EXPORT};
use wasmtime::{Caller, Linker, Memory, Trap};

use super::host_state::{HostState, MAX_STATE_KEY_BYTES, guest_slice};
use super::{WasmError, wt_err};

/// Trap for a host import naming memory outside the guest's linear memory,
/// classified like the guest's own out-of-bounds access.
fn out_of_bounds() -> wasmtime::Error {
    Trap::MemoryOutOfBounds.into()
}

fn memory_of(caller: &mut Caller<'_, HostState>) -> Result<Memory, wasmtime::Error> {
    caller
        .get_export(MEMORY_EXPORT)
        .and_then(wasmtime::Extern::into_memory)
        .ok_or_else(|| wasmtime::Error::msg("missing memory export"))
}

fn read_bytes(
    caller: &mut Caller<'_, HostState>,
    ptr: u32,
    len: u32,
) -> Result<Vec<u8>, wasmtime::Error> {
    let memory = memory_of(caller)?;
    guest_slice(memory.data(&*caller), ptr, len)
        .map(<[u8]>::to_vec)
        .ok_or_else(out_of_bounds)
}

/// [`read_bytes`] for a state key, which must also fit the trie.
fn read_key(
    caller: &mut Caller<'_, HostState>,
    ptr: u32,
    len: u32,
) -> Result<Vec<u8>, wasmtime::Error> {
    if len as usize > MAX_STATE_KEY_BYTES {
        return Err(wasmtime::Error::msg("state key too long for the trie"));
    }
    read_bytes(caller, ptr, len)
}

fn write_bytes(
    caller: &mut Caller<'_, HostState>,
    ptr: u32,
    bytes: &[u8],
) -> Result<(), wasmtime::Error> {
    let memory = memory_of(caller)?;
    memory
        .write(caller, ptr as usize, bytes)
        .map_err(|_| out_of_bounds())
}

// Six host imports registered as inline closures keeps each handler
// next to its description and avoids name-pollution helper functions.
// Every import validates its guest-supplied arguments and returns a trap
// error on violation: a panic here would unwind out of wasmtime into the
// node thread that called the runtime.
pub(super) fn register_host_imports(linker: &mut Linker<HostState>) -> Result<(), WasmError> {
    linker
        .func_wrap(
            HOST_IMPORT_MODULE,
            "state_read_len",
            |mut caller: Caller<'_, HostState>,
             key_ptr: u32,
             key_len: u32|
             -> wasmtime::Result<i32> {
                let key = read_key(&mut caller, key_ptr, key_len)?;
                caller.data_mut().read_len(&key)
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            HOST_IMPORT_MODULE,
            "state_read_into",
            |mut caller: Caller<'_, HostState>, value_ptr: u32| -> wasmtime::Result<()> {
                let value = caller
                    .data_mut()
                    .pending_read_value
                    .take()
                    .ok_or_else(|| wasmtime::Error::msg("no pending state_read_len value"))?;
                write_bytes(&mut caller, value_ptr, &value)
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            HOST_IMPORT_MODULE,
            "state_write",
            |mut caller: Caller<'_, HostState>,
             key_ptr: u32,
             key_len: u32,
             value_ptr: u32,
             value_len: u32|
             -> wasmtime::Result<()> {
                let key = read_key(&mut caller, key_ptr, key_len)?;
                let value = read_bytes(&mut caller, value_ptr, value_len)?;
                let host = caller.data_mut();
                if host.read_only {
                    // Query mode: drop the write silently and flag the
                    // attempt so the caller substitutes
                    // PermissionDenied for the runtime's response.
                    host.write_attempted = true;
                    return Ok(());
                }
                host.write(&key, value)
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            HOST_IMPORT_MODULE,
            "state_delete",
            |mut caller: Caller<'_, HostState>,
             key_ptr: u32,
             key_len: u32|
             -> wasmtime::Result<()> {
                let key = read_key(&mut caller, key_ptr, key_len)?;
                let host = caller.data_mut();
                if host.read_only {
                    // Query mode: drop the delete silently and flag
                    // the attempt; see `state_write`.
                    host.write_attempted = true;
                    return Ok(());
                }
                host.delete(&key)?;
                Ok(())
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            HOST_IMPORT_MODULE,
            "pre_state_root",
            |mut caller: Caller<'_, HostState>, out_ptr: u32| -> wasmtime::Result<()> {
                let root = caller.data().pre_root;
                write_bytes(&mut caller, out_ptr, &root)
            },
        )
        .map_err(wt_err)?;

    linker
        .func_wrap(
            HOST_IMPORT_MODULE,
            "post_state_root",
            |mut caller: Caller<'_, HostState>, out_ptr: u32| -> wasmtime::Result<()> {
                let root = caller.data().scratch.root();
                write_bytes(&mut caller, out_ptr, &root)
            },
        )
        .map_err(wt_err)?;

    Ok(())
}
