//! WASM import module and export names the host links against.

/// WASM import module through which the host supplies state access to a
/// runtime.
pub const HOST_IMPORT_MODULE: &str = "neutrin0";

/// Linear-memory export the host reads inputs from and writes outputs to.
pub const MEMORY_EXPORT: &str = "memory";

/// Runtime export that allocates a zeroed input buffer of the given length
/// and returns its pointer.
pub const ALLOCATE_ENTRYPOINT: &str = "neutrin0_allocate";

/// Runtime export that frees a `(pointer, length)` buffer previously
/// returned by [`ALLOCATE_ENTRYPOINT`] or by an entrypoint's packed result.
pub const DEALLOCATE_ENTRYPOINT: &str = "neutrin0_deallocate";

/// Runtime function name used by the host to apply one block. Takes a
/// borsh-encoded STF input and returns a packed `pointer << 32 | length`
/// output buffer.
pub const APPLY_BLOCK_ENTRYPOINT: &str = "apply_block";

/// Runtime function name used by the host to run a single transaction
/// admission check against the WASM dynamic runtime.
pub const VALIDATE_TX_ENTRYPOINT: &str = "_neutrin0_validate_tx";

/// Runtime function name used by the host to run a single read-only query
/// against the WASM dynamic runtime.
///
/// The runtime reads a [`QueryRequest`](crate::QueryRequest) from its input
/// buffer and writes a [`QueryResponse`](crate::QueryResponse) to its output
/// buffer. State writes are forbidden; the
/// host discards the state overlay regardless of what the runtime
/// attempts. New query methods need no change to the wire envelope.
pub const QUERY_ENTRYPOINT: &str = "_neutrin0_query";
