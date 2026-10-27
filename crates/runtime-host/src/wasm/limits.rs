//! Fuel and linear-memory budgets of guest calls.

use wasmtime::{StoreLimits, StoreLimitsBuilder};

/// Default [`WasmLimits::block_fuel`]: room for a maximum-size block whose
/// every transaction costs a signature check, with a wide margin.
pub const DEFAULT_BLOCK_FUEL: u64 = 1_000_000_000_000;

/// Fuel and linear-memory budgets applied to every guest call.
///
/// Fuel counts executed wasm instructions, so the bound is deterministic
/// and independent of host speed. Queries and admission checks run on
/// behalf of untrusted callers and get tight caps. Block execution gets a
/// cap far above what any block that fits the block gossip limit can need,
/// so it never rejects a block the SP1 Guest would prove; it only stops a
/// runtime that never returns from wedging the node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WasmLimits {
    /// Fuel budget for one `query` call.
    pub query_fuel: u64,
    /// Linear-memory cap in bytes for one `query` call.
    pub query_memory_bytes: usize,
    /// Fuel budget for one `validate_tx` call.
    pub validate_tx_fuel: u64,
    /// Linear-memory cap in bytes for one `validate_tx` call.
    pub validate_tx_memory_bytes: usize,
    /// Fuel budget for one `apply_block` dry run.
    pub block_fuel: u64,
    /// Linear-memory cap in bytes for one `apply_block` dry run.
    pub block_memory_bytes: usize,
}

impl Default for WasmLimits {
    fn default() -> Self {
        Self {
            query_fuel: 2_000_000_000,
            query_memory_bytes: 64 * 1024 * 1024,
            // EVM admission hashes the complete calldata before recovering its
            // signature. Cover ordinary bounded large transactions as well as
            // small transfers while retaining a finite untrusted-call budget.
            validate_tx_fuel: 100_000_000,
            validate_tx_memory_bytes: 64 * 1024 * 1024,
            block_fuel: DEFAULT_BLOCK_FUEL,
            block_memory_bytes: 512 * 1024 * 1024,
        }
    }
}

impl WasmLimits {
    /// Reject budgets that would make every call fail.
    ///
    /// # Errors
    /// Returns a static description of the offending field.
    pub const fn validate(self) -> Result<(), &'static str> {
        if self.query_fuel == 0 || self.validate_tx_fuel == 0 || self.block_fuel == 0 {
            return Err("wasm fuel budgets must be positive");
        }
        if self.query_memory_bytes < 1024 * 1024
            || self.validate_tx_memory_bytes < 1024 * 1024
            || self.block_memory_bytes < 1024 * 1024
        {
            return Err("wasm memory caps must be at least 1 MiB");
        }
        Ok(())
    }
}

pub(super) fn store_limits(memory_bytes: usize) -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size(memory_bytes)
        .memories(1)
        .tables(1)
        .build()
}
