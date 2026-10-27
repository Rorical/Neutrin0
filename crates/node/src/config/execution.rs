//! `[execution]` section: head-state mode and WASM budgets.

use serde::Deserialize;

use super::NodeRole;

/// Fuel and linear-memory budgets for untrusted WASM entrypoints.
///
/// Mirrors [`neutrin0_runtime_host::wasm::WasmLimits`]; see there for the
/// semantics. The block fuel cap only guards against a runtime that never
/// returns; lowering it far enough to reject valid blocks would split this
/// node from the chain.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ExecutionLimitsConfig {
    /// How this node advances its head state; see [`ExecutionMode`]. Unset
    /// selects the role's default: `validator`, `full` and `reporter` follow
    /// receipts, `archive` executes.
    pub mode: Option<ExecutionMode>,
    /// Fuel for one RPC `runtime_call` query.
    pub query_fuel: u64,
    /// Memory cap in bytes for one RPC query.
    pub query_memory_bytes: usize,
    /// Fuel for one mempool admission check.
    pub validate_tx_fuel: u64,
    /// Memory cap in bytes for one admission check.
    pub validate_tx_memory_bytes: usize,
    /// Fuel for one block dry run.
    pub block_fuel: u64,
    /// Memory cap in bytes for one block dry run.
    pub block_memory_bytes: usize,
}

impl Default for ExecutionLimitsConfig {
    fn default() -> Self {
        let limits = neutrin0_runtime_host::wasm::WasmLimits::default();
        Self {
            mode: None,
            query_fuel: limits.query_fuel,
            query_memory_bytes: limits.query_memory_bytes,
            validate_tx_fuel: limits.validate_tx_fuel,
            validate_tx_memory_bytes: limits.validate_tx_memory_bytes,
            block_fuel: limits.block_fuel,
            block_memory_bytes: limits.block_memory_bytes,
        }
    }
}

/// How a node advances its materialized head state (design 07).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    /// Re-execute every imported block through the WASM runtime. The default
    /// for archives, whose genesis replay cannot rely on pruned historical
    /// diffs; opt-in for any other node that wants to hold witnesses for
    /// every block.
    Execute,
    /// Import every peer block from its `ProvenBlock` bundle: verify the
    /// receipt and apply the state diff instead of executing the body. The
    /// default for validators, full and reporter nodes. A validator still
    /// executes the blocks it produces itself. Finality still requires
    /// complete Chunk proofs.
    ProofFollow,
}

impl ExecutionMode {
    /// Mode a role runs when the configuration leaves `mode` unset.
    #[must_use]
    pub const fn default_for(role: NodeRole) -> Self {
        match role {
            NodeRole::Validator | NodeRole::Full | NodeRole::Reporter => Self::ProofFollow,
            NodeRole::Archive | NodeRole::LightClient => Self::Execute,
        }
    }

    /// Whether `role` may run this mode.
    #[must_use]
    pub const fn allowed_for(self, role: NodeRole) -> bool {
        match self {
            Self::Execute => true,
            Self::ProofFollow => !matches!(role, NodeRole::LightClient),
        }
    }
}

impl ExecutionLimitsConfig {
    /// Mode this node runs: the configured one, or the role's default.
    #[must_use]
    pub fn effective_mode(&self, role: NodeRole) -> ExecutionMode {
        self.mode
            .unwrap_or_else(|| ExecutionMode::default_for(role))
    }

    /// Reject an execution mode the configured role cannot run.
    ///
    /// # Errors
    /// Returns an error when `mode = "proof_follow"` is combined with the
    /// `light-client` role, which holds no execution state.
    pub fn validate(&self, role: NodeRole) -> Result<(), String> {
        if !self.effective_mode(role).allowed_for(role) {
            return Err(format!(
                "execution.mode = \"proof_follow\" is not allowed for role {role:?}"
            ));
        }
        Ok(())
    }

    /// Convert into the runtime-host limit set.
    #[must_use]
    pub const fn to_wasm_limits(self) -> neutrin0_runtime_host::wasm::WasmLimits {
        neutrin0_runtime_host::wasm::WasmLimits {
            query_fuel: self.query_fuel,
            query_memory_bytes: self.query_memory_bytes,
            validate_tx_fuel: self.validate_tx_fuel,
            validate_tx_memory_bytes: self.validate_tx_memory_bytes,
            block_fuel: self.block_fuel,
            block_memory_bytes: self.block_memory_bytes,
        }
    }
}
