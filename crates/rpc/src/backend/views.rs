//! Observations the backend hands the RPC layer: selectors, summaries and retention.

use neutrin0_primitives::{BlockHash, ChunkId, Hash, Height, Slot, StateRoot};

/// Identifier referencing a block, with Ethereum's tag meanings.
///
/// The JSON deserialiser accepts:
///
/// - `"latest"` / omitted — the head: the tip of the executed candidate chain
///   the node follows, which may still reorganize
/// - `"safe"` — the proven head: every ancestor since finality has a verified
///   receipt (design 08)
/// - `"finalized"` — the latest proof-finalized chunk boundary, or genesis
/// - `"0x..."` hex string — block hash
/// - decimal-or-`"0x..."` integer — block height on the head's chain
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum BlockId {
    /// Head of the executed candidate chain the node follows; its execution
    /// may not be proven yet.
    #[default]
    Latest,
    /// Proven head: the highest block whose every ancestor since finality
    /// has a verified receipt (design 08).
    Safe,
    /// Latest finalized block.
    Finalized,
    /// Explicit block hash.
    Hash(BlockHash),
    /// Explicit block height.
    Height(Height),
}

/// Immutable genesis facts for genesis queries and Ethereum block projections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenesisInfo {
    /// Native genesis identifier.
    pub hash: Hash,
    /// Authenticated initial execution root.
    pub state_root: Hash,
    /// Genesis timestamp.
    pub timestamp: u64,
    /// Native block gas ceiling.
    pub gas_limit: u64,
    /// Initial consensus seed.
    pub seed: Hash,
}

/// Summary of the local head as observed by the RPC layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadInfo {
    /// Height of the unfinalised head block.
    pub height: Height,
    /// Hash of the head block.
    pub hash: BlockHash,
    /// Slot at which the head block was produced.
    pub slot: Slot,
    /// Post-execution state root of the head block.
    pub state_root: StateRoot,
}

/// Summary of the latest proof-finalized chunk boundary, or trusted genesis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FinalizedInfo {
    /// Latest finalized chunk ID; `None` before the first chunk finalizes.
    pub chunk_id: Option<ChunkId>,
    /// Hash of the finalized block.
    pub block_hash: BlockHash,
    /// Height of the finalized block.
    pub height: Height,
    /// Post-execution state root committed at the finalized boundary.
    pub state_root: StateRoot,
}

/// Successful response from a [`RpcBackend::runtime_call`](super::RpcBackend::runtime_call).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeCallResponse {
    /// Runtime-defined status code. `0` means success per
    /// [`neutrin0_runtime_abi::QueryStatus::Ok`].
    pub code: u32,
    /// Runtime-defined response payload.
    pub payload: Vec<u8>,
    /// Gas the query consumed.
    pub gas_used: u64,
}

/// Actual persisted history availability, separate from the requested retention policy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct HistoryRetention {
    /// This provider retains complete history from genesis under archive policy.
    pub archive: bool,
    /// Earliest complete chunk payload; `None` for verifier-only nodes.
    pub retained_from_chunk: Option<ChunkId>,
    /// Earliest complete block payload; `None` for verifier-only nodes.
    pub retained_from_height: Option<Height>,
    /// Complete chunks finalized by consensus; the latest chunk receipt is the
    /// History proof of all of them.
    pub finalized_chunks: u64,
}
