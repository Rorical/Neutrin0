//! JSON shapes of blocks, headers and chain endpoints.

use neutrin0_consensus_types::{Block, Body, Header};
use serde::{Deserialize, Serialize};

use super::{BytesHex, HashHex};
use crate::backend::{FinalizedInfo, HeadInfo};

/// Immutable genesis facts from the locally authenticated chain specification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GenesisInfoJson {
    /// Native genesis block identifier.
    pub hash: HashHex,
    /// Authenticated genesis execution root.
    pub state_root: HashHex,
    /// Genesis timestamp.
    pub timestamp: u64,
    /// Initial block gas ceiling.
    pub gas_limit: u64,
    /// Initial consensus seed.
    pub seed: HashHex,
}

impl From<crate::backend::GenesisInfo> for GenesisInfoJson {
    fn from(genesis: crate::backend::GenesisInfo) -> Self {
        Self {
            hash: HashHex(genesis.hash),
            state_root: HashHex(genesis.state_root),
            timestamp: genesis.timestamp,
            gas_limit: genesis.gas_limit,
            seed: HashHex(genesis.seed),
        }
    }
}

/// JSON representation of a block header.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeaderJson {
    /// Block height.
    pub height: u64,
    /// Slot at which the block was produced.
    pub slot: u64,
    /// Parent header hash.
    pub parent_hash: HashHex,
    /// Block hash (BLAKE3 over the canonical-signed-payload).
    pub block_hash: HashHex,
    /// Proposer index in the active validator set.
    pub proposer_index: u32,
    /// Post-execution state root.
    pub state_root: HashHex,
    /// Transactions root.
    pub transactions_root: HashHex,
    /// Finality votes root.
    pub votes_root: HashHex,
    /// Data-availability root.
    pub da_root: HashHex,
    /// Runtime-defined commitment (typically the validator-set root).
    pub runtime_extra: HashHex,
    /// Runtime-emitted per-block receipts commitment.
    pub receipts_root: HashHex,
    /// Gas consumed by the block.
    pub gas_used: u64,
    /// Gas limit the block was run with.
    pub gas_limit: u64,
    /// UNIX-epoch timestamp in seconds.
    pub timestamp: u64,
}

impl From<&Header> for HeaderJson {
    fn from(h: &Header) -> Self {
        Self {
            height: h.height,
            slot: h.slot,
            parent_hash: HashHex(h.parent_hash),
            block_hash: HashHex(h.hash()),
            proposer_index: h.proposer_index,
            state_root: HashHex(h.state_root),
            transactions_root: HashHex(h.transactions_root),
            votes_root: HashHex(h.votes_root),
            da_root: HashHex(h.da_root),
            runtime_extra: HashHex(h.runtime_extra),
            receipts_root: HashHex(h.receipts_root),
            gas_used: h.gas_used,
            gas_limit: h.gas_limit,
            timestamp: h.timestamp,
        }
    }
}

/// JSON representation of a block body. Transaction blobs are exposed
/// as opaque hex strings; their decoding is runtime-defined.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BodyJson {
    /// Runtime-defined transaction blobs.
    pub transactions: Vec<BytesHex>,
    /// Number of compact individually signed participation acknowledgements.
    pub participation_acks: u32,
}

impl From<&Body> for BodyJson {
    fn from(b: &Body) -> Self {
        Self {
            transactions: b.transactions.iter().cloned().map(BytesHex).collect(),
            participation_acks: u32::try_from(b.participation_acks.len()).unwrap_or(u32::MAX),
        }
    }
}

/// JSON representation of a full block.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockJson {
    /// Block header.
    pub header: HeaderJson,
    /// Block body.
    pub body: BodyJson,
}

impl From<&Block> for BlockJson {
    fn from(b: &Block) -> Self {
        Self {
            header: HeaderJson::from(&b.header),
            body: BodyJson::from(&b.body),
        }
    }
}

/// JSON shape returned by `chain_head`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeadInfoJson {
    /// Head block height.
    pub height: u64,
    /// Head block hash.
    pub hash: HashHex,
    /// Slot of the head block.
    pub slot: u64,
    /// Post-execution state root of the head block.
    pub state_root: HashHex,
}

impl From<HeadInfo> for HeadInfoJson {
    fn from(h: HeadInfo) -> Self {
        Self {
            height: h.height,
            hash: HashHex(h.hash),
            slot: h.slot,
            state_root: HashHex(h.state_root),
        }
    }
}

/// JSON shape returned by `chain_finalized`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FinalizedInfoJson {
    /// Finalized chunk ID, or `None` at genesis.
    pub chunk_id: Option<u64>,
    /// Finalized block hash.
    pub block_hash: HashHex,
    /// Finalized block height.
    pub height: u64,
    /// Finalized state root.
    pub state_root: HashHex,
}

impl From<FinalizedInfo> for FinalizedInfoJson {
    fn from(f: FinalizedInfo) -> Self {
        Self {
            chunk_id: f.chunk_id,
            block_hash: HashHex(f.block_hash),
            height: f.height,
            state_root: HashHex(f.state_root),
        }
    }
}
