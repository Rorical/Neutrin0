//! Stored observations and decoded indexing records. No type here authorizes consensus.
use crate::{Error, Result};
use neutrin0_rpc::types::{ChainCursorJson, ChainPointJson, GenesisInfoJson, HeaderJson};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Immutable binding of one index database to its source and decoding semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Binding {
    /// Complete pinned specification commitment.
    pub chain_spec_hash: String,
    /// Exact decimal numeric identity.
    pub chain_id: String,
    /// Immutable genesis facts supplied by the node.
    pub genesis: GenesisInfoJson,
    /// Blocks in one finalized Chunk.
    pub chunk_size: u64,
    /// Configured decoding-profile commitment.
    pub decoder_hash: String,
}
/// Durable ingestion progress and totals; cursor publication follows committed data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexState {
    /// Immutable source binding.
    pub binding: Binding,
    /// Last completely stored canonical block, or genesis.
    pub head: ChainPointJson,
    /// Last indexed complete Chunk endpoint, or genesis.
    pub finalized: ChainPointJson,
    /// Indexed complete Chunk count.
    pub finalized_chunks: u64,
    /// Last reconciled source cursor, not merely the last fetched cursor.
    pub cursor: Option<ChainCursorJson>,
    /// Changes only on canonical rollback; invalidates query pagination cursors.
    pub generation: u64,
    /// Canonical transaction envelope count.
    pub transactions: u64,
    /// Canonical EVM log count.
    pub logs: u64,
    /// Exact decimal accumulated canonical gas.
    pub gas: String,
    /// Source target being reconciled.
    pub source_head: ChainPointJson,
    /// Source finalized target.
    pub source_finalized: ChainPointJson,
    /// starting, backfilling, live or error.
    pub phase: String,
    /// Explicit last source/database error; never converted to empty results.
    pub last_error: Option<String>,
    /// Wall-clock observation time, independent of chain timestamps.
    pub observed_at: String,
}
/// One declared/executed transaction, retaining both native envelope and runtime IDs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexedTransaction {
    /// Runtime transaction ID, or BLAKE3 envelope ID for opaque input.
    pub hash: String,
    /// BLAKE3 commitment of the exact common envelope.
    pub envelope_hash: String,
    /// Position in the native block body, including evidence inputs.
    pub position: u32,
    /// Runtime/action label.
    pub kind: String,
    /// Provider-recovered Ethereum sender.
    pub from: Option<String>,
    /// Destination/validator, if decoded.
    pub to: Option<String>,
    /// Successfully created Ethereum contract, if any.
    pub contract_address: Option<String>,
    /// Exact decimal sequence.
    pub nonce: Option<String>,
    /// Exact decimal declared native-token value.
    pub value: Option<String>,
    /// success, failed, `not_executed` or unknown.
    pub status: String,
    /// Charged gas when supplied by a receipt.
    pub gas_used: Option<String>,
    /// Exact provider receipt/native status projection.
    pub receipt: Option<Value>,
    /// Additional decoded runtime fields.
    pub details: Value,
    /// Exact bytes, kept in BYTEA rather than duplicated in JSON.
    #[serde(skip)]
    pub raw: Vec<u8>,
}
/// One committed EVM log; indexes are native body positions and block-global log positions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexedLog {
    /// Native body envelope position.
    pub transaction_position: u32,
    /// Runtime transaction identity.
    pub transaction_hash: String,
    /// Block-global log sequence.
    pub index: u32,
    /// Emitting EVM contract.
    pub address: String,
    /// Ordered topics.
    pub topics: Vec<String>,
    /// Exact event data hex.
    pub data: String,
}
/// Event-shaped token movement; no contract-interface or balance claim is inferred.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexedTransfer {
    /// Native body position.
    pub transaction_position: u32,
    /// Runtime transaction identity.
    pub transaction_hash: String,
    /// Parent log index.
    pub log_index: u32,
    /// Position within an ERC-1155 batch, zero for single transfers.
    pub item_index: u32,
    /// Emitting contract.
    pub contract: String,
    /// ERC20, ERC721 or ERC1155 event shape.
    pub standard: String,
    /// Event-declared source, including the mint zero address.
    pub from: String,
    /// Event-declared destination, including the burn zero address.
    pub to: String,
    /// Exact decimal quantity, one for ERC-721.
    pub amount: String,
    /// Exact decimal token identity for NFT/multi-token events.
    pub token_id: Option<String>,
}
/// Completely fetched block data prepared before a PostgreSQL publication transaction.
#[derive(Clone, Debug)]
pub struct IndexedBlock {
    /// Header supplied by the full node.
    pub header: HeaderJson,
    /// Historical runtime content hash.
    pub runtime_hash: String,
    /// Decoding mode; opaque payloads never gain invented addresses/statuses.
    pub decoding: String,
    /// Header-bound canonical Borsh execution artifacts.
    pub artifacts: Vec<u8>,
    /// Exact ordered native envelopes.
    pub transactions: Vec<IndexedTransaction>,
    /// Committed Ethereum logs.
    pub logs: Vec<IndexedLog>,
    /// Recognized transfer event layouts.
    pub transfers: Vec<IndexedTransfer>,
}
/// Canonical lowercase hexadecimal bytes.
pub fn hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
/// Normalize a native chain/content hash.
pub fn hash(value: &str) -> Result<String> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|_| Error::Data("invalid hash".into()))?;
    if bytes.len() != 32 {
        return Err(Error::Data("native hashes require 32 bytes".into()));
    }
    Ok(hex(&bytes))
}
/// Normalize an Ethereum or native account identifier.
pub fn address(value: &str) -> Result<String> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|_| Error::Data("invalid address".into()))?;
    if !matches!(bytes.len(), 20 | 32) {
        return Err(Error::Data("addresses require 20 or 32 bytes".into()));
    }
    Ok(hex(&bytes))
}
/// Checked numeric input, represented as text in GraphQL to preserve all bits.
pub fn number(value: &str) -> Result<u64> {
    let result = value
        .parse::<u64>()
        .map_err(|_| Error::Data("invalid decimal u64".into()))?;
    if result.to_string() != value {
        return Err(Error::Data("noncanonical decimal u64".into()));
    }
    Ok(result)
}
