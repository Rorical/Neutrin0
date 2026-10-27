//! Block, transaction, log and token transfer records.
use super::text;
use crate::{
    api::{gql, view},
    db::{ReadView, query::Record},
    model::{IndexedLog, IndexedTransaction, IndexedTransfer},
};
use async_graphql::{ComplexObject, Context, Json, SimpleObject};
use serde_json::Value;

/// Canonical block summary, or an exact retained orphan when queried by hash.
#[derive(Clone, SimpleObject)]
pub struct Block {
    /// Native identifier.
    pub hash: String,
    /// Exact height.
    pub height: String,
    /// Native parent identity.
    pub parent_hash: String,
    /// Execution state commitment.
    pub state_root: String,
    /// Chain timestamp.
    pub timestamp: String,
    /// Charged gas.
    pub gas_used: String,
    /// Resource ceiling.
    pub gas_limit: String,
    /// All common envelope inputs.
    pub transaction_count: String,
    /// Source runtime artifact.
    pub runtime_code_hash: String,
    /// Selected indexing decoder.
    pub decoding: String,
    /// Current membership in this query snapshot.
    pub canonical: bool,
    /// Endpoint is covered by indexed complete Chunks.
    pub finalized: bool,
    /// Provider header projection; large values in this JSON retain provider encoding.
    pub header: Json<Value>,
}
impl Block {
    pub(in crate::api) fn from_record(
        row: Record,
        state: &ReadView,
        canonical: bool,
    ) -> crate::Result<Self> {
        let h: neutrin0_rpc::HeaderJson = serde_json::from_value(row.data["header"].clone())?;
        Ok(Self {
            hash: row.block_hash,
            height: row.height.to_string(),
            parent_hash: crate::model::hex(&h.parent_hash.0),
            state_root: crate::model::hex(&h.state_root.0),
            timestamp: h.timestamp.to_string(),
            gas_used: h.gas_used.to_string(),
            gas_limit: h.gas_limit.to_string(),
            transaction_count: text(&row.data, "txCount")?,
            runtime_code_hash: text(&row.data, "runtimeHash")?,
            decoding: text(&row.data, "decoding")?,
            canonical,
            finalized: canonical && row.height <= state.state.finalized.height,
            header: Json(row.data["header"].clone()),
        })
    }
}
/// Bounded exact bytes; the parent transaction's envelope hash pins every slice.
#[derive(SimpleObject)]
pub struct ByteSlice {
    /// Total envelope bytes.
    pub total_bytes: String,
    /// Returned start offset.
    pub offset: String,
    /// Exact lowercase hex.
    pub bytes: String,
}
/// One canonical transaction attempt, identified by block and native body position.
#[derive(Clone, SimpleObject)]
#[graphql(complex)]
pub struct TransactionRecord {
    /// Stable attempt identifier, distinguishing native resubmissions.
    pub id: String,
    /// Runtime transaction identifier.
    pub hash: String,
    /// BLAKE3 common envelope commitment.
    pub envelope_hash: String,
    /// Native parent block.
    pub block_hash: String,
    /// Canonical height.
    pub height: String,
    /// Native envelope position (not Ethereum-only ordinal).
    pub position: String,
    /// Runtime operation label.
    pub kind: String,
    /// Provider-recovered Ethereum sender.
    pub from: Option<String>,
    /// Declared destination/validator.
    pub to: Option<String>,
    /// Successfully created Ethereum contract.
    pub contract_address: Option<String>,
    /// Exact nonce if decoded.
    pub nonce: Option<String>,
    /// Declared native-token quantity, not a claim of successful transfer.
    pub value: Option<String>,
    /// success, failed, `not_executed` or unknown.
    pub status: String,
    /// Charged gas if decoded.
    pub gas_used: Option<String>,
    /// Covered by indexed complete Chunk finality.
    pub finalized: bool,
    /// Receipt metadata. Ethereum logs are queried through paginated logs.
    pub receipt: Option<Json<Value>>,
    /// Bounded runtime summary; complete signed bytes remain in rawEnvelope slices.
    pub details: Json<Value>,
    #[graphql(skip)]
    native_position: u32,
}
impl TransactionRecord {
    pub(in crate::api) fn from_record(row: Record, state: &ReadView) -> crate::Result<Self> {
        let tx: IndexedTransaction = serde_json::from_value(row.data)?;
        Ok(Self {
            id: format!("{}:{}", row.block_hash, tx.position),
            hash: tx.hash,
            envelope_hash: tx.envelope_hash,
            block_hash: row.block_hash,
            height: row.height.to_string(),
            position: tx.position.to_string(),
            kind: tx.kind,
            from: tx.from,
            to: tx.to,
            nonce: tx.nonce,
            contract_address: tx.contract_address,
            value: tx.value,
            status: tx.status,
            gas_used: tx.gas_used,
            finalized: row.height <= state.state.finalized.height,
            receipt: tx.receipt.map(Json),
            details: Json(tx.details),
            native_position: tx.position,
        })
    }
}
#[ComplexObject]
impl TransactionRecord {
    /// Bounded exact envelope bytes; no upstream call or execution is performed.
    #[graphql(complexity = "1 + length as usize / 1024")]
    async fn raw_envelope(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 0)] offset: u32,
        #[graphql(default = 65536)] length: u32,
    ) -> async_graphql::Result<ByteSlice> {
        let view = view(ctx)?;
        let (total, bytes) = view
            .raw(&self.block_hash, self.native_position, offset, length)
            .await
            .map_err(gql)?;
        Ok(ByteSlice {
            total_bytes: total.to_string(),
            offset: offset.to_string(),
            bytes: crate::model::hex(&bytes),
        })
    }
}
/// Committed EVM event with bounded data preview.
#[derive(Clone, SimpleObject)]
pub struct Log {
    /// Native block/log identity.
    pub id: String,
    /// Native block.
    pub block_hash: String,
    /// Canonical height.
    pub height: String,
    /// Runtime transaction.
    pub transaction_hash: String,
    /// Native envelope position.
    pub transaction_position: String,
    /// Block-global event index.
    pub log_index: String,
    /// Emitting contract.
    pub address: String,
    /// Ordered indexed topics.
    pub topics: Vec<String>,
    /// First 256 data bytes. Exact larger events can be read with logData slices.
    pub data_prefix: String,
    /// Exact data byte count.
    pub data_bytes: String,
    /// Indexed Chunk coverage.
    pub finalized: bool,
}
impl Log {
    pub(in crate::api) fn from_record(row: Record, state: &ReadView) -> crate::Result<Self> {
        let data_bytes = text(&row.data, "dataBytes")?;
        let log: IndexedLog = serde_json::from_value(row.data)?;
        Ok(Self {
            id: format!("{}:{}", row.block_hash, log.index),
            block_hash: row.block_hash,
            height: row.height.to_string(),
            transaction_hash: log.transaction_hash,
            transaction_position: log.transaction_position.to_string(),
            log_index: log.index.to_string(),
            address: log.address,
            topics: log.topics,
            data_prefix: log.data.get(..514).unwrap_or(&log.data).into(),
            data_bytes,
            finalized: row.height <= state.state.finalized.height,
        })
    }
}
/// Standard-shaped transfer event, without inferred token-interface/balance claims.
#[derive(Clone, SimpleObject)]
pub struct TokenTransfer {
    /// Native block/log/batch identity.
    pub id: String,
    /// Native block.
    pub block_hash: String,
    /// Canonical height.
    pub height: String,
    /// Runtime transaction.
    pub transaction_hash: String,
    /// Parent event index.
    pub log_index: String,
    /// Batch item index.
    pub item_index: String,
    /// Emitting contract.
    pub contract: String,
    /// ERC20, ERC721 or ERC1155 event shape.
    pub standard: String,
    /// Event source.
    pub from: String,
    /// Event destination.
    pub to: String,
    /// Exact decimal quantity.
    pub amount: String,
    /// Exact NFT/multi-token identifier.
    pub token_id: Option<String>,
    /// Indexed Chunk coverage.
    pub finalized: bool,
}
impl TokenTransfer {
    pub(in crate::api) fn from_record(row: Record, state: &ReadView) -> crate::Result<Self> {
        let t: IndexedTransfer = serde_json::from_value(row.data)?;
        Ok(Self {
            id: format!("{}:{}:{}", row.block_hash, t.log_index, t.item_index),
            block_hash: row.block_hash,
            height: row.height.to_string(),
            transaction_hash: t.transaction_hash,
            log_index: t.log_index.to_string(),
            item_index: t.item_index.to_string(),
            contract: t.contract,
            standard: t.standard,
            from: t.from,
            to: t.to,
            amount: t.amount,
            token_id: t.token_id,
            finalized: row.height <= state.state.finalized.height,
        })
    }
}
