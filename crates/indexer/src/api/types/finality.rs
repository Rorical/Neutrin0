//! Finalized Chunk and proof availability records.
use super::text;
use crate::{
    api::{gql, view},
    db::query::Record,
};
use async_graphql::{ComplexObject, Context, Json, SimpleObject};
use serde_json::Value;

/// Finalized Chunk summary and commitments.
#[derive(Clone, SimpleObject)]
#[graphql(complex)]
pub struct Chunk {
    /// Exact sequential identity.
    pub id: String,
    /// Canonical Chunk commitment.
    pub hash: String,
    /// First block height.
    pub start_height: String,
    /// Last block height.
    pub end_height: String,
    /// First block identity.
    pub start_block_hash: String,
    /// Last block identity.
    pub end_block_hash: String,
    /// Incoming committee root.
    pub active_validator_set_root: String,
    /// Outgoing committee root.
    pub next_validator_set_root: String,
    /// Runtime-independent committed descriptor.
    pub details: Json<Value>,
}
impl Chunk {
    pub(in crate::api) fn from_record(row: &Record) -> crate::Result<Self> {
        let c: neutrin0_rpc::types::ChunkJson = serde_json::from_value(row.data["chunk"].clone())?;
        Ok(Self {
            id: c.chunk_id.to_string(),
            hash: crate::model::hex(&c.hash.0),
            start_height: c.start_height.to_string(),
            end_height: c.end_height.to_string(),
            start_block_hash: crate::model::hex(&c.start_block_hash.0),
            end_block_hash: crate::model::hex(&c.end_block_hash.0),
            active_validator_set_root: crate::model::hex(&c.active_validator_set_root.0),
            next_validator_set_root: crate::model::hex(&c.next_validator_set_root.0),
            details: Json(row.data["chunk"].clone()),
        })
    }
}
#[ComplexObject]
impl Chunk {
    /// Retained certificate summary, bounded separately from list pagination.
    #[graphql(complexity = 100)]
    async fn certificate(&self, ctx: &Context<'_>) -> async_graphql::Result<Option<Json<Value>>> {
        Ok(view(ctx)?
            .certificate(&self.id)
            .await
            .map_err(gql)?
            .map(Json))
    }
}
/// Exact proof/certificate metadata observed from the source; proof bytes are not fabricated/cached.
#[derive(Clone, SimpleObject)]
pub struct Proof {
    /// Native block height, or finalized Chunk endpoint height.
    pub height: String,
    /// Native block identity for block proofs, absent for Chunk/certificate locators.
    pub block_hash: Option<String>,
    /// Source artifact locator.
    pub locator: Json<Value>,
    /// `block_proof`, `chunk_proof` or certificate.
    pub kind: String,
    /// Source observed availability.
    pub availability: String,
    /// Exact Borsh envelope commitment if known.
    pub artifact_hash: Option<String>,
    /// Exact encoded envelope length if known.
    pub encoded_bytes: Option<String>,
    /// Opaque raw proof length if known.
    pub proof_bytes: Option<String>,
    /// This service retains metadata, not proof blobs.
    pub stored_bytes: bool,
    /// Last source availability observation.
    pub observed_at: String,
    /// Complete saved provider metadata.
    pub metadata: Option<Json<Value>>,
}
impl Proof {
    pub(in crate::api) fn from_record(row: &Record) -> crate::Result<Self> {
        let info: Option<neutrin0_rpc::types::ArtifactInfoJson> =
            serde_json::from_value(row.data["info"].clone())?;
        Ok(Self {
            height: row.height.to_string(),
            block_hash: (!row.block_hash.is_empty()).then(|| row.block_hash.clone()),
            locator: Json(row.data["locator"].clone()),
            kind: text(&row.data, "kind")?,
            availability: text(&row.data, "availability")?,
            artifact_hash: info.as_ref().map(|i| crate::model::hex(&i.artifact_hash.0)),
            encoded_bytes: info.as_ref().map(|i| i.encoded_bytes.to_string()),
            proof_bytes: info.as_ref().map(|i| i.proof_bytes.to_string()),
            stored_bytes: false,
            observed_at: text(&row.data, "observedAt")?,
            metadata: info.map(|_| Json(row.data["info"].clone())),
        })
    }
}
