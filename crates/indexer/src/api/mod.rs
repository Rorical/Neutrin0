//! Read-only GraphQL schema; all resolver data comes from one repeatable-read PostgreSQL snapshot.
mod filters;
pub mod server;
mod types;
use crate::{
    Error,
    db::{
        ReadView,
        query::{Filter, Kind},
    },
};
use async_graphql::{
    Context, EmptyMutation, EmptySubscription, ErrorExtensions, Json, Object, Schema,
};
use filters::event_filter;
pub use filters::{EventFilter, TransactionFilter};
use std::sync::Arc;
pub use types::*;
/// GraphQL query root. No mutations, runtime calls or node control operations are registered.
pub struct Query;
/// Read-only schema, independent of source connectivity.
pub type IndexerSchema = Schema<Query, EmptyMutation, EmptySubscription>;
/// Build a schema with explicit parsing/selection work bounds.
pub fn schema() -> IndexerSchema {
    Schema::build(Query, EmptyMutation, EmptySubscription)
        .limit_depth(8)
        .limit_complexity(1024)
        .limit_directives(16)
        .limit_recursive_depth(32)
        .finish()
}
pub(super) fn view<'a>(ctx: &'a Context<'_>) -> async_graphql::Result<&'a ReadView> {
    ctx.data::<Arc<ReadView>>().map(Arc::as_ref)
}
#[allow(
    clippy::needless_pass_by_value,
    reason = "map_err consumes the source error"
)]
pub(super) fn gql(error: Error) -> async_graphql::Error {
    let code = match &error {
        Error::Cursor(code) => *code,
        Error::Database(_) => "DATABASE_UNAVAILABLE",
        _ => "INVALID_INPUT",
    };
    let message = if matches!(error, Error::Database(_)) {
        "indexed database unavailable".into()
    } else {
        error.to_string()
    };
    async_graphql::Error::new(message).extend_with(|_, extension| extension.set("code", code))
}
#[Object]
impl Query {
    /// Atomic index/source progress and total counts, from the same durable,
    /// canonical snapshot as every listing in this request.
    #[allow(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "GraphQL resolvers must be asynchronous"
    )]
    async fn status(&self, ctx: &Context<'_>) -> async_graphql::Result<Status> {
        Ok(Status::from(view(ctx)?))
    }
    /// Immutable genesis facts, without a fabricated genesis body.
    #[allow(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "GraphQL resolvers must be asynchronous"
    )]
    async fn genesis(&self, ctx: &Context<'_>) -> async_graphql::Result<Json<serde_json::Value>> {
        Ok(Json(serde_json::json!(view(ctx)?.state.binding.genesis)))
    }
    /// Canonical block by height, or exact retained block/orphan by hash. Supply exactly one selector.
    async fn block(
        &self,
        ctx: &Context<'_>,
        height: Option<String>,
        hash: Option<String>,
    ) -> async_graphql::Result<Option<Block>> {
        let view = view(ctx)?;
        let hash = match (height, hash) {
            (Some(height), None) => view
                .canonical_hash(crate::model::number(&height).map_err(gql)?)
                .await
                .map_err(gql)?,
            (None, Some(hash)) => Some(crate::model::hash(&hash).map_err(gql)?),
            _ => {
                return Err(gql(Error::Data(
                    "supply exactly one block height/hash".into(),
                )));
            }
        };
        let Some(hash) = hash else {
            return Ok(None);
        };
        let Some(row) = view.block(&hash).await.map_err(gql)? else {
            return Ok(None);
        };
        let canonical =
            view.canonical_hash(row.height).await.map_err(gql)? == Some(row.block_hash.clone());
        Block::from_record(row, view, canonical)
            .map(Some)
            .map_err(gql)
    }
    /// Descending canonical block keyset page.
    #[graphql(complexity = "first.clamp(1,100) as usize * child_complexity")]
    async fn blocks(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 20)] first: i32,
        after: Option<String>,
    ) -> async_graphql::Result<BlockConnection> {
        let view = view(ctx)?;
        let page = view
            .page(Kind::Blocks, Filter::default(), first, after.as_deref())
            .await
            .map_err(gql)?;
        let page_info = PageInfo::new(&page);
        let edges = page
            .records
            .into_iter()
            .map(|r| {
                Ok(BlockEdge {
                    cursor: r.cursor.clone(),
                    node: Block::from_record(r, view, true)?,
                })
            })
            .collect::<crate::Result<_>>()
            .map_err(gql)?;
        Ok(BlockConnection { edges, page_info })
    }
    /// Most recent canonical attempt for a runtime/envelope ID. Use transactions(hash) for all native attempts.
    async fn transaction(
        &self,
        ctx: &Context<'_>,
        hash: String,
    ) -> async_graphql::Result<Option<TransactionRecord>> {
        let view = view(ctx)?;
        let page = view
            .page(
                Kind::Transactions,
                Filter {
                    hash: Some(hash),
                    ..Filter::default()
                },
                1,
                None,
            )
            .await
            .map_err(gql)?;
        page.records
            .into_iter()
            .next()
            .map(|r| TransactionRecord::from_record(r, view))
            .transpose()
            .map_err(gql)
    }
    /// Descending canonical attempts, with indexed account/block/action/status filters.
    #[graphql(complexity = "first.clamp(1,100) as usize * child_complexity")]
    async fn transactions(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 20)] first: i32,
        after: Option<String>,
        filter: Option<TransactionFilter>,
    ) -> async_graphql::Result<TransactionConnection> {
        let f = filter.unwrap_or_default();
        let view = view(ctx)?;
        let page = view
            .page(
                Kind::Transactions,
                Filter {
                    address: f.address,
                    block_hash: f.block_hash,
                    hash: f.hash,
                    kind: f.kind,
                    status: f.status,
                    finalized_only: f.finalized_only,
                    ..Filter::default()
                },
                first,
                after.as_deref(),
            )
            .await
            .map_err(gql)?;
        let page_info = PageInfo::new(&page);
        let edges = page
            .records
            .into_iter()
            .map(|r| {
                Ok(TransactionEdge {
                    cursor: r.cursor.clone(),
                    node: TransactionRecord::from_record(r, view)?,
                })
            })
            .collect::<crate::Result<_>>()
            .map_err(gql)?;
        Ok(TransactionConnection { edges, page_info })
    }
    /// Indexed address activity. Balances/nonce state and internal-call traces are not inferred.
    #[graphql(complexity = 20)]
    async fn address(
        &self,
        ctx: &Context<'_>,
        address: String,
    ) -> async_graphql::Result<Json<serde_json::Value>> {
        Ok(Json(view(ctx)?.address(&address).await.map_err(gql)?))
    }
    /// Descending committed events, never orphan or reverted logs.
    #[graphql(complexity = "first.clamp(1,100) as usize * child_complexity")]
    async fn logs(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 20)] first: i32,
        after: Option<String>,
        filter: Option<EventFilter>,
    ) -> async_graphql::Result<LogConnection> {
        let view = view(ctx)?;
        let page = view
            .page(Kind::Logs, event_filter(filter), first, after.as_deref())
            .await
            .map_err(gql)?;
        let page_info = PageInfo::new(&page);
        let edges = page
            .records
            .into_iter()
            .map(|r| {
                Ok(LogEdge {
                    cursor: r.cursor.clone(),
                    node: Log::from_record(r, view)?,
                })
            })
            .collect::<crate::Result<_>>()
            .map_err(gql)?;
        Ok(LogConnection { edges, page_info })
    }
    /// Bounded exact event data from retained block/log identity.
    #[graphql(complexity = "1 + length as usize / 1024")]
    async fn log_data(
        &self,
        ctx: &Context<'_>,
        block_hash: String,
        log_index: u32,
        #[graphql(default = 0)] offset: u32,
        #[graphql(default = 65536)] length: u32,
    ) -> async_graphql::Result<ByteSlice> {
        let (total, bytes) = view(ctx)?
            .log_data(&block_hash, log_index, offset, length)
            .await
            .map_err(gql)?;
        Ok(ByteSlice {
            total_bytes: total.to_string(),
            offset: offset.to_string(),
            bytes,
        })
    }
    /// ERC20/ERC721/ERC1155 event-shaped movement history.
    #[graphql(complexity = "first.clamp(1,100) as usize * child_complexity")]
    async fn token_transfers(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 20)] first: i32,
        after: Option<String>,
        filter: Option<EventFilter>,
    ) -> async_graphql::Result<TransferConnection> {
        let view = view(ctx)?;
        let page = view
            .page(
                Kind::Transfers,
                event_filter(filter),
                first,
                after.as_deref(),
            )
            .await
            .map_err(gql)?;
        let page_info = PageInfo::new(&page);
        let edges = page
            .records
            .into_iter()
            .map(|r| {
                Ok(TransferEdge {
                    cursor: r.cursor.clone(),
                    node: TokenTransfer::from_record(r, view)?,
                })
            })
            .collect::<crate::Result<_>>()
            .map_err(gql)?;
        Ok(TransferConnection { edges, page_info })
    }
    /// Indexed finalized Chunk by its exact decimal ID.
    async fn chunk(&self, ctx: &Context<'_>, id: String) -> async_graphql::Result<Option<Chunk>> {
        view(ctx)?
            .chunk(&id)
            .await
            .map_err(gql)?
            .map(|r| Chunk::from_record(&r))
            .transpose()
            .map_err(gql)
    }
    /// Descending complete Chunk history.
    #[graphql(complexity = "first.clamp(1,100) as usize * child_complexity")]
    async fn chunks(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 20)] first: i32,
        after: Option<String>,
    ) -> async_graphql::Result<ChunkConnection> {
        let page = view(ctx)?
            .page(Kind::Chunks, Filter::default(), first, after.as_deref())
            .await
            .map_err(gql)?;
        let page_info = PageInfo::new(&page);
        let edges = page
            .records
            .into_iter()
            .map(|r| {
                Ok(ChunkEdge {
                    cursor: r.cursor.clone(),
                    node: Chunk::from_record(&r)?,
                })
            })
            .collect::<crate::Result<_>>()
            .map_err(gql)?;
        Ok(ChunkConnection { edges, page_info })
    }
    /// Last observed source committee for the current indexed finalized boundary; null if not observed yet.
    #[graphql(complexity = 100)]
    async fn validators(
        &self,
        ctx: &Context<'_>,
    ) -> async_graphql::Result<Option<Json<serde_json::Value>>> {
        let value = view(ctx)?.validators().await.map_err(gql)?;
        Ok((!value.is_null()).then_some(Json(value)))
    }
    /// One indexed artifact observation by the node's exact {kind, block/chunk} JSON locator.
    async fn proof(
        &self,
        ctx: &Context<'_>,
        locator: Json<serde_json::Value>,
    ) -> async_graphql::Result<Option<Proof>> {
        let id = serde_json::from_value(locator.0).map_err(|error| gql(Error::Json(error)))?;
        view(ctx)?
            .proof(&id)
            .await
            .map_err(gql)?
            .map(|row| Proof::from_record(&row))
            .transpose()
            .map_err(gql)
    }
    /// Hash/size/availability metadata for block/Chunk/certificate artifacts.
    #[graphql(complexity = "first.clamp(1,100) as usize * child_complexity")]
    async fn proofs(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 20)] first: i32,
        after: Option<String>,
        kind: Option<String>,
    ) -> async_graphql::Result<ProofConnection> {
        let page = view(ctx)?
            .page(
                Kind::Proofs,
                Filter {
                    kind,
                    ..Filter::default()
                },
                first,
                after.as_deref(),
            )
            .await
            .map_err(gql)?;
        let page_info = PageInfo::new(&page);
        let edges = page
            .records
            .into_iter()
            .map(|r| {
                Ok(ProofEdge {
                    cursor: r.cursor.clone(),
                    node: Proof::from_record(&r)?,
                })
            })
            .collect::<crate::Result<_>>()
            .map_err(gql)?;
        Ok(ProofConnection { edges, page_info })
    }
    /// At most 168 hourly/daily activity buckets, with canonical block/transaction/gas totals.
    #[graphql(complexity = 50)]
    async fn activity(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 24)] buckets: i32,
        #[graphql(default = 3600)] seconds: i32,
    ) -> async_graphql::Result<Vec<Json<serde_json::Value>>> {
        Ok(view(ctx)?
            .activity(buckets, seconds)
            .await
            .map_err(gql)?
            .into_iter()
            .map(Json)
            .collect())
    }
}
