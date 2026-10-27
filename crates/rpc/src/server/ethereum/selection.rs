//! Block selection: Ethereum tags, EIP-1898 objects and their resolution.
use super::codec::{error, fixed, height};
use crate::backend::BlockId;
use crate::server::RpcContext;
use crate::server::errors::{invalid_params, query_err};
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::Value;

pub(super) fn block_id(value: Option<&Value>) -> Result<(BlockId, bool), ErrorObjectOwned> {
    let Some(value) = value else {
        return Ok((BlockId::Latest, false));
    };
    if let Some(object) = value.as_object() {
        if object
            .get("requireCanonical")
            .is_some_and(|value| !value.is_boolean())
        {
            return Err(invalid_params("requireCanonical must be a boolean"));
        }
        return match (object.get("blockHash"), object.get("blockNumber")) {
            (Some(hash), None) => Ok((BlockId::Hash(fixed(hash)?), false)),
            (None, Some(number)) => Ok((BlockId::Height(height(number)?), false)),
            _ => Err(invalid_params("select exactly one block hash or number")),
        };
    }
    match value
        .as_str()
        .ok_or_else(|| invalid_params("block tag or hex quantity expected"))?
    {
        // Ethereum's tags: the executed head, the proven head, the
        // proof-finalized boundary, and a simulated block above the head.
        "latest" => Ok((BlockId::Latest, false)),
        "safe" => Ok((BlockId::Safe, false)),
        "finalized" => Ok((BlockId::Finalized, false)),
        "earliest" => Ok((BlockId::Height(0), false)),
        "pending" => Ok((BlockId::Latest, true)),
        _ => Ok((BlockId::Height(height(value)?), false)),
    }
}
pub(super) async fn selected_id(
    ctx: &RpcContext,
    value: Option<&Value>,
) -> Result<(BlockId, bool), ErrorObjectOwned> {
    let (at, pending) = block_id(value)?;
    if pending {
        return Ok((at, true));
    }
    let hash = resolved(ctx, &at)
        .await?
        .ok_or_else(|| query_err(&crate::backend::QueryError::BlockNotFound))?;
    if value
        .and_then(Value::as_object)
        .and_then(|object| object.get("requireCanonical"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        let genesis = ctx
            .backend()
            .genesis_info()
            .await
            .map_err(|error| query_err(&error))?;
        if genesis.is_none_or(|genesis| genesis.hash != hash) {
            let header = ctx
                .backend()
                .header_by_hash(hash)
                .await
                .map_err(|error| query_err(&error))?
                .ok_or_else(|| query_err(&crate::backend::QueryError::BlockNotFound))?;
            let canonical = ctx
                .backend()
                .header_by_height(header.height)
                .await
                .map_err(|error| query_err(&error))?;
            if canonical.is_none_or(|header| header.hash() != hash) {
                return Err(error("selected block is not canonical"));
            }
        }
    }
    // A multi-step call/estimate must keep one historical root even if the
    // canonical head changes while the runtime query is being awaited.
    Ok((BlockId::Hash(hash), false))
}
pub(super) async fn resolved(
    ctx: &RpcContext,
    at: &BlockId,
) -> Result<Option<[u8; 32]>, ErrorObjectOwned> {
    ctx.backend()
        .resolve_block_id(at)
        .await
        .map_err(|error| query_err(&error))
}
pub(super) async fn selected_height(
    ctx: &RpcContext,
    value: Option<&Value>,
    latest: u64,
) -> Result<u64, ErrorObjectOwned> {
    let (at, pending) = block_id(value)?;
    if pending {
        return Err(invalid_params(
            "pending logs and fee history are unavailable",
        ));
    }
    match at {
        BlockId::Latest => Ok(latest),
        BlockId::Safe => {
            let hash = resolved(ctx, &BlockId::Safe)
                .await?
                .ok_or_else(|| query_err(&crate::backend::QueryError::BlockNotFound))?;
            Ok(ctx
                .backend()
                .header_by_hash(hash)
                .await
                .map_err(|error| query_err(&error))?
                .map_or(0, |header| header.height))
        }
        BlockId::Finalized => Ok(ctx
            .backend()
            .finalized()
            .await
            .map_err(|error| query_err(&error))?
            .height),
        BlockId::Height(height) => Ok(height),
        BlockId::Hash(_) => Err(invalid_params("block number expected")),
    }
}
