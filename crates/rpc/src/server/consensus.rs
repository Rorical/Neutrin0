//! Finalized consensus artifact queries and durable cursor-based event subscriptions.

use super::{
    RpcContext, RpcStartError,
    errors::{BUSY_CODE, invalid_params, query_err, reg_err},
};
use crate::{
    QueryError,
    types::{ArtifactIdJson, ChainCursorJson, ChainNotificationJson, HashHex},
};
use jsonrpsee::server::RpcModule;

pub(super) fn register(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    module
        .register_async_method("chain_getBlockArtifacts", |params, ctx, _| async move {
            let (block,): (HashHex,) = params.parse()?;
            ctx.backend
                .block_artifacts(block.0)
                .await
                .map_err(|error| query_err(&error))
        })
        .map_err(reg_err)?;
    module
        .register_async_method("chain_getChunk", |params, ctx, _| async move {
            optional_params(&params, 1)?;
            let mut params = params.sequence();
            let id = params.optional_next::<u64>()?;
            ctx.backend
                .chunk(id)
                .await
                .map_err(|error| query_err(&error))
        })
        .map_err(reg_err)?;
    module
        .register_async_method("chain_getCertificate", |params, ctx, _| async move {
            let (id,): (u64,) = params.parse()?;
            ctx.backend
                .certificate(id)
                .await
                .map_err(|error| query_err(&error))
        })
        .map_err(reg_err)?;
    module
        .register_async_method("chain_getArtifact", |params, ctx, _| async move {
            let (id,): (ArtifactIdJson,) = params.parse()?;
            ctx.backend
                .artifact(id)
                .await
                .map_err(|error| query_err(&error))
        })
        .map_err(reg_err)?;
    module
        .register_async_method("chain_getArtifactBytes", |params, ctx, _| async move {
            let (id, expected, offset, length): (ArtifactIdJson, HashHex, u64, u32) =
                params.parse()?;
            ctx.backend
                .artifact_bytes(id, expected.0, offset, length)
                .await
                .map_err(|error| query_err(&error))
        })
        .map_err(reg_err)?;
    module
        .register_async_method("chain_getEvents", |params, ctx, _| async move {
            optional_params(&params, 2)?;
            let mut params = params.sequence();
            let after = params.optional_next::<ChainCursorJson>()?;
            let limit = params.optional_next::<u32>()?.unwrap_or(128);
            ctx.backend
                .chain_events(after, limit)
                .await
                .map_err(|error| query_err(&error))
        })
        .map_err(reg_err)?;
    register_subscription(module)
}

fn register_subscription(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    module
        .register_subscription(
            "chain_subscribeEvents",
            "chain_event",
            "chain_unsubscribeEvents",
            |params, pending, ctx, extensions| async move {
                if let Err(error) = optional_params(&params, 1) {
                    pending.reject(error).await;
                    return Ok(());
                }
                let mut sequence = params.sequence();
                let after = match sequence.optional_next::<ChainCursorJson>() {
                    Ok(after) => after,
                    Err(error) => {
                        pending.reject(invalid_params(error)).await;
                        return Ok(());
                    }
                };
                let client = extensions.get::<super::clients::ClientIp>().copied();
                let Some(permit) = ctx.chain_subscriptions.acquire(client) else {
                    pending
                        .reject(jsonrpsee::types::ErrorObjectOwned::owned(
                            BUSY_CODE,
                            "chain event subscription limit reached",
                            None::<()>,
                        ))
                        .await;
                    return Ok(());
                };
                let first = match ctx.backend.chain_events(after.clone(), 128).await {
                    Ok(page) => page,
                    Err(error) => {
                        pending.reject(query_err(&error)).await;
                        return Ok(());
                    }
                };
                let mut cursor = after.unwrap_or_else(|| first.status.latest.clone());
                let sink = pending.accept().await?;
                let snapshot = ChainNotificationJson::Snapshot {
                    status: first.status.clone(),
                    after: cursor.clone(),
                };
                let send = |value| serde_json::value::to_raw_value(&value);
                sink.send(send(snapshot)?).await?;
                let mut page = first;
                loop {
                    for event in page.events {
                        let next = event.cursor.clone();
                        sink.send(send(ChainNotificationJson::Event { event })?)
                            .await?;
                        cursor = next;
                    }
                    if !page.has_more {
                        tokio::select! {
                            () = sink.closed() => break,
                            () = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
                        }
                    }
                    match ctx.backend.chain_events(Some(cursor.clone()), 128).await {
                        Ok(next) => page = next,
                        Err(error) => {
                            let (reason, status) = match error {
                                QueryError::EventCursor { reason, status } => {
                                    (reason, Some(*status))
                                }
                                other => (other.to_string(), None),
                            };
                            sink.send(send(ChainNotificationJson::ResetRequired {
                                reason,
                                status,
                            })?)
                            .await?;
                            break;
                        }
                    }
                }
                drop(sink);
                drop(permit);
                Ok::<(), jsonrpsee::core::SubscriptionError>(())
            },
        )
        .map_err(reg_err)?;
    Ok(())
}

fn optional_params(
    params: &jsonrpsee::types::Params<'_>,
    maximum: usize,
) -> Result<(), jsonrpsee::types::ErrorObjectOwned> {
    let values: Option<Vec<serde_json::Value>> = params.parse()?;
    if values.is_some_and(|values| values.len() > maximum) {
        return Err(invalid_params("too many parameters"));
    }
    Ok(())
}
