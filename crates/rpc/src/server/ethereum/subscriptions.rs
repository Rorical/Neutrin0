//! `eth_subscribe`: `newHeads` and `logs` streams driven by a polling filter.
use super::codec::{fixed, q};
use super::filters::{FilterKind, PollFilter, initial_filter_anchor, poll_filter};
use super::logs::LogSelector;
use super::render::block_json;
use crate::server::RpcContext;
use crate::server::errors::{invalid_params, query_err};
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};

#[allow(
    clippy::significant_drop_tightening,
    reason = "Reported inside the `tokio::select!` expansion of the subscription loop, whose sink must live for the whole loop."
)]
pub(super) async fn subscribe(
    params: jsonrpsee::types::Params<'static>,
    pending: jsonrpsee::server::PendingSubscriptionSink,
    ctx: Arc<RpcContext>,
    client: Option<crate::server::clients::ClientIp>,
) -> Result<(), jsonrpsee::core::SubscriptionError> {
    let args = match params.parse::<Vec<Value>>() {
        Ok(args) => args,
        Err(error) => {
            pending.reject(error).await;
            return Ok(());
        }
    };
    let Some(kind) = args.first().and_then(Value::as_str) else {
        pending
            .reject(invalid_params("subscription kind expected"))
            .await;
        return Ok(());
    };
    let head = match ctx.backend().head().await {
        Ok(head) => head,
        Err(error) => {
            pending.reject(query_err(&error)).await;
            return Ok(());
        }
    };
    let filter_kind = match subscription_filter(kind, &args, head.height) {
        Ok(kind) => kind,
        Err(error) => {
            pending.reject(error).await;
            return Ok(());
        }
    };
    let Some(_slot) = ctx.ethereum_subscriptions.acquire(client) else {
        pending
            .reject(ErrorObjectOwned::owned(
                crate::server::errors::BUSY_CODE,
                "Ethereum subscription limit reached",
                None::<()>,
            ))
            .await;
        return Ok(());
    };
    let sink = pending.accept().await?;
    let mut filter = PollFilter {
        last_used: Instant::now(),
        initialized: true,
        kind: filter_kind,
        cursor: head.height,
        known: initial_filter_anchor(head.height, head.hash),
        pending: BTreeSet::new(),
    };
    loop {
        let changes = tokio::select! {
            () = sink.closed() => return Ok(()),
            changes = tokio::time::timeout(ctx.runtime_call_timeout, subscription_changes(&ctx, kind, &mut filter)) => changes,
        };
        // A short-lived backend stall must not discard the subscription or its
        // cursor. Retry from the same anchor after the normal polling interval.
        if let Ok(changes) = changes {
            for value in changes? {
                tokio::select! {
                    () = sink.closed() => return Ok(()),
                    sent = sink.send(serde_json::value::to_raw_value(&value)?) => sent?,
                }
            }
        }
        tokio::select! {
            () = sink.closed() => break,
            () = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    }
    Ok::<(), jsonrpsee::core::SubscriptionError>(())
}

pub(super) fn subscription_filter(
    kind: &str,
    args: &[Value],
    height: u64,
) -> Result<FilterKind, ErrorObjectOwned> {
    match kind {
        "newHeads" if args.len() == 1 => Ok(FilterKind::Blocks),
        "logs" if args.len() <= 2 => {
            let value = args.get(1).cloned().unwrap_or_else(|| json!({}));
            let selector = LogSelector::parse(&value)?;
            if ["fromBlock", "toBlock", "blockHash"]
                .iter()
                .any(|field| value.get(field).is_some())
            {
                return Err(invalid_params(
                    "log subscriptions select addresses and topics only",
                ));
            }
            Ok(FilterKind::Logs {
                value: json!({"fromBlock": q(u128::from(height))}),
                selector,
            })
        }
        _ => Err(invalid_params("subscription supports logs and newHeads")),
    }
}

async fn subscription_value(
    ctx: &RpcContext,
    kind: &str,
    change: Value,
) -> Result<Value, ErrorObjectOwned> {
    if kind != "newHeads" {
        return Ok(change);
    }
    let hash = fixed::<32>(&change)?;
    let block = ctx
        .backend()
        .block_by_hash(hash)
        .await
        .map_err(|error| query_err(&error))?
        .ok_or_else(|| query_err(&crate::backend::QueryError::BodyUnavailable))?;
    let mut value = block_json(ctx, &block, false).await?;
    if let Some(object) = value.as_object_mut() {
        object.remove("transactions");
        object.remove("uncles");
    }
    Ok(value)
}

/// Render the whole poll before publishing its cursor. Cancellation during a
/// header projection leaves the previous anchor intact for the next attempt.
async fn subscription_changes(
    ctx: &RpcContext,
    kind: &str,
    filter: &mut PollFilter,
) -> Result<Vec<Value>, ErrorObjectOwned> {
    let mut next = filter.clone();
    next.last_used = Instant::now();
    let changes = poll_filter(ctx, &mut next).await?;
    let mut values = Vec::with_capacity(changes.len());
    for change in changes {
        values.push(subscription_value(ctx, kind, change).await?);
    }
    *filter = next;
    Ok(values)
}

#[cfg(test)]
mod tests;
