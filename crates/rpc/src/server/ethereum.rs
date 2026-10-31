//! Ethereum facade over opaque, historically selected runtime execution.
use super::{
    RpcContext, RpcStartError,
    clients::ClientIp,
    errors::{invalid_params, query_err, reg_err},
};
use jsonrpsee::{server::RpcModule, types::ErrorObjectOwned};
use serde_json::{Value, json};

mod blocks;
mod codec;
mod fees;
mod filters;
mod logs;
mod queries;
mod render;
mod selection;
mod state;
mod subscriptions;
#[cfg(test)]
mod tests;
mod transactions;

pub(super) use filters::Filters;

use blocks::{block_operation, block_receipts};
use codec::{argument, error, q};
use fees::fee_history;
use filters::filter_operation;
use logs::get_logs;
use queries::fees;
use state::{account_operation, call_operation};
use subscriptions::subscribe;
use transactions::{submit_operation, transaction_operation};

const METHODS: &[&str] = &[
    "eth_chainId",
    "net_version",
    "web3_clientVersion",
    "eth_syncing",
    "eth_blockNumber",
    "eth_getBalance",
    "eth_getTransactionCount",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_sendRawTransaction",
    "eth_call",
    "eth_estimateGas",
    "eth_gasPrice",
    "eth_maxPriorityFeePerGas",
    "eth_getBlockByNumber",
    "eth_getBlockByHash",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "eth_getBlockReceipts",
    "eth_getBlockTransactionCountByNumber",
    "eth_getBlockTransactionCountByHash",
    "eth_getTransactionByBlockHashAndIndex",
    "eth_getTransactionByBlockNumberAndIndex",
    "eth_feeHistory",
    "eth_getLogs",
    "eth_newFilter",
    "eth_newBlockFilter",
    "eth_newPendingTransactionFilter",
    "eth_getFilterChanges",
    "eth_getFilterLogs",
    "eth_uninstallFilter",
];

pub(super) fn register(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    for &method in METHODS {
        module
            .register_async_method(method, move |params, ctx, extensions| async move {
                // Wallet clients omit parameters or send null for zero-argument calls.
                let args = params
                    .parse::<Option<Vec<Value>>>()
                    .map_err(invalid_params)?
                    .unwrap_or_default();
                let client = extensions.get::<ClientIp>().copied();
                tokio::time::timeout(
                    ctx.runtime_call_timeout,
                    dispatch(&ctx, client, method, &args),
                )
                .await
                .unwrap_or_else(|_| {
                    Err(ErrorObjectOwned::owned(
                        -32012,
                        "Ethereum RPC operation timed out",
                        None::<()>,
                    ))
                })
            })
            .map_err(reg_err)?;
    }
    module
        .register_subscription(
            "eth_subscribe",
            "eth_subscription",
            "eth_unsubscribe",
            |params, pending, ctx, extensions| {
                let client = extensions.get::<ClientIp>().copied();
                subscribe(params, pending, ctx, client)
            },
        )
        .map_err(reg_err)?;
    Ok(())
}

async fn dispatch(
    ctx: &RpcContext,
    client: Option<ClientIp>,
    method: &str,
    args: &[Value],
) -> Result<Value, ErrorObjectOwned> {
    check_arguments(method, args)?;
    match method {
        "eth_newFilter"
        | "eth_newBlockFilter"
        | "eth_newPendingTransactionFilter"
        | "eth_getFilterChanges"
        | "eth_getFilterLogs"
        | "eth_uninstallFilter" => filter_operation(ctx, client, method, args).await,
        "eth_getLogs" => Ok(json!(get_logs(ctx, argument(args, 0)?).await?)),
        "eth_feeHistory" => fee_history(ctx, args).await,
        "eth_chainId" => Ok(q(u128::from(ctx.backend().chain_id()))),
        "net_version" => Ok(json!(ctx.backend().chain_id().to_string())),
        "web3_clientVersion" => Ok(json!(concat!("Neutrin0/", env!("CARGO_PKG_VERSION")))),
        "eth_syncing" => {
            if ctx.backend().is_syncing() {
                let head = ctx
                    .backend()
                    .head()
                    .await
                    .map_err(|error| query_err(&error))?;
                Ok(
                    json!({"startingBlock": "0x0", "currentBlock": q(u128::from(head.height)), "highestBlock": q(u128::from(head.height))}),
                )
            } else {
                Ok(Value::Bool(false))
            }
        }
        "eth_blockNumber" => Ok(q(u128::from(
            ctx.backend()
                .head()
                .await
                .map_err(|error| query_err(&error))?
                .height,
        ))),
        "eth_getBalance" | "eth_getTransactionCount" | "eth_getCode" | "eth_getStorageAt" => {
            account_operation(ctx, method, args).await
        }
        "eth_sendRawTransaction" => submit_operation(ctx, args).await,
        "eth_call" | "eth_estimateGas" => call_operation(ctx, method, args).await,
        "eth_gasPrice" => Ok(q(u128::from(fees(ctx).await?) + 1_000_000_000)),
        "eth_maxPriorityFeePerGas" => Ok(q(1_000_000_000)),
        "eth_getBlockByNumber"
        | "eth_getBlockByHash"
        | "eth_getBlockTransactionCountByNumber"
        | "eth_getBlockTransactionCountByHash"
        | "eth_getTransactionByBlockHashAndIndex"
        | "eth_getTransactionByBlockNumberAndIndex" => block_operation(ctx, method, args).await,
        "eth_getBlockReceipts" => block_receipts(ctx, argument(args, 0)?).await,
        "eth_getTransactionByHash" | "eth_getTransactionReceipt" => {
            transaction_operation(ctx, method, args).await
        }
        _ => Err(error("Ethereum operation unavailable")),
    }
}

fn check_arguments(method: &str, args: &[Value]) -> Result<(), ErrorObjectOwned> {
    let (minimum, maximum) = match method {
        "eth_chainId"
        | "net_version"
        | "web3_clientVersion"
        | "eth_syncing"
        | "eth_blockNumber"
        | "eth_gasPrice"
        | "eth_maxPriorityFeePerGas"
        | "eth_newBlockFilter"
        | "eth_newPendingTransactionFilter" => (0, 0),
        "eth_getBalance"
        | "eth_getTransactionCount"
        | "eth_getCode"
        | "eth_call"
        | "eth_estimateGas" => (1, 2),
        "eth_getStorageAt" | "eth_feeHistory" => (2, 3),
        "eth_getBlockByNumber"
        | "eth_getBlockByHash"
        | "eth_getTransactionByBlockHashAndIndex"
        | "eth_getTransactionByBlockNumberAndIndex" => (2, 2),
        _ => (1, 1),
    };
    if !(minimum..=maximum).contains(&args.len()) {
        return Err(invalid_params(format!(
            "{method} expects {minimum}..{maximum} arguments; state and block overrides are unsupported"
        )));
    }
    if matches!(method, "eth_getBlockByNumber" | "eth_getBlockByHash") && !args[1].is_boolean() {
        return Err(invalid_params(
            "full transaction selector must be a boolean",
        ));
    }
    Ok(())
}
