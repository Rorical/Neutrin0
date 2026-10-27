//! Transaction submission and lookup by hash.
use super::codec::{argument, bytes, data, error, fixed};
use super::queries::{artifacts, decoded};
use super::render::{receipt_json, transaction_json};
use crate::server::RpcContext;
use crate::server::errors::{invalid_params, query_err, submit_err};
use jsonrpsee::types::ErrorObjectOwned;
use neutrin0_runtime_abi::RuntimeTransaction;
use serde_json::Value;

pub(super) async fn submit_operation(
    ctx: &RpcContext,
    args: &[Value],
) -> Result<Value, ErrorObjectOwned> {
    let envelope = borsh::to_vec(&RuntimeTransaction::User(data(argument(args, 0)?)?))
        .map_err(invalid_params)?;
    let tx = decoded(ctx, envelope.clone(), None).await?;
    match ctx.backend().submit_transaction(envelope).await {
        Ok(_) | Err(crate::backend::SubmitError::Duplicate) => Ok(bytes(&tx.hash)),
        Err(error) => Err(submit_err(&error)),
    }
}

pub(super) async fn transaction_operation(
    ctx: &RpcContext,
    method: &str,
    args: &[Value],
) -> Result<Value, ErrorObjectOwned> {
    let identifier = fixed(argument(args, 0)?)?;
    let pending = ctx.backend().pending_transaction(identifier).await;
    let found = ctx.backend().execution_transaction(identifier).await;
    let found = match found {
        Ok(found) => found,
        Err(crate::backend::QueryError::Pruned { .. }) if pending.is_some() => None,
        Err(error) => return Err(query_err(&error)),
    };
    let Some((hash, _)) = found else {
        if method == "eth_getTransactionByHash"
            && let Some(raw) = pending
        {
            let tx = decoded(ctx, raw, None).await?;
            return Ok(transaction_json(&tx, None, tx.fee_cap));
        }
        return Ok(Value::Null);
    };
    let block = ctx
        .backend()
        .block_by_hash(hash)
        .await
        .map_err(|error| query_err(&error))?
        .ok_or_else(|| error("indexed block body unavailable"))?;
    let projection = artifacts(ctx, &block).await?;
    let mut log_start = 0;
    for (index, receipt) in projection.receipts.iter().enumerate() {
        if receipt.transaction_hash == identifier {
            if method == "eth_getTransactionReceipt" {
                return Ok(receipt_json(
                    receipt,
                    hash,
                    block.header.height,
                    index,
                    log_start,
                ));
            }
            let raw = block
                .body
                .transactions
                .get(receipt.envelope_index as usize)
                .ok_or_else(|| error("invalid receipt index"))?
                .clone();
            return Ok(transaction_json(
                &decoded(ctx, raw, Some(hash)).await?,
                Some((hash, block.header.height, index)),
                receipt.effective_gas_price,
            ));
        }
        log_start += receipt.logs.len();
    }
    Err(error(
        "authenticated transaction index lacks a matching receipt",
    ))
}
