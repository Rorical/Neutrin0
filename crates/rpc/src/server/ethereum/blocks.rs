//! Block queries: bodies, transaction counts, indexed transactions and block receipts.
use super::codec::{argument, error, fixed, q, quantity};
use super::queries::{artifacts, decoded, pending_query};
use super::render::{block_json, genesis_json, pending_block_json, receipt_json, transaction_json};
use super::selection::{block_id, resolved, selected_id};
use crate::backend::BlockId;
use crate::server::RpcContext;
use crate::server::errors::{invalid_params, query_err};
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::{Value, json};

pub(super) async fn block_operation(
    ctx: &RpcContext,
    method: &str,
    args: &[Value],
) -> Result<Value, ErrorObjectOwned> {
    let at = if method.contains("Hash") {
        BlockId::Hash(fixed(argument(args, 0)?)?)
    } else {
        let (at, pending) = block_id(args.first())?;
        if pending {
            let block: neutrin0_runtime_abi::ethereum::PendingBlock =
                pending_query(ctx, "evm:block", Vec::new()).await?;
            if method.starts_with("eth_getBlockTransactionCount") {
                return Ok(q(block.transactions.len() as u128));
            }
            if method.starts_with("eth_getTransactionByBlock") {
                let index =
                    usize::try_from(quantity(argument(args, 1)?)?).map_err(invalid_params)?;
                return Ok(block.transactions.get(index).map_or(Value::Null, |tx| {
                    transaction_json(
                        tx,
                        None,
                        tx.fee_cap.min(
                            u128::from(block.metadata.base_fee)
                                .saturating_add(tx.tip_cap.unwrap_or(tx.fee_cap)),
                        ),
                    )
                }));
            }
            return Ok(pending_block_json(
                &block,
                args.get(1).and_then(Value::as_bool).unwrap_or(false),
            ));
        }
        at
    };
    let Some(hash) = resolved(ctx, &at).await? else {
        return Ok(Value::Null);
    };
    let Some(block) = ctx
        .backend()
        .block_by_hash(hash)
        .await
        .map_err(|error| query_err(&error))?
    else {
        if let Some(genesis) = genesis_json(ctx, hash).await? {
            return Ok(if method.starts_with("eth_getBlockTransactionCount") {
                q(0)
            } else if method.starts_with("eth_getTransactionByBlock") {
                Value::Null
            } else {
                genesis
            });
        }
        return Ok(Value::Null);
    };
    if method.starts_with("eth_getBlockTransactionCount") {
        return Ok(q(artifacts(ctx, &block).await?.receipts.len() as u128));
    }
    if method.starts_with("eth_getTransactionByBlock") {
        let projected = artifacts(ctx, &block).await?;
        let index = usize::try_from(quantity(argument(args, 1)?)?).map_err(invalid_params)?;
        let Some(receipt) = projected.receipts.get(index) else {
            return Ok(Value::Null);
        };
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
    block_json(
        ctx,
        &block,
        args.get(1).and_then(Value::as_bool).unwrap_or(false),
    )
    .await
}

pub(super) async fn block_receipts(
    ctx: &RpcContext,
    value: &Value,
) -> Result<Value, ErrorObjectOwned> {
    let (at, pending) = if value.as_str().is_some_and(|text| text.len() == 66) {
        (BlockId::Hash(fixed(value)?), false)
    } else if value.get("requireCanonical").and_then(Value::as_bool) == Some(true) {
        selected_id(ctx, Some(value)).await?
    } else {
        block_id(Some(value))?
    };
    if pending {
        return Err(invalid_params("pending blocks have no committed receipts"));
    }
    let Some(hash) = resolved(ctx, &at).await? else {
        return Ok(Value::Null);
    };
    let Some(block) = ctx
        .backend()
        .block_by_hash(hash)
        .await
        .map_err(|error| query_err(&error))?
    else {
        return Ok(
            if ctx
                .backend()
                .genesis_info()
                .await
                .map_err(|error| query_err(&error))?
                .is_some_and(|genesis| genesis.hash == hash)
            {
                json!([])
            } else {
                Value::Null
            },
        );
    };
    let projection = artifacts(ctx, &block).await?;
    let mut log_start = 0;
    let receipts = projection
        .receipts
        .iter()
        .enumerate()
        .map(|(index, receipt)| {
            let result = receipt_json(receipt, hash, block.header.height, index, log_start);
            log_start += receipt.logs.len();
            result
        })
        .collect::<Vec<_>>();
    Ok(Value::Array(receipts))
}
