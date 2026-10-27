//! `eth_feeHistory`: base fees, gas ratios and reward percentiles over a range.
use super::codec::{argument, error, q, quantity};
use super::logs::{ReadBudget, check_range_block};
use super::queries::{artifacts, query};
use super::selection::{resolved, selected_height};
use crate::backend::BlockId;
use crate::server::RpcContext;
use crate::server::errors::{invalid_params, query_err};
use jsonrpsee::types::ErrorObjectOwned;
use neutrin0_runtime_abi::ethereum::{EvmArtifacts, FeeState};
use serde_json::{Value, json};

#[allow(
    clippy::cast_precision_loss,
    reason = "RPC reward percentiles are floating-point estimates, independent of consensus accounting."
)]
fn gas_percentile(
    receipts: &[neutrin0_runtime_abi::ethereum::EvmReceipt],
    base_fee: u64,
    percentile: f64,
) -> u128 {
    let mut bids = receipts
        .iter()
        .map(|receipt| {
            (
                receipt
                    .effective_gas_price
                    .saturating_sub(u128::from(base_fee)),
                receipt.gas_used,
            )
        })
        .collect::<Vec<_>>();
    bids.sort_unstable_by_key(|bid| bid.0);
    let total = bids.iter().map(|bid| bid.1).sum::<u64>();
    let target = (percentile * total as f64 / 100.0).ceil();
    let mut used = 0_u64;
    for (tip, gas) in bids {
        used += gas;
        if used as f64 >= target {
            return tip;
        }
    }
    0
}
pub(super) async fn fee_history(
    ctx: &RpcContext,
    args: &[Value],
) -> Result<Value, ErrorObjectOwned> {
    let count = u64::try_from(quantity(argument(args, 0)?)?).map_err(invalid_params)?;
    if count == 0 || count > 1024 {
        return Err(invalid_params(
            "fee history count must be between one and 1024",
        ));
    }
    let head = ctx
        .backend()
        .head()
        .await
        .map_err(|error| query_err(&error))?;
    let end = selected_height(ctx, args.get(1), head.height).await?;
    if end > head.height {
        return Err(query_err(&crate::backend::QueryError::BlockNotFound));
    }
    let percentiles = reward_percentiles(args.get(2))?;
    let oldest = end.saturating_sub(count - 1);
    let endpoint = resolved(ctx, &BlockId::Height(end))
        .await?
        .ok_or_else(|| query_err(&crate::backend::QueryError::BlockNotFound))?;
    let mut base_fees = Vec::new();
    let mut ratios = Vec::new();
    let mut rewards = Vec::new();
    let mut previous = None;
    let mut read = ReadBudget::default();
    for height in oldest..=end {
        if height == 0 {
            base_fees.push(genesis_base_fee(ctx).await?);
            ratios.push(0.0);
            rewards.push(vec![q(0); percentiles.len()]);
            continue;
        }
        let block = ctx
            .backend()
            .block_by_height(height)
            .await
            .map_err(|error| query_err(&error))?
            .ok_or_else(|| query_err(&crate::backend::QueryError::BlockNotFound))?;
        read.charge(&block.body)?;
        let projection = artifacts(ctx, &block).await?;
        check_range_block(&block, previous)?;
        previous = Some(block.hash());
        base_fees.push(q(u128::from(projection.metadata.base_fee)));
        ratios.push(gas_ratio(block.header.gas_used, block.header.gas_limit));
        rewards.push(block_rewards(&projection, &percentiles));
    }
    if previous.is_some_and(|hash| hash != endpoint) {
        return Err(error(
            "canonical chain changed during fee query; retry the request",
        ));
    }
    // The endpoint is pinned by hash so a reorg cannot silently change its fee.
    let next = query::<Option<FeeState>>(
        ctx,
        "evm:next_base_fee",
        Vec::new(),
        &BlockId::Hash(endpoint),
    )
    .await?
    .ok_or_else(|| error("historical endpoint fee state unavailable"))?;
    base_fees.push(q(u128::from(next.next_base_fee)));
    let mut response = json!({"oldestBlock":q(u128::from(oldest)),"baseFeePerGas":base_fees,"gasUsedRatio":ratios});
    if args.get(2).is_some() {
        response["reward"] = json!(rewards);
    }
    Ok(response)
}

fn reward_percentiles(value: Option<&Value>) -> Result<Vec<f64>, ErrorObjectOwned> {
    let percentiles = value
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| invalid_params("reward percentile array expected"))?
                .iter()
                .map(|value| {
                    value
                        .as_f64()
                        .filter(|value| value.is_finite() && *value >= 0.0 && *value <= 100.0)
                        .ok_or_else(|| invalid_params("reward percentile outside 0..100"))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    if percentiles.len() > 100 || !percentiles.windows(2).all(|pair| pair[0] <= pair[1]) {
        return Err(invalid_params(
            "percentiles must be sorted with at most 100 entries",
        ));
    }
    Ok(percentiles)
}

async fn genesis_base_fee(ctx: &RpcContext) -> Result<Value, ErrorObjectOwned> {
    let initial =
        query::<Option<FeeState>>(ctx, "evm:next_base_fee", Vec::new(), &BlockId::Height(0))
            .await?
            .ok_or_else(|| error("genesis fee unavailable"))?;
    Ok(q(u128::from(initial.next_base_fee)))
}

fn block_rewards(projection: &EvmArtifacts, percentiles: &[f64]) -> Vec<Value> {
    percentiles
        .iter()
        .map(|percentile| {
            q(gas_percentile(
                &projection.receipts,
                projection.metadata.base_fee,
                *percentile,
            ))
        })
        .collect::<Vec<_>>()
}

#[allow(
    clippy::cast_precision_loss,
    reason = "Ethereum JSON gas ratios and reward percentiles are floating-point estimates; no consensus or debit uses them."
)]
fn gas_ratio(used: u64, limit: u64) -> f64 {
    used as f64 / limit as f64
}
