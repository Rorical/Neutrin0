//! Log selection over ranges and single blocks, with response and read budgets.
use super::codec::{error, fixed};
use super::queries::artifacts;
use super::render::receipt_json;
use super::selection::{resolved, selected_height};
use crate::backend::BlockId;
use crate::server::RpcContext;
use crate::server::errors::{invalid_params, query_err};
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::Value;

#[derive(Clone, Default)]
pub(super) struct LogSelector {
    addresses: Option<Vec<[u8; 20]>>,
    topics: Vec<Option<Vec<[u8; 32]>>>,
}
impl LogSelector {
    pub(super) fn parse(value: &Value) -> Result<Self, ErrorObjectOwned> {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_params("log filter object expected"))?;
        let addresses = object
            .get("address")
            .map(|value| {
                value.as_array().map_or_else(
                    || fixed::<20>(value).map(|address| vec![address]),
                    |list| list.iter().map(fixed::<20>).collect(),
                )
            })
            .transpose()?;
        let topics = object
            .get("topics")
            .map(|value| {
                let list = value
                    .as_array()
                    .ok_or_else(|| invalid_params("topic array expected"))?;
                if list.len() > 4 {
                    return Err(invalid_params("at most four topic positions"));
                }
                list.iter()
                    .map(|value| {
                        if value.is_null() {
                            Ok(None)
                        } else if let Some(list) = value.as_array() {
                            if list.iter().any(Value::is_null) {
                                Ok(None)
                            } else {
                                list.iter()
                                    .map(fixed::<32>)
                                    .collect::<Result<Vec<_>, _>>()
                                    .map(Some)
                            }
                        } else {
                            fixed::<32>(value).map(|topic| Some(vec![topic]))
                        }
                    })
                    .collect::<Result<Vec<_>, ErrorObjectOwned>>()
            })
            .transpose()?
            .unwrap_or_default();
        Ok(Self { addresses, topics })
    }
    fn matches(&self, log: &neutrin0_runtime_abi::ethereum::EvmLog) -> bool {
        self.addresses
            .as_ref()
            .is_none_or(|addresses| addresses.contains(&log.address))
            && log.topics.len() >= self.topics.len()
            && self.topics.iter().enumerate().all(|(index, topics)| {
                topics
                    .as_ref()
                    .is_none_or(|topics| topics.contains(&log.topics[index]))
            })
    }
}
pub(super) async fn log_block(
    ctx: &RpcContext,
    block: &neutrin0_consensus_types::Block,
    selector: &LogSelector,
) -> Result<Vec<Value>, ErrorObjectOwned> {
    let projection = artifacts(ctx, block).await?;
    let mut start = 0;
    let mut result = Vec::new();
    for (index, receipt) in projection.receipts.iter().enumerate() {
        let projected = receipt_json(receipt, block.hash(), block.header.height, index, start);
        for (log, json) in receipt.logs.iter().zip(
            projected["logs"]
                .as_array()
                .ok_or_else(|| error("log projection unavailable"))?,
        ) {
            if selector.matches(log) {
                result.push(json.clone());
            }
        }
        start += receipt.logs.len();
    }
    Ok(result)
}
pub(super) async fn get_logs(
    ctx: &RpcContext,
    value: &Value,
) -> Result<Vec<Value>, ErrorObjectOwned> {
    let selector = LogSelector::parse(value)?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid_params("filter object expected"))?;
    if let Some(hash) = object.get("blockHash") {
        if object.contains_key("fromBlock") || object.contains_key("toBlock") {
            return Err(invalid_params(
                "blockHash cannot be combined with a block range",
            ));
        }
        let hash = fixed(hash)?;
        let block = ctx
            .backend()
            .block_by_hash(hash)
            .await
            .map_err(|error| query_err(&error))?;
        let Some(block) = block else {
            if ctx
                .backend()
                .genesis_info()
                .await
                .map_err(|error| query_err(&error))?
                .is_some_and(|genesis| genesis.hash == hash)
            {
                return Ok(Vec::new());
            }
            return Err(query_err(&crate::backend::QueryError::BlockNotFound));
        };
        let logs = log_block(ctx, &block, &selector).await?;
        check_log_budget(&logs)?;
        return Ok(logs);
    }
    let head = ctx
        .backend()
        .head()
        .await
        .map_err(|error| query_err(&error))?;
    let from = selected_height(ctx, object.get("fromBlock"), head.height).await?;
    let to = selected_height(ctx, object.get("toBlock"), head.height).await?;
    if from > to {
        return Ok(Vec::new());
    }
    if to - from >= 1024 {
        return Err(error("log range exceeds 1024 blocks"));
    }
    if to > head.height {
        return Err(query_err(&crate::backend::QueryError::BlockNotFound));
    }
    let endpoint = resolved(ctx, &BlockId::Height(to))
        .await?
        .ok_or_else(|| query_err(&crate::backend::QueryError::BlockNotFound))?;
    let mut logs = Vec::new();
    let mut previous = None;
    let mut read = ReadBudget::default();
    let mut budget = LogBudget::default();
    for height in from.max(1)..=to {
        let block = ctx
            .backend()
            .block_by_height(height)
            .await
            .map_err(|error| query_err(&error))?
            .ok_or_else(|| query_err(&crate::backend::QueryError::BlockNotFound))?;
        read.charge(&block.body)?;
        check_range_block(&block, previous)?;
        previous = Some(block.hash());
        let found = log_block(ctx, &block, &selector).await?;
        budget.add(&found)?;
        logs.extend(found);
    }
    if previous.is_some_and(|hash| hash != endpoint) {
        return Err(error(
            "canonical chain changed during log query; retry the request",
        ));
    }
    Ok(logs)
}

pub(super) fn check_range_block(
    block: &neutrin0_consensus_types::Block,
    previous: Option<[u8; 32]>,
) -> Result<(), ErrorObjectOwned> {
    if previous.is_some_and(|hash| block.header.parent_hash != hash) {
        return Err(error(
            "canonical chain changed during range query; retry the request",
        ));
    }
    Ok(())
}

pub(super) fn check_log_budget(logs: &[Value]) -> Result<(), ErrorObjectOwned> {
    LogBudget::default().add(logs)
}

/// Logs one response may carry, counted as they are found so a range
/// query never re-serializes what it already holds.
#[derive(Default)]
pub(super) struct LogBudget {
    entries: usize,
    bytes: usize,
}

impl LogBudget {
    pub(super) fn add(&mut self, logs: &[Value]) -> Result<(), ErrorObjectOwned> {
        self.entries = self.entries.saturating_add(logs.len());
        self.bytes = self
            .bytes
            .saturating_add(serde_json::to_vec(logs).map_err(invalid_params)?.len());
        if self.entries > 10_000 || self.bytes > 2 * 1024 * 1024 {
            return Err(error("log result exceeds local response budget"));
        }
        Ok(())
    }
}

/// Block bodies one range query may read before it must be narrowed.
const MAX_BLOCK_BYTES_PER_CALL: usize = 64 * 1024 * 1024;

#[derive(Default)]
pub(super) struct ReadBudget(usize);

impl ReadBudget {
    pub(super) fn charge(
        &mut self,
        body: &neutrin0_consensus_types::Body,
    ) -> Result<(), ErrorObjectOwned> {
        self.0 = self
            .0
            .saturating_add(borsh::object_length(body).map_err(invalid_params)?);
        if self.0 > MAX_BLOCK_BYTES_PER_CALL {
            return Err(error(
                "range reads more block data than the local budget; narrow the range",
            ));
        }
        Ok(())
    }
}
