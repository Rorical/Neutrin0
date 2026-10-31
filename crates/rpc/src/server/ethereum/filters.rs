//! Installed polling filters: inventory, polling and change computation.
use super::codec::{argument, bytes, error, height, q};
use super::logs::{LogSelector, check_log_budget, check_range_block, get_logs, log_block};
use super::selection::{resolved, selected_height};
use crate::backend::BlockId;
use crate::server::RpcContext;
use crate::server::clients::{ClientIp, ClientSlot, ClientSlots};
use crate::server::errors::{invalid_params, query_err};
use jsonrpsee::types::ErrorObjectOwned;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Polling filters installed at once, and by one client.
const FILTERS: usize = 128;
const FILTERS_PER_CLIENT: usize = 16;

pub(in crate::server) struct Filters {
    inner: Mutex<FilterInventory>,
    slots: ClientSlots,
}
impl Default for Filters {
    fn default() -> Self {
        Self {
            inner: Mutex::default(),
            slots: ClientSlots::new(FILTERS, FILTERS_PER_CLIENT),
        }
    }
}
#[derive(Default)]
struct FilterInventory {
    next: u64,
    /// Each filter with the slot it holds until it is removed or expires.
    filters: BTreeMap<u64, (Arc<tokio::sync::Mutex<PollFilter>>, ClientSlot)>,
}
#[derive(Clone)]
pub(super) struct PollFilter {
    pub(super) last_used: Instant,
    pub(super) initialized: bool,
    pub(super) kind: FilterKind,
    pub(super) cursor: u64,
    pub(super) known: BTreeMap<u64, ([u8; 32], Vec<Value>)>,
    pub(super) pending: BTreeSet<[u8; 32]>,
}
#[derive(Clone)]
pub(super) enum FilterKind {
    Logs { value: Value, selector: LogSelector },
    Blocks,
    Pending,
}
impl Filters {
    fn insert(
        &self,
        filter: PollFilter,
        client: Option<ClientIp>,
    ) -> Result<u64, ErrorObjectOwned> {
        let mut inventory = self
            .inner
            .lock()
            .map_err(|_| error("filter inventory unavailable"))?;
        inventory.filters.retain(|_, (filter, _)| {
            filter.try_lock().map_or(true, |filter| {
                filter.last_used.elapsed() < Duration::from_secs(300)
            })
        });
        let id = inventory
            .next
            .checked_add(1)
            .ok_or_else(|| error("filter identifier exhausted"))?;
        inventory.filters.insert(
            id,
            (
                Arc::new(tokio::sync::Mutex::new(filter)),
                self.slots
                    .acquire(client)
                    .ok_or_else(|| error("local filter capacity reached"))?,
            ),
        );
        inventory.next = id;
        drop(inventory);
        Ok(id)
    }
    fn get(&self, id: u64) -> Result<Arc<tokio::sync::Mutex<PollFilter>>, ErrorObjectOwned> {
        self.inner
            .lock()
            .map_err(|_| error("filter inventory unavailable"))?
            .filters
            .get(&id)
            .map(|(filter, _)| Arc::clone(filter))
            .ok_or_else(|| error("filter not found"))
    }
    fn remove(&self, id: u64) -> Result<bool, ErrorObjectOwned> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| error("filter inventory unavailable"))?
            .filters
            .remove(&id)
            .is_some())
    }
}
async fn new_filter(
    ctx: &RpcContext,
    client: Option<ClientIp>,
    method: &str,
    args: &[Value],
) -> Result<u64, ErrorObjectOwned> {
    let head = ctx
        .backend()
        .head()
        .await
        .map_err(|error| query_err(&error))?;
    let mut initialized = true;
    let kind = if method == "eth_newFilter" {
        let mut value = argument(args, 0)?.clone();
        let selector = LogSelector::parse(&value)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| invalid_params("filter object expected"))?;
        if object.contains_key("blockHash") {
            return Err(invalid_params(
                "blockHash selects a static eth_getLogs query; polling filters use ranges",
            ));
        }
        let starts_at_head = object
            .get("fromBlock")
            .is_none_or(|value| value == "latest");
        if starts_at_head {
            object.insert("fromBlock".into(), q(u128::from(head.height)));
        } else {
            initialized = false;
        }
        // Reject invalid/pending bounds during installation, rather than
        // publishing an unusable filter identifier.
        let _ = selected_height(ctx, object.get("fromBlock"), head.height).await?;
        let _ = selected_height(ctx, object.get("toBlock"), head.height).await?;
        FilterKind::Logs { value, selector }
    } else if method == "eth_newBlockFilter" {
        FilterKind::Blocks
    } else {
        FilterKind::Pending
    };
    let pending = if matches!(kind, FilterKind::Pending) {
        ctx.backend()
            .pending_identifiers()
            .await
            .into_iter()
            .collect()
    } else {
        BTreeSet::new()
    };
    ctx.ethereum_filters.insert(
        PollFilter {
            last_used: Instant::now(),
            initialized,
            kind,
            cursor: head.height,
            known: initial_filter_anchor(head.height, head.hash),
            pending,
        },
        client,
    )
}
pub(super) async fn poll_filter(
    ctx: &RpcContext,
    filter: &mut PollFilter,
) -> Result<Vec<Value>, ErrorObjectOwned> {
    if filter.last_used.elapsed() >= Duration::from_secs(300) {
        return Err(error("filter expired"));
    }
    filter.last_used = Instant::now();
    if matches!(filter.kind, FilterKind::Pending) {
        return pending_filter_changes(ctx, filter).await;
    }
    let head = ctx
        .backend()
        .head()
        .await
        .map_err(|error| query_err(&error))?;
    let finalized = ctx
        .backend()
        .finalized()
        .await
        .map_err(|error| query_err(&error))?;
    let mut changes = Vec::new();
    let mut replay = filter.cursor.saturating_add(1);
    let mut known = filter.known.clone();
    let (removed, heights, rewind) = removed_logs(ctx, &filter.known, head.height, replay).await?;
    changes.extend(removed);
    for height in heights {
        known.remove(&height);
    }
    replay = rewind;
    let (replay, end) = replay_window(ctx, filter, head.height, replay).await?;
    let mut previous = None;
    for height in replay.max(1)..=end {
        let block = ctx
            .backend()
            .block_by_height(height)
            .await
            .map_err(|error| query_err(&error))?
            .ok_or_else(|| query_err(&crate::backend::QueryError::BlockNotFound))?;
        let logs = match &filter.kind {
            FilterKind::Logs { selector, .. } => log_block(ctx, &block, selector).await?,
            FilterKind::Blocks => {
                changes.push(bytes(&block.hash()));
                Vec::new()
            }
            FilterKind::Pending => Vec::new(),
        };
        check_range_block(&block, previous)?;
        previous = Some(block.hash());
        changes.extend(logs.clone());
        known.insert(height, (block.hash(), logs));
        if changes.len() > 10_000
            || serde_json::to_vec(&changes).map_err(invalid_params)?.len() > 2 * 1024 * 1024
        {
            return Err(error("filter change response budget exceeded"));
        }
    }
    if resolved(ctx, &BlockId::Height(head.height)).await? != Some(head.hash) {
        return Err(error(
            "canonical chain changed during filter poll; retry the request",
        ));
    }
    check_log_budget(&changes)?;
    prune_filter_cache(&mut known, finalized.height)?;
    filter.known = known;
    filter.cursor = head.height;
    filter.initialized = true;
    Ok(changes)
}

/// The heights one poll replays: the rewound cursor clamped to a log
/// filter's range, bounded to the 1024-block polling window.
async fn replay_window(
    ctx: &RpcContext,
    filter: &PollFilter,
    head_height: u64,
    mut replay: u64,
) -> Result<(u64, u64), ErrorObjectOwned> {
    if let FilterKind::Logs { value, .. } = &filter.kind {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_params("filter object expected"))?;
        let from = selected_height(ctx, object.get("fromBlock"), head_height).await?;
        if !filter.initialized {
            replay = replay.min(from);
        }
        replay = replay.max(from);
    }
    let mut end = head_height;
    if let FilterKind::Logs { value, .. } = &filter.kind {
        end = end.min(selected_height(ctx, value.get("toBlock"), head_height).await?);
    }
    if replay <= end && end - replay >= 1024 {
        return Err(error("filter fell beyond its 1024-block polling window"));
    }
    Ok((replay, end))
}

pub(super) fn initial_filter_anchor(
    height: u64,
    hash: [u8; 32],
) -> BTreeMap<u64, ([u8; 32], Vec<Value>)> {
    if height == 0 {
        BTreeMap::new()
    } else {
        BTreeMap::from([(height, (hash, Vec::new()))])
    }
}
pub(super) async fn filter_operation(
    ctx: &RpcContext,
    client: Option<ClientIp>,
    method: &str,
    args: &[Value],
) -> Result<Value, ErrorObjectOwned> {
    if [
        "eth_newFilter",
        "eth_newBlockFilter",
        "eth_newPendingTransactionFilter",
    ]
    .contains(&method)
    {
        return Ok(q(u128::from(new_filter(ctx, client, method, args).await?)));
    }
    let id = height(argument(args, 0)?)?;
    if method == "eth_uninstallFilter" {
        return Ok(Value::Bool(ctx.ethereum_filters.remove(id)?));
    }
    let shared = ctx.ethereum_filters.get(id)?;
    let mut filter = shared.lock().await;
    if method == "eth_getFilterLogs" {
        if filter.last_used.elapsed() >= Duration::from_secs(300) {
            return Err(error("filter expired"));
        }
        filter.last_used = Instant::now();
        if let FilterKind::Logs { value, .. } = &filter.kind {
            let value = value.clone();
            drop(filter);
            return Ok(json!(get_logs(ctx, &value).await?));
        }
        drop(filter);
        return Err(invalid_params("filter does not select logs"));
    }
    let changes = poll_filter(ctx, &mut filter).await?;
    drop(filter);
    Ok(json!(changes))
}

async fn removed_logs(
    ctx: &RpcContext,
    previous: &BTreeMap<u64, ([u8; 32], Vec<Value>)>,
    head_height: u64,
    mut replay: u64,
) -> Result<(Vec<Value>, Vec<u64>, u64), ErrorObjectOwned> {
    let mut changes = Vec::new();
    let mut changed_heights = Vec::new();
    for (height, (old, logs)) in previous {
        let canonical = ctx
            .backend()
            .header_by_height(*height)
            .await
            .map_err(|error| query_err(&error))?
            .map(|header| header.hash());
        if *height > head_height || canonical != Some(*old) {
            for mut log in logs.clone() {
                log["removed"] = Value::Bool(true);
                changes.push(log);
            }
            changed_heights.push(*height);
            replay = replay.min(*height);
        }
    }
    Ok((changes, changed_heights, replay))
}

fn prune_filter_cache(
    known: &mut BTreeMap<u64, ([u8; 32], Vec<Value>)>,
    finalized_height: u64,
) -> Result<(), ErrorObjectOwned> {
    known.retain(|height, _| *height > finalized_height);
    if known.len() > 1024
        || serde_json::to_vec(
            &known
                .values()
                .flat_map(|(_, logs)| logs.iter())
                .collect::<Vec<_>>(),
        )
        .map_err(invalid_params)?
        .len()
            > 2 * 1024 * 1024
    {
        return Err(error("filter unfinalized cache budget exceeded"));
    }
    Ok(())
}

async fn pending_filter_changes(
    ctx: &RpcContext,
    filter: &mut PollFilter,
) -> Result<Vec<Value>, ErrorObjectOwned> {
    let pending = ctx
        .backend()
        .pending_identifiers()
        .await
        .into_iter()
        .collect::<BTreeSet<_>>();
    let new = pending
        .difference(&filter.pending)
        .map(|hash| bytes(hash))
        .collect();
    filter.pending = pending;
    Ok(new)
}
