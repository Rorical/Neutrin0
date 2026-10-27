//! Durable local chain-event journal rendering and cursor validation.

use neutrin0_consensus_engine::store::{
    CHAIN_EVENT_WINDOW, ChainEvent, ChainEventState, ChainPoint,
};
use neutrin0_rpc::types::{
    ChainCursorJson, ChainEventJson, ChainEventStatusJson, ChainPointJson, HashHex,
};

pub(super) const fn point(point: ChainPoint) -> ChainPointJson {
    ChainPointJson {
        hash: HashHex(point.hash),
        height: point.height,
    }
}
pub(super) fn cursor(state: &ChainEventState, sequence: u64) -> ChainCursorJson {
    ChainCursorJson {
        stream_id: HashHex(state.stream_id),
        sequence: sequence.to_string(),
    }
}
pub(super) fn status(state: &ChainEventState) -> ChainEventStatusJson {
    ChainEventStatusJson {
        chain_spec_hash: HashHex(state.chain_spec_hash),
        head: point(state.head),
        finalized: point(state.finalized),
        finalized_chunks: state.finalized_chunks,
        latest: cursor(state, state.next - 1),
        replay_from: cursor(state, state.oldest - 1),
        retention_events: CHAIN_EVENT_WINDOW,
    }
}

/// Why `after` cannot continue the journal, if it cannot.
pub(super) fn cursor_rejection(
    after: &ChainCursorJson,
    sequence: &Result<u64, core::num::ParseIntError>,
    status: &ChainEventStatusJson,
    state: &ChainEventState,
) -> Option<&'static str> {
    if after.stream_id != status.latest.stream_id {
        Some("wrong_stream")
    } else if sequence.as_ref().is_err()
        || sequence
            .as_ref()
            .is_ok_and(|value| value.to_string() != after.sequence)
    {
        Some("malformed")
    } else if sequence.as_ref().is_ok_and(|value| *value >= state.next) {
        Some("future")
    } else if sequence
        .as_ref()
        .is_ok_and(|value| *value < state.oldest - 1)
    {
        Some("expired")
    } else {
        None
    }
}

fn event_kind(event: &ChainEvent) -> &'static str {
    if event.previous_head.is_none() {
        "snapshot"
    } else if event.common_ancestor.is_none() {
        "checkpoint"
    } else if event.previous_head == Some(event.head) {
        "finalized"
    } else if event.common_ancestor != event.previous_head {
        "reorg"
    } else {
        "head"
    }
}

pub(super) fn event_json(
    state: &ChainEventState,
    sequence: u64,
    event: &ChainEvent,
) -> ChainEventJson {
    ChainEventJson {
        cursor: cursor(state, sequence),
        kind: event_kind(event).into(),
        previous_head: event.previous_head.map(point),
        head: point(event.head),
        common_ancestor: event.common_ancestor.map(point),
        previous_finalized: point(event.previous_finalized),
        finalized: point(event.finalized),
        previous_finalized_chunks: event.previous_finalized_chunks,
        finalized_chunks: event.finalized_chunks,
    }
}
