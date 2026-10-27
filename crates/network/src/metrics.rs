//! Bounded, process-lifetime network measurements with fixed label sets.

use crate::rpc::RpcProtocol;
use libp2p::gossipsub;
use libp2p::request_response::{InboundFailure, OutboundFailure};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;

mod render;

const OUTCOMES: [&str; 10] = [
    "ok",
    "remote_error",
    "timeout",
    "connection_closed",
    "unsupported",
    "dial_failure",
    "io",
    "delivery_failed",
    "cancelled",
    "response_omission",
];
const BOOTNODE_STATES: [&str; BootnodeState::COUNT] = [
    "connected",
    "pending",
    "backoff",
    "ready",
    "disabled",
    "blocked",
];
const DIAL_FAILURES: [&str; 5] = ["self", "wrong_peer", "transport", "denied", "other"];
const BUCKETS_MILLIS: [u64; 10] = [1, 5, 10, 50, 100, 500, 1_000, 5_000, 10_000, 30_000];

const GOSSIP_PUBLISH: [&str; 3] = ["ok", "duplicate", "failed"];
const GOSSIP_VALIDATION: [&str; 3] = ["accept", "reject", "ignore"];

const GUARD_ACTIONS: [&str; 7] = [
    "connection_limit",
    "handshake",
    "gossip_budget",
    "inbound_rpc_budget",
    "outbound_rpc_budget",
    "quarantine",
    "address_filter",
];

#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum GuardAction {
    Connection,
    Handshake,
    Gossip,
    InboundRpc,
    OutboundRpc,
    Quarantine,
    Address,
}

/// `RpcProtocol::ALL` lists every variant in declaration order.
const fn protocol_index(protocol: RpcProtocol) -> usize {
    protocol as usize
}

/// Reconnect state of one configured bootnode address. Discriminants index
/// the `neutrin0_bootnodes{state}` labels in `BOOTNODE_STATES`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum BootnodeState {
    Connected,
    Pending,
    Backoff,
    Ready,
    Disabled,
    Blocked,
}

impl BootnodeState {
    /// Number of states, and therefore of exported state labels.
    pub(crate) const COUNT: usize = 6;
}

fn protocol_label(protocol: RpcProtocol) -> &'static str {
    let id = protocol.protocol_id();
    id.strip_prefix("/neutrin0/req/").unwrap_or(id)
}

#[derive(Clone, Copy)]
pub(crate) enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    const fn index(self) -> usize {
        match self {
            Self::Inbound => 0,
            Self::Outbound => 1,
        }
    }
    const fn label(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum RpcOutcome {
    Ok,
    RemoteError,
    Timeout,
    ConnectionClosed,
    Unsupported,
    DialFailure,
    Io,
    DeliveryFailed,
    Cancelled,
    ResponseOmission,
}

impl RpcOutcome {
    const fn index(self) -> usize {
        match self {
            Self::Ok => 0,
            Self::RemoteError => 1,
            Self::Timeout => 2,
            Self::ConnectionClosed => 3,
            Self::Unsupported => 4,
            Self::DialFailure => 5,
            Self::Io => 6,
            Self::DeliveryFailed => 7,
            Self::Cancelled => 8,
            Self::ResponseOmission => 9,
        }
    }

    pub(crate) const fn outbound(error: &OutboundFailure) -> Self {
        match error {
            OutboundFailure::DialFailure => Self::DialFailure,
            OutboundFailure::Timeout => Self::Timeout,
            OutboundFailure::ConnectionClosed => Self::ConnectionClosed,
            OutboundFailure::UnsupportedProtocols => Self::Unsupported,
            OutboundFailure::Io(_) => Self::Io,
        }
    }

    const fn inbound(error: &InboundFailure) -> Self {
        match error {
            InboundFailure::Timeout => Self::Timeout,
            InboundFailure::ConnectionClosed => Self::ConnectionClosed,
            InboundFailure::UnsupportedProtocols => Self::Unsupported,
            InboundFailure::ResponseOmission => Self::ResponseOmission,
            InboundFailure::Io(_) => Self::Io,
        }
    }
}

#[derive(Debug, Default)]
struct Histogram {
    buckets: [AtomicU64; BUCKETS_MILLIS.len()],
    overflow: AtomicU64,
    sum_micros: AtomicU64,
}

impl Histogram {
    fn observe(&self, elapsed: Duration) {
        let bucket = BUCKETS_MILLIS
            .iter()
            .position(|millis| elapsed <= Duration::from_millis(*millis));
        bucket
            .map_or(&self.overflow, |index| &self.buckets[index])
            .fetch_add(1, Ordering::Relaxed);
        self.sum_micros.fetch_add(
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }
}

#[derive(Debug, Default)]
struct RpcMeasurements {
    started: AtomicU64,
    completed: [AtomicU64; OUTCOMES.len()],
    transport_failures: [AtomicU64; OUTCOMES.len()],
    latency: Histogram,
}

impl RpcMeasurements {
    /// Every completion follows its start, so reading completions first keeps
    /// the difference non-negative under concurrent updates.
    fn inflight(&self) -> u64 {
        let completed: u64 = self
            .completed
            .iter()
            .map(|value| value.load(Ordering::Relaxed))
            .sum();
        self.started
            .load(Ordering::Relaxed)
            .saturating_sub(completed)
    }
}

/// Shared network metrics. All labels are finite protocol, direction, state or
/// outcome enums; peer identities, addresses and error text never become labels.
#[derive(Debug, Default)]
pub struct NetworkMetrics {
    bootnode_attempts: AtomicU64,
    bootnode_failures: [AtomicU64; DIAL_FAILURES.len()],
    bootnode_states: [AtomicU64; BOOTNODE_STATES.len()],
    opened: [AtomicU64; 2],
    closed: [AtomicU64; 2],
    peer_connections: AtomicU64,
    peer_disconnects: AtomicU64,
    ping_ok: AtomicU64,
    ping_failed: AtomicU64,
    ping_latency: Histogram,
    rpc: [[RpcMeasurements; 2]; RpcProtocol::ALL.len()],
    gossip_received: AtomicU64,
    gossip_received_bytes: AtomicU64,
    gossip_publish: [AtomicU64; GOSSIP_PUBLISH.len()],
    gossip_validation: [AtomicU64; GOSSIP_VALIDATION.len()],
    listener_failures: AtomicU64,
    guard_actions: [AtomicU64; GUARD_ACTIONS.len()],
}

impl NetworkMetrics {
    pub(crate) fn guard_action(&self, action: GuardAction) {
        self.guard_actions[action as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn bootnode_attempt(&self) {
        self.bootnode_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn bootnode_failure(&self, error: &libp2p::swarm::DialError) {
        use libp2p::swarm::DialError;
        let index = match error {
            DialError::LocalPeerId { .. } => 0,
            DialError::WrongPeerId { .. } => 1,
            DialError::Transport(_) => 2,
            DialError::Denied { .. } => 3,
            _ => 4,
        };
        self.bootnode_failures[index].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn bootnode_states(&self, states: [u64; BOOTNODE_STATES.len()]) {
        for (value, state) in states.into_iter().zip(&self.bootnode_states) {
            state.store(value, Ordering::Relaxed);
        }
    }

    pub(crate) fn connected(&self, outbound: bool, first: bool) {
        self.opened[usize::from(outbound)].fetch_add(1, Ordering::Relaxed);
        if first {
            self.peer_connections.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn disconnected(&self, outbound: bool, last: bool) {
        self.closed[usize::from(outbound)].fetch_add(1, Ordering::Relaxed);
        if last {
            self.peer_disconnects.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn ping(&self, result: Option<Duration>) {
        if let Some(elapsed) = result {
            self.ping_ok.fetch_add(1, Ordering::Relaxed);
            self.ping_latency.observe(elapsed);
        } else {
            self.ping_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn rpc_start(
        self: &Arc<Self>,
        protocol: RpcProtocol,
        direction: Direction,
    ) -> RpcObservation {
        let metrics = &self.rpc[protocol_index(protocol)][direction.index()];
        metrics.started.fetch_add(1, Ordering::Relaxed);
        RpcObservation {
            metrics: Arc::clone(self),
            protocol,
            direction,
            started: Instant::now(),
            finished: false,
        }
    }

    pub(crate) fn inbound_failure(
        &self,
        protocol: RpcProtocol,
        error: &InboundFailure,
    ) -> RpcOutcome {
        let outcome = RpcOutcome::inbound(error);
        self.rpc[protocol_index(protocol)][Direction::Inbound.index()].transport_failures
            [outcome.index()]
        .fetch_add(1, Ordering::Relaxed);
        outcome
    }

    pub(crate) fn outbound_failure(&self, protocol: RpcProtocol, error: &OutboundFailure) {
        self.rpc[protocol_index(protocol)][Direction::Outbound.index()].transport_failures
            [RpcOutcome::outbound(error).index()]
        .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn gossip_received(&self, bytes: usize) {
        self.gossip_received.fetch_add(1, Ordering::Relaxed);
        self.gossip_received_bytes
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
    pub(crate) fn gossip_publish<T>(&self, result: &Result<T, gossipsub::PublishError>) {
        let index = match result {
            Ok(_) => 0,
            Err(gossipsub::PublishError::Duplicate) => 1,
            Err(_) => 2,
        };
        self.gossip_publish[index].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn gossip_validation(&self, acceptance: gossipsub::MessageAcceptance) {
        let index = match acceptance {
            gossipsub::MessageAcceptance::Accept => 0,
            gossipsub::MessageAcceptance::Reject => 1,
            gossipsub::MessageAcceptance::Ignore => 2,
        };
        self.gossip_validation[index].fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn listener_failure(&self) {
        self.listener_failures.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) struct RpcObservation {
    metrics: Arc<NetworkMetrics>,
    protocol: RpcProtocol,
    direction: Direction,
    started: Instant,
    finished: bool,
}

impl RpcObservation {
    pub(crate) fn complete(&mut self, outcome: RpcOutcome) {
        if self.finished {
            return;
        }
        self.finished = true;
        let value = &self.metrics.rpc[protocol_index(self.protocol)][self.direction.index()];
        value.completed[outcome.index()].fetch_add(1, Ordering::Relaxed);
        value.latency.observe(self.started.elapsed());
    }
}

impl Drop for RpcObservation {
    fn drop(&mut self) {
        self.complete(RpcOutcome::Cancelled);
    }
}

#[cfg(test)]
mod tests;
