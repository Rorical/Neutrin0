//! Networking service driving the libp2p swarm event loop.
//!
//! The service owns the [`libp2p::Swarm`] and runs as a long-lived `tokio`
//! task. Callers communicate with it via a pair of `mpsc` channels:
//!
//! - [`crate::service::NetworkCommand`] — outbound instructions from the host (dial,
//!   subscribe, publish, send RPC request, send RPC response, ...).
//! - [`crate::service::NetworkEvent`] — inbound notifications to the host (peer events,
//!   received gossip messages, incoming RPC requests, ...).
//!
//! Gossipsub is configured to match `docs/design/21-networking.md`:
//! mesh degree D = 8 (D_low = 6, D_high = 12), 700 ms heartbeat,
//! six-heartbeat history window, strict validation, BLAKE3 message IDs,
//! and per-topic byte caps from [`crate::topic::Topic::max_transmit_size`].
//!
//! Each request/response RPC from design 21 runs as its own
//! [`libp2p::request_response::Behaviour`]; outbound and inbound state is
//! tracked through `RpcDispatch` so callers see one unified
//! [`crate::service::NetworkCommand::SendRpcRequest`]/[`crate::service::NetworkEvent::RpcRequestReceived`]
//! API regardless of the protocol id. Outbound state is keyed by the protocol
//! and libp2p's own [`libp2p::request_response::OutboundRequestId`]. Inbound state is keyed by a
//! service-local monotonic `u64` because libp2p does not expose a public
//! constructor for `InboundRequestId`.

use crate::behaviour::Neutrin0Behaviour;
use crate::bootnodes::Bootnodes;
use crate::metrics::NetworkMetrics;
use crate::rpc::{self, RpcError, RpcInboundId, RpcRequest, RpcResponse};
use crate::topic::Topic;
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm, TransportError, core::transport::ListenerId, gossipsub,
    identity::Keypair, noise, swarm::SwarmEvent, tcp, yamux,
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

mod commands;
mod construction;
mod dialing;
mod discovery;
mod guard;
mod rpc_dispatch;
mod rpc_events;
mod swarm_events;

use construction::{build_behaviour, topic_index};
use dialing::wait_for_bootnode_retry;
use rpc_dispatch::RpcDispatch;

/// Errors returned when constructing or driving the network service.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// Noise handshake key derivation failed.
    #[error("noise key derivation failed: {0}")]
    Noise(#[from] noise::Error),
    /// Gossipsub configuration validation failed.
    #[error("gossipsub config error: {0}")]
    GossipsubConfig(String),
    /// Gossipsub behaviour construction failed.
    #[error("gossipsub behaviour error: {0}")]
    GossipsubBehaviour(String),
    /// Listener could not bind to the requested address.
    #[error("transport error: {0}")]
    Transport(#[from] TransportError<io::Error>),
    /// System DNS resolver initialisation failed.
    #[error("dns transport error: {0}")]
    Dns(io::Error),
    /// Operator-supplied bootnodes exceed bounds or name this node.
    #[error("invalid bootnode configuration: {0}")]
    Bootnodes(String),
    /// A bound listener failed or stopped unexpectedly.
    #[error("network listener failed: {0}")]
    Listener(String),
    /// The host stopped consuming events while network commands remain live.
    #[error("network event receiver closed")]
    EventReceiverClosed,
}

/// The network a peer connects from: its IPv4 /24 or IPv6 /48 prefix.
pub type HostGroup = [u8; 6];

/// Events emitted by [`NetworkService`] for the host to consume.
#[derive(Debug)]
pub enum NetworkEvent {
    /// A peer transitioned to the connected state.
    PeerConnected(PeerId),
    /// The network a newly connected peer reached this node from, sent just
    /// before its [`Self::PeerConnected`]. Loopback and configured bootnode
    /// peers have none and are told apart by identity alone.
    PeerHost {
        /// The connected peer.
        peer: PeerId,
        /// Its address prefix.
        host: HostGroup,
    },
    /// A peer's last connection closed.
    PeerDisconnected(PeerId),
    /// A node started listening on a new address.
    NewListenAddr(Multiaddr),
    /// A gossip message was received on a topic to which we are subscribed.
    ///
    /// The host MUST eventually return a verdict by sending
    /// [`crate::service::NetworkCommand::ReportGossipValidation`] referencing the
    /// supplied `message_id`. Failing to do so leaves the message in
    /// the gossipsub pipeline as "pending" forever — accepted-but-not-
    /// forwarded — which silently breaks mesh propagation.
    GossipMessage {
        /// Peer that propagated the message to us (not necessarily the originator).
        propagation_source: PeerId,
        /// Topic the message was published on.
        topic: Topic,
        /// Raw message bytes (borsh-encoded payload).
        data: Vec<u8>,
        /// Gossipsub message id; required to report a validation
        /// result back into the scoring engine.
        message_id: gossipsub::MessageId,
    },
    /// An inbound RPC request was received. The host must reply with
    /// [`crate::service::NetworkCommand::SendRpcResponse`] referencing the provided
    /// [`RpcInboundId`]; otherwise libp2p will time the request out.
    RpcRequestReceived {
        /// Peer that sent the request.
        peer: PeerId,
        /// Stable inbound id used to correlate the eventual response.
        inbound_id: RpcInboundId,
        /// Decoded request payload.
        request: RpcRequest,
    },
}

/// Commands the host sends to [`NetworkService`].
pub enum NetworkCommand {
    /// Dial a multiaddress to attempt a new connection.
    Dial(Multiaddr),
    /// Subscribe to a gossip topic.
    Subscribe(Topic),
    /// Publish a message on a topic.
    Publish {
        /// Target topic.
        topic: Topic,
        /// Raw message bytes (borsh-encoded payload).
        data: Vec<u8>,
    },
    /// Send an RPC request to a connected peer.
    ///
    /// The result will be delivered to `response_tx`. If the peer is not
    /// reachable, an error variant is returned.
    SendRpcRequest {
        /// Target peer.
        peer: PeerId,
        /// Request to send.
        request: RpcRequest,
        /// One-shot result channel.
        response_tx: oneshot::Sender<Result<RpcResponse, RpcError>>,
    },
    /// Send an RPC response for a previously emitted
    /// [`crate::service::NetworkEvent::RpcRequestReceived`].
    SendRpcResponse {
        /// Inbound id returned in the event.
        inbound_id: RpcInboundId,
        /// Response payload; must match the inbound protocol.
        response: RpcResponse,
    },
    /// Read the gossipsub peer scores for every currently-known peer.
    ///
    /// Returns a snapshot keyed by `PeerId`. Scores reflect the live
    /// strict-scoring parameters configured at service start (see
    /// `build_peer_score_config`).
    QueryPeerScores {
        /// One-shot reply channel with `(peer, score)` pairs.
        response_tx: oneshot::Sender<Vec<(PeerId, f64)>>,
    },
    /// Forward an application-level validation verdict back into
    /// gossipsub so it can update peer scores.
    ///
    /// The driver invokes this after handling each
    /// [`crate::service::NetworkEvent::GossipMessage`]. Repeated `Reject` verdicts
    /// against the same peer will eventually drive their score below
    /// `graylist_threshold` and exclude them from the mesh.
    ReportGossipValidation {
        /// Identifier from the originating [`crate::service::NetworkEvent::GossipMessage`].
        message_id: gossipsub::MessageId,
        /// Peer the message arrived through.
        propagation_source: PeerId,
        /// Verdict to record.
        acceptance: gossipsub::MessageAcceptance,
    },
}

impl core::fmt::Debug for NetworkCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Dial(addr) => f.debug_tuple("Dial").field(addr).finish(),
            Self::Subscribe(topic) => f.debug_tuple("Subscribe").field(topic).finish(),
            Self::Publish { topic, data } => f
                .debug_struct("Publish")
                .field("topic", topic)
                .field("data_len", &data.len())
                .finish(),
            Self::SendRpcRequest { peer, request, .. } => f
                .debug_struct("SendRpcRequest")
                .field("peer", peer)
                .field("protocol", &request.protocol())
                .finish(),
            Self::SendRpcResponse {
                inbound_id,
                response,
            } => f
                .debug_struct("SendRpcResponse")
                .field("inbound_id", inbound_id)
                .field("protocol", &response.protocol())
                .finish(),
            Self::QueryPeerScores { .. } => f.debug_struct("QueryPeerScores").finish(),
            Self::ReportGossipValidation {
                message_id,
                propagation_source,
                acceptance,
            } => f
                .debug_struct("ReportGossipValidation")
                .field("message_id", message_id)
                .field("propagation_source", propagation_source)
                .field("acceptance", &format_args!("{acceptance:?}"))
                .finish(),
        }
    }
}

/// The libp2p driver task for Neutrin0.
pub struct NetworkService {
    swarm: Swarm<Neutrin0Behaviour>,
    command_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
    rpc: RpcDispatch,
    bootnodes: Bootnodes,
    metrics: Arc<NetworkMetrics>,
    /// Default topics by wire hash, resolved once instead of per message.
    topics: HashMap<gossipsub::TopicHash, Topic>,
    guard: guard::Guard,
    control_events: VecDeque<NetworkEvent>,
    gossip_pending: HashMap<gossipsub::MessageId, (usize, bool)>,
    gossip_bytes: usize,
    consensus_gossip_bytes: usize,
    accepted_connections: HashMap<libp2p::swarm::ConnectionId, (PeerId, bool)>,
    identified_addresses: HashMap<PeerId, Vec<Multiaddr>>,
    local_status: Option<rpc::Status>,
    discovery: discovery::Discovery,
}

impl NetworkService {
    /// Construct a new [`NetworkService`].
    ///
    /// Builds the QUIC and TCP+Noise+Yamux transport stack, composes
    /// [`Neutrin0Behaviour`], and applies the gossipsub
    /// configuration from design 21.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError`] if any sub-protocol construction fails.
    pub fn new(
        local_key: Keypair,
        command_rx: mpsc::Receiver<NetworkCommand>,
        event_tx: mpsc::Sender<NetworkEvent>,
    ) -> Result<Self, NetworkError> {
        let local_peer_id = local_key.public().to_peer_id();
        let behaviour = build_behaviour(&local_key, local_peer_id)?;

        let swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_dns()
            .map_err(NetworkError::Dns)?
            .with_behaviour(|_| behaviour)
            .expect("infallible: behaviour already constructed")
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        let metrics = Arc::new(NetworkMetrics::default());
        Ok(Self {
            swarm,
            command_rx,
            event_tx,
            rpc: RpcDispatch {
                metrics: Arc::clone(&metrics),
                ..RpcDispatch::default()
            },
            bootnodes: Bootnodes::default(),
            metrics,
            topics: topic_index(),
            guard: guard::Guard::default(),
            control_events: VecDeque::new(),
            gossip_pending: HashMap::new(),
            gossip_bytes: 0,
            consensus_gossip_bytes: 0,
            accepted_connections: HashMap::new(),
            identified_addresses: HashMap::new(),
            local_status: None,
            discovery: discovery::Discovery::default(),
        })
    }

    /// Shared process-lifetime measurements; obtain before moving this service
    /// into its task. The handle does not retain the swarm.
    #[must_use]
    pub fn metrics(&self) -> Arc<NetworkMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Begin listening on the given multiaddress.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`TransportError`] when the address cannot be bound.
    pub fn listen_on(&mut self, addr: Multiaddr) -> Result<ListenerId, TransportError<io::Error>> {
        let result = self.swarm.listen_on(addr);
        if result.is_err() {
            self.metrics.listener_failure();
        }
        result
    }

    /// Require a matching chain handshake before application gossip and bulk RPC.
    pub const fn require_chain(&mut self, status: rpc::Status) {
        self.guard.chain = Some((status.chain_id, status.chain_spec_hash));
        self.local_status = Some(status);
    }

    fn queue_control(&mut self, event: NetworkEvent) {
        self.control_events.push_back(event);
    }

    /// The local node's [`PeerId`].
    #[must_use]
    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Drive the swarm and command queue until the command channel closes.
    ///
    /// # Errors
    /// Returns an error when a listener fails or the host event receiver closes.
    pub async fn run(mut self) -> Result<(), NetworkError> {
        let mut maintenance = tokio::time::interval(Duration::from_secs(1));
        let mut walk = tokio::time::interval(discovery::WALK_INTERVAL);
        loop {
            self.publish_bootnode_metrics();
            let retry_at = self.bootnodes.next_deadline();
            tokio::select! {
                permit = self.event_tx.clone().reserve_owned(), if !self.control_events.is_empty() => {
                    let permit = permit.map_err(|_| NetworkError::EventReceiverClosed)?;
                    if let Some(event) = self.control_events.pop_front() { permit.send(event); }
                },
                _ = maintenance.tick() => self.maintain_guard(),
                _ = walk.tick() => self.discover_peers(),
                event = self.swarm.select_next_some() => {
                    match &event {
                        SwarmEvent::ListenerError { listener_id, error } => {
                            self.metrics.listener_failure();
                            return Err(NetworkError::Listener(format!("{listener_id:?}: {error}")));
                        }
                        SwarmEvent::ListenerClosed { listener_id, reason, .. } => {
                            self.metrics.listener_failure();
                            return Err(NetworkError::Listener(format!("{listener_id:?} closed: {reason:?}")));
                        }
                        _ => {}
                    }
                    self.handle_swarm_event(event);
                },
                () = wait_for_bootnode_retry(retry_at) => self.dial_due_bootnodes(),
                () = self.event_tx.closed() => return Err(NetworkError::EventReceiverClosed),
                command = self.command_rx.recv() => if let Some(cmd) = command {
                    self.handle_command(cmd);
                } else {
                    debug!("command channel closed, network service shutting down");
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod bootnode_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod security_tests;
