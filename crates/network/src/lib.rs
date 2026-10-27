#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]
#![warn(missing_docs)]

//! Networking stack for Neutrin0 consensus and execution gossip.
//!
//! The crate exposes a libp2p-based [`service::NetworkService`] with a
//! composed [`behaviour::Neutrin0Behaviour`] that wires up the discovery
//! (Kademlia), pub/sub (Gossipsub), connection-keepalive (identify + ping),
//! and request/response RPC layers described in `docs/design/21-networking.md`.
//! Topic strings and per-topic size caps live in [`topic`]; RPC wire types
//! and codecs live in [`rpc`].

/// Core libp2p behaviour composition for Neutrin0.
pub mod behaviour;
mod bootnodes;
/// Kademlia restricted to dialable targets.
pub mod kademlia;
/// Bounded process-lifetime network measurements for Prometheus exposition.
pub mod metrics;
/// Request/response RPC wire types and codec.
pub mod rpc;
/// The main networking service driving the swarm event loop.
pub mod service;
/// Sync state machine implementing design 21's `Init → ... → Following` flow.
pub mod sync;
/// Canonical gossip topic registry.
pub mod topic;

pub use libp2p;
pub use libp2p::{Multiaddr, PeerId};
pub use rpc::{RpcInboundId, RpcProtocol, RpcRequest, RpcResponse};
pub use sync::{
    LocalProgress, SyncCommand, SyncEvent, SyncMachine, SyncMode, SyncStallReason, SyncState,
};
pub use topic::Topic;
