#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! JSON-RPC service for Neutrin0 nodes.
//!
//! The crate exposes a single async [`serve`] function that binds an
//! HTTP + WebSocket listener and registers all canonical methods
//! against any implementation of [`RpcBackend`]. The methods split
//! into three layers:
//!
//! - **Chain-agnostic** (`chain_*`, `system_*`, `state_getStorage`,
//!   `mempool_*`): served directly from the engine + mempool. They
//!   only touch consensus-side data (headers, raw trie nodes, mempool
//!   buffers, peer counts).
//! - **Runtime view calls** (`runtime_call`): proxied through the
//!   runtime's `_neutrin0_query` entrypoint. Per-method semantics are
//!   decided by the installed runtime; the host is a pure pipe.
//! - **Ethereum facade** (`eth_*`, `net_*`, `web3_*`): translates Ethereum
//!   requests into the installed runtime's account, simulation and authenticated
//!   execution-artifact query contracts.
//!
//! This layering means the node binary never has to learn about
//! runtime-specific account layouts. The EVM runtime and facade agree on query
//! payloads; the node continues to resolve authenticated state and programs.

pub mod backend;
pub mod client;
pub mod management;
pub mod metrics;
pub mod server;
pub mod types;

pub use backend::{
    BlockId, FinalizedInfo, HeadInfo, HistoryRetention, QueryError, RpcBackend, RuntimeCallError,
    RuntimeCallResponse, SubmitError,
};
pub use server::{
    RpcConfig, RpcContext, RpcStartError, build_module, build_module_with, serve,
    serve_with_metrics,
};
pub use types::{
    ArtifactProgressJson, BlockIdJson, BlockJson, BodyJson, BytesHex, FinalizedInfoJson, HashHex,
    HeadInfoJson, HeaderJson, HealthJson, InstalledGuestJson, PersistedArtifactJson,
    ProgramsStatusJson, ProvingStatusJson, RuntimeCallResultJson, SubmitResultJson, SystemInfoJson,
    ValidatorJson, Wei,
};
