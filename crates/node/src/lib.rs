#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]
#![warn(missing_docs)]

//! Full-node assembly.
//!
//! This crate wires together the libp2p network stack
//! ([`neutrin0-network`](neutrin0_network)) and the engine-side sync
//! driver ([`neutrin0-sync`](neutrin0_sync)) into a single async
//! lifetime managed by [`run`]. The binary entry-point in `main.rs` is a
//! thin TOML-driven wrapper around this library.
//!
//! Provides TOML configuration, networking, full synchronization, WASM execution,
//! SP1 proof jobs, chunk BFT, validator production and optional JSON-RPC.

pub mod chain_backend;
pub mod chain_spec;
pub mod config;
pub mod db;
pub mod execution_metrics;
pub mod fork;
pub mod genesis;
pub(crate) mod health;
pub mod identity;
#[cfg(unix)]
pub mod management;
pub mod metrics;
mod process_metrics;
pub(crate) mod producer;
pub mod programs;
pub mod proof_metrics;
pub mod reporter_metrics;
pub mod runner;
mod storage_guard;

pub use chain_backend::{ChainBackend, SnapshotSummary};
pub use chain_spec::{AccountEntry, ChainSpecError, ChainSpecFile, ValidatorEntry};
pub use config::{
    ExecutionLimitsConfig, ExecutionMode, NodeConfig, NodeRole, PROPOSER_IKM_ENV, ProposerIkmError,
    ProposerIkmSource, ReporterConfig,
};
pub use db::{NodeDb, NodeDbError};
pub use genesis::{GenesisState, build_genesis_state};
pub use metrics::{MetricsSnapshot, MetricsSource, NodeMetrics};
pub use runner::{NodeError, run};

mod proof_queue;
mod proving_budget;
pub(crate) mod supervision;

/// Wall-clock Unix time in whole seconds; a clock before the epoch reads zero.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
