#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]
#![warn(missing_docs)]

//! Sync driver bridging [`neutrin0-network`](neutrin0_network) and the
//! consensus engine.
//!
//! The driver translates [`NetworkEvent`](neutrin0_network::service::NetworkEvent)s
//! into FSM input (drives [`neutrin0_network::SyncMachine`]) and translates
//! [`SyncCommand`](neutrin0_network::SyncCommand)s back into outbound
//! [`NetworkCommand`](neutrin0_network::service::NetworkCommand)s. Verification
//! and persistence are delegated to a host-provided [`SyncBackend`]
//! implementation; this keeps the driver crate independent of the consensus
//! engine and trivially unit-testable against an in-memory mock.

extern crate alloc;

pub mod backend;
pub mod driver;
/// Fixed-label synchronization and bootstrap measurements.
pub mod metrics;

pub use backend::{
    CheckpointsImported, ChunkProofImported, EvidenceProofAcceptance, HeadersImported,
    ProposalArtifacts, ReceiptsImported, StateProgress, SyncBackend, SyncBackendError,
};
pub use driver::{SyncDriver, SyncDriverConfig, SyncStatus};

// Re-export the FSM types so callers do not need to depend on
// `neutrin0-network` directly when they only want the driver.
pub use neutrin0_network::{LocalProgress, SyncMachine, SyncMode, SyncState};
