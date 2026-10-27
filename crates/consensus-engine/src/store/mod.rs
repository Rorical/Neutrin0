//! Typed wrappers over a column-family [`Database`](neutrin0_storage::Database).
//!
//! `ChainStore` borsh-encodes every value and centralises the key
//! conventions for every consensus column (headers, bodies, proofs,
//! chunks, checkpoints, validator-set snapshots, pointers, metadata).
//!
//! The encoding rule is uniform: all integer keys are stored as
//! big-endian byte arrays so iteration order matches numeric order, and
//! every value is borsh-encoded. Pointers in the `Finalized` and `Meta`
//! columns use stable ASCII names (`tip`, `finalized_head`,
//! `latest_chunk_id`, ...).

mod availability;
mod bootstrap;
mod canonical;
mod chain_events;
mod chain_store;
pub use chain_events::{CHAIN_EVENT_WINDOW, ChainEvent, ChainEventState, ChainPoint};
mod error;
mod fork_carry;
mod history;
pub mod keys;
pub mod pointers;
mod reporter;
mod reporter_metrics;
mod retention;
mod snapshot;
mod state;
mod state_install;

pub use availability::SignedArtifactMetadata;
pub use chain_store::{ChainStore, StoredChunkReceipt, StoredReceipt, ValidatorSetSnapshot};
pub(crate) use chain_store::{chunk_receipt_key, receipt_key};
pub use error::StoreError;
pub use fork_carry::CarrySummary;
pub use reporter_metrics::{ReporterStorageStats, RetainedInventory};
pub(crate) use state::StatePin;
pub use state_install::StateInstall;
