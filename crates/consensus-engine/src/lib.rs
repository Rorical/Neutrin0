#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Consensus engine: slot-driven block production, proof FSM, and persistence.
//!
//! The engine executes and proves blocks, collects chunk BFT certificates,
//! and atomically installs complete consensus proof transitions.

pub mod availability;
pub mod bft_loop;
mod block_state;
mod bls_verdicts;
pub mod body;
pub mod bootstrap;
mod certified;
pub mod clock;
mod doppelganger;
pub mod engine;
pub mod error;
pub mod execution_claims;
pub mod finalize;
pub mod full_chunk;
pub mod history;
pub mod import;
pub mod local_control;
pub mod merkle;
pub mod produce;
pub mod programs;
mod projected;
pub mod proposer;
pub mod prove;
pub mod receipts;
mod reporter;
pub mod retention;
pub mod sign_request;
pub mod signature;
pub mod signing;
pub mod signing_transfer;
pub mod signing_validation;
pub use local_control::LocalSigningPolicy;
pub mod slashing;
pub mod store;
#[cfg(test)]
mod test_db;
pub mod validator_set;

pub use bft_loop::{BftAction, BftLoopError, BftQuorumIdentity, BftSession, BftSessionOverview};
pub use block_state::BlockState;
pub use body::{BodyRoots, apply_body_roots, compute_body_roots};
pub use certified::ValidatedExecutionChunk;
pub use clock::SlotClock;
pub use doppelganger::Doppelganger;
pub use engine::{Engine, StateSource};
pub use error::EngineError;
pub use finalize::{FinalizeError, FinalizeOutcome};
pub use import::{
    ImportBlockOutcome, ImportBlockProofOutcome, ImportChunkProofOutcome, ImportError,
    ReceiptOutcome,
};
pub use merkle::{EMPTY_MERKLE_ROOT, hash_leaf, merkle_root, merkle_root_of_hashes};
pub use produce::{ProductionConfig, ProductionError, ProductionOutcome};
pub use projected::{PendingProjection, ValidatedProjection};
pub use proposer::{ProposerKey, SignerError};
pub use prove::{ProveError, ProveOutcome, statement_key};
pub use sign_request::{RemoteSigner, SignRequest};
pub use signature::{SignatureError, proposer_signed_message, verify_header_signature};
pub use slashing::{SlashingError, SlashingMonitor, extract_single_signer};
pub use store::{
    ChainStore, StoreError, StoredChunkReceipt, StoredReceipt, ValidatorSetSnapshot, keys, pointers,
};
pub use validator_set::validator_set_root;

pub use history::history_proof_of;

pub use reporter::ReporterIdentity;
pub use retention::{RetentionInfo, RetentionPolicy};
