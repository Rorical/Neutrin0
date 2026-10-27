#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Proof-system trait and backends.
//!
//! [`ProofSystem`] binds block execution, evidence receipts and complete
//! consensus chunks, each chunk recursively verifying its predecessor's, to
//! canonical public statements. [`MockProofSystem`] supplies block-only
//! fixtures; it never authorizes chunk finalization or History proofs.

extern crate alloc;

pub mod artifacts;
pub mod error;
pub mod executor;
pub mod history;
pub mod mock;
pub mod system;

pub use error::ProofError;
pub use executor::{
    BlockExecutionContext, BlockExecutor, ErasedBlockExecutor, ExecutionOutcome,
    UnsupportedExecutor, execution_inputs_commitment,
};
pub use history::{VerifiedHistory, verify_history_proof};
pub use mock::{MOCK_BLOCK_DOMAIN, MockBlockProof, MockProofSystem};
pub use system::ProofSystem;
