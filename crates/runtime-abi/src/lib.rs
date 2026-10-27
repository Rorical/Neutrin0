#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Stable wire definitions for the Neutrin0 runtime ABI.
//!
//! This crate is the single source of truth for the contract between the
//! consensus node and any runtime (WASM dynamic runtime or SP1 guest). It
//! declares:
//!
//! - The WASM import module and export names the host links against
//!   ([`HOST_IMPORT_MODULE`], [`APPLY_BLOCK_ENTRYPOINT`], ...).
//! - The borsh-encoded read-only query request and response types
//!   ([`QueryRequest`], [`QueryResponse`]).
//! - The fixed-width transaction-validity result format
//!   ([`TxValidity`], [`TxValidationCode`]).
//! - The witness envelope handed to the SP1 Guest
//!   ([`StateWitness`], [`TrieNodeBytes`], [`TrieValueBytes`]).
//!
//! Field layouts are consensus-critical; the chain pins the runtime artifact hash.

extern crate alloc;

/// Protocol-level evidence-prefix ceiling shared by hosts and execution Guests.
pub const MAX_EVIDENCE_ADMISSIONS: u32 = 4096;

pub mod ethereum;
pub mod execution;
pub mod operational;
pub use execution::{
    AccountabilityOutput, BlockReceiptStatement, ExecutionArtifacts, RuntimeBlockInput,
    RuntimeBlockOutput, RuntimeBlockResult, RuntimeTransaction, Sanction, TransactionSummary,
};

mod call;
mod entrypoints;
mod query;
mod validity;
mod witness;

pub use call::{RuntimeCallInput, RuntimeCallOutput, RuntimeGenesisInput, RuntimeGenesisOutput};
pub use entrypoints::{
    ALLOCATE_ENTRYPOINT, APPLY_BLOCK_ENTRYPOINT, DEALLOCATE_ENTRYPOINT, HOST_IMPORT_MODULE,
    MEMORY_EXPORT, QUERY_ENTRYPOINT, VALIDATE_TX_ENTRYPOINT,
};
pub use query::{QueryRequest, QueryResponse, QueryStatus};
pub use validity::{
    TX_VALIDITY_ENCODED_LEN, TransactionDependency, TxValidationCode, TxValidity,
    TxValidityDecodeError,
};
pub use witness::{StateWitness, TrieNodeBytes, TrieValueBytes};

#[cfg(test)]
mod tests;
