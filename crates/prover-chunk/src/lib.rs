#![no_std]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Deterministic validation shared by native and SP1 chunk proof paths.
//!
//! Validation alone does not verify the inner SP1 proofs. The guest must
//! recursively verify each block proof and commit the validated statement.

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod bft;
pub mod bls;
pub mod body;
pub mod consensus;
pub mod evidence;
pub mod execution;
pub mod finality;
pub mod history;
pub mod identity_sanctions;
#[cfg(feature = "sp1-verification")]
pub mod proof_verification;
pub mod proposer;
#[cfg(feature = "sp1-verification")]
pub mod receipt_codec;
pub mod rotation;
pub mod slashing;

/// Reusable cryptographic fact compression.
pub mod facts;
