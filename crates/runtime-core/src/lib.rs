#![no_std]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Framework code shared by every Neutrin0 runtime.
//!
//! Defines the [`StateBackend`] trait that the STF is generic over and
//! two backend implementations that share the binary sparse Merkle
//! trie from `neutrin0-trie`:
//!
//! - [`WitnessState`] — `no_std + alloc`. Used inside the SP1 Guest;
//!   built from a [`StateWitness`](neutrin0_runtime_abi::StateWitness) via
//!   `Trie::from_persisted`, refuses
//!   reads of unwitnessed keys, and computes `post_state_root` by
//!   re-rooting the partial trie after the STF's writes.
//! - [`host::TracingState`] — only available with the `host` feature.
//!   Used by the dynamic runtime host during dry-run to record the
//!   read / write set, then materialise it into a `StateWitness` by
//!   collecting on-path trie nodes via `Trie::collect_path_nodes`.
//!
//! Wire formats live in `neutrin0-runtime-abi`. This crate is pure
//! Rust code that depends only on `neutrin0-trie` and the wire types.

extern crate alloc;
pub mod overlay;

pub mod execution;

mod backend;
mod witness;

#[cfg(feature = "host")]
pub mod host;

pub use backend::StateBackend;
pub use witness::{WitnessError, WitnessState};

use neutrin0_primitives::StateRoot;

/// State root of an empty trie. Mirrors `neutrin0_trie::EMPTY_TRIE_ROOT`
/// (`[0; 32]`).
pub const EMPTY_STATE_ROOT: StateRoot = neutrin0_trie::EMPTY_TRIE_ROOT;

/// Returns the canonical empty-state root.
#[must_use]
pub const fn empty_state_root() -> StateRoot {
    EMPTY_STATE_ROOT
}

#[cfg(test)]
mod tests;
