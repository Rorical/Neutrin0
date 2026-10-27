#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Binary sparse Merkle trie with prefix compression.
//!
//! The state trie described in `docs/design/04-state-and-storage.md`: a
//! deterministic trie that stores values by content hash, stores trie nodes
//! by node hash, and exposes read/write plus inclusion/exclusion proof
//! generation and verification.
//!
//! The empty trie root is `[0; 32]`. Non-empty roots are hashes of
//! canonical node encodings under the selected [`Hasher`].

extern crate alloc;

mod bits;
mod error;
mod hasher;
mod node;
mod poseidon2;
mod proof;
mod trie;

use neutrin0_primitives::{StateRoot, ZERO_HASH};

pub use error::TrieError;
pub use hasher::{Blake3Hasher, Hasher, TRIE_NODE_DOMAIN};
pub use node::{NODE_TAG_BRANCH, NODE_TAG_EXTENSION, NODE_TAG_LEAF, Node};
pub use poseidon2::{Poseidon2Hasher, TRIE_NODE_DOMAIN_POSEIDON2};
pub use proof::{Proof, ProofError, ProofOutcome, ProofStep, ProofTerminal};
#[cfg(feature = "store")]
pub use trie::NodeSource;
pub use trie::{Trie, lookup_persisted};

/// Empty trie root.
pub const EMPTY_TRIE_ROOT: StateRoot = ZERO_HASH;
