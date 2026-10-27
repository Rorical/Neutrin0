#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

//! Bounded, deterministic transaction mempool.
//!
//! The mempool is opaque to transaction contents. Callers admit
//! transactions with the runtime's validity verdict. The pool itself
//! enforces uniqueness by BLAKE3 hash, a caller-supplied byte budget,
//! and deterministic priority ordering with FIFO ties.

extern crate alloc;

mod pool;

pub use pool::{InsertError, Mempool, MempoolEntry};
