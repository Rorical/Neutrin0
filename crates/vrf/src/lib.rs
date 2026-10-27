//! BLS-VRF for proposer election plus the RANDAO-style finalized-seed mix.
//!
//! See `docs/design/15-randomness.md` for the full protocol description.
//!
//! # Construction
//!
//! Neutrin0 reuses BLS12-381 (min-pk, POP scheme) from
//! [`neutrin0_crypto::bls`] for both the per-validator secret leader
//! election and the chain-wide public seed:
//!
//! * [`eval`] signs the canonical [`vrf_message`] with a validator's BLS
//!   secret key. BLS uniqueness makes the resulting signature a VRF
//!   proof; `SHA-256(proof_bytes)` is the 32-byte VRF output.
//! * [`verify`] checks the proof against the proposer's public key and
//!   recomputes the output so an honest verifier can feed it into the
//!   threshold check without re-doing the hash.
//! * [`is_eligible`] is the Algorand/Praos stake-weighted threshold check.
//!   It returns `true` iff `U256(output) < floor((2^256-1) * E * stake /
//!   total_stake)`, where `E = expected_proposers_per_slot / 2^64`.
//! * [`fold_seed`] computes the next public seed from the previous seed
//!   and every VRF proof in the chunk that finalized it
//!   (`SHA-256(prev_seed || proof_0 || ... || proof_n)`).
//!
//! All four operations are deterministic, side-effect free, and share the
//! same BLS verifier the Chunk Guest uses for finality-vote aggregation.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![allow(clippy::doc_markdown)]

extern crate alloc;

mod eval;
mod seed;
mod threshold;

pub use eval::{VrfOutput, vrf_message};
#[cfg(feature = "std")]
pub use eval::{VrfProof, eval, verify};
pub use seed::{fold_seed, proof_output};
pub use threshold::is_eligible;
