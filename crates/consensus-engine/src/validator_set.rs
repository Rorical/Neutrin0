//! Validator-set commitment helpers shared by genesis and per-chunk
//! computations.
//!
//! The engine commits to the canonical borsh encoding of the full validator
//! vector via BLAKE3, which binds every `(pubkey, stake, status)` record of
//! the active set and is trivial to recompute deterministically.

use neutrin0_primitives::{Hash, Validator};

/// Compute the canonical validator-set commitment for `validators`.
///
/// The commitment is `BLAKE3(DOMAIN_VALIDATORS || borsh(validators))`
/// ([`neutrin0_primitives::validators_root`]); the empty set's is non-zero by
/// construction. A slice encodes exactly like the vector it borrows from.
#[must_use]
pub fn validator_set_root(validators: &[Validator]) -> Hash {
    neutrin0_consensus_types::evidence::commitment(validators)
}

#[cfg(test)]
mod tests;
