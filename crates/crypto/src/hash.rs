//! Hash function wrappers.
//!
//! `blake3_256` lives in `neutrin0-primitives` so that crate can hash its
//! own types without a dependency cycle; we re-export it here for ergonomic
//! `crypto::blake3_256` access.

pub use neutrin0_primitives::{Hash, blake3_256};

use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};

/// Computes SHA-256.
///
/// Used by BLS hash-to-curve (transitively, via [`bls`](crate::bls)) and by
/// runtimes that need to hash for EIP-2333-compatible derivation paths.
pub fn sha256(input: &[u8]) -> Hash {
    let digest = Sha256::digest(input);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

/// Computes Keccak-256.
///
/// Used by EVM-compatible runtimes; not part of any consensus-critical
/// hash chain in Neutrin0 itself.
pub fn keccak256(input: &[u8]) -> Hash {
    let mut output = [0_u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(&mut output);
    output
}

#[cfg(test)]
mod tests;
