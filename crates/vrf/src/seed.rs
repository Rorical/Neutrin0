//! Public-seed fold: `SHA-256(prev_seed || vrf_proof_0 || ... || vrf_proof_n)`.

use neutrin0_primitives::{BlsSignature, Seed};
use sha2::{Digest, Sha256};

/// Derive the public output from a BLS-VRF proof. Authenticity is checked separately.
pub fn proof_output(proof: &BlsSignature) -> Seed {
    Sha256::digest(proof).into()
}

/// Fold a new public seed from `prev_seed` and the VRF proofs of every
/// block in the chunk that finalized the new seed.
///
/// Hash construction (see `docs/design/15-randomness.md`
/// §"Public seed: mix of finalized VRF outputs"):
///
/// ```text
/// seed_next = SHA-256(prev_seed || proof_0 || ... || proof_n)
/// ```
///
/// Each proof is fed in its 96-byte compressed G2 representation.
///
/// # Order
///
/// The input order is part of the canonical hash and **must** be the
/// block-height order within the chunk. Callers reordering this slice will
/// derive a different seed and fork the chain.
///
/// # Empty input
///
/// An empty `vrf_proofs` slice is permitted and yields `SHA-256(prev_seed)`.
/// In practice the engine only invokes this on finalized chunks, which by
/// construction contain at least one block.
#[must_use]
pub fn fold_seed(prev_seed: &Seed, vrf_proofs: &[BlsSignature]) -> Seed {
    let mut hasher = Sha256::new();
    hasher.update(prev_seed);
    for proof in vrf_proofs {
        hasher.update(proof);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests;
