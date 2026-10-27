//! Bounded finalized randomness access with explicit source identities.

use alloc::{string::String, vec::Vec};
use neutrin0_runtime_core::StateBackend;

/// State key of one of eight finalized seed records.
pub fn seed_key(index: u64) -> Vec<u8> {
    let mut key = Vec::from(&b"evm:finalized_seed:"[..]);
    key.extend_from_slice(&index.to_be_bytes());
    key
}

/// Read a finalized source-chunk seed; unavailable and overwritten sources are errors.
pub fn source_seed<B: StateBackend>(state: &mut B, source: u64) -> Result<[u8; 32], String> {
    let record: Option<(u64, [u8; 32])> = crate::state::read_record(state, &seed_key(source % 8))?;
    let Some((index, seed)) = record else {
        return Err("randomness source unavailable".into());
    };
    if source != index {
        return Err("randomness source no longer retained".into());
    }
    Ok(seed)
}
