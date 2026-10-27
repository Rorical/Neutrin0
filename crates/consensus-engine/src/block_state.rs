//! Per-block production, proof and complete-consensus finalization states.

use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt;

/// State of a persisted block. Borsh encodes its variant tag as one byte.
#[derive(
    BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub enum BlockState {
    /// Block has been produced and persisted; its proof has not been
    /// started.
    BlockProduced,
    /// A prover has started work on the block proof but has not
    /// returned yet.
    PendingProof,
    /// The block proof has been produced and verified.
    Proven,
    /// A complete chunk proof and BFT certificate finalized this block.
    Finalized,
}

impl fmt::Display for BlockState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlockProduced => f.write_str("BlockProduced"),
            Self::PendingProof => f.write_str("PendingProof"),
            Self::Proven => f.write_str("Proven"),
            Self::Finalized => f.write_str("Finalized"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_wire_roundtrip() {
        let states = [
            BlockState::BlockProduced,
            BlockState::PendingProof,
            BlockState::Proven,
            BlockState::Finalized,
        ];
        for (index, state) in states.iter().enumerate() {
            let encoded = borsh::to_vec(state).unwrap();
            assert_eq!(encoded, [u8::try_from(index).unwrap()]);
            assert_eq!(borsh::from_slice::<BlockState>(&encoded).unwrap(), *state);
        }
    }
}
