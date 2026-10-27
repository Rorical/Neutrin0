//! Bounded availability hints for the next chunk BFT session.

use crate::{Chunk, PaymentSelection, QuorumCertificate};
use borsh::{BorshDeserialize, BorshSerialize};

/// Local transport cap, rather than a consensus validator-set limit.
pub const MAX_CANDIDATE_SIGNERS: u32 = 65_536;

/// A branch that its provider has fully verified with the current proof backend.
///
/// The round is advisory: only a local timeout or an authenticated earlier
/// prevote quorum can authorize changing an active session.
#[derive(BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct BftCandidate {
    /// Semantic block and proof commitments, including the fixed branch endpoint.
    pub chunk: Chunk,
    /// Provider's current round or the next round justified by its target quorum.
    pub round: u32,
    /// Independently verified earlier prevote quorum for this target, if known.
    pub justification: Option<QuorumCertificate>,
    /// The payment selection the justification signed, which a leader
    /// re-proposing this value reproduces (design 08).
    pub selection: Option<PaymentSelection>,
}

impl BorshDeserialize for BftCandidate {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let chunk = Chunk::deserialize_reader(reader)?;
        let round = u32::deserialize_reader(reader)?;
        // Same option tag, bitmap bound (`MAX_BFT_SIGNERS` is this crate's
        // `MAX_CANDIDATE_SIGNERS`) and `InvalidData` rejections as BFT votes.
        let justification = crate::bft::read_optional_quorum(reader)?;
        let selection = Option::<PaymentSelection>::deserialize_reader(reader)?;
        Ok(Self {
            chunk,
            round,
            justification,
            selection,
        })
    }
}

#[cfg(test)]
mod tests;
