//! Canonical gossip topic registry.
//!
//! All topics follow the structure `/neutrin0/<topic>/<format>` as
//! defined in `docs/design/21-networking.md`. The wire format is always
//! `borsh`. Each topic has one current payload format.
//!
//! Per-topic transmission byte caps, also defined in design 21, are enforced on
//! the gossipsub `Config` at service construction.

use core::fmt;

/// Number of aggregate finality-vote subnet topics (design 21).
pub const VOTE_SUBNETS: u8 = neutrin0_primitives::MAX_VOTE_SUBNETS;

/// The set of canonical Neutrin0 gossip topics.
///
/// Every variant maps to one canonical protocol string.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Topic {
    /// `/neutrin0/blocks/borsh`: a proposer's candidate publication, the
    /// `CandidateBlock` of signed block and write set, accepted or rejected
    /// as one unit (design 08).
    Blocks,
    /// `/neutrin0/receipts/borsh`: one `BlockReceipt`, the proof bytes of a
    /// block's execution, published by whoever proved it.
    Receipts,
    /// `/neutrin0/txs/borsh`: mempool transaction gossip.
    Transactions,
    /// `/neutrin0/slashing_evidence/borsh`: objective slashing reports.
    SlashingEvidence,
    /// Independently proven objective offences.
    EvidenceProofs,
    /// `/neutrin0/chunk_proofs/borsh`: aggregated chunk proofs.
    ChunkProofs,
    /// `/neutrin0/checkpoints/borsh`: compact authenticated-endpoint availability notices.
    Checkpoints,
    /// Fully proven next-chunk branch availability; rounds are advisory.
    BftCandidates,
    /// Bounded original-source availability inventory.
    SignedArtifacts,
    /// Signed leader proposals, nil votes and round-change declarations.
    BftMessages,
    /// `/neutrin0/finality_votes_prevote/borsh`: BFT prevote votes.
    FinalityVotesPrevote,
    /// `/neutrin0/finality_votes_precommit/borsh`: BFT precommit votes.
    FinalityVotesPrecommit,
    /// `/neutrin0/aggregate_finality_votes_<subnet>/borsh` for `subnet` in
    /// `0..VOTE_SUBNETS`.
    AggregateFinalityVotes(u8),
}

impl Topic {
    /// All non-subnet topics, in canonical order.
    pub const STATIC: [Self; 12] = [
        Self::Blocks,
        Self::Receipts,
        Self::Transactions,
        Self::SlashingEvidence,
        Self::EvidenceProofs,
        Self::ChunkProofs,
        Self::Checkpoints,
        Self::BftCandidates,
        Self::SignedArtifacts,
        Self::BftMessages,
        Self::FinalityVotesPrevote,
        Self::FinalityVotesPrecommit,
    ];

    /// All default gossip topics, including the 16 aggregate-vote subnet topics.
    pub fn all_default() -> impl Iterator<Item = Self> {
        Self::STATIC
            .into_iter()
            .chain((0..VOTE_SUBNETS).map(Self::AggregateFinalityVotes))
    }

    /// Maximum permitted transmission size in bytes, per design 21.
    ///
    /// Enforced by gossipsub via `max_transmit_size_for_topic`. Messages
    /// larger than this are dropped before propagation.
    #[must_use]
    pub const fn max_transmit_size(self) -> usize {
        match self {
            Self::Blocks => neutrin0_primitives::MAX_PROVEN_BLOCK_BYTES,
            Self::Receipts => 2 * 1024 * 1024,
            Self::BftMessages
            | Self::ChunkProofs
            | Self::EvidenceProofs
            | Self::SlashingEvidence
            | Self::FinalityVotesPrevote
            | Self::FinalityVotesPrecommit
            | Self::AggregateFinalityVotes(_) => 8 * 1024 * 1024,
            Self::Checkpoints => 1024,
            Self::SignedArtifacts => 2048,
            Self::BftCandidates => 16 * 1024,
            Self::Transactions => 128 * 1024,
        }
    }

    /// Canonical protocol string, e.g. `/neutrin0/blocks/borsh`.
    #[must_use]
    pub fn protocol_string(self) -> String {
        match self {
            Self::Blocks => "/neutrin0/blocks/borsh".to_owned(),
            Self::Receipts => "/neutrin0/receipts/borsh".to_owned(),
            Self::Transactions => "/neutrin0/txs/borsh".to_owned(),
            Self::EvidenceProofs => "/neutrin0/evidence_proofs/borsh".to_owned(),
            Self::SlashingEvidence => "/neutrin0/slashing_evidence/borsh".to_owned(),
            Self::ChunkProofs => "/neutrin0/chunk_proofs/borsh".to_owned(),
            Self::Checkpoints => "/neutrin0/checkpoints/borsh".to_owned(),
            Self::BftCandidates => "/neutrin0/bft_candidates/borsh".to_owned(),
            Self::SignedArtifacts => "/neutrin0/signed_artifacts/borsh".to_owned(),
            Self::BftMessages => "/neutrin0/bft_messages/borsh".to_owned(),
            Self::FinalityVotesPrevote => "/neutrin0/finality_votes_prevote/borsh".to_owned(),
            Self::FinalityVotesPrecommit => "/neutrin0/finality_votes_precommit/borsh".to_owned(),
            Self::AggregateFinalityVotes(subnet) => {
                format!("/neutrin0/aggregate_finality_votes_{subnet}/borsh")
            }
        }
    }

    /// Convert to a libp2p [`libp2p::gossipsub::IdentTopic`].
    #[must_use]
    pub fn to_ident(self) -> libp2p::gossipsub::IdentTopic {
        libp2p::gossipsub::IdentTopic::new(self.protocol_string())
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.protocol_string())
    }
}

#[cfg(test)]
mod tests;
