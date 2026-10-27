//! Deterministic vote-subnet and aggregator-committee membership.

use neutrin0_primitives::ChunkId;
use neutrin0_storage::Database;

use super::Engine;

impl<DB: Database> Engine<DB> {
    /// Subnet index used by the aggregator role to route the
    /// aggregated vote for `chunk_id` onto a single
    /// `AggregateFinalityVotes` subnet.
    ///
    /// The mapping is deterministic across the network: every node
    /// derives the same subnet from `chunk_id` and the chain spec's
    /// `vote_subnets`, so a publisher and a subscriber never need
    /// to coordinate which subnet to use for a given chunk.
    #[must_use]
    pub fn subnet_for_chunk(&self, chunk_id: ChunkId) -> u8 {
        let subnets = u64::from(self.chain_spec.consensus.vote_subnets.max(1));
        u8::try_from(chunk_id % subnets).expect("modulo by u16 fits u8")
    }

    /// Whether the local validator is part of the VRF-elected
    /// aggregator committee for `(chunk_id, round)`.
    ///
    /// Returns `false` when no local voter is configured, when the
    /// committee selection itself errors (e.g. empty active set),
    /// or when the local validator's index is not selected.
    #[must_use]
    pub fn local_is_aggregator_for(&self, chunk_id: ChunkId, round: u32) -> bool {
        let Some(voter) = self.active_local_voter() else {
            return false;
        };
        let local_idx = voter.validator_index();
        neutrin0_consensus_vrf::is_aggregator(
            self.active_validator_set(),
            &self.finalized_seed(),
            chunk_id,
            round,
            local_idx,
            self.chain_spec.consensus.expected_aggregators_per_round,
        )
        .unwrap_or(false)
    }
}
