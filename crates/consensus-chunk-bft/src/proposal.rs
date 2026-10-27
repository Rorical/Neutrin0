//! Designated-leader proposal admission and the value votes held before it.

use alloc::vec::Vec;

use neutrin0_consensus_types::{
    BftProposal, FinalityVote, FinalityVoteData, FinalityVotePhase, QuorumCertificate, bft_leader,
};
use neutrin0_primitives::Hash;

use crate::stake::quorum_reached;
use crate::verify::{
    verify_individual_native, verify_round_certificate_native, verify_value_quorum_native,
};
use crate::{BftError, ChunkBft};

impl ChunkBft {
    /// Authenticate and retain the exact designated leader proposal for this tuple.
    /// Receipt/body validation remains the engine's prerequisite to accepting it.
    pub fn set_proposal(&mut self, proposal: BftProposal) -> Result<(), BftError> {
        self.verify_designated_leader(&proposal)?;
        self.verify_round_entry(&proposal)?;
        self.verify_valid_quorum(&proposal)?;
        if let Some(known) = &self.proposal {
            return if known == &proposal {
                Ok(())
            } else {
                Err(BftError::WrongVoteTarget)
            };
        }
        self.adopt_proposal(proposal);
        Ok(())
    }

    /// The proposal names this exact tuple and is signed by its designated
    /// round leader.
    fn verify_designated_leader(&self, proposal: &BftProposal) -> Result<(), BftError> {
        if proposal.chunk != self.chunk
            || proposal.round != self.round
            || bft_leader(
                self.domain.chain_id,
                self.chunk.chunk_id,
                self.round,
                &self.seed,
                &self.active_set,
            ) != Some(proposal.proposer_index)
        {
            return Err(BftError::WrongVoteTarget);
        }
        verify_individual_native(
            &self.active_set,
            proposal.proposer_index,
            &proposal.signing_message(self.domain),
            &proposal.signature,
        )
    }

    /// Round zero carries no entry certificate; every later round carries a
    /// valid one for this tuple whose highest QC the proposal does not downgrade.
    fn verify_round_entry(&self, proposal: &BftProposal) -> Result<(), BftError> {
        match (proposal.round, &proposal.round_change_certificate) {
            (0, None) => Ok(()),
            (0, Some(_)) | (_, None) => Err(BftError::WrongVoteTarget),
            (_, Some(certificate)) => {
                if certificate.chunk_id != self.chunk.chunk_id || certificate.round != self.round {
                    return Err(BftError::WrongVoteTarget);
                }
                verify_round_certificate_native(
                    self.domain,
                    &self.active_set,
                    self.total_stake,
                    certificate,
                    self.prevote_quorum,
                )?;
                if certificate.highest_quorum().is_some_and(|highest| {
                    proposal.valid_quorum.as_ref().is_none_or(|valid| {
                        valid.data.round < highest.data.round
                            || (valid.data.round == highest.data.round
                                && !valid.data.same_value(&highest.data))
                    })
                }) {
                    return Err(BftError::WrongVoteTarget);
                }
                Ok(())
            }
        }
    }

    fn verify_valid_quorum(&self, proposal: &BftProposal) -> Result<(), BftError> {
        // A justified proposal re-proposes the locked value: the chunk and the
        // payment selection its quorum signed (design 08).
        let Some(quorum) = &proposal.valid_quorum else {
            return Ok(());
        };
        if quorum.data.chunk_id != self.chunk.chunk_id
            || quorum.data.chunk_hash != self.chunk.hash()
            || quorum.data.selection != proposal.selection()
            || quorum.data.round >= self.round
        {
            return Err(BftError::WrongVoteTarget);
        }
        verify_value_quorum_native(
            self.domain,
            &self.active_set,
            Some(self.total_stake),
            quorum,
            self.prevote_quorum,
        )
    }

    fn adopt_proposal(&mut self, proposal: BftProposal) {
        // Votes held before the proposal count only for its selection.
        let selection = proposal.selection();
        if let Some(held) = self.pending_prevotes.remove(&selection) {
            self.prevotes = held;
        }
        if let Some(held) = self.pending_precommits.remove(&selection) {
            self.precommits = held;
        }
        self.pending_prevotes.clear();
        self.pending_precommits.clear();
        self.proposal = Some(proposal);
    }

    /// Prevote quorums reached by votes held before the round's proposal, one
    /// per selection. Each is an authenticated quorum certificate, so it is
    /// lock evidence whether or not the proposal arrives (design 08).
    #[must_use]
    pub fn pending_prevote_quorums(&self) -> Vec<QuorumCertificate> {
        self.pending_prevotes
            .iter()
            .filter(|(_, held)| {
                quorum_reached(held.aggregate_stake, self.total_stake, self.prevote_quorum)
            })
            .filter_map(|(selection, held)| {
                Some(QuorumCertificate {
                    data: FinalityVoteData {
                        chunk_id: self.chunk.chunk_id,
                        round: self.round,
                        chunk_hash: self.chunk.hash(),
                        selection: *selection,
                        phase: FinalityVotePhase::Prevote,
                    },
                    aggregate: held.aggregate()?,
                })
            })
            .collect()
    }

    /// Value votes held before the round's proposal, one aggregate per phase
    /// and selection, for durable restoration through `add_prevote` and
    /// `add_precommit`. Empty once a proposal is accepted.
    #[must_use]
    pub fn pending_votes(&self) -> Vec<FinalityVote> {
        let data = |selection: Hash, phase| FinalityVoteData {
            chunk_id: self.chunk.chunk_id,
            round: self.round,
            chunk_hash: self.chunk.hash(),
            selection,
            phase,
        };
        self.pending_prevotes
            .iter()
            .filter_map(|(selection, held)| held.vote(data(*selection, FinalityVotePhase::Prevote)))
            .chain(
                self.pending_precommits
                    .iter()
                    .filter_map(|(selection, held)| {
                        held.vote(data(*selection, FinalityVotePhase::Precommit))
                    }),
            )
            .collect()
    }
}
