//! Leader-authorized value selection and quorum-synchronized phase deadlines.

use neutrin0_consensus_types::{
    BftProposal, Chunk, PaymentSelection, QuorumCertificate, RoundChangeCertificate,
};
use neutrin0_storage::Database;

use super::{BftSession, MAX_BFT_CANDIDATES, qc_rank};
use crate::Engine;

mod leader;
mod proposals;
mod rounds;

impl BftSession {
    /// Authenticated leader proposal selected for this round.
    #[must_use]
    pub const fn proposal(&self) -> Option<&BftProposal> {
        self.proposal.as_ref()
    }

    /// Highest independently authenticated valid value seen in an entered round.
    #[must_use]
    pub fn highest_valid_quorum(&self) -> Option<&QuorumCertificate> {
        self.valid_value.as_ref().map(|(_, _, quorum)| quorum)
    }

    /// Quorum-certified entry into this round, absent for initial round zero.
    #[must_use]
    pub const fn round_change_certificate(&self) -> Option<&RoundChangeCertificate> {
        self.round_certificate.as_ref()
    }
}

impl<DB: Database> Engine<DB> {
    pub(super) fn remember_bft_candidate(session: &mut BftSession, chunk: Chunk) {
        session.candidates.insert(chunk.hash(), chunk);
        while session.candidates.len() > MAX_BFT_CANDIDATES {
            let evict = session
                .candidates
                .keys()
                .find(|hash| {
                    **hash != session.chunk_hash
                        && session
                            .valid_value
                            .as_ref()
                            .is_none_or(|(chunk, _, _)| chunk.hash() != **hash)
                        && session
                            .highest_lock
                            .as_ref()
                            .is_none_or(|lock| lock.data.chunk_hash != **hash)
                        && session
                            .round_certificate
                            .as_ref()
                            .and_then(RoundChangeCertificate::highest_quorum)
                            .is_none_or(|quorum| quorum.data.chunk_hash != **hash)
                        && session
                            .local_round_report
                            .as_ref()
                            .and_then(|report| report.highest_quorum.as_ref())
                            .is_none_or(|quorum| quorum.data.chunk_hash != **hash)
                })
                .copied();
            let Some(evict) = evict else { break };
            session.candidates.remove(&evict);
        }
    }

    /// Retain a selection a leader signed or a quorum certified, bounded like
    /// the candidate inventory. Selections a retained quorum or the current
    /// proposal signed are never evicted.
    pub(super) fn remember_bft_selection(session: &mut BftSession, selection: PaymentSelection) {
        session.selections.insert(selection.commitment(), selection);
        while session.selections.len() > MAX_BFT_CANDIDATES {
            let evict = session
                .selections
                .keys()
                .find(|key| {
                    session.selection() != Some(**key)
                        && session
                            .valid_value
                            .as_ref()
                            .is_none_or(|(_, _, quorum)| quorum.data.selection != **key)
                        && session
                            .highest_lock
                            .as_ref()
                            .is_none_or(|lock| lock.data.selection != **key)
                        && session
                            .round_certificate
                            .as_ref()
                            .and_then(RoundChangeCertificate::highest_quorum)
                            .is_none_or(|quorum| quorum.data.selection != **key)
                        && session
                            .local_round_report
                            .as_ref()
                            .and_then(|report| report.highest_quorum.as_ref())
                            .is_none_or(|quorum| quorum.data.selection != **key)
                })
                .copied();
            let Some(evict) = evict else { break };
            session.selections.remove(&evict);
        }
    }

    /// Retain `quorum` as the highest valid value when it outranks the prior
    /// one: `chunk` with the payment `selection` the quorum signed. Returns
    /// whether it became the new valid value.
    pub(super) fn remember_bft_valid_value(
        session: &mut BftSession,
        chunk: Chunk,
        selection: PaymentSelection,
        quorum: QuorumCertificate,
    ) -> bool {
        if chunk.hash() != quorum.data.chunk_hash || selection.commitment() != quorum.data.selection
        {
            return false;
        }
        let higher = session
            .valid_value
            .as_ref()
            .is_none_or(|(_, _, prior)| qc_rank(&quorum) > qc_rank(prior));
        if higher {
            // Pin the new highest value before enforcing the cache bounds.
            // Otherwise it may be the first unprotected eviction victim.
            session.valid_value = Some((chunk.clone(), selection.clone(), quorum));
            Self::remember_bft_candidate(session, chunk);
            Self::remember_bft_selection(session, selection);
        }
        higher
    }
}

#[cfg(test)]
mod tests;
