//! Doppelganger protection.
//!
//! Another process signing with this node's key would sooner or later sign a
//! message that conflicts with one this node signed, which forfeits the
//! validator's whole slashable balance. Both processes see each other's
//! messages on gossip, so two defences apply. After it starts, the node signs
//! nothing for a quiet period (`[doppelganger] quiet_chunks` chunks of slots),
//! long enough for a running twin to show itself. And at every time, each
//! authenticated message signed by the local key is compared with the signing
//! journal: one the journal did not reserve pauses signing and production
//! durably, as an operator pause would, until the operator resumes them.

use neutrin0_consensus_types::Header;
use neutrin0_primitives::{BlsPublicKey, Slot};
use neutrin0_storage::Database;

use crate::signing::{Ownership, Seen};
use crate::{Engine, LocalSigningPolicy};

/// A message signed by the local key that this node did not sign.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Doppelganger {
    /// The local key another process signs with.
    pub identity: BlsPublicKey,
    /// What was seen: the message kind and its chunk and round, or slot.
    pub seen: String,
}

impl<DB: Database> Engine<DB> {
    /// Sign nothing until `chunks` chunks of slots have passed from now.
    pub fn set_doppelganger_quiet_chunks(&mut self, chunks: u64) {
        let slots = chunks.saturating_mul(self.chain_spec().consensus.chunk_size);
        self.signing_quiet_until = self.local_slot().saturating_add(slots);
    }

    /// The first slot this node may sign in after its quiet period.
    #[must_use]
    pub const fn signing_quiet_until(&self) -> Slot {
        self.signing_quiet_until
    }

    /// The message that paused signing since startup, if one did.
    #[must_use]
    pub const fn doppelganger(&self) -> Option<&Doppelganger> {
        self.doppelganger.as_ref()
    }

    /// Compare `seen`, authenticated as signed by `identity`, with the
    /// journal when `identity` is a local key, and pause signing durably if
    /// another process signed it. While such a pause stands nothing more is
    /// compared; the operator's resume clears it and detection resumes.
    pub(crate) fn check_doppelganger(&mut self, identity: &BlsPublicKey, seen: &Seen<'_>) {
        let local = [self.local_voter.as_ref(), self.standby_voter.as_ref()]
            .into_iter()
            .flatten()
            .any(|voter| voter.public_key_bytes() == identity);
        if !local || self.doppelganger.is_some() {
            return;
        }
        // A journal that cannot be read tells nothing; a later message is
        // compared again.
        if self.journal_ownership(identity, seen).ok() != Some(Ownership::Foreign) {
            return;
        }
        self.doppelganger = Some(Doppelganger {
            identity: *identity,
            seen: describe(seen),
        });
        // A failed write still closes both gates in memory.
        let _ = self.set_local_signing_policy(LocalSigningPolicy {
            signing_paused: true,
            production_paused: true,
        });
    }
}

fn describe(seen: &Seen<'_>) -> String {
    match seen {
        Seen::Vote(data) => format!(
            "{:?} of chunk {} round {}",
            data.phase, data.chunk_id, data.round
        ),
        Seen::NilVote(data) => format!(
            "nil {:?} of chunk {} round {}",
            data.phase, data.chunk_id, data.round
        ),
        Seen::Proposal(proposal) => format!(
            "proposal of chunk {} round {}",
            proposal.chunk.chunk_id, proposal.round
        ),
        Seen::RoundChange(report) => format!(
            "round change of chunk {} round {}",
            report.chunk_id, report.round
        ),
        Seen::Header(header) => header_description(header),
    }
}

fn header_description(header: &Header) -> String {
    format!("header at slot {} height {}", header.slot, header.height)
}
