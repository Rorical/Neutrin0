//! Whether a message seen signed by a local key is one this node's journal
//! reserved (doppelganger detection, design 19).

use neutrin0_consensus_types::{BftProposal, FinalityVoteData, Header, NilVoteData, RoundChange};
use neutrin0_primitives::BlsPublicKey;
use neutrin0_storage::{Column, Database};

use super::{
    MessageIntent, MessageWatermark, PROPOSAL_MESSAGE_TAG, ProposalWatermark,
    ROUND_CHANGE_MESSAGE_TAG, VoteIntent, intent_key, message_watermark_key, nil_key, proposal_key,
    round_message_key,
};
use crate::{Engine, EngineError, StoreError};

/// A message seen signed by a local key, as the journal knows it.
#[expect(
    clippy::redundant_pub_crate,
    reason = "Re-exported crate-wide by the signing module."
)]
pub(crate) enum Seen<'a> {
    /// A value vote.
    Vote(&'a FinalityVoteData),
    /// A nil vote.
    NilVote(&'a NilVoteData),
    /// A round leader's proposal.
    Proposal(&'a BftProposal),
    /// A round change.
    RoundChange(&'a RoundChange),
    /// A block header.
    Header(&'a Header),
}

/// Whether this node's journal reserved a seen message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "Re-exported crate-wide by the signing module."
)]
pub(crate) enum Ownership {
    /// The journal reserved exactly this message.
    Own,
    /// The journal reserved another message at its position, or has signed
    /// nothing at or beyond it: another process signed it with this key.
    Foreign,
    /// The journal no longer holds that position (an earlier round or a
    /// finalized chunk), so it cannot tell.
    Unknown,
}

impl<DB: Database> Engine<DB> {
    /// Whether this node's journal reserved `seen`, signed by `identity`.
    pub(crate) fn journal_ownership(
        &self,
        identity: &BlsPublicKey,
        seen: &Seen<'_>,
    ) -> Result<Ownership, EngineError<DB::Error>> {
        let (chunk_id, round) = match seen {
            Seen::Header(header) => return self.header_ownership(identity, header),
            Seen::Vote(data) => (data.chunk_id, data.round),
            Seen::NilVote(data) => (data.chunk_id, data.round),
            Seen::Proposal(proposal) => (proposal.chunk.chunk_id, proposal.round),
            Seen::RoundChange(report) => (report.chunk_id, report.round),
        };
        if chunk_id < self.signing_finalized_floor()? {
            return Ok(Ownership::Unknown);
        }
        let read = |key: &[u8]| {
            self.store()
                .db()
                .get(Column::SigningJournal, key)
                .map_err(StoreError::Database)
        };
        let reserved = match seen {
            Seen::Vote(data) => {
                let nil = NilVoteData {
                    chunk_id,
                    round,
                    phase: data.phase,
                };
                if read(&nil_key(identity, &nil))?.is_some() {
                    return Ok(Ownership::Foreign);
                }
                read(&intent_key(identity, data))?
                    .map(|bytes| borsh::from_slice::<VoteIntent>(&bytes))
                    .transpose()?
                    .map(|intent| intent.data == **data)
            }
            Seen::NilVote(data) => {
                let value = FinalityVoteData {
                    chunk_id,
                    round,
                    phase: data.phase,
                    chunk_hash: [0; 32],
                    selection: [0; 32],
                };
                if read(&intent_key(identity, &value))?.is_some() {
                    return Ok(Ownership::Foreign);
                }
                read(&nil_key(identity, data))?.map(|_| true)
            }
            Seen::Proposal(proposal) => {
                return self.message_ownership(
                    identity,
                    PROPOSAL_MESSAGE_TAG,
                    chunk_id,
                    round,
                    &proposal.signing_message(self.consensus_domain()),
                );
            }
            Seen::RoundChange(report) => {
                return self.message_ownership(
                    identity,
                    ROUND_CHANGE_MESSAGE_TAG,
                    chunk_id,
                    round,
                    &report.signing_message(self.consensus_domain()),
                );
            }
            Seen::Header(_) => unreachable!("returned above"),
        };
        if let Some(same) = reserved {
            return Ok(if same {
                Ownership::Own
            } else {
                Ownership::Foreign
            });
        }
        // Nothing at this position: an earlier round may have been compacted,
        // but the journal has signed nothing at this round or a later one.
        Ok(match self.signing_round_for(identity, chunk_id)? {
            Some(highest) if round < highest => Ownership::Unknown,
            _ => Ownership::Foreign,
        })
    }

    fn message_ownership(
        &self,
        identity: &BlsPublicKey,
        tag: u8,
        chunk_id: u64,
        round: u32,
        message: &[u8],
    ) -> Result<Ownership, EngineError<DB::Error>> {
        let read = |key: &[u8]| {
            self.store()
                .db()
                .get(Column::SigningJournal, key)
                .map_err(StoreError::Database)
        };
        if let Some(bytes) = read(&round_message_key(tag, identity, chunk_id, round))? {
            let intent: MessageIntent = borsh::from_slice(&bytes)?;
            return Ok(if intent.message == message {
                Ownership::Own
            } else {
                Ownership::Foreign
            });
        }
        let highest = read(&message_watermark_key(tag, identity, chunk_id))?
            .map(|bytes| borsh::from_slice::<MessageWatermark>(&bytes))
            .transpose()?
            .map(|watermark| watermark.round);
        Ok(match highest {
            Some(highest) if round < highest => Ownership::Unknown,
            _ => Ownership::Foreign,
        })
    }

    fn header_ownership(
        &self,
        identity: &BlsPublicKey,
        header: &Header,
    ) -> Result<Ownership, EngineError<DB::Error>> {
        let Some(bytes) = self
            .store()
            .db()
            .get(Column::SigningJournal, &proposal_key(identity))
            .map_err(StoreError::Database)?
        else {
            return Ok(Ownership::Foreign);
        };
        let watermark: ProposalWatermark = borsh::from_slice(&bytes)?;
        Ok(if header.slot < watermark.slot {
            Ownership::Unknown
        } else if header.slot == watermark.slot && header.hash() == watermark.hash {
            Ownership::Own
        } else {
            Ownership::Foreign
        })
    }
}
