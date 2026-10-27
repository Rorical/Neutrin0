//! Receipt selection and the voter's refusals (design 08).
//!
//! A block may hold several valid receipts. The proposer's own receipt wins
//! (rule P); inside the exclusive window after the block's slot no other
//! receipt is selectable (rule W); afterwards the leader names any valid
//! receipt it holds (rule L), its own whenever it proved the block. Chunk
//! `N - 1`'s proof is likewise any valid one the leader of chunk `N` holds. A
//! voter refuses a proposal that names a receipt or proof it does not hold,
//! a third-party receipt inside the window, or a third-party receipt while it
//! held the proposer's before the proposal arrived.

extern crate alloc;

use alloc::vec::Vec;

use neutrin0_consensus_types::bft::{ChunkRatification, ReceiptChoice};
use neutrin0_consensus_types::{BftProposal, Chunk, Header};
use neutrin0_primitives::{Hash, Slot};
use neutrin0_storage::Database;

use crate::bft_loop::{BftLoopError, conflict};
use crate::engine::Engine;
use crate::import::MAX_CLOCK_DRIFT_SECS;
use crate::store::{StoreError, StoredReceipt};

mod awaited;

/// Most proposals and certificates whose receipts are awaited at once.
const MAX_AWAITED: usize = 64;

/// The awaited-receipts slot of a verified chunk certificate, after every
/// proposal round.
pub(crate) const CERTIFIED_SLOT: u32 = u32::MAX;

/// The slot, receipt choices and ratification list a leader signs.
pub type ProposalSelection = (Slot, Vec<ReceiptChoice>, Vec<ChunkRatification>);

/// Blocks whose named receipt is missing and ratified chunks whose named
/// proof is missing, with that proof's statement key.
pub type MissingArtifacts = (Vec<neutrin0_primitives::BlockHash>, Vec<(u64, Hash)>);

/// Whether `receipt` is attributed to its block's proposer.
fn is_proposers(receipt: &StoredReceipt) -> bool {
    receipt.proof.prover_address == receipt.proof.public_inputs.proposer_address
}

/// Slots after its block's slot within which the proposer's receipt wins
/// whatever else is held.
///
/// That is half the exclusive window, when other nodes start proving a block
/// still unproven (design 08). Later, it wins only by arriving first, so a
/// proposer that withholds until someone else proves cannot then take the
/// payment.
#[must_use]
pub const fn proposer_lease(exclusive_slots: u64) -> u64 {
    exclusive_slots / 2
}

/// Slots by which a voter's first sighting of a third-party receipt must
/// trail the proposer's before the proposer's priority holds against it:
/// leader and voter clocks differ by about this much.
const ARRIVAL_TOLERANCE: u64 = 2;

/// Whether the proposer's `receipt` has priority over the other receipts
/// `held` for `header`: it arrived within the lease, or before them all.
fn proposer_priority(
    header: &Header,
    receipt: &StoredReceipt,
    held: &[StoredReceipt],
    exclusive_slots: u64,
    tolerance: u64,
) -> bool {
    receipt.first_verified_slot < header.slot.saturating_add(proposer_lease(exclusive_slots))
        || held.iter().all(|other| {
            is_proposers(other)
                || receipt.first_verified_slot
                    <= other.first_verified_slot.saturating_add(tolerance)
        })
}

/// The receipt a leader picks for `header` at `proposal_slot` among `held`.
///
/// That is the proposer's while it has priority, else after the exclusive
/// window the one `preferred` proved, else the earliest verified; `None`
/// while the block has no selectable receipt yet.
#[must_use]
pub fn select_receipt<'a>(
    header: &Header,
    held: &'a [StoredReceipt],
    proposal_slot: Slot,
    exclusive_slots: u64,
    preferred: Option<Hash>,
) -> Option<&'a StoredReceipt> {
    let proposers = held.iter().find(|receipt| is_proposers(receipt));
    if let Some(proposers) =
        proposers.filter(|receipt| proposer_priority(header, receipt, held, exclusive_slots, 0))
    {
        return Some(proposers);
    }
    if proposal_slot < header.slot.saturating_add(exclusive_slots) {
        // Inside the window only the proposer's receipt is selectable.
        return proposers;
    }
    held.iter()
        .find(|receipt| Some(receipt.proof.prover_address) == preferred)
        .or_else(|| {
            held.iter()
                .min_by_key(|receipt| (receipt.first_verified_slot, receipt.proof.statement_key))
        })
}

impl<DB: Database> Engine<DB> {
    /// The headers of `chunk`'s range in height order, from the retained
    /// branch ending at its end block.
    fn chunk_headers(&self, chunk: &Chunk) -> Result<Option<Vec<Header>>, StoreError<DB::Error>> {
        let mut headers = Vec::new();
        let mut cursor = chunk.end_block_hash;
        for height in (chunk.start_height..=chunk.end_height).rev() {
            let Some(header) = self.store().get_header(&cursor)? else {
                return Ok(None);
            };
            if header.height != height || header.hash() != cursor {
                return Err(StoreError::Corrupt("BFT branch header mismatch"));
            }
            cursor = header.parent_hash;
            headers.push(header);
        }
        headers.reverse();
        Ok(Some(headers))
    }

    /// The slot a local leader signs into its proposal: the wall-clock slot,
    /// never below the slot of the range's last block.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn leader_proposal_slot(&self, chunk: &Chunk) -> Result<Slot, StoreError<DB::Error>> {
        let last = self
            .store()
            .get_header(&chunk.end_block_hash)?
            .map_or(0, |header| header.slot);
        Ok(self.local_slot().max(last))
    }

    /// The receipts the selection rules pick for every height of `chunk` at
    /// `proposal_slot`, or `None` while some height has no selectable
    /// receipt: the leader then waits for the proposer's receipt or the end
    /// of the exclusive window.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn selected_receipts(
        &self,
        chunk: &Chunk,
        proposal_slot: Slot,
    ) -> Result<Option<Vec<ReceiptChoice>>, StoreError<DB::Error>> {
        let Some(headers) = self.chunk_headers(chunk)? else {
            return Ok(None);
        };
        let exclusive = self.chain_spec().consensus.proof_exclusive_slots;
        let preferred = self.prover_address().ok();
        let mut choices = Vec::with_capacity(headers.len());
        for header in &headers {
            let held = self.store().block_receipts(&header.hash())?;
            let Some(selected) = select_receipt(header, &held, proposal_slot, exclusive, preferred)
            else {
                return Ok(None);
            };
            choices.push(ReceiptChoice {
                prover_address: selected.proof.prover_address,
                statement_key: selected.proof.statement_key,
            });
        }
        Ok(Some(choices))
    }

    /// The slot, receipts and ratification list a local leader would sign for
    /// `chunk` now; the receipt list is empty while some height has no
    /// selectable receipt.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn proposal_selection(
        &self,
        chunk: &Chunk,
    ) -> Result<ProposalSelection, StoreError<DB::Error>> {
        let slot = self.leader_proposal_slot(chunk)?;
        let receipts = self.selected_receipts(chunk, slot)?.unwrap_or_default();
        let ratified = self.ratification_selection(chunk)?.unwrap_or_default();
        Ok((slot, receipts, ratified))
    }

    /// Whether a local leader could propose `chunk` now: every height has a
    /// selectable receipt at the slot it would sign.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn chunk_proposable(&self, chunk: &Chunk) -> Result<bool, StoreError<DB::Error>> {
        let slot = self.leader_proposal_slot(chunk)?;
        Ok(self.selected_receipts(chunk, slot)?.is_some())
    }

    /// The chunk proof a leader ratifies for `chunk_id` among the held ones:
    /// its own whenever it proved the chunk, else the earliest verified.
    fn select_chunk_receipt(
        &self,
        chunk_id: u64,
    ) -> Result<Option<crate::store::StoredChunkReceipt>, StoreError<DB::Error>> {
        let held = self.store().chunk_receipts(chunk_id)?;
        let preferred = self.prover_address().ok();
        Ok(held
            .iter()
            .find(|receipt| Some(receipt.proof.prover_address) == preferred)
            .or_else(|| {
                held.iter()
                    .min_by_key(|receipt| (receipt.first_verified_slot, receipt.statement_key))
            })
            .cloned())
    }

    /// The ratification a leader proposing `chunk` signs: nothing for the
    /// specification's first chunk, else a valid proof of the previous chunk
    /// (design 08). `None`
    /// while no such proof is held: no certificate of a later chunk exists
    /// without it. A session opens only after the previous chunk finalized,
    /// so a node that finalized it by proof holds one.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn ratification_selection(
        &self,
        chunk: &Chunk,
    ) -> Result<Option<Vec<ChunkRatification>>, StoreError<DB::Error>> {
        let Some(previous) = self.chain_spec().previous_chunk(chunk.chunk_id) else {
            return Ok(Some(Vec::new()));
        };
        Ok(self.select_chunk_receipt(previous)?.map(|selected| {
            alloc::vec![ChunkRatification {
                chunk_id: previous,
                prover_address: selected.proof.prover_address,
                finality_cert_hash: neutrin0_consensus_types::evidence::commitment(
                    &selected.proof.finality_cert,
                ),
                statement_key: selected.statement_key,
            }]
        }))
    }

    /// Whether the block `hash` holds no receipt attributed to its proposer.
    /// Its proposer keeps proving it after a foreign receipt proved it: rule P
    /// selects the proposer's receipt whenever held.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn lacks_proposer_receipt(&self, hash: &Hash) -> Result<bool, StoreError<DB::Error>> {
        Ok(!self.store().block_receipts(hash)?.iter().any(is_proposers))
    }

    /// Check a proposal's ratification (design 08): it names exactly the
    /// previous chunk's proof, which this node holds under that attribution
    /// and certificate. Any valid proof is acceptable.
    fn check_ratifications(&self, proposal: &BftProposal) -> Result<(), BftLoopError<DB::Error>> {
        let list = &proposal.ratified_chunk_proofs;
        if !neutrin0_consensus_types::proving::ratifies_previous(
            list,
            self.chain_spec().previous_chunk(proposal.chunk.chunk_id),
        ) {
            return Err(conflict());
        }
        for entry in list {
            let held = self.store().chunk_receipts(entry.chunk_id)?;
            // Rule 4: an unheld proof is unavailable, retried on arrival.
            let Some(named) = held
                .iter()
                .find(|receipt| receipt.statement_key == entry.statement_key)
            else {
                return Err(BftLoopError::ChunkProofUnavailable {
                    chunk_id: entry.chunk_id,
                    statement_key: entry.statement_key,
                });
            };
            if named.proof.prover_address != entry.prover_address
                || neutrin0_consensus_types::evidence::commitment(&named.proof.finality_cert)
                    != entry.finality_cert_hash
            {
                return Err(conflict());
            }
        }
        Ok(())
    }

    /// Apply the voter's refusals to a leader proposal received at
    /// `arrival_slot`.
    ///
    /// # Errors
    /// Returns [`BftLoopError::ReceiptUnavailable`] for a named receipt this
    /// node does not hold, and a conflict for a selection the rules forbid.
    pub fn check_receipt_selection(
        &self,
        proposal: &BftProposal,
        arrival_slot: Slot,
    ) -> Result<(), BftLoopError<DB::Error>> {
        let chunk = &proposal.chunk;
        let Some(headers) = self.chunk_headers(chunk)? else {
            return Err(BftLoopError::Candidate(
                crate::FinalizeError::MissingBlock {
                    height: chunk.end_height,
                },
            ));
        };
        if proposal.receipts.len() != headers.len() {
            return Err(conflict());
        }
        // The signed slot is not below the range's last block and not ahead
        // of the local clock by more than the clock drift bound.
        let latest = self
            .clock()
            .slot_for(self.wall_clock_secs().saturating_add(MAX_CLOCK_DRIFT_SECS));
        if headers
            .last()
            .is_some_and(|last| proposal.proposal_slot < last.slot)
            || proposal.proposal_slot > latest
        {
            return Err(conflict());
        }
        let exclusive = self.chain_spec().consensus.proof_exclusive_slots;
        let justified = proposal.valid_quorum.is_some();
        for (header, choice) in headers.iter().zip(&proposal.receipts) {
            let block_hash = header.hash();
            let held = self.store().block_receipts(&block_hash)?;
            // Rule 1: a receipt the voter does not hold is unavailable, not
            // invalid; the node fetches it and retries. A choice whose prover
            // differs from the held receipt's attribution is invalid.
            let Some(named) = held
                .iter()
                .find(|receipt| receipt.proof.statement_key == choice.statement_key)
            else {
                return Err(BftLoopError::ReceiptUnavailable {
                    block_hash,
                    statement_key: choice.statement_key,
                });
            };
            if named.proof.prover_address != choice.prover_address {
                return Err(conflict());
            }
            if is_proposers(named) {
                continue;
            }
            // Rule 3: inside the exclusive window only the proposer's receipt
            // is selectable, on the signed slot and on this voter's clock at
            // arrival, so the drift allowance on the signed slot cannot open
            // the window early.
            if proposal.proposal_slot.min(arrival_slot) < header.slot.saturating_add(exclusive) {
                return Err(conflict());
            }
            // Rule 2 compares against the voter's current holdings, which a
            // justified re-proposal of the selection an earlier quorum signed
            // does not revisit: the proposer's receipt, held before the
            // proposal arrived, wins while it has priority.
            if !justified
                && held.iter().any(|receipt| {
                    is_proposers(receipt)
                        && receipt.first_verified_slot < arrival_slot
                        && proposer_priority(
                            header,
                            receipt,
                            core::slice::from_ref(named),
                            exclusive,
                            ARRIVAL_TOLERANCE,
                        )
                })
            {
                return Err(conflict());
            }
        }
        self.check_ratifications(proposal)
    }
}

#[cfg(test)]
mod tests;
