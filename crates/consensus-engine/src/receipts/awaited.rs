//! Receipts and chunk proofs a proposal or certificate names that this node
//! must keep or still fetch.

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use neutrin0_consensus_types::BftProposal;
use neutrin0_primitives::Hash;
use neutrin0_storage::Database;

use super::{MAX_AWAITED, MissingArtifacts};
use crate::engine::Engine;
use crate::store::StoreError;

impl<DB: Database> Engine<DB> {
    /// Statement keys the receipt store keeps beyond its per-block cap:
    /// every key an open session, the certified execution or an awaited
    /// authenticated proposal or certificate names. Evicting one would leave
    /// a value nobody can vote for or prove.
    pub(crate) fn protected_receipt_keys(&self) -> BTreeSet<Hash> {
        let mut keys: BTreeSet<Hash> = self
            .bft_sessions
            .values()
            .flat_map(crate::bft_loop::BftSession::named_receipt_keys)
            .collect();
        if let Some(certified) = &self.certified_execution {
            keys.extend(certified.witness.finality_cert.proposal.receipt_keys());
        }
        keys.extend(self.awaited_receipts.values().flatten().copied());
        keys
    }

    /// Keep the receipts `proposal` names once they arrive, until the next
    /// finalization. Callers pass only an authenticated proposal (`round` is
    /// its round) or the proposal of a verified certificate
    /// ([`CERTIFIED_SLOT`]). Only the next chunk to finalize registers, with
    /// one receipt per height, and the first proposal per round stays, so an
    /// equivocating leader cannot crowd out others. Past the bound the lowest
    /// round leaves first; a certificate's slot is the highest. Accepted
    /// values stay protected through their session regardless.
    pub(crate) fn await_receipts(&mut self, round: u32, proposal: &BftProposal) {
        let chunk = &proposal.chunk;
        let heights = chunk
            .end_height
            .checked_sub(chunk.start_height)
            .and_then(|span| span.checked_add(1));
        if chunk.chunk_id != self.finalized_next_chunk_id()
            || heights != u64::try_from(proposal.receipts.len()).ok()
        {
            return;
        }
        self.awaited_receipts
            .entry((chunk.chunk_id, round))
            .or_insert_with(|| proposal.receipt_keys());
        while self.awaited_receipts.len() > MAX_AWAITED {
            self.awaited_receipts.pop_first();
        }
    }

    /// The artifacts `proposal` names that this node does not hold: the blocks
    /// of its range whose named receipt is missing, and the ratified chunks
    /// whose named proof is missing with its statement key. The node fetches
    /// them before refusing the proposal as unavailable (design 08, voter
    /// rules 1 and 4). Blocks of a range this node does not hold yet are
    /// fetched by branch backfill instead and are not listed.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn missing_proposal_artifacts(
        &self,
        proposal: &BftProposal,
    ) -> Result<MissingArtifacts, StoreError<DB::Error>> {
        let mut receipts = Vec::new();
        if let Some(headers) = self.chunk_headers(&proposal.chunk)? {
            for (header, choice) in headers.iter().zip(&proposal.receipts) {
                let hash = header.hash();
                if !self
                    .store()
                    .block_receipts(&hash)?
                    .iter()
                    .any(|held| held.proof.statement_key == choice.statement_key)
                {
                    receipts.push(hash);
                }
            }
        }
        let mut chunk_proofs = Vec::new();
        for entry in &proposal.ratified_chunk_proofs {
            if !self
                .store()
                .chunk_receipts(entry.chunk_id)?
                .iter()
                .any(|held| held.statement_key == entry.statement_key)
            {
                chunk_proofs.push((entry.chunk_id, entry.statement_key));
            }
        }
        Ok((receipts, chunk_proofs))
    }
}
