//! Program sets of unfinalized chunks and the end of the chain (design 20).
//!
//! Finalized boundaries carry their program set. For a chunk beyond the
//! finalized one the set follows from the runtime's `ScheduledUpgrade`
//! record in the post-state of the previous chunk's last canonical block,
//! by the rule the chunk Guest applies at that boundary
//! ([`programs_entering`]). Records are cached by that block's hash, so
//! reorganisations never reuse a stale answer. A scheduled hard fork travels
//! in every boundary up to its count, so the latest boundary tells which
//! chunks this chain still proves.

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};

use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::history_proof::ProgramSet;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofError;
use neutrin0_prover_chunk::rotation::programs_entering;
use neutrin0_storage::Database;

use crate::{Engine, FinalizeError, StoreError};

/// Retained upgrade records; older chunks are dropped as finality advances.
const MAX_CACHED_SWITCHES: usize = 64;

impl<DB: Database> Engine<DB> {
    /// Program set the block at `height` executes under.
    pub fn programs_for_height(&self, height: u64) -> Result<ProgramSet, FinalizeError<DB::Error>> {
        self.programs_at_chunk(self.chunk_of_height(height).unwrap_or(0))
    }

    /// Program set of chunk `chunk_id`, finalized or not.
    pub fn programs_at_chunk(&self, chunk_id: u64) -> Result<ProgramSet, FinalizeError<DB::Error>> {
        if let Some(state) = self.successor_state()
            && state.boundary.next_chunk_id == chunk_id
        {
            return Ok(state.boundary.programs);
        }
        let finalized = self.finalized_next_chunk_id();
        if chunk_id <= finalized {
            return Ok(self.canonical_boundary(chunk_id)?.programs);
        }
        let mut programs = self.canonical_boundary(finalized)?.programs;
        for next in finalized + 1..=chunk_id {
            let boundary_height = next
                .checked_mul(self.chunk_size())
                .ok_or(ProofError::InvalidWitness)?;
            let record = self.upgrade_record_at(boundary_height)?;
            programs = programs_entering(programs, next, record.as_deref());
        }
        Ok(programs)
    }

    /// The upgrade record in the post-state of the canonical block at
    /// `boundary_height`, the last block of the chunk ending there.
    fn upgrade_record_at(
        &self,
        boundary_height: u64,
    ) -> Result<Option<Vec<u8>>, FinalizeError<DB::Error>> {
        let header = self
            .store()
            .get_header_by_height(boundary_height)?
            .ok_or(ProofError::InvalidWitness)?;
        let hash = header.hash();
        if let Some(cached) = self.program_switches.borrow().get(&hash) {
            return Ok(cached.clone());
        }
        let record = if header.state_root == self.head_state_root() {
            self.state()
                .get(neutrin0_consensus_types::runtime::UPGRADE_KEY)
        } else {
            self.persisted_trie(header.state_root)?
                .get(neutrin0_consensus_types::runtime::UPGRADE_KEY)
        }
        .map_err(|_| crate::StoreError::Corrupt("boundary state trie is incomplete"))?;
        let mut cache = self.program_switches.borrow_mut();
        if cache.len() >= MAX_CACHED_SWITCHES {
            cache.clear();
        }
        cache.insert(hash, record.clone());
        Ok(record)
    }

    /// Whether this chain proves chunk `chunk_id`: not at or beyond the count
    /// of a hard fork the latest boundary carries, the certified or projected
    /// successor's, else the finalized one. The chunk Guest refuses those
    /// chunks, so nothing is signed or produced for them.
    pub(crate) fn proves_chunk(&self, chunk_id: u64) -> Result<bool, StoreError<DB::Error>> {
        if let Some(state) = self.successor_state() {
            return Ok(state.boundary.proves(chunk_id));
        }
        Ok(self
            .store()
            .get_consensus_state()?
            .map_or_else(
                || neutrin0_primitives::ConsensusBoundary::first(self.chain_spec()),
                |state| state.boundary,
            )
            .proves(chunk_id))
    }

    /// Runtime artifact the block at `height` must be executed with.
    pub fn runtime_code_hash_for(&self, height: u64) -> Result<Hash, FinalizeError<DB::Error>> {
        let finalized = self.finalized_next_chunk_id();
        if let Some(chunk) = self.chunk_of_height(height)
            && chunk != 0
            && chunk < finalized
            && self.store().consensus_boundary(chunk)?.is_none()
        {
            // A checkpoint snapshot retains the state producer's authenticated
            // context, while the complete preceding boundary may be absent.
            let opening = self.store().historical_opening(chunk, finalized)?;
            let root = self.canonical_boundary(finalized)?.history_root;
            if !opening
                .path
                .verify(commitment(&opening.record.evidence_context()), root)
            {
                return Err(ProofError::PublicInputMismatch.into());
            }
            return Ok(opening.record.runtime_code_hash);
        }
        Ok(self.programs_for_height(height)?.runtime_code_hash)
    }

    pub(crate) const fn new_program_switch_cache()
    -> core::cell::RefCell<BTreeMap<Hash, Option<Vec<u8>>>> {
        core::cell::RefCell::new(BTreeMap::new())
    }
}
