//! Header and body admission shared by every block import path.

use neutrin0_consensus_types::history::is_recent_history_index;
use neutrin0_consensus_types::{Block, Header};
use neutrin0_consensus_vrf::{self as consensus_vrf};
use neutrin0_primitives::{BlockHash, ChunkId};
use neutrin0_storage::Database;

use super::{AdmittedBlock, ImportError, MAX_CLOCK_DRIFT_SECS, PROGRAMS_UNAVAILABLE};
use crate::body::{BodyRoots, compute_body_roots};
use crate::engine::Engine;
use crate::signature::verify_header_signature;

impl<DB: Database> Engine<DB> {
    /// Authenticate a header under its exact retained incoming validator
    /// boundary before treating its missing dependencies as a recovery hint.
    ///
    /// # Errors
    /// Returns invalid height, unavailable context, signature or VRF errors.
    pub fn authenticate_import_header(
        &self,
        header: &neutrin0_consensus_types::Header,
    ) -> Result<(), ImportError<DB::Error>> {
        if header.height == 0 {
            return Err(ImportError::HeightMismatch {
                expected: 1,
                actual: 0,
            });
        }
        let (validators, seed) = self
            .validator_context_for_height(header.height)
            .map_err(|_| ImportError::DryRunFailed(PROGRAMS_UNAVAILABLE.to_owned()))?;
        verify_header_signature(header, &validators, self.consensus_domain())
            .map_err(|error| self.header_verdict(header, ImportError::HeaderSignature(error)))?;
        consensus_vrf::verify_header_proposer(
            header,
            &validators,
            self.consensus_domain(),
            &seed,
            self.chain_spec().consensus.expected_proposers_per_slot,
        )
        .map_err(|error| self.header_verdict(header, ImportError::HeaderVrf(error)))
        .map(|_| ())
    }

    /// A header authentication failure as a verdict, unless only projected.
    ///
    /// Against a projected context another candidate of the open chunk may
    /// still win and give the header a different committee or seed.
    fn header_verdict(
        &self,
        header: &neutrin0_consensus_types::Header,
        error: ImportError<DB::Error>,
    ) -> ImportError<DB::Error> {
        let projected = self.certified_execution_boundary().is_none()
            && self.successor_state().is_some_and(|state| {
                self.chunk_of_height(header.height) == Some(state.boundary.next_chunk_id)
            });
        if projected {
            ImportError::ProjectedContext(Box::new(error))
        } else {
            error
        }
    }

    /// Admission checks every block import performs before any execution,
    /// receipt verification or storage: ancestry, height, gas limit, slot
    /// timing, proposer signature and VRF eligibility, body lanes and the
    /// embedded historical-vote window.
    pub(crate) fn admit_block_header_and_body(
        &mut self,
        block: &Block,
    ) -> Result<AdmittedBlock, ImportError<DB::Error>> {
        let parent_hash = block.header.parent_hash;
        let parent_header = self.admitted_parent_header(parent_hash)?;
        self.check_header_timing(&block.header, parent_header.as_ref())?;
        let chunk_id = self.authenticate_and_retain_header(&block.header)?;
        self.check_body_commitments(block, chunk_id)?;

        let parent_state_root = parent_header
            .as_ref()
            .map_or_else(|| self.chain_spec().genesis_state_root, |h| h.state_root);
        Ok(AdmittedBlock {
            parent_hash,
            parent_state_root,
            extends_materialised_head: parent_hash == self.head_hash(),
        })
    }

    /// The stored parent header, or `None` for the synthetic genesis parent.
    fn admitted_parent_header(
        &self,
        parent_hash: BlockHash,
    ) -> Result<Option<Header>, ImportError<DB::Error>> {
        // Look up the parent header so we can check height-vs-parent
        // and (later) runtime_extra-vs-parent. The genesis block
        // hash is synthetic — there is no header for it — so it is
        // handled as a special case below.
        let parent_is_genesis = parent_hash == self.chain_spec().genesis_block_hash;
        if parent_is_genesis {
            return Ok(None);
        }
        let h = self.store().get_header(&parent_hash)?;
        if h.is_none() {
            return Err(ImportError::ParentMismatch {
                expected: self.head_hash(),
                actual: parent_hash,
            });
        }
        Ok(h)
    }

    /// Height, gas limit, timestamp and slot checks against the parent and
    /// the local clock, in that order.
    fn check_header_timing(
        &self,
        header: &Header,
        parent_header: Option<&Header>,
    ) -> Result<(), ImportError<DB::Error>> {
        let parent_height = parent_header.map_or(0, |h| h.height);
        let expected_height = parent_height.saturating_add(1);
        if header.height != expected_height {
            return Err(ImportError::HeightMismatch {
                expected: expected_height,
                actual: header.height,
            });
        }
        // The runtime executes under the header's limit and the block proof
        // binds it, so only consensus can stop a proposer from raising it.
        let gas_limit = self.chain_spec().genesis_gas_limit;
        if header.gas_limit != gas_limit {
            return Err(ImportError::GasLimitMismatch {
                expected: gas_limit,
                actual: header.gas_limit,
            });
        }

        // Chain time is the slot schedule: the header's timestamp is exactly
        // its slot's start, as the chunk Guest requires. Strictly increasing
        // slots then make timestamps strictly increase, so no proposer can
        // move time forward and stall the producers after it.
        let expected_timestamp = self.clock().timestamp_for(header.slot);
        if header.timestamp != expected_timestamp {
            return Err(ImportError::HeaderTimestampMismatch {
                actual: header.timestamp,
                expected: expected_timestamp,
            });
        }
        // Slots strictly increase along a branch, as production and the chunk
        // Guest require, and a slot must have started locally: the header's
        // own timestamp is self-consistent with any slot it names, so only the
        // local clock bounds how far ahead a proposer may claim to be.
        let parent_slot = parent_header.as_ref().map_or(0, |header| header.slot);
        if header.slot <= parent_slot {
            return Err(ImportError::SlotNotIncreasing {
                parent_slot,
                slot: header.slot,
            });
        }
        let now = self.wall_clock_secs();
        if expected_timestamp > now.saturating_add(MAX_CLOCK_DRIFT_SECS) {
            return Err(ImportError::FutureSlot {
                slot: header.slot,
                slot_start: expected_timestamp,
                now,
            });
        }
        Ok(())
    }

    /// Authenticate the header under its exact incoming validator boundary
    /// and retain it for reporter accountability; returns its chunk id.
    fn authenticate_and_retain_header(
        &mut self,
        header: &Header,
    ) -> Result<ChunkId, ImportError<DB::Error>> {
        // Authenticate the header before doing any further work: a
        // mis-signed or non-eligible header is rejected before its
        // body is inspected or persisted. Membership and randomness come
        // from this header's exact authenticated incoming boundary.
        let (validators, seed) = self
            .validator_context_for_height(header.height)
            .map_err(|_| ImportError::DryRunFailed(PROGRAMS_UNAVAILABLE.to_owned()))?;
        verify_header_signature(header, &validators, self.consensus_domain())
            .map_err(|error| self.header_verdict(header, ImportError::HeaderSignature(error)))?;
        let chunk_id = self.chunk_of_height(header.height).unwrap_or(0);
        // Retained before the VRF check on purpose: a signed header is
        // double-proposal evidence whether or not its proposer was eligible.
        // Per-owner statement caps bound what one signer can make us store.
        self.store_mut()
            .retain_reporter_header(chunk_id, header, &validators)?;
        consensus_vrf::verify_header_proposer(
            header,
            &validators,
            self.consensus_domain(),
            &seed,
            self.chain_spec().consensus.expected_proposers_per_slot,
        )
        .map_err(|error| self.header_verdict(header, ImportError::HeaderVrf(error)))?;
        Ok(chunk_id)
    }

    /// Body lane roots, program pieces, the embedded historical-vote window
    /// and the declared inputs root, in that order.
    fn check_body_commitments(
        &self,
        block: &Block,
        chunk_id: ChunkId,
    ) -> Result<(), ImportError<DB::Error>> {
        if block.body.artifacts.commitment() != block.header.receipts_root {
            return Err(ImportError::ReceiptsRootMismatch {
                expected: block.header.receipts_root,
                computed: block.body.artifacts.commitment(),
            });
        }
        if !block.body.programs_well_formed() {
            return Err(ImportError::ProgramPieces);
        }
        let header_roots = BodyRoots {
            transactions_root: block.header.transactions_root,
            votes_root: block.header.votes_root,
            da_root: block.header.da_root,
        };
        let computed_roots = compute_body_roots(&block.body);
        if header_roots != computed_roots {
            return Err(ImportError::BodyRootsMismatch {
                header: Box::new(header_roots),
                computed: Box::new(computed_roots),
            });
        }
        if let Some(vote) = block
            .body
            .participation_acks
            .iter()
            .find(|vote| !is_recent_history_index(vote.data.chunk_id, chunk_id))
        {
            return Err(ImportError::HistoricalVoteOutsideWindow {
                chunk_id,
                referenced_chunk: vote.data.chunk_id,
            });
        }
        // Every node, executing or not, derives the inputs the block consumes
        // and refuses a header that declares others (design 08).
        let expected = self
            .expected_inputs_root(&block.header, &block.body)
            .map_err(ImportError::DryRunFailed)?;
        if block.header.inputs_root != expected {
            return Err(ImportError::InputsRootMismatch {
                declared: block.header.inputs_root,
                expected,
            });
        }
        Ok(())
    }
}
