//! Canonical block-proof public inputs and the body bindings a receipt's
//! statement must reproduce.

extern crate alloc;
use alloc::vec::Vec;

use neutrin0_consensus_types::{BlockProofPublicInputs, Body, Header};
use neutrin0_primitives::{BlockHash, Hash, Seed, StateRoot, Validator};
use neutrin0_proof_system::ProofError;
use neutrin0_storage::Database;

use super::BlockStatementBindings;
use crate::engine::Engine;
use crate::finalize::FinalizeError;
use crate::store::StoreError;

impl<DB: Database> Engine<DB> {
    /// State root preceding `header`, or `None` when its parent header is not
    /// stored. The parent state of the specification's first block is its
    /// first boundary's root (genesis or a hard fork's start).
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn state_root_before(
        &self,
        header: &Header,
    ) -> Result<Option<StateRoot>, StoreError<DB::Error>> {
        Ok(self.claim_parent(header)?.map(|(_, state_root)| state_root))
    }

    /// Authenticate retained body lanes and derive the extra execution bindings.
    /// A valid cryptographic receipt for other participation inputs is unusable
    /// for this body, but that is not an objective proof-verification failure.
    pub(crate) fn block_statement_bindings(
        &self,
        header: &Header,
        body: &Body,
    ) -> Result<BlockStatementBindings, String> {
        let roots = crate::body::compute_body_roots(body);
        if roots.transactions_root != header.transactions_root
            || roots.votes_root != header.votes_root
            || roots.da_root != header.da_root
            || body.artifacts.commitment() != header.receipts_root
        {
            return Err("retained block body differs from signed header".into());
        }
        // Design 08: a block before its chunk's carrier consumes no new
        // report and commits the start boundary's.
        let participation = match self.participation_for_block(header, body)? {
            Some(report) => report.commitment(),
            None => {
                self.execution_boundary(
                    self.chunk_of_height(header.height)
                        .ok_or_else(|| String::from("invalid participation height"))?,
                )
                .map_err(|_| String::from(crate::import::HISTORY_UNAVAILABLE))?
                .participation
            }
        };
        let acknowledgements = self
            .participation_acknowledgements(header.height, body)
            .map_err(|_| String::from(crate::import::PARTICIPATION_UNAVAILABLE))?;
        Ok(BlockStatementBindings {
            anchor: self.evidence_anchor(header.height)?,
            participation,
            participation_acks: neutrin0_consensus_types::participation::acknowledgement_commitment(
                &acknowledgements,
            ),
            program_pieces: neutrin0_consensus_types::program_pieces_commitment(
                &neutrin0_consensus_types::program_piece_refs(&body.programs),
            ),
        })
    }

    /// Canonical block-proof public inputs for `header` under the program set
    /// of its chunk and the proposer account in the active validator set.
    pub(crate) fn block_public_inputs(
        &self,
        header: &Header,
        state_root_before: StateRoot,
        block_hash: BlockHash,
    ) -> Result<BlockProofPublicInputs, FinalizeError<DB::Error>> {
        let programs = self.programs_for_height(header.height)?;
        Ok(super::header_public_inputs(
            &neutrin0_prover_chunk::execution::runtime_context(
                header,
                self.execution_boundary(
                    self.chunk_of_height(header.height)
                        .ok_or(neutrin0_proof_system::ProofError::InvalidWitness)?,
                )?,
            ),
            self.chain_spec().chain_id,
            header,
            state_root_before,
            block_hash,
            &programs,
            self.proposer_runtime_address(header)?,
        ))
    }

    /// Resolve the exact validator vector and seed authenticated at a block's
    /// incoming boundary. Retained historical blocks never use the live set.
    ///
    /// # Errors
    /// Returns unavailable/pruned context, malformed membership or storage errors.
    pub fn validator_context_for_height(
        &self,
        height: u64,
    ) -> Result<(Vec<Validator>, Seed), FinalizeError<DB::Error>> {
        let chunk_id = self
            .chunk_of_height(height)
            .ok_or(ProofError::InvalidWitness)?;
        if let Some(state) = self.successor_state()
            && state.boundary.next_chunk_id == chunk_id
        {
            return Ok((
                state.next_context.active_validators.clone(),
                state.next_seed,
            ));
        }
        let boundary = self.canonical_boundary(chunk_id)?;
        let validators = match self.store().get_validator_set_snapshot(chunk_id)? {
            Some(validators) => validators,
            None => {
                self.store()
                    .historical_chunk(chunk_id)?
                    .ok_or(ProofError::InvalidWitness)?
                    .validators
            }
        };
        if neutrin0_consensus_types::evidence::commitment(&validators) != boundary.validators_root {
            return Err(ProofError::PublicInputMismatch.into());
        }
        Ok((validators, boundary.seed))
    }

    /// Runtime fee recipient of this header's historically indexed proposer.
    pub(crate) fn proposer_runtime_address(
        &self,
        header: &Header,
    ) -> Result<Hash, FinalizeError<DB::Error>> {
        let (validators, _) = self.validator_context_for_height(header.height)?;
        let index =
            usize::try_from(header.proposer_index).map_err(|_| ProofError::InvalidWitness)?;
        validators
            .get(index)
            .map(|validator| validator.withdrawal_credentials)
            .ok_or_else(|| ProofError::InvalidWitness.into())
    }
}
