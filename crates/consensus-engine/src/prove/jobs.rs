//! The proving FSM of a produced block: snapshot a job, prove outside the
//! engine lock, commit the verified receipt.

use neutrin0_primitives::{BlockHash, Hash};
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_storage::Database;

use super::{BlockProofJob, CompletedBlockProof, ProveError, ProveOutcome};
use crate::block_state::BlockState;
use crate::engine::Engine;

impl<DB: Database> Engine<DB> {
    /// Snapshot a produced block and mark it pending. The returned job owns its
    /// inputs and can prove without borrowing the engine. Completion rechecks
    /// this snapshot before atomically persisting the verified proof and state.
    pub fn prepare_block_proof(
        &mut self,
        block_hash: &BlockHash,
    ) -> Result<BlockProofJob, ProveError<DB::Error>> {
        // Load + sanity-check the FSM state.
        let current_state = self
            .store()
            .get_block_state(block_hash)?
            .ok_or(ProveError::NoBlockState(*block_hash))?;
        match current_state {
            BlockState::BlockProduced | BlockState::PendingProof => {}
            // Rule P (design 08): the proposer keeps proving its own block
            // after another receipt proved it first; checked below against
            // the address its receipt would name.
            BlockState::Proven if self.lacks_proposer_receipt(block_hash)? => {}
            other => return Err(ProveError::AlreadyAdvanced { current: other }),
        }

        // Move FSM forward to PendingProof if it isn't there yet.
        if current_state == BlockState::BlockProduced {
            self.store_mut()
                .put_block_state(block_hash, BlockState::PendingProof)?;
        }

        // Reconstruct the public inputs from the persisted header and
        // chain spec.
        let header = self
            .store()
            .get_header(block_hash)?
            .ok_or(ProveError::UnknownBlock(*block_hash))?;
        if header.hash() != *block_hash {
            return Err(ProofError::PublicInputMismatch.into());
        }
        let Some(state_root_before) = self.state_root_before(&header)? else {
            return Err(ProveError::MissingParentHeader {
                parent_hash: header.parent_hash,
            });
        };
        let public_inputs = self
            .block_public_inputs(&header, state_root_before, *block_hash)
            .map_err(|_| ProveError::Backend(ProofError::InvalidWitness))?;

        let witness_bytes = self
            .store()
            .get_witness(block_hash)?
            .ok_or(ProveError::MissingWitness(*block_hash))?;

        let bindings = if self.programs.is_some() {
            let body = self
                .store()
                .get_body(block_hash)?
                .ok_or(ProveError::MissingBody(*block_hash))?;
            Some(
                self.block_statement_bindings(&header, &body)
                    .map_err(|_| ProofError::InvalidWitness)?,
            )
        } else {
            None
        };

        // Without a configured account or an active local validator the
        // receipt credits the block's own proposer.
        let prover_address = self
            .prover_address()
            .unwrap_or(public_inputs.proposer_address);
        if current_state == BlockState::Proven && prover_address != public_inputs.proposer_address {
            return Err(ProveError::AlreadyAdvanced {
                current: current_state,
            });
        }
        Ok(BlockProofJob {
            header,
            public_inputs,
            witness_bytes,
            bindings,
            prover_address,
        })
    }

    /// Account this node names in the receipts it produces: the configured
    /// prover address, else the local validator's withdrawal credentials.
    ///
    /// # Errors
    /// Returns [`ProveError::NoProverAddress`] when neither is available.
    pub fn prover_address(&self) -> Result<Hash, ProveError<DB::Error>> {
        if let Some(address) = self.prover_address {
            return Ok(address);
        }
        let voter = self.local_voter().ok_or(ProveError::NoProverAddress)?;
        self.active_validator_set()
            .iter()
            .find(|validator| validator.pubkey == *voter.public_key_bytes())
            .map(|validator| validator.withdrawal_credentials)
            .ok_or(ProveError::NoProverAddress)
    }

    /// Name `address` in the receipts this node produces (design 08).
    pub const fn set_prover_address(&mut self, address: Hash) {
        self.prover_address = Some(address);
    }

    /// Complete a verified job without holding a lock during backend work.
    /// A concurrently imported proof is retained and a finalized FSM never regresses.
    pub fn commit_block_proof(
        &mut self,
        completed: CompletedBlockProof,
    ) -> Result<ProveOutcome, ProveError<DB::Error>> {
        let CompletedBlockProof { job, proof } = completed;
        let hash = job.public_inputs.block_hash;
        if self.store().get_header(&hash)?.as_ref() != Some(&job.header)
            || self.store().get_witness(&hash)?.as_ref() != Some(&job.witness_bytes)
            || job.bindings.is_some() != self.programs.is_some()
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        if let Some(bindings) = job.bindings {
            let body = self
                .store()
                .get_body(&hash)?
                .ok_or(ProveError::MissingBody(hash))?;
            if self
                .block_statement_bindings(&job.header, &body)
                .map_err(|_| ProofError::InvalidWitness)?
                != bindings
            {
                return Err(ProofError::PublicInputMismatch.into());
            }
        }
        let current = self
            .store()
            .get_block_state(&hash)?
            .ok_or(ProveError::NoBlockState(hash))?;
        let block_proof = if matches!(current, BlockState::Proven | BlockState::Finalized) {
            let stored = self
                .store()
                .get_block_proof(&hash)?
                .ok_or(ProofError::InvalidWitness)?;
            if stored.public_inputs != job.public_inputs {
                return Err(ProofError::PublicInputMismatch.into());
            }
            // Rule P (design 08): the proposer's own receipt decides
            // selection even when another receipt proved the block first, so
            // it is kept and published rather than discarded. A finalized
            // block's selection is settled.
            if current == BlockState::Proven
                && proof.prover_address == proof.public_inputs.proposer_address
            {
                let (slot, max) = (self.local_slot(), self.max_receipts_per_block());
                let protected = self.protected_receipt_keys();
                self.store_mut()
                    .put_block_receipt(&proof, slot, max, false, &protected)?;
                proof
            } else {
                stored
            }
        } else {
            let (slot, max) = (self.local_slot(), self.max_receipts_per_block());
            let protected = self.protected_receipt_keys();
            self.store_mut()
                .put_block_receipt(&proof, slot, max, true, &protected)?;
            proof
        };
        let status = if current == BlockState::Finalized {
            neutrin0_consensus_fork_choice::ProofStatus::Finalized
        } else {
            neutrin0_consensus_fork_choice::ProofStatus::Proven
        };
        let _ = self.fork_choice.on_block_proof(hash, status);
        Ok(ProveOutcome {
            block_hash: hash,
            state: if current == BlockState::Finalized {
                current
            } else {
                BlockState::Proven
            },
            public_inputs: job.public_inputs,
            block_proof,
        })
    }

    /// Synchronous convenience for callers that own an engine without a mutex.
    pub fn prove_block<PS: ProofSystem>(
        &mut self,
        block_hash: &BlockHash,
        proof_system: &PS,
    ) -> Result<ProveOutcome, ProveError<DB::Error>> {
        let job = self.prepare_block_proof(block_hash)?;
        let completed = job.prove(proof_system)?;
        self.commit_block_proof(completed)
    }
}
