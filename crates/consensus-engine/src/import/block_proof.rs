//! Verification and archival of block receipts for retained blocks.

use neutrin0_consensus_fork_choice::ProofStatus;
use neutrin0_consensus_types::{BlockProof, BlockProofPublicInputs, Body, Header};
use neutrin0_primitives::{BlockHash, StateRoot};
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_storage::Database;

use super::{
    ImportBlockProofOutcome, ImportError, PARTICIPATION_UNAVAILABLE, PROGRAMS_UNAVAILABLE,
};
use crate::block_state::BlockState;
use crate::engine::Engine;

impl<DB: Database> Engine<DB> {
    /// Import a peer-supplied block proof for an already stored block.
    ///
    /// This entry point verifies and archives the receipt with no execution
    /// replay when proof admission changes the fork-choice head. Callers with
    /// an executor can use [`Self::import_block_proof_with_dry_run`] to also
    /// materialize a newly selected branch.
    ///
    /// # Errors
    /// Returns [`ImportError`] for an unknown block, mismatched envelope/public
    /// inputs, malformed or invalid proof bytes, or storage failure.
    pub fn import_block_proof<PS: ProofSystem>(
        &mut self,
        proof: &BlockProof,
        proof_system: &PS,
    ) -> Result<ImportBlockProofOutcome, ImportError<DB::Error>> {
        self.import_block_proof_inner(proof, proof_system, None)
    }

    /// Companion to [`Self::import_block_proof`] that threads a
    /// dynamic-runtime executor through to the post-proof reorg
    /// materialisation step, so a newly selected branch is materialized
    /// after successful receipt admission. Rejected alternative receipts
    /// never change the block's fork-choice status or the materialized head.
    pub fn import_block_proof_with_dry_run<PS: ProofSystem>(
        &mut self,
        proof: &BlockProof,
        proof_system: &PS,
        executor: &dyn ErasedBlockExecutor,
    ) -> Result<ImportBlockProofOutcome, ImportError<DB::Error>> {
        self.import_block_proof_inner(proof, proof_system, Some(executor))
    }

    /// Shared body of [`Self::import_block_proof`] and
    /// [`Self::import_block_proof_with_dry_run`].
    ///
    /// The proof envelope and public inputs are reconstructed against the
    /// canonical header in the local store before the active proof backend
    /// verifies the backend proof bytes. On success the proof is persisted and
    /// the block FSM advances to [`BlockState::Proven`] unless it is already
    /// past that state.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError`] when the block is unknown, the proof is not
    /// bound to the canonical header, backend proof bytes fail to decode, proof
    /// verification fails, or persistence fails.
    pub(super) fn import_block_proof_inner<PS: ProofSystem>(
        &mut self,
        proof: &BlockProof,
        proof_system: &PS,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<ImportBlockProofOutcome, ImportError<DB::Error>> {
        let header = self
            .store()
            .get_header(&proof.block_hash)?
            .ok_or(ImportError::UnknownBlock(proof.block_hash))?;
        let canonical_hash = header.hash();
        if proof.block_hash != canonical_hash || proof.height != header.height {
            return Err(ImportError::BlockProofEnvelopeMismatch {
                expected_hash: canonical_hash,
                actual_hash: proof.block_hash,
                expected_height: header.height,
                actual_height: proof.height,
            });
        }

        let Some(state_root_before) = self.state_root_before(&header)? else {
            return Err(ImportError::MissingParentHeader {
                parent_hash: header.parent_hash,
            });
        };
        let body = if self.programs.is_some() {
            Some(
                self.store()
                    .get_body(&canonical_hash)?
                    .ok_or_else(|| ImportError::DryRunFailed(PARTICIPATION_UNAVAILABLE.into()))?,
            )
        } else {
            None
        };
        let statement = self.verify_block_receipt(
            &header,
            body.as_ref(),
            state_root_before,
            proof,
            proof_system,
        )?;
        let mut receipt = proof.clone();
        crate::prove::attribute(&mut receipt, &statement);
        let mark_proven = !matches!(
            self.store().get_block_state(&canonical_hash)?,
            Some(BlockState::Finalized)
        );
        let (slot, max) = (self.local_slot(), self.max_receipts_per_block());
        let protected = self.protected_receipt_keys();
        self.store_mut()
            .put_block_receipt(&receipt, slot, max, mark_proven, &protected)?;
        // Record successful proof availability in the fork-choice DAG.
        // Pending branches remain eligible for optimistic head selection.
        let _ = self
            .fork_choice
            .on_block_proof(canonical_hash, ProofStatus::Proven);

        // Proof status can change the fork-choice head. Replay and publish
        // that selected branch when an executor is available; earlier proof
        // archival and DAG status changes remain if replay fails.
        self.materialise_to_fork_choice_head(executor)?;

        Ok(ImportBlockProofOutcome {
            block_hash: canonical_hash,
            height: header.height,
        })
    }

    /// Verify `proof` as the receipt of `header` under the canonical public
    /// inputs derived from the header, its pre-state root and the program set
    /// of its chunk, then check the receipt's body-selected execution context
    /// when the program set is known locally.
    ///
    /// Rejected or malformed proof bytes are cached for later signed
    /// proof-attestation evidence; their rejection says nothing about the
    /// header itself.
    ///
    /// # Errors
    /// Returns context-unavailable dry-run failures, public-input or context
    /// mismatches, [`ImportError::Codec`] or [`ImportError::InvalidBlockProof`].
    pub(crate) fn verify_block_receipt<PS: ProofSystem>(
        &mut self,
        header: &Header,
        body: Option<&Body>,
        state_root_before: StateRoot,
        proof: &BlockProof,
        proof_system: &PS,
    ) -> Result<neutrin0_runtime_abi::BlockReceiptStatement, ImportError<DB::Error>> {
        let canonical_hash = header.hash();
        let expected_public_inputs = self
            .block_public_inputs(header, state_root_before, canonical_hash)
            .map_err(|_| ImportError::DryRunFailed(PROGRAMS_UNAVAILABLE.to_owned()))?;
        if proof.public_inputs != expected_public_inputs {
            return Err(ImportError::BlockProofPublicInputsMismatch {
                hash: canonical_hash,
            });
        }

        let bindings = if self.programs.is_some() {
            let body =
                body.ok_or_else(|| ImportError::DryRunFailed(PARTICIPATION_UNAVAILABLE.into()))?;
            Some(
                self.block_statement_bindings(header, body)
                    .map_err(ImportError::DryRunFailed)?,
            )
        } else {
            None
        };

        let statement = self.verified_receipt_statement(
            header,
            canonical_hash,
            &expected_public_inputs,
            proof,
            proof_system,
        )?;
        if let Some(bindings) = bindings
            && !bindings.matches_statement(&statement.output)
        {
            return Err(ImportError::BlockProofContextMismatch {
                hash: canonical_hash,
            });
        }
        // The runtime pays only runtime accounts; a receipt crediting any
        // other value is not a receipt the protocol can settle.
        if !neutrin0_primitives::is_runtime_account(&statement.prover_address) {
            return Err(ImportError::NonRuntimeProver {
                hash: canonical_hash,
            });
        }
        Ok(statement)
    }

    /// Decode and verify `proof` against the canonical public inputs. A
    /// rejected or malformed envelope is cached for later signed
    /// proof-attestation evidence before the rejection is returned.
    fn verified_receipt_statement<PS: ProofSystem>(
        &mut self,
        header: &Header,
        canonical_hash: BlockHash,
        expected_public_inputs: &BlockProofPublicInputs,
        proof: &BlockProof,
        proof_system: &PS,
    ) -> Result<neutrin0_runtime_abi::BlockReceiptStatement, ImportError<DB::Error>> {
        let backend_proof: PS::BlockProof = match borsh::from_slice(&proof.proof_bytes) {
            Ok(decoded) => decoded,
            Err(error) => {
                self.record_rejected_proof(
                    canonical_hash,
                    proof.clone(),
                    neutrin0_consensus_types::ProofRejectionReason::MalformedProof,
                );
                return Err(ImportError::Codec(error));
            }
        };
        match proof_system.verify_block_statement(&backend_proof, &proof.public_inputs) {
            Ok(statement) => Ok(statement),
            Err(err) => {
                // Cache the rejected proof envelope so the
                // `InvalidProofSigning` detector can surface evidence
                // when a peer precommit later arrives for a chunk
                // covering this block. A later valid receipt cannot change the
                // verdict of these exact rejected bytes, which a delayed signed
                // attestation may still reference.
                let reason = match err {
                    neutrin0_proof_system::ProofError::MalformedProof => {
                        neutrin0_consensus_types::ProofRejectionReason::MalformedProof
                    }
                    neutrin0_proof_system::ProofError::PublicInputMismatch => {
                        neutrin0_consensus_types::ProofRejectionReason::PublicInputsMismatch
                    }
                    _ => neutrin0_consensus_types::ProofRejectionReason::VerifierRejected,
                };
                self.record_rejected_proof(canonical_hash, proof.clone(), reason);
                // A receipt that verifies under the header's inputs but
                // commits other results contradicts the header itself.
                if matches!(err, neutrin0_proof_system::ProofError::PublicInputMismatch) {
                    self.note_contradicting_receipt(
                        header,
                        expected_public_inputs,
                        &backend_proof,
                        proof,
                        proof_system,
                    );
                }
                // Receipt bytes are an unauthenticated alternative witness. Their
                // rejection says nothing about the header or checked execution, so
                // it must not evict a valid pending block or cancel local proving.
                // Keep the exact bytes for later signed proof-attestation evidence.
                Err(ImportError::InvalidBlockProof(err))
            }
        }
    }
}
