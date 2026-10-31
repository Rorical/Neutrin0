//! Once-per-value native validation of the open BFT value before local signing.
//!
//! A restored or running session may sign only a value whose complete candidate
//! validates under the running backend. That verdict is a function of the
//! session's exact value (chunk hash, branch end and named receipts), the
//! backend's Guest programs and the trusted incoming boundary, so it is reused
//! while all of them are unchanged: every BFT tick and incoming vote would
//! otherwise rebuild and revalidate the whole witness. Installing a boundary
//! starts a new generation and discards every verdict. Only successes are kept,
//! and whether the backend can still prove under the boundary's programs is
//! checked on every use.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use neutrin0_consensus_types::history_proof::GuestPrograms;
use neutrin0_primitives::{ChunkId, ExecutionPrograms, Hash};
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_prover_chunk::consensus::{ConsensusWitness, as_chunk, validate_candidate};
use neutrin0_storage::Database;

use crate::full_chunk::PendingConsensusChunk;
use crate::{Engine, FinalizeError};

/// Retained verdicts: the open value plus a few superseded round selections.
const MAX_SIGNING_VERDICTS: usize = 8;

/// The exact inputs an open BFT value's validation depends on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningInputs {
    generation: u64,
    chunk_id: ChunkId,
    chunk_hash: Hash,
    end_block_hash: Hash,
    receipts: Option<Vec<Hash>>,
    guests: GuestPrograms,
}

/// A successful validation; only [`PendingSigning::validate`] creates one.
#[derive(Clone, Debug)]
pub struct ValidatedSigning {
    inputs: SigningInputs,
    /// The boundary's execution programs, for the per-use proving check.
    execution: ExecutionPrograms,
}

/// The gathered witness of an open value that has no verdict yet. Gathering
/// needs the engine; validation does not, so callers validate without the lock.
#[derive(Debug)]
pub struct PendingSigning {
    inputs: SigningInputs,
    witness: ConsensusWitness,
}

/// Owned receipt sources for pre-signing validation outside the engine lock.
pub struct PendingSigningInputs {
    inputs: SigningInputs,
    pending: PendingConsensusChunk,
}

impl PendingSigningInputs {
    /// Verify the receipts and complete candidate before recording a verdict.
    ///
    /// # Errors
    /// Rejects malformed receipts, invalid consensus or a different session value.
    pub fn validate<P: ProofSystem, E>(
        self,
        prover: &P,
    ) -> Result<ValidatedSigning, FinalizeError<E>> {
        let (witness, _) = self.pending.witness(prover)?;
        PendingSigning {
            inputs: self.inputs,
            witness,
        }
        .validate()
        .map_err(Into::into)
    }
}

impl PendingSigning {
    /// Validate the gathered candidate and bind it to the session's value.
    ///
    /// # Errors
    /// Returns an invalid candidate or one that is not the session's value.
    pub fn validate(self) -> Result<ValidatedSigning, ProofError> {
        let candidate =
            validate_candidate(&self.witness).map_err(|_| ProofError::InvalidWitness)?;
        if as_chunk(&candidate.execution.chunk).hash() != self.inputs.chunk_hash {
            return Err(ProofError::PublicInputMismatch);
        }
        Ok(ValidatedSigning {
            inputs: self.inputs,
            execution: self.witness.context.programs.execution,
        })
    }
}

/// Bounded successful verdicts of the current boundary generation.
#[derive(Debug, Default)]
pub(crate) struct SigningVerdicts {
    generation: u64,
    verdicts: VecDeque<ValidatedSigning>,
    validations: usize,
}

impl SigningVerdicts {
    /// A new boundary was installed: no earlier verdict applies to it.
    pub(crate) fn next_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.verdicts.clear();
    }
}

impl<DB: Database> Engine<DB> {
    fn signing_inputs<P: ProofSystem>(
        &self,
        chunk_id: ChunkId,
        proof_system: &P,
    ) -> Result<Option<SigningInputs>, FinalizeError<DB::Error>> {
        let Some(session) = self.bft_session(chunk_id) else {
            return Ok(None);
        };
        Ok(Some(SigningInputs {
            generation: self.signing_verdicts.generation,
            chunk_id,
            chunk_hash: session.chunk_hash(),
            end_block_hash: session.end_block_hash(),
            receipts: session.named_receipts(),
            guests: proof_system.programs().ok_or(ProofError::Unsupported)?,
        }))
    }

    fn signing_validated<P: ProofSystem>(&self, inputs: &SigningInputs, proof_system: &P) -> bool {
        self.signing_verdicts.verdicts.iter().any(|verdict| {
            verdict.inputs == *inputs
                && proof_system.can_prove(&GuestPrograms {
                    execution: verdict.execution,
                    chunk: inputs.guests.chunk,
                })
        })
    }

    /// Gather the witness of chunk `chunk_id`'s open BFT value when it still
    /// needs validation under `proof_system`: `None` without a session or
    /// with a current verdict. Validate the result outside the engine lock and
    /// pass it to [`Self::record_bft_signing`].
    ///
    /// # Errors
    /// Returns unavailable or unverifiable inputs of the session's branch.
    pub fn pending_bft_signing<P: ProofSystem>(
        &self,
        chunk_id: ChunkId,
        proof_system: &P,
    ) -> Result<Option<PendingSigning>, FinalizeError<DB::Error>> {
        let Some(pending) = self.pending_bft_signing_inputs(chunk_id, proof_system)? else {
            return Ok(None);
        };
        let (witness, _) = pending.pending.witness(proof_system)?;
        Ok(Some(PendingSigning {
            inputs: pending.inputs,
            witness,
        }))
    }

    /// Capture an unchecked open value without decoding or verifying its backend
    /// proofs. The returned inputs are validated without holding the engine.
    ///
    /// # Errors
    /// Returns unavailable sources or an unsupported backend.
    pub fn pending_bft_signing_inputs<P: ProofSystem>(
        &self,
        chunk_id: ChunkId,
        proof_system: &P,
    ) -> Result<Option<PendingSigningInputs>, FinalizeError<DB::Error>> {
        let Some(inputs) = self.signing_inputs(chunk_id, proof_system)? else {
            return Ok(None);
        };
        if self.signing_validated(&inputs, proof_system) {
            return Ok(None);
        }
        let pending = self.pending_consensus_chunk(
            chunk_id,
            inputs.end_block_hash,
            inputs.receipts.as_deref(),
        )?;
        Ok(Some(PendingSigningInputs { inputs, pending }))
    }

    /// Retain a verdict. One from an earlier boundary generation never
    /// matches the current inputs and is dropped.
    pub fn record_bft_signing(&mut self, validated: ValidatedSigning) {
        let verdicts = &mut self.signing_verdicts;
        if validated.inputs.generation != verdicts.generation
            || verdicts
                .verdicts
                .iter()
                .any(|verdict| verdict.inputs == validated.inputs)
        {
            return;
        }
        if verdicts.verdicts.len() == MAX_SIGNING_VERDICTS {
            verdicts.verdicts.pop_front();
        }
        verdicts.validations = verdicts.validations.saturating_add(1);
        verdicts.verdicts.push_back(validated);
    }

    /// Require chunk `chunk_id`'s open BFT value to validate under
    /// `proof_system` before local signing, validating here only when no
    /// verdict for its exact inputs exists.
    ///
    /// # Errors
    /// Returns unavailable inputs, an unsupported backend or an invalid value.
    pub fn validate_bft_signing<P: ProofSystem>(
        &mut self,
        chunk_id: ChunkId,
        proof_system: &P,
    ) -> Result<(), FinalizeError<DB::Error>> {
        if let Some(pending) = self.pending_bft_signing(chunk_id, proof_system)? {
            let validated = pending.validate()?;
            self.record_bft_signing(validated);
        }
        Ok(())
    }

    /// Number of signing validations performed, for tests of verdict reuse.
    #[doc(hidden)]
    #[must_use]
    pub const fn bft_signing_validations(&self) -> usize {
        self.signing_verdicts.validations
    }
}
