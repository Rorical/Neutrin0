//! Successor execution projected from a complete proven candidate (design 08).
//!
//! A chunk's outgoing boundary is a function of its blocks alone. Once every
//! block of the chunk being decided is proven, the engine projects the
//! successor's boundary and execution context from that candidate, so the
//! successor's blocks can be produced and imported before the certificate
//! exists. The certificate is consumed later by the successor's carrier
//! block. A certificate for another branch, a new candidate or finality
//! drops the projection; blocks built on a losing projection are orphaned
//! by the ordinary reorganization.

use neutrin0_primitives::Hash;
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_storage::Database;

use crate::{Engine, FinalizeError, full_chunk::ConsensusState};

/// The successor state projected from a proven, not yet certified candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "Engine state remains internal to this crate."
)]
pub(crate) struct ProjectedExecution {
    /// The candidate the projection follows.
    pub(crate) chunk_hash: Hash,
    /// Its outgoing boundary and the successor's execution context.
    pub(crate) state: ConsensusState,
}

/// Owned candidate inputs for successor projection outside the engine lock.
pub struct PendingProjection {
    pending: crate::full_chunk::PendingConsensusChunk,
    start: neutrin0_consensus_types::history_proof::ConsensusBoundary,
}

/// A projection bound to the exact trusted incoming boundary and session value.
#[derive(Debug)]
pub struct ValidatedProjection {
    start: neutrin0_consensus_types::history_proof::ConsensusBoundary,
    projected: ProjectedExecution,
}

impl PendingProjection {
    /// Verify receipts and derive the successor without holding the engine.
    ///
    /// # Errors
    /// Returns invalid receipts, candidate consensus or successor derivation.
    pub fn validate<P: ProofSystem, E>(
        self,
        prover: &P,
    ) -> Result<ValidatedProjection, FinalizeError<E>> {
        let (witness, _) = self.pending.witness(prover)?;
        let projected = neutrin0_prover_chunk::consensus::project_successor(&witness)
            .map_err(|_| ProofError::InvalidWitness)?;
        Ok(ValidatedProjection {
            start: self.start,
            projected: ProjectedExecution {
                chunk_hash: projected.chunk_hash,
                state: ConsensusState {
                    boundary: projected.end,
                    next_seed: projected.end.seed,
                    next_context: projected.next_context,
                    frontier: projected.frontier,
                },
            },
        })
    }
}

impl<DB: Database> Engine<DB> {
    /// Project the successor of the open BFT session's candidate once all its
    /// receipts are held (design 08). Returns whether a new projection was
    /// installed. A certified successor takes precedence and clears it.
    ///
    /// # Errors
    /// Returns unavailable receipts or an invalid candidate.
    pub fn project_successor_execution<P: ProofSystem>(
        &mut self,
        proof_system: &P,
    ) -> Result<bool, FinalizeError<DB::Error>> {
        let Some(pending) = self.pending_successor_execution()? else {
            return Ok(false);
        };
        let validated = pending.validate::<P, DB::Error>(proof_system)?;
        self.record_successor_execution(validated)
    }

    /// Capture the current unprojected session without receipt verification.
    ///
    /// # Errors
    /// Returns unavailable branch sources or a missing incoming boundary.
    pub fn pending_successor_execution(
        &mut self,
    ) -> Result<Option<PendingProjection>, FinalizeError<DB::Error>> {
        if self.certified_execution.is_some() {
            self.projected_execution = None;
            return Ok(None);
        }
        let chunk_id = self.finalized_next_chunk_id();
        let Some(chunk_hash) = self
            .bft_session(chunk_id)
            .map(crate::BftSession::chunk_hash)
        else {
            self.projected_execution = None;
            return Ok(None);
        };
        if self
            .projected_execution
            .as_ref()
            .is_some_and(|projected| projected.chunk_hash == chunk_hash)
        {
            return Ok(None);
        }
        let (context, seed, _) = self.consensus_boundary(chunk_id)?;
        let start = neutrin0_prover_chunk::consensus::context_boundary(&context, seed)
            .map_err(|_| ProofError::InvalidWitness)?;
        let pending = self.pending_bft_consensus_chunk(chunk_id)?;
        Ok(Some(PendingProjection { pending, start }))
    }

    /// Publish a validated projection only while its boundary and session value
    /// remain current. A durable execution certificate always takes precedence.
    ///
    /// # Errors
    /// Rejects a stale boundary or candidate.
    pub fn record_successor_execution(
        &mut self,
        validated: ValidatedProjection,
    ) -> Result<bool, FinalizeError<DB::Error>> {
        if self.certified_execution.is_some() {
            return Ok(false);
        }
        let (context, seed, _) = self.consensus_boundary(validated.start.next_chunk_id)?;
        if neutrin0_prover_chunk::consensus::context_boundary(&context, seed)
            .map_err(|_| ProofError::InvalidWitness)?
            != validated.start
            || self
                .bft_session(context.chunk_id)
                .map(crate::BftSession::chunk_hash)
                != Some(validated.projected.chunk_hash)
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        self.projected_execution = Some(validated.projected);
        Ok(true)
    }

    /// The successor state ordinary execution may use: the certified one, else
    /// the projected one.
    pub(crate) fn successor_state(&self) -> Option<&ConsensusState> {
        self.certified_execution
            .as_ref()
            .map(|value| &value.state)
            .or_else(|| self.current_projection().map(|value| &value.state))
    }

    /// The projection, while it still follows the open session's candidate;
    /// a session that moved to another candidate makes it stale.
    fn current_projection(&self) -> Option<&ProjectedExecution> {
        self.projected_execution.as_ref().filter(|projected| {
            self.bft_session(self.finalized_next_chunk_id())
                .is_some_and(|session| session.chunk_hash() == projected.chunk_hash)
        })
    }
}
