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
        if self.certified_execution.is_some() {
            self.projected_execution = None;
            return Ok(false);
        }
        let chunk_id = self.finalized_next_chunk_id();
        let Some(chunk_hash) = self
            .bft_session(chunk_id)
            .map(crate::BftSession::chunk_hash)
        else {
            self.projected_execution = None;
            return Ok(false);
        };
        if self
            .projected_execution
            .as_ref()
            .is_some_and(|projected| projected.chunk_hash == chunk_hash)
        {
            return Ok(false);
        }
        let prepared = self.prepare_bft_consensus_chunk(chunk_id, proof_system)?;
        let projected = neutrin0_prover_chunk::consensus::project_successor(&prepared.witness)
            .map_err(|_| ProofError::InvalidWitness)?;
        if projected.chunk_hash != chunk_hash {
            return Err(ProofError::PublicInputMismatch.into());
        }
        self.projected_execution = Some(ProjectedExecution {
            chunk_hash,
            state: ConsensusState {
                boundary: projected.end,
                next_seed: projected.end.seed,
                next_context: projected.next_context,
                frontier: projected.frontier,
            },
        });
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
