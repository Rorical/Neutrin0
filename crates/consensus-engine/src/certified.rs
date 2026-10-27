//! Durable, certificate-authenticated execution ahead of complete proof finality.

extern crate alloc;

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::history_proof::ConsensusBoundary;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_prover_chunk::{
    consensus::ConsensusWitness,
    history::{HistoricalChunk, HistoryWitness},
};
use neutrin0_storage::Database;

use crate::{Engine, FinalizeError, StoreError, full_chunk::ConsensusState};

mod certification;

/// One durable execution dependency; it never occupies a finalized column.
#[expect(
    clippy::redundant_pub_crate,
    reason = "Shared only with engine implementation modules."
)]
pub(crate) const CERTIFIED_EXECUTION_KEY: &[u8] = b"certified_execution";
/// Bound the locally retained native witness before decoding or persistence.
const MAX_CERTIFIED_BYTES: usize = 64 * 1024 * 1024;

/// Complete native validation retained independently of proof finality.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "Engine state remains internal to this crate."
)]
pub(crate) struct CertifiedExecution {
    pub(crate) witness: ConsensusWitness,
    pub(crate) state: ConsensusState,
    pub(crate) record: HistoricalChunk,
    pub(crate) certified_at_secs: u64,
}

impl<DB: Database> Engine<DB> {
    /// Exact current certificate identity used by asynchronous Chunk proof work.
    #[must_use]
    pub fn execution_quorum_identity(&self, chunk_id: u64) -> Option<crate::BftQuorumIdentity> {
        self.certified_execution_witness()
            .filter(|witness| witness.context.chunk_id == chunk_id)
            .map(|witness| crate::BftQuorumIdentity::from_certificate(&witness.finality_cert))
            .or_else(|| self.bft_quorum_identity(chunk_id))
    }

    /// Reconstruct proven inputs for the durable certified value without new signatures.
    ///
    /// # Errors
    /// Returns missing/invalid source data or an unavailable proof backend.
    pub fn prepare_certified_execution<P: ProofSystem>(
        &self,
        proof_system: &P,
    ) -> Result<crate::full_chunk::PreparedConsensusChunk<P>, FinalizeError<DB::Error>> {
        let certified = self
            .certified_execution
            .as_ref()
            .ok_or(ProofError::InvalidWitness)?;
        let mut prepared = self.prepare_consensus_chunk_on_branch(
            certified.record.chunk.chunk_id,
            certified.record.chunk.end_block_hash,
            Some(&certified.witness.finality_cert.proposal.receipt_keys()),
            proof_system,
        )?;
        self.install_finality_certificate(&mut prepared, certified.witness.finality_cert.clone())?;
        let (checked, _) =
            self.validate_execution_certificate(&prepared.witness, certified.certified_at_secs)?;
        if checked.state != certified.state {
            return Err(ProofError::PublicInputMismatch.into());
        }
        Ok(prepared)
    }

    pub(crate) fn production_committee(&self) -> (&[neutrin0_primitives::Validator], Hash) {
        if let Some(state) = self.successor_state()
            && self
                .head_height()
                .checked_add(1)
                .and_then(|height| self.chunk_of_height(height))
                == Some(state.boundary.next_chunk_id)
        {
            return (&state.next_context.active_validators, state.next_seed);
        }
        (self.active_validator_set(), self.finalized_seed())
    }

    /// The optional successor boundary certified for ordinary execution only.
    #[must_use]
    pub fn certified_execution_boundary(&self) -> Option<&ConsensusBoundary> {
        self.certified_execution
            .as_ref()
            .map(|value| &value.state.boundary)
    }

    /// The History context the certified chunk has once finalized. A snapshot
    /// supersedes the dependency only if its History holds exactly this
    /// context for the chunk; another one there is a conflicting finalization.
    #[must_use]
    pub fn certified_history_context(
        &self,
    ) -> Option<neutrin0_consensus_types::evidence::EvidenceContext> {
        self.certified_execution
            .as_ref()
            .map(|value| value.record.evidence_context())
    }

    /// The committee of the chunk after the certified one, whose round-zero
    /// leader ratifies the certified chunk's proof (design 08), and that
    /// chunk's incoming seed, which draws the leader.
    #[must_use]
    pub fn certified_successor(
        &self,
    ) -> Option<(&[neutrin0_primitives::Validator], neutrin0_primitives::Seed)> {
        self.certified_execution.as_ref().map(|value| {
            (
                value.state.next_context.active_validators.as_slice(),
                value.state.next_context.seed,
            )
        })
    }

    /// Exact certified witness, retained so any node can prove the certified chunk.
    #[must_use]
    pub fn certified_execution_witness(&self) -> Option<&ConsensusWitness> {
        self.certified_execution
            .as_ref()
            .map(|value| &value.witness)
    }

    /// Time this process first durably authenticated the current certificate.
    #[must_use]
    pub fn execution_certified_at_secs(&self) -> Option<u64> {
        self.certified_execution
            .as_ref()
            .map(|value| value.certified_at_secs)
    }

    /// Incoming boundary usable by ordinary execution, including one certified successor.
    /// This is not an API for authenticating finality or pruning.
    ///
    /// # Errors
    /// Rejects unavailable boundaries and requests beyond the bounded execution window.
    pub fn execution_boundary(
        &self,
        count: u64,
    ) -> Result<ConsensusBoundary, FinalizeError<DB::Error>> {
        if let Some(state) = self.successor_state()
            && state.boundary.next_chunk_id == count
        {
            return Ok(state.boundary);
        }
        self.canonical_boundary(count)
    }

    /// Whether another block fits inside the authenticated execution window.
    #[must_use]
    pub fn can_extend_execution(&self) -> bool {
        let Some(chunk) = self
            .head_height()
            .checked_add(1)
            .and_then(|height| self.chunk_of_height(height))
        else {
            return false;
        };
        // A successor boundary extends exactly the branch it was derived from
        // (design 08): the head must be that boundary's end block.
        if let Some(state) = self.successor_state()
            && state.boundary.next_chunk_id == chunk
            && state.boundary.block_hash != self.head_hash()
            && state.boundary.height == self.head_height()
        {
            return false;
        }
        self.execution_boundary(chunk).is_ok()
    }

    pub(crate) fn execution_consensus_boundary(
        &self,
        count: u64,
    ) -> Result<
        (
            neutrin0_prover_chunk::execution::ExecutionContext,
            Hash,
            HistoryWitness,
        ),
        FinalizeError<DB::Error>,
    > {
        if let Some(state) = self.successor_state()
            && state.boundary.next_chunk_id == count
        {
            return Ok((
                state.next_context.clone(),
                state.next_seed,
                HistoryWitness {
                    frontier: state.frontier.clone(),
                    records: Vec::new(),
                },
            ));
        }
        self.consensus_boundary(count)
    }

    pub(crate) fn execution_history_chunk(
        &self,
        id: u64,
        incoming: u64,
    ) -> Result<Option<HistoricalChunk>, StoreError<DB::Error>> {
        if let Some(value) = &self.certified_execution
            && value.record.chunk.chunk_id == id
            && value.state.boundary.next_chunk_id == incoming
        {
            return Ok(Some(value.record.clone()));
        }
        self.store().historical_chunk(id)
    }

    /// Extend a finalized reporter opening solely for an authenticated execution input.
    /// The durable report and finalized history remain anchored at proof finality.
    ///
    /// # Errors
    /// Rejects unauthenticated openings, unavailable execution boundaries and
    /// any request outside the single certified successor.
    pub fn evidence_submission_for_execution(
        &self,
        height: u64,
        statement: &neutrin0_consensus_types::evidence::EvidenceStatement,
        path: &neutrin0_consensus_types::history::HistoryPath,
    ) -> Result<neutrin0_consensus_types::evidence::EvidenceSubmission, FinalizeError<DB::Error>>
    {
        let mut submission = self.evidence_submission_with_path(statement, path)?;
        let incoming = self
            .chunk_of_height(height)
            .ok_or(ProofError::InvalidWitness)?;
        if incoming == self.finalized_next_chunk_id() {
            return Ok(submission);
        }
        let certified = self
            .certified_execution
            .as_ref()
            .filter(|value| {
                value.state.boundary.next_chunk_id == incoming
                    && value.record.chunk.chunk_id == submission.history.count
            })
            .ok_or(ProofError::InvalidWitness)?;
        let frontier = self.store().history_frontier(submission.history.count)?;
        if frontier != certified.witness.history.frontier {
            return Err(ProofError::PublicInputMismatch.into());
        }
        let leaf = commitment(&statement.context);
        submission
            .history
            .advance(
                leaf,
                &frontier,
                commitment(&certified.record.evidence_context()),
            )
            .ok_or(ProofError::InvalidWitness)?;
        if !submission
            .history
            .verify(leaf, certified.state.boundary.history_root)
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        Ok(submission)
    }
}
