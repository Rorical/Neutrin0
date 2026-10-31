//! Certifying a successor context from proven blocks and restoring the
//! durable dependency on restart.

use neutrin0_proof_system::{ErasedBlockExecutor, ProofError, ProofSystem};
use neutrin0_prover_chunk::consensus::{ConsensusWitness, ValidatedConsensus};
use neutrin0_storage::{Batch, Column, Database};

use super::{CERTIFIED_EXECUTION_KEY, CertifiedExecution, MAX_CERTIFIED_BYTES};
use crate::{BlockState, Engine, FinalizeError, StoreError};

impl<DB: Database> Engine<DB> {
    /// Authenticate a successor context from proven blocks and complete native BFT validation.
    /// Persist before permitting any successor header to be signed. Finality stays unchanged.
    ///
    /// # Errors
    /// Rejects invalid receipts/certificates, conflicting certification, missing sources,
    /// replay failures and storage errors without publishing partial execution progress.
    pub fn certify_execution_chunk<P: ProofSystem>(
        &mut self,
        prepared: &crate::full_chunk::PreparedConsensusChunk<P>,
        proof_system: &P,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<bool, FinalizeError<DB::Error>> {
        let checked = super::ValidatedExecutionChunk::validate(prepared, proof_system)?;
        self.commit_execution_certificate(checked, executor)
    }

    /// Recheck owned validation against the live boundary, then durably publish
    /// execution progress. The receipt and signature work has already finished.
    ///
    /// # Errors
    /// Rejects stale sources, conflicting certification, replay or storage failure.
    pub fn commit_execution_certificate(
        &mut self,
        checked: super::ValidatedExecutionChunk,
        executor: Option<&dyn ErasedBlockExecutor>,
    ) -> Result<bool, FinalizeError<DB::Error>> {
        let super::ValidatedExecutionChunk {
            mut certified,
            validated,
        } = checked;
        self.require_execution_sources(&certified.witness)?;
        if let Some(previous) = &self.certified_execution {
            if previous.state != certified.state || previous.record.chunk != certified.record.chunk
            {
                return Err(ProofError::PublicInputMismatch.into());
            }
            return Ok(false);
        }
        certified.certified_at_secs = self.wall_clock_secs();
        // A certificate can precede the first finalized chunk. Persist the local
        // immutable trust profile before its durable dependency, so restart
        // never derives the consensus Guest identity from the witness itself.
        self.set_history_domain(neutrin0_consensus_types::history_proof::ProofDomain {
            chain: self.chain_binding(),
            chunk: self.chain_spec().genesis_chunk,
            programs: self.genesis_programs(),
        })?;
        let bytes = borsh::to_vec(&certified)?;
        if bytes.len() > MAX_CERTIFIED_BYTES {
            return Err(ProofError::InvalidWitness.into());
        }
        let mut batch = Batch::new();
        batch.put(Column::Meta, CERTIFIED_EXECUTION_KEY, bytes);
        let end = certified.state.boundary;
        if self.store().get_block_hash_by_height(end.height)? == Some(end.block_hash) {
            self.store_mut().write_observed_batch(batch, true)?;
        } else {
            let mut replayed = self
                .replay_branch(end.block_hash, executor)
                .map_err(FinalizeError::Replay)?;
            replayed
                .stage_witnesses(&mut batch)
                .map_err(|error| FinalizeError::Replay(crate::import::ImportError::Codec(error)))?;
            self.commit_materialized_head_with_batch(
                replayed.height,
                replayed.hash,
                replayed.state_root,
                Some(replayed.state),
                batch,
            )?;
        }
        self.projected_execution = None;
        self.certified_execution = Some(certified);
        self.certified_validation = Some(validated);
        Ok(true)
    }

    /// Check the exact persisted sources and trusted incoming boundary again
    /// after off-lock validation. No caller-supplied verdict replaces this check.
    fn require_execution_sources(
        &self,
        witness: &ConsensusWitness,
    ) -> Result<(), FinalizeError<DB::Error>> {
        let (context, seed, history) = self.consensus_boundary(witness.context.chunk_id)?;
        // Native certification has no recursive Fact receipt transport. Verify
        // every signature directly rather than trusting supplied Fact statements.
        if !witness.facts.is_empty()
            || witness.context != context
            || witness.seed != seed
            || witness.chain_spec != *self.chain_spec()
            || witness.history.frontier != history.frontier
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        for block in &witness.blocks {
            let hash = block.header.hash();
            if self.store().get_header(&hash)?.as_ref() != Some(&block.header)
                || self.store().get_block_state(&hash)? != Some(BlockState::Proven)
                || self
                    .store()
                    .get_block_proof(&hash)?
                    .as_ref()
                    .is_none_or(|proof| proof.public_inputs != block.public_inputs)
            {
                return Err(ProofError::InvalidWitness.into());
            }
        }
        Ok(())
    }

    pub(super) fn validate_execution_certificate(
        &self,
        witness: &ConsensusWitness,
        certified_at_secs: u64,
    ) -> Result<(CertifiedExecution, ValidatedConsensus), FinalizeError<DB::Error>> {
        self.require_execution_sources(witness)?;
        super::validate_certificate(witness, certified_at_secs).map_err(Into::into)
    }

    pub(crate) fn restore_certified_execution(
        &mut self,
    ) -> Result<(), crate::EngineError<DB::Error>> {
        let Some(bytes) = self
            .store()
            .db()
            .get(Column::Meta, CERTIFIED_EXECUTION_KEY)
            .map_err(StoreError::Database)?
        else {
            return Ok(());
        };
        if bytes.len() > MAX_CERTIFIED_BYTES {
            return Err(
                StoreError::Corrupt("certified execution witness exceeds local bound").into(),
            );
        }
        let stored: CertifiedExecution = borsh::from_slice(&bytes).map_err(StoreError::from)?;
        let (checked, validated) = self
            .validate_execution_certificate(&stored.witness, stored.certified_at_secs)
            .map_err(|_| StoreError::Corrupt("certified execution dependency is invalid"))?;
        if stored != checked
            || self.head_height() < stored.state.boundary.height
            || self
                .store()
                .get_block_hash_by_height(stored.state.boundary.height)?
                != Some(stored.state.boundary.block_hash)
            || self.chunk_of_height(self.head_height()) > Some(stored.state.boundary.next_chunk_id)
        {
            return Err(StoreError::Corrupt("certified execution pointers disagree").into());
        }
        self.projected_execution = None;
        self.certified_execution = Some(checked);
        self.certified_validation = Some(validated);
        Ok(())
    }
}
