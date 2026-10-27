//! Certification and atomic, proof-gated commitment of a complete chunk.

use neutrin0_consensus_types::ChunkProof;
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::history_proof::{ChunkReceiptStatement, ConsensusStatement};
use neutrin0_primitives::Hash;
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_prover_chunk::{
    consensus::{
        ConsensusWitness, ValidatedConsensus, as_chunk, context_boundary,
        validate_consensus_with_context,
    },
    execution::ExecutionContext,
    history::HistoricalChunk,
};
use neutrin0_storage::{Column, Database};

use super::{ConsensusState, PreparedConsensusChunk};
use crate::{Engine, FinalizeError, FinalizeOutcome, ProposerKey};

impl<DB: Database> Engine<DB> {
    /// Obtain the finality certificate before asking a prover to attest to it.
    /// A failed proof attempt leaves the BFT session available for retry.
    pub fn certify_consensus_chunk<P: ProofSystem>(
        &mut self,
        prepared: &mut PreparedConsensusChunk<P>,
        voter: &ProposerKey,
    ) -> Result<(), FinalizeError<DB::Error>> {
        self.certify_validated_consensus_chunk(prepared, voter)
            .map(|_| ())
    }

    /// Certify `prepared` and return the complete consensus validation of the
    /// certified witness.
    pub(crate) fn certify_validated_consensus_chunk<P: ProofSystem>(
        &mut self,
        prepared: &mut PreparedConsensusChunk<P>,
        voter: &ProposerKey,
    ) -> Result<ValidatedConsensus, FinalizeError<DB::Error>> {
        let chunk = as_chunk(&prepared.candidate.execution.chunk);
        let certificate =
            self.run_chunk_bft(&chunk, chunk.hash(), voter, chunk.active_validator_set_root)?;
        self.install_finality_certificate(prepared, certificate)?;
        validate_consensus_with_context(&prepared.witness)
            .map_err(|_| ProofError::InvalidWitness.into())
    }

    /// Verify a complete proof, recheck its still-current anchor and persist
    /// finality, proof, history, penalties, seed and rotation in one DB batch.
    pub fn commit_consensus_chunk<P: ProofSystem>(
        &mut self,
        witness: &ConsensusWitness,
        proof: &P::ChunkProof,
        proof_system: &P,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        self.commit_consensus_chunk_inner(witness, proof, proof_system, false, None, None)
    }

    /// [`Self::commit_consensus_chunk`] for a witness whose complete
    /// consensus validation the caller already holds.
    pub(crate) fn commit_validated_consensus_chunk<P: ProofSystem>(
        &mut self,
        witness: &ConsensusWitness,
        proof: &P::ChunkProof,
        proof_system: &P,
        validated: ValidatedConsensus,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        self.commit_consensus_chunk_inner(
            witness,
            proof,
            proof_system,
            false,
            None,
            Some(validated),
        )
    }

    pub(crate) fn commit_imported_consensus_chunk<P: ProofSystem>(
        &mut self,
        witness: &ConsensusWitness,
        proof: &P::ChunkProof,
        proof_system: &P,
        executor: Option<&dyn neutrin0_proof_system::ErasedBlockExecutor>,
        validated: ValidatedConsensus,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        self.commit_consensus_chunk_inner(
            witness,
            proof,
            proof_system,
            true,
            executor,
            Some(validated),
        )
    }

    /// Commit complete consensus for the saved BFT target. When that target
    /// differs from fork choice, replay its already-proven branch with the
    /// installed executor before atomically publishing finality and live state.
    pub fn commit_bft_consensus_chunk<P: ProofSystem>(
        &mut self,
        witness: &ConsensusWitness,
        proof: &P::ChunkProof,
        proof_system: &P,
        executor: Option<&dyn neutrin0_proof_system::ErasedBlockExecutor>,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        if let Some(certified) = &self.certified_execution {
            if crate::BftQuorumIdentity::from_certificate(&certified.witness.finality_cert)
                != crate::BftQuorumIdentity::from_certificate(&witness.finality_cert)
            {
                return Err(ProofError::PublicInputMismatch.into());
            }
            // Certification validated exactly this witness when it is unchanged.
            let validated = self
                .certified_validation
                .clone()
                .filter(|_| certified.witness == *witness);
            return self.commit_consensus_chunk_inner(
                witness,
                proof,
                proof_system,
                true,
                executor,
                validated,
            );
        }
        let session = self
            .bft_session(witness.context.chunk_id)
            .ok_or(FinalizeError::FinalizationStalled)?;
        // Complete validation subsumes the candidate's; commit reuses it.
        let validated =
            validate_consensus_with_context(witness).map_err(|_| ProofError::InvalidWitness)?;
        if as_chunk(&validated.statement.chunk).hash() != session.chunk_hash() {
            return Err(ProofError::PublicInputMismatch.into());
        }
        if self.bft_quorum_identity(witness.context.chunk_id)
            != Some(crate::BftQuorumIdentity::from_certificate(
                &witness.finality_cert,
            ))
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        self.commit_consensus_chunk_inner(
            witness,
            proof,
            proof_system,
            true,
            executor,
            Some(validated),
        )
    }

    /// `validated`, when present, is the complete consensus validation of this
    /// exact `witness`; it replaces the otherwise identical revalidation.
    fn commit_consensus_chunk_inner<P: ProofSystem>(
        &mut self,
        witness: &ConsensusWitness,
        proof: &P::ChunkProof,
        proof_system: &P,
        imported: bool,
        executor: Option<&dyn neutrin0_proof_system::ErasedBlockExecutor>,
        validated: Option<ValidatedConsensus>,
    ) -> Result<FinalizeOutcome, FinalizeError<DB::Error>> {
        let (context, seed) = self.require_committed_witness(witness, imported)?;
        let validated = if let Some(validated) = validated {
            validated
        } else {
            validate_consensus_with_context(witness).map_err(|_| ProofError::InvalidWitness)?
        };
        let statement = validated.statement;
        if let Some(certified) = &self.certified_execution
            && (certified.state.boundary != statement.end
                || certified.record.chunk.hash() != as_chunk(&statement.chunk).hash())
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        let receipt_statement = verified_chunk_receipt(proof_system, proof, &statement)?;
        let chunk = as_chunk(&statement.chunk);
        let wire = ChunkProof {
            finality_cert: witness.finality_cert.clone(),
            chunk_id: chunk.chunk_id,
            chunk_hash: chunk.hash(),
            public_inputs: statement.chunk.clone(),
            prover_address: receipt_statement.chunk_prover_address,
            proof_bytes: borsh::to_vec(proof)?,
        };
        let state =
            finalized_consensus_state(witness, context, seed, &statement, validated.next_context)?;
        let identity_sanctions =
            self.persist_finalization(witness, &wire, &statement, &state, executor)?;

        self.certified_execution = None;
        self.certified_validation = None;
        self.awaited_receipts.clear();
        self.install_consensus_state(&state);
        self.identity_sanctions = self.store().state_at(identity_sanctions.root());
        self.bft_sessions.remove(&chunk.chunk_id);
        let _ = self
            .fork_choice
            .add_finalized_chunk(&chunk, &witness.finality_cert);
        Ok(FinalizeOutcome {
            chunk_hash: chunk.hash(),
            chunk,
            chunk_proof: wire,
            public_inputs: statement.chunk,
            finality_cert: witness.finality_cert.clone(),
        })
    }

    /// The trusted incoming context and seed `witness` must start from, after
    /// checking that every block of the witness is the retained one.
    fn require_committed_witness(
        &self,
        witness: &ConsensusWitness,
        imported: bool,
    ) -> Result<(ExecutionContext, Hash), FinalizeError<DB::Error>> {
        let (context, seed, _) = self.consensus_boundary(witness.context.chunk_id)?;
        if witness.context != context
            || witness.seed != seed
            || witness.chain_spec != *self.chain_spec()
        {
            return Err(ProofError::PublicInputMismatch.into());
        }
        for block in &witness.blocks {
            let stored = if imported {
                self.store().get_header(&block.header.hash())?
            } else {
                self.store().get_header_by_height(block.header.height)?
            };
            if stored.as_ref() != Some(&block.header) {
                return Err(ProofError::PublicInputMismatch.into());
            }
        }
        Ok((context, seed))
    }

    /// Durably commit finality, proof, history, penalties, seed, rotation and
    /// the identity sanctions transition in one batch, replaying the proven
    /// branch first when the chunk's end block is not the canonical one.
    /// Returns the committed identity sanctions trie.
    fn persist_finalization(
        &mut self,
        witness: &ConsensusWitness,
        wire: &ChunkProof,
        statement: &ConsensusStatement,
        state: &ConsensusState,
        executor: Option<&dyn neutrin0_proof_system::ErasedBlockExecutor>,
    ) -> Result<neutrin0_trie::Trie, FinalizeError<DB::Error>> {
        let chunk = as_chunk(&statement.chunk);
        let receipt_statement = ChunkReceiptStatement {
            statement: statement.clone(),
            chunk_prover_address: wire.prover_address,
        };
        let mut batch = self
            .store()
            .consensus_finalization_batch(witness, wire, statement, state)?;
        batch.put(
            Column::ChunkReceipts,
            crate::store::chunk_receipt_key(chunk.chunk_id, &receipt_statement.statement_key()),
            borsh::to_vec(&crate::store::StoredChunkReceipt {
                proof: wire.clone(),
                statement_key: receipt_statement.statement_key(),
                first_verified_slot: self.local_slot(),
            })?,
        );
        batch.delete(Column::Meta, crate::certified::CERTIFIED_EXECUTION_KEY);
        let identity_sanctions =
            self.identity_sanctions_transition(witness, statement.end.identity_sanctions_root)?;
        self.store()
            .state_writer(&mut batch)
            .pin(crate::store::StatePin::Sanctions, &identity_sanctions)?;
        if self.store().get_block_hash_by_height(chunk.end_height)? == Some(chunk.end_block_hash) {
            self.store_mut().write_observed_batch(batch, true)?;
        } else {
            // Proof verification precedes replay; a failed replay or DB batch
            // cannot change either finality or the selected chain/state.
            let mut replayed = self
                .replay_branch(chunk.end_block_hash, executor)
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
        Ok(identity_sanctions)
    }
}

/// Verify `proof` against `statement` and the credited account it commits.
/// Design 08: the credited account is committed outside the statement; the
/// proof is verified against both.
fn verified_chunk_receipt<P: ProofSystem, E>(
    proof_system: &P,
    proof: &P::ChunkProof,
    statement: &ConsensusStatement,
) -> Result<ChunkReceiptStatement, FinalizeError<E>> {
    let chunk_prover_address = proof_system.chunk_prover_address(proof)?;
    if !neutrin0_primitives::is_runtime_account(&chunk_prover_address) {
        return Err(ProofError::PublicInputMismatch.into());
    }
    let receipt_statement = ChunkReceiptStatement {
        statement: statement.clone(),
        chunk_prover_address,
    };
    proof_system.verify_consensus_chunk(proof, &receipt_statement)?;
    Ok(receipt_statement)
}

/// The outgoing consensus state the chunk's History record and `statement`
/// derive, which must reproduce the statement's end boundary.
fn finalized_consensus_state<E>(
    witness: &ConsensusWitness,
    context: ExecutionContext,
    seed: Hash,
    statement: &ConsensusStatement,
    next_context: ExecutionContext,
) -> Result<ConsensusState, FinalizeError<E>> {
    let chunk = as_chunk(&statement.chunk);
    let record = HistoricalChunk {
        runtime_code_hash: context.programs.runtime_code_hash,
        block_guest_vk_digest: context.programs.execution.block,
        start_boundary: statement.start.commitment(),
        chunk,
        validators: context.active_validators,
        seed,
        finality: witness.finality_cert.clone(),
    };
    let mut frontier = witness.history.frontier.clone();
    let history_root = frontier
        .append(commitment(&record.evidence_context()))
        .ok_or(ProofError::InvalidWitness)?;
    if history_root != statement.end.history_root
        || context_boundary(&next_context, statement.end.seed)
            .map_err(|_| ProofError::InvalidWitness)?
            != statement.end
    {
        return Err(ProofError::PublicInputMismatch.into());
    }
    let next_seed = statement.end.seed;
    Ok(ConsensusState {
        boundary: statement.end,
        next_context,
        next_seed,
        frontier,
    })
}
