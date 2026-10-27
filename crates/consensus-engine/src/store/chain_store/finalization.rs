//! The durable batch of one complete chunk finality: chunk, proof,
//! boundaries, validator set, history append and finalized sanctions.

use neutrin0_consensus_types::{Chunk, ChunkProof};
use neutrin0_storage::{Column, Database};

use super::ChainStore;
use crate::block_state::BlockState;
use crate::store::{StoreError, keys, pointers};

impl<DB: Database> ChainStore<DB> {
    /// Load the last proof-gated consensus boundary and replay ledger.
    pub fn get_consensus_state(
        &self,
    ) -> Result<Option<crate::full_chunk::ConsensusState>, StoreError<DB::Error>> {
        self.get_decoded(Column::Finalized, pointers::CONSENSUS_STATE)
    }

    /// Atomically persist complete finality and its outgoing trust boundary.
    pub(crate) fn consensus_finalization_batch(
        &self,
        witness: &neutrin0_prover_chunk::consensus::ConsensusWitness,
        proof: &ChunkProof,
        statement: &neutrin0_consensus_types::history_proof::ConsensusStatement,
        state: &crate::full_chunk::ConsensusState,
    ) -> Result<neutrin0_storage::Batch, StoreError<DB::Error>> {
        let mut batch = neutrin0_storage::Batch::new();
        let chunk = neutrin0_prover_chunk::consensus::as_chunk(&statement.chunk);
        let key = keys::chunk_id_key(chunk.chunk_id);
        batch.put(Column::Chunks, key, borsh::to_vec(&chunk)?);
        batch.put(Column::ChunkProofs, key, borsh::to_vec(proof)?);
        batch.put(
            Column::Finalized,
            pointers::CONSENSUS_STATE,
            borsh::to_vec(state)?,
        );
        batch.put(Column::Finalized, pointers::LATEST_FINALIZED_CHUNK_ID, key);
        batch.put(
            Column::Finalized,
            pointers::FINALIZED_HEAD,
            chunk.end_block_hash,
        );
        batch.put(Column::Finalized, pointers::FINALIZED_SEED, state.next_seed);
        let next = &state.next_context;
        batch.put(
            Column::ValidatorSetSnapshots,
            keys::checkpoint_index_key(next.chunk_id),
            borsh::to_vec(&next.active_validators)?,
        );
        batch.put(
            Column::Finalized,
            pointers::LATEST_VALIDATOR_SET_INDEX,
            keys::checkpoint_index_key(next.chunk_id),
        );
        batch.put(Column::ChunkStatements, key, borsh::to_vec(statement)?);
        batch.put(
            Column::ConsensusBoundaries,
            keys::chunk_id_key(statement.start.next_chunk_id),
            borsh::to_vec(&statement.start)?,
        );
        batch.put(
            Column::ConsensusBoundaries,
            keys::chunk_id_key(statement.end.next_chunk_id),
            borsh::to_vec(&statement.end)?,
        );
        self.append_finalized_history_batch(&mut batch, witness, statement, state, &chunk)?;
        for block in &witness.blocks {
            for admission in &block.output.accountability.admitted {
                batch.put(
                    Column::FinalizedOffences,
                    admission.offence_id,
                    block.header.height.to_be_bytes(),
                );
                if admission.kind == neutrin0_consensus_types::evidence::SanctionKind::Slash {
                    batch.put(
                        Column::FinalizedSlashes,
                        admission.offender.pubkey,
                        block.header.height.to_be_bytes(),
                    );
                }
            }
            batch.put(
                Column::BlockStates,
                block.header.hash(),
                borsh::to_vec(&BlockState::Finalized)?,
            );
        }
        Ok(batch)
    }

    fn append_finalized_history_batch(
        &self,
        batch: &mut neutrin0_storage::Batch,
        witness: &neutrin0_prover_chunk::consensus::ConsensusWitness,
        statement: &neutrin0_consensus_types::history_proof::ConsensusStatement,
        state: &crate::full_chunk::ConsensusState,
        chunk: &Chunk,
    ) -> Result<(), StoreError<DB::Error>> {
        let record = neutrin0_prover_chunk::history::HistoricalChunk {
            runtime_code_hash: witness.context.programs.runtime_code_hash,
            block_guest_vk_digest: witness.context.programs.execution.block,
            start_boundary: statement.start.commitment(),
            chunk: chunk.clone(),
            validators: witness.context.active_validators.clone(),
            seed: witness.seed,
            finality: witness.finality_cert.clone(),
        };
        let frontier = self.append_history_batch(batch, &record)?;
        self.retain_reporter_finalization_batch(
            batch,
            &record,
            &statement.start,
            witness.blocks.iter().map(|block| block.header.clone()),
        )?;
        if frontier != state.frontier || frontier.root() != Some(state.boundary.history_root) {
            return Err(StoreError::Corrupt(
                "proven history append differs from archive",
            ));
        }
        Ok(())
    }
}
