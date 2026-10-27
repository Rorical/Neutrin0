//! Fault-injected atomic storage for publication regression tests.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Share test helpers within the crate without exporting a test-only API."
)]

use neutrin0_consensus_types::Header;
use neutrin0_primitives::{
    BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo,
    RuntimeParams, Validator, ZERO_HASH,
};
use neutrin0_storage::{Batch, Column, ColumnSnapshot, Database, MemoryDatabase};

#[derive(Clone, Debug, Default)]
/// Memory storage that can reject an atomic batch before any writes.
pub(crate) struct FaultDb {
    inner: MemoryDatabase,
    /// Reject the next batch while preserving persisted data.
    pub fail_batch: bool,
    /// Fail the durable operation after this many successful durable writes.
    pub fail_durable_after: Option<usize>,
}

impl Database for FaultDb {
    type Error = std::io::Error;
    fn read_handle(&self) -> std::sync::Arc<dyn neutrin0_storage::ReadHandle> {
        self.inner.read_handle()
    }
    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.inner.get(column, key).unwrap())
    }
    fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        self.inner.put(column, key, value).unwrap();
        Ok(())
    }
    fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), Self::Error> {
        self.inner.delete(column, key).unwrap();
        Ok(())
    }
    fn write_batch(&mut self, batch: Batch) -> Result<(), Self::Error> {
        if self.fail_batch {
            return Err(std::io::Error::other("injected batch failure"));
        }
        self.inner.write_batch(batch).unwrap();
        Ok(())
    }
    fn iter_column(&self, column: Column) -> Result<ColumnSnapshot, Self::Error> {
        Ok(self.inner.iter_column(column).unwrap())
    }

    fn write_batch_durable(&mut self, batch: Batch) -> Result<(), Self::Error> {
        if let Some(remaining) = &mut self.fail_durable_after {
            if *remaining == 0 {
                return Err(std::io::Error::other("injected durable failure"));
            }
            *remaining -= 1;
        }
        self.write_batch(batch)
    }
}

/// Header fixture with caller-selected branch and state commitments.
pub(crate) fn header(height: u64, slot: u64, parent: [u8; 32], root: [u8; 32]) -> Header {
    Header {
        height,
        slot,
        parent_hash: parent,
        state_root: root,
        proposer_index: 0,
        vrf_proof: [0; 96],
        transactions_root: [0; 32],
        votes_root: [0; 32],
        da_root: [0; 32],
        runtime_extra: [0; 32],
        inputs_root: [0; 32],
        receipts_root: [0; 32],
        gas_used: 0,
        gas_limit: 1_000_000,
        timestamp: slot * 4,
        signature: [0; 96],
    }
}

/// Chain specification fixture over `validators` with default parameters.
/// Callers override the fields their scenario depends on.
pub(crate) fn spec(name: &[u8], chain_id: u64, validators: Vec<Validator>) -> ChainSpec {
    ChainSpec {
        genesis_execution: neutrin0_primitives::ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
        name: BoundedBytes::new(name.to_vec()).expect("name fits"),
        chain_id,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [0xBB; 32],
        genesis_chunk: [7; 8],
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: [0xCC; 32],
        genesis_state_root: ZERO_HASH,
        genesis_block_hash: [0xAA; 32],
        genesis_validator_set_root: crate::validator_set_root(&validators),
        consensus: ConsensusParams::default(),
        proof: ProofParams::default(),
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty metadata fits"),
    }
}

/// Weight `block` and its descendants in fork choice through one chunk vote, so a
/// test can choose the head without finalizing anything. A later call replaces the
/// previous support.
pub(crate) fn support_block<DB: Database>(
    engine: &mut crate::Engine<DB>,
    block: neutrin0_primitives::BlockHash,
) {
    let chunk = neutrin0_consensus_types::Chunk {
        chunk_id: 0,
        start_height: 0,
        end_height: 0,
        start_state_root: ZERO_HASH,
        end_state_root: ZERO_HASH,
        start_block_hash: block,
        end_block_hash: block,
        block_hash_root: ZERO_HASH,
        block_proof_root: ZERO_HASH,
        vrf_proof_root: ZERO_HASH,
        active_validator_set_root: ZERO_HASH,
        next_validator_set_root: ZERO_HASH,
        next_identity_sanctions_root: ZERO_HASH,
        da_root: ZERO_HASH,
    };
    let chunk_hash = engine.fork_choice.add_chunk(&chunk);
    engine.fork_choice.add_vote(
        0,
        neutrin0_consensus_fork_choice::ChunkVote {
            data: neutrin0_consensus_types::FinalityVoteData {
                chunk_id: 0,
                round: 0,
                chunk_hash,
                selection: [0; 32],
                phase: neutrin0_consensus_types::FinalityVotePhase::Precommit,
            },
            weight: 100,
        },
    );
}
