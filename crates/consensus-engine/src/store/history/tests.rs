use super::*;
use core::cell::Cell;
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::{AggregatedVote, Chunk, FinalityCert};
use neutrin0_primitives::BitVec;
use neutrin0_prover_chunk::history::{MAX_HISTORY_CONTEXT_BYTES, MAX_HISTORY_READS};
use neutrin0_storage::{ColumnSnapshot, MemoryDatabase};

#[derive(Default)]
struct MeasuredDb {
    inner: MemoryDatabase,
    reads: Cell<usize>,
}
impl Database for MeasuredDb {
    type Error = core::convert::Infallible;
    fn read_handle(&self) -> std::sync::Arc<dyn neutrin0_storage::ReadHandle> {
        self.inner.read_handle()
    }
    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        self.reads.set(self.reads.get() + 1);
        self.inner.get(column, key)
    }
    fn put(&mut self, column: Column, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        self.inner.put(column, key, value)
    }
    fn delete(&mut self, column: Column, key: &[u8]) -> Result<(), Self::Error> {
        self.inner.delete(column, key)
    }
    fn write_batch(&mut self, batch: Batch) -> Result<(), Self::Error> {
        self.inner.write_batch(batch)
    }
    fn write_batch_durable(&mut self, batch: Batch) -> Result<(), Self::Error> {
        self.inner.write_batch_durable(batch)
    }
    fn iter_column(&self, column: Column) -> Result<ColumnSnapshot, Self::Error> {
        assert!(
            !matches!(column, Column::HistoricalChunks | Column::HistoryNodes),
            "history append/open must not enumerate archived records or tree nodes"
        );
        self.inner.iter_column(column)
    }
    fn iter_prefix(&self, column: Column, prefix: &[u8]) -> Result<ColumnSnapshot, Self::Error> {
        self.inner.iter_prefix(column, prefix)
    }
}
pub(in crate::store) fn record(id: u64) -> HistoricalChunk {
    let validators = vec![neutrin0_primitives::Validator {
        pubkey: [9; 48],
        withdrawal_credentials: neutrin0_primitives::runtime_account([10; 20]),
        effective_stake: 100,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }];
    let chunk = Chunk {
        next_identity_sanctions_root: [0; 32],

        chunk_id: id,
        start_height: id + 1,
        end_height: id + 1,
        start_state_root: [1; 32],
        end_state_root: [2; 32],
        start_block_hash: [3; 32],
        end_block_hash: [4; 32],
        block_hash_root: [5; 32],
        block_proof_root: [6; 32],
        vrf_proof_root: [7; 32],
        active_validator_set_root: commitment(&validators),
        next_validator_set_root: commitment(&validators),
        da_root: [8; 32],
    };
    let vote = AggregatedVote {
        aggregation_bits: BitVec::default(),
        signature: [0; 96],
    };
    let finality = FinalityCert {
        proposal: neutrin0_consensus_types::BftProposal {
            chunk: chunk.clone(),
            round: 0,
            proposer_index: 0,
            valid_quorum: None,
            round_change_certificate: None,
            proposal_slot: 0,
            receipts: Vec::new(),
            ratified_chunk_proofs: Vec::new(),
            signature: [0; 96],
        },
        prevote_attestations: Vec::new(),
        precommit_attestations: Vec::new(),
        proof_manifests: Vec::new(),
        chunk_id: id,
        round: 0,
        chunk_hash: chunk.hash(),
        prevote: vote.clone(),
        precommit: vote,
        active_validator_set_root: chunk.active_validator_set_root,
    };
    HistoricalChunk {
        runtime_code_hash: [0; 32],
        block_guest_vk_digest: [0; 8],
        start_boundary: boundary(id).commitment(),
        chunk,
        validators,
        seed: [9; 32],
        finality,
    }
}

#[test]
fn persistent_history_retains_old_roots_without_scanning_and_with_bounded_reads() {
    let mut store = ChainStore::new(MeasuredDb::default());
    store
        .set_retention_policy(RetentionPolicy::Archive)
        .unwrap();
    let mut leaves = Vec::new();
    let mut roots = Vec::new();
    for id in 0..70 {
        let record = record(id);
        leaves.push(commitment(&record.evidence_context()));
        let mut batch = Batch::new();
        store.db.reads.set(0);
        let frontier = store.append_history_batch(&mut batch, &record).unwrap();
        assert!(store.db.reads.get() <= 65);
        let root = frontier.root().unwrap();
        assert_eq!(
            root,
            neutrin0_consensus_types::history::history_root(&leaves)
        );
        roots.push(root);
        store.db.write_batch(batch).unwrap();
    }
    for count in [1, 2, 3, 7, 8, 9, 63, 64, 65, 70] {
        for index in [0, count / 2, count - 1] {
            store.db.reads.set(0);
            let opening = store.historical_opening(index, count).unwrap();
            assert!(store.db.reads.get() <= 70);
            assert!(opening.path.verify(
                commitment(&opening.record.evidence_context()),
                roots[usize::try_from(count).unwrap() - 1]
            ));
            assert!(
                !opening
                    .path
                    .verify(commitment(&opening.record.evidence_context()), [0; 32])
            );
        }
    }
    assert!(store.historical_opening(70, 70).is_err());
    let witness = store.history_witness(70, [65, 62, 65]).unwrap();
    assert_eq!(witness.records.len(), 2);
    assert_eq!(witness.records[0].record.chunk.chunk_id, 62);
    assert_eq!(witness.records[1].record.chunk.chunk_id, 65);
    witness.authenticate(70, roots[69]).unwrap();
}

#[test]
fn witness_rejects_expired_reads_before_any_archive_io() {
    let store = ChainStore::new(MeasuredDb::default());
    let count = u64::try_from(MAX_HISTORY_READS).unwrap() + 1;
    assert!(matches!(
        store.history_witness(count, 0..count),
        Err(StoreError::Corrupt("history index outside boundary"))
    ));
    assert_eq!(store.db.reads.get(), 0);
    assert!(matches!(
        store.history_witness(0, [0]),
        Err(StoreError::Corrupt("history index outside boundary"))
    ));
    assert_eq!(store.db.reads.get(), 0);
}

#[test]
fn witness_reads_only_certificate_independent_contexts() {
    let mut store = ChainStore::new(MeasuredDb::default());
    for id in 0..3 {
        let record = record(id);
        let mut batch = Batch::new();
        store.append_history_batch(&mut batch, &record).unwrap();
        store.db.write_batch(batch).unwrap();
    }
    let deduplicated = store.history_witness(3, [0, 0]).unwrap();
    assert_eq!(deduplicated.records.len(), 1);
    store.db.reads.set(0);
    let witness = store.history_witness(3, [0, 1, 2]).unwrap();
    assert_eq!(witness.records.len(), 3);
    for (id, opening) in witness.records.iter().enumerate() {
        assert_eq!(opening.record, (&record(u64::try_from(id).unwrap())).into());
    }
    assert!(borsh::object_length(&witness).unwrap() < MAX_HISTORY_CONTEXT_BYTES);
    // One frontier lookup and three retained record/path/root openings.
    assert_eq!(store.db.reads.get(), 1 + 3 * 3);
}

#[test]
fn failed_history_append_batch_publishes_no_partial_record_or_frontier() {
    let mut store = ChainStore::new(crate::test_db::FaultDb::default());
    let mut batch = Batch::new();
    store.append_history_batch(&mut batch, &record(0)).unwrap();
    store.db.fail_batch = true;
    assert!(store.db.write_batch(batch).is_err());
    assert!(store.historical_chunk(0).unwrap().is_none());
    assert!(store.history_frontier(1).is_err());
    assert_eq!(store.history_frontier(0).unwrap().count, 0);
    store.db.fail_batch = false;
    let mut batch = Batch::new();
    store.append_history_batch(&mut batch, &record(0)).unwrap();
    store.db.write_batch(batch).unwrap();
    assert_eq!(store.historical_opening(0, 1).unwrap().record, record(0));
}

#[test]
fn immutable_history_node_corruption_is_detected() {
    let mut store = ChainStore::new(MemoryDatabase::new());
    store
        .set_retention_policy(RetentionPolicy::Archive)
        .unwrap();
    let mut batch = Batch::new();
    store.append_history_batch(&mut batch, &record(0)).unwrap();
    store.db.write_batch(batch).unwrap();
    store
        .db
        .delete(Column::HistoryPaths, &keys::pair_key(1, 0))
        .unwrap();
    let (_, root) = store.history_snapshot(1).unwrap();
    store
        .db
        .put(
            Column::HistoryNodes,
            &root,
            &borsh::to_vec(&([0u8; 32], [0u8; 32])).unwrap(),
        )
        .unwrap();
    assert!(store.historical_opening(0, 1).is_err());
}

/// A well-formed compact boundary at `count`.
pub(in crate::store) fn boundary(
    count: u64,
) -> neutrin0_consensus_types::history_proof::ConsensusBoundary {
    use neutrin0_consensus_types::history_proof::{
        ConsensusBoundary, ExecutionPrograms, ProgramSet,
    };
    ConsensusBoundary {
        identity_sanctions_root: [0; 32],

        next_chunk_id: count,
        height: count,
        block_hash: [3; 32],
        state_root: [4; 32],
        slot: count,
        validators_root: [5; 32],
        seed: [6; 32],
        history_root: [7; 32],
        programs: ProgramSet {
            runtime_code_hash: [2; 32],
            execution: ExecutionPrograms {
                fact: [1; 8],
                evidence: [2; 8],
                block: [3; 8],
            },
        },
        participation: [8; 32],
        proving: neutrin0_consensus_types::proving::NO_PROVING,
        fork: None,
    }
}
