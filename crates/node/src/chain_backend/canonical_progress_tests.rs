//! Persisted-artifact cursor contracts, without accepting synthetic proofs.

use super::{ChainBackend, state_sync_tests};
use neutrin0_consensus_engine::{Engine, RetentionInfo, RetentionPolicy, compute_body_roots};
use neutrin0_consensus_types::{
    Block, BlockProof, BlockProofPublicInputs, Body, Header, ProvenBlock,
};
use neutrin0_primitives::{BlockHash, Height, ZERO_HASH};
use neutrin0_proof_system::MockProofSystem;
use neutrin0_rpc::{QueryError, RpcBackend};
use neutrin0_storage::{Batch, Column, ColumnSnapshot, Database, MemoryDatabase};
use neutrin0_sync::{SyncBackend, SyncBackendError};
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};

type Backend = ChainBackend<FaultDatabase, MockProofSystem>;
type Read = (Column, Vec<u8>);

#[derive(Default)]
struct FaultDatabase {
    inner: MemoryDatabase,
    fail_get: Option<Read>,
    reads: RefCell<Vec<Read>>,
}

impl Database for FaultDatabase {
    type Error = &'static str;
    fn read_handle(&self) -> std::sync::Arc<dyn neutrin0_storage::ReadHandle> {
        self.inner.read_handle()
    }

    fn get(&self, column: Column, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        self.reads.borrow_mut().push((column, key.to_vec()));
        if self
            .fail_get
            .as_ref()
            .is_some_and(|(failed_column, failed_key)| {
                *failed_column == column && failed_key == key
            })
        {
            return Err("injected progress read failure");
        }
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
        self.inner.write_batch(batch).unwrap();
        Ok(())
    }

    fn write_batch_durable(&mut self, batch: Batch) -> Result<(), Self::Error> {
        self.inner.write_batch_durable(batch).unwrap();
        Ok(())
    }

    fn iter_column(&self, column: Column) -> Result<ColumnSnapshot, Self::Error> {
        Ok(self.inner.iter_column(column).unwrap())
    }
}

/// Build query-layer records and reopen their selected canonical suffix. This
/// fixture exercises store consistency, not signature or receipt admission.
fn chain(count: Height) -> (Engine<FaultDatabase>, Vec<Block>) {
    let mut spec = state_sync_tests::spec();
    spec.consensus.chunk_size = 2;
    let mut engine = Engine::genesis(spec.clone(), FaultDatabase::default()).unwrap();
    let mut parent_hash = spec.genesis_block_hash;
    let body = Body::default();
    let roots = compute_body_roots(&body);
    let mut blocks = Vec::new();
    for height in 1..=count {
        let block = Block {
            header: Header {
                height,
                slot: height,
                parent_hash,
                proposer_index: 0,
                vrf_proof: [0; 96],
                state_root: ZERO_HASH,
                transactions_root: roots.transactions_root,
                votes_root: roots.votes_root,
                da_root: roots.da_root,
                runtime_extra: ZERO_HASH,
                inputs_root: [0; 32],
                receipts_root: body.artifacts.commitment(),
                gas_used: 0,
                gas_limit: spec.genesis_gas_limit,
                timestamp: height * spec.consensus.slot_duration_secs,
                signature: [0; 96],
            },
            body: body.clone(),
        };
        parent_hash = engine.store_mut().put_header(&block.header).unwrap();
        engine.store_mut().put_body(&parent_hash, &body).unwrap();
        blocks.push(block);
    }
    engine
        .store_mut()
        .commit_tip(parent_hash, spec.genesis_block_hash, Batch::new())
        .unwrap();
    let db = FaultDatabase {
        inner: engine.store().db().inner.clone(),
        ..FaultDatabase::default()
    };
    (Engine::open(spec, db).unwrap(), blocks)
}

fn envelope(block: &Block) -> BlockProof {
    BlockProof {
        height: block.header.height,
        block_hash: block.hash(),
        public_inputs: BlockProofPublicInputs {
            context: Box::default(),
            chain_id: 0,
            height: 0,
            parent_block_hash: ZERO_HASH,
            block_hash: ZERO_HASH,
            state_root_before: ZERO_HASH,
            state_root_after: ZERO_HASH,
            transactions_root: ZERO_HASH,
            receipt_root: ZERO_HASH,
            da_root: ZERO_HASH,
            vm_code_hash: ZERO_HASH,
            block_program: [0; 8],
            gas_used: 0,
            gas_limit: 0,
            proposer_address: ZERO_HASH,
            runtime_extra: ZERO_HASH,
            inputs_root: [0; 32],
        },
        prover_address: [0; 32],
        statement_key: [0; 32],
        proof_bytes: vec![255],
    }
}

fn put_proof(engine: &mut Engine<FaultDatabase>, hash: BlockHash, proof: &BlockProof) {
    // Bypass verified admission only to model persisted cursor inputs. Neither
    // the fixture receipt nor its public inputs are cryptographically accepted.
    engine
        .store_mut()
        .db_mut()
        .put(Column::BlockProofs, &hash, &borsh::to_vec(proof).unwrap())
        .unwrap();
}

fn set_floor(engine: &mut Engine<FaultDatabase>, first_retained_height: Height) {
    let info = RetentionInfo {
        policy: RetentionPolicy::Pruned,
        pruned_before_chunk: (first_retained_height - 1) / engine.chain_spec().consensus.chunk_size,
        first_retained_height,
    };
    // Query-layer fixture for a committed watermark; the engine retention suite
    // independently checks authorization and atomic deletion.
    engine
        .store_mut()
        .db_mut()
        .put(
            Column::Meta,
            b"history_retention",
            &borsh::to_vec(&info).unwrap(),
        )
        .unwrap();
}

fn assert_storage(result: Result<Height, SyncBackendError>, message: &str) {
    assert_eq!(
        result.unwrap_err(),
        SyncBackendError::Storage(message.to_owned())
    );
}

#[test]
fn genesis_and_empty_retained_suffix_return_the_preceding_height() {
    let (engine, _) = chain(0);
    assert_eq!(Backend::contiguous_proven_height(&engine).unwrap(), 0);

    let (mut engine, _) = chain(2);
    set_floor(&mut engine, 3);
    engine.store().db().reads.borrow_mut().clear();
    assert_eq!(Backend::contiguous_proven_height(&engine).unwrap(), 2);
    assert!(
        engine
            .store()
            .db()
            .reads
            .borrow()
            .iter()
            .all(|(column, _)| *column == Column::Meta)
    );
}

#[test]
fn artifact_gaps_stop_before_later_missing_indexes_and_corruption() {
    let (mut engine, blocks) = chain(3);
    put_proof(&mut engine, blocks[0].hash(), &envelope(&blocks[0]));
    let db = engine.store_mut().db_mut();
    db.delete(Column::Blocks, &blocks[1].hash()).unwrap();
    db.put(Column::Blocks, &blocks[2].hash(), &[255]).unwrap();
    db.delete(Column::HeaderByHeight, &3_u64.to_be_bytes())
        .unwrap();
    db.fail_get = Some((Column::Headers, blocks[1].hash().to_vec()));
    db.reads.borrow_mut().clear();
    assert_eq!(Backend::contiguous_proven_height(&engine).unwrap(), 1);
    let reads = engine.store().db().reads.borrow();
    assert!(!reads.contains(&(Column::HeaderByHeight, 3_u64.to_be_bytes().to_vec())));
    assert!(!reads.contains(&(Column::Headers, blocks[1].hash().to_vec())));
}

#[test]
fn missing_canonical_height_is_an_error_before_loading_its_artifact() {
    let (mut engine, blocks) = chain(2);
    put_proof(&mut engine, blocks[0].hash(), &envelope(&blocks[0]));
    let db = engine.store_mut().db_mut();
    db.delete(Column::HeaderByHeight, &2_u64.to_be_bytes())
        .unwrap();
    db.reads.borrow_mut().clear();
    assert_storage(
        Backend::contiguous_proven_height(&engine),
        "canonical height is missing",
    );
    let reads = engine.store().db().reads.borrow();
    for column in [Column::Blocks, Column::BlockProofs] {
        assert!(!reads.contains(&(column, blocks[1].hash().to_vec())));
    }
}

#[test]
fn retained_suffix_does_not_revisit_pruned_indexes_or_artifacts() {
    let (mut engine, blocks) = chain(4);
    for block in &blocks[2..] {
        put_proof(&mut engine, block.hash(), &envelope(block));
    }
    set_floor(&mut engine, 3);
    let db = engine.store_mut().db_mut();
    db.delete(Column::HeaderByHeight, &1_u64.to_be_bytes())
        .unwrap();
    db.put(Column::BlockProofs, &blocks[0].hash(), &[255])
        .unwrap();
    db.put(Column::Blocks, &blocks[0].hash(), &[255]).unwrap();
    db.reads.borrow_mut().clear();
    assert_eq!(Backend::contiguous_proven_height(&engine).unwrap(), 4);
    let reads = engine.store().db().reads.borrow();
    for height in [1_u64, 2] {
        assert!(!reads.contains(&(Column::HeaderByHeight, height.to_be_bytes().to_vec())));
    }
}

#[test]
fn missing_optional_header_does_not_remove_proof_progress() {
    let (mut engine, blocks) = chain(1);
    put_proof(&mut engine, blocks[0].hash(), &envelope(&blocks[0]));
    engine
        .store_mut()
        .db_mut()
        .delete(Column::Headers, &blocks[0].hash())
        .unwrap();
    assert_eq!(Backend::contiguous_proven_height(&engine).unwrap(), 1);
}

#[test]
fn proof_envelope_hash_and_height_mismatches_do_not_count_as_a_gap() {
    for mismatch_height in [true, false] {
        let (mut engine, blocks) = chain(1);
        let mut proof = envelope(&blocks[0]);
        if mismatch_height {
            proof.height += 1;
        } else {
            proof.block_hash = [9; 32];
        }
        put_proof(&mut engine, blocks[0].hash(), &proof);
        assert_storage(
            Backend::contiguous_proven_height(&engine),
            "canonical proof cursor is inconsistent",
        );
    }
}

#[test]
fn malformed_stored_receipt_bytes_preserve_codec_failures() {
    let (mut engine, blocks) = chain(1);
    put_proof(&mut engine, blocks[0].hash(), &envelope(&blocks[0]));
    engine
        .store_mut()
        .db_mut()
        .put(Column::BlockProofs, &blocks[0].hash(), &[255])
        .unwrap();
    let result = Backend::contiguous_proven_height(&engine);
    assert!(
        matches!(result, Err(SyncBackendError::Storage(message)) if message.starts_with("codec error: "))
    );
}

#[test]
fn storage_read_failures_preserve_mapping_at_each_cursor_lookup() {
    for column in [
        Column::Meta,
        Column::HeaderByHeight,
        Column::BlockProofs,
        Column::Blocks,
        Column::Headers,
    ] {
        let (mut engine, blocks) = chain(1);
        put_proof(&mut engine, blocks[0].hash(), &envelope(&blocks[0]));
        let key = match column {
            Column::Meta => b"history_retention".to_vec(),
            Column::HeaderByHeight => 1_u64.to_be_bytes().to_vec(),
            _ => blocks[0].hash().to_vec(),
        };
        engine.store_mut().db_mut().fail_get = Some((column, key));
        let error = "database error: injected progress read failure";
        if matches!(column, Column::Blocks | Column::Headers) {
            assert_eq!(Backend::contiguous_proven_height(&engine).unwrap(), 1);
        } else {
            assert_storage(Backend::contiguous_proven_height(&engine), error);
        }
    }
}

#[tokio::test]
async fn missing_transaction_locator_after_pruning_reports_unavailable_history() {
    let (mut engine, _) = chain(4);
    set_floor(&mut engine, 3);
    let backend = Backend::new(engine, MockProofSystem::new());
    assert_eq!(
        backend.execution_transaction([9; 32]).await,
        Err(QueryError::Pruned {
            retained_from_chunk: 1,
            retained_from_height: 3,
        })
    );
}

#[tokio::test]
async fn missing_transaction_locator_before_pruning_is_known_local_absence() {
    let (engine, _) = chain(1);
    let backend = Backend::new(engine, MockProofSystem::new());
    assert_eq!(backend.execution_transaction([9; 32]).await.unwrap(), None);
}

/// Pause exactly one pool revalidation after the canonical engine lock has
/// been released, then reject what it validated. This fixture exercises
/// publication ordering, not execution validity, signature admission or
/// proof acceptance.
struct PausingAdmission {
    armed: Arc<AtomicBool>,
    entered: mpsc::Sender<()>,
    resume: Mutex<mpsc::Receiver<()>>,
}

impl neutrin0_proof_system::ErasedBlockExecutor for PausingAdmission {
    fn execute_block(
        &self,
        _context: &neutrin0_proof_system::BlockExecutionContext,
        _body: &Body,
        _state: &mut neutrin0_trie::Trie,
    ) -> Result<neutrin0_proof_system::ExecutionOutcome, String> {
        Err("publication-order fixture does not execute blocks".into())
    }

    fn query(
        &self,
        _request: &neutrin0_runtime_abi::QueryRequest,
        _runtime: BlockHash,
        _state: &neutrin0_trie::Trie,
    ) -> Result<neutrin0_runtime_abi::QueryResponse, String> {
        Err("publication-order fixture does not answer runtime queries".into())
    }

    fn validate_tx(
        &self,
        _bytes: &[u8],
        _chain_id: u64,
        _gas_limit: u64,
        _runtime: BlockHash,
        _state: &neutrin0_trie::Trie,
    ) -> Result<neutrin0_runtime_abi::TxValidity, String> {
        if self.armed.swap(false, Ordering::AcqRel) {
            self.entered.send(()).unwrap();
            self.resume.lock().unwrap().recv().unwrap();
            return Ok(neutrin0_runtime_abi::TxValidity::invalid(
                neutrin0_runtime_abi::TxValidationCode::NonceMismatch,
            ));
        }
        Ok(neutrin0_runtime_abi::TxValidity::valid(1))
    }

    fn install_runtime(&self, _bytes: &[u8]) -> Result<BlockHash, String> {
        Err("publication-order fixture cannot install runtime artifacts".into())
    }

    fn installed_runtimes(&self) -> Vec<BlockHash> {
        Vec::new()
    }
}

fn select_stored_tip(engine: &mut Engine<FaultDatabase>, tip: BlockHash) {
    let spec = engine.chain_spec().clone();
    engine
        .store_mut()
        .commit_tip(tip, spec.genesis_block_hash, Batch::new())
        .unwrap();
    let db = FaultDatabase {
        inner: engine.store().db().inner.clone(),
        ..FaultDatabase::default()
    };
    *engine = Engine::open(spec, db).unwrap();
}

#[test]
fn pool_revalidation_holds_no_fence_and_never_applies_verdicts_for_an_old_head() {
    let (engine, blocks) = chain(2);
    let backend = Arc::new(Backend::new(engine, MockProofSystem::new()));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let armed = Arc::new(AtomicBool::new(false));
    backend.set_block_executor(PausingAdmission {
        armed: Arc::clone(&armed),
        entered: entered_tx,
        resume: Mutex::new(resume_rx),
    });
    backend.submit_transaction(vec![1]).unwrap();
    armed.store(true, Ordering::Release);
    let first_tip = blocks[0].hash();
    let first_backend = Arc::clone(&backend);
    let first = std::thread::spawn(move || {
        first_backend.with_engine_mut(|engine| select_stored_tip(engine, first_tip));
    });
    entered_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    // The pass validates holding neither the engine nor the publication
    // fence: admission and the next head publication proceed meanwhile.
    assert!(backend.engine.try_lock().is_ok());
    assert!(backend.head_updates.try_lock().is_ok());
    backend.submit_transaction(vec![2]).unwrap();
    backend.with_engine_mut(|engine| {
        let tip = engine.chain_spec().genesis_block_hash;
        select_stored_tip(engine, tip);
    });
    // The paused pass then rejects what it validated against the first tip;
    // the head has moved, so those verdicts are dropped and the pass repeats
    // at the current head.
    resume_tx.send(()).unwrap();
    first.join().unwrap();
    assert_eq!(backend.head_height(), 0);
    assert_eq!(backend.mempool_len(), 2);
    assert!(backend.engine_state_invariant_holds());
}

#[tokio::test]
async fn missing_local_proof_parent_is_unavailable_before_invalidity_can_be_decided() {
    let (mut engine, blocks) = chain(2);
    let parent = &blocks[0].header;
    let publication = ProvenBlock {
        block: blocks[1].clone(),
        proof_bytes: vec![255],
        writes: Vec::new(),
    };
    engine
        .store_mut()
        .db_mut()
        .delete(Column::Headers, &parent.hash())
        .unwrap();
    let backend = Backend::new(engine, MockProofSystem::new());
    assert!(matches!(
        backend
            .verify_and_import_proven_blocks(vec![publication.clone()])
            .await,
        Err(SyncBackendError::ChainBehind(_))
    ));
    // Availability is neutral. Restoring the dependency must still expose
    // this fixture receipt's invalid bytes rather than accepting them.
    backend.with_engine_mut(|engine| engine.store_mut().put_header(parent).unwrap());
    assert!(matches!(
        backend
            .verify_and_import_proven_blocks(vec![publication])
            .await,
        Err(SyncBackendError::Rejected(_))
    ));
}
