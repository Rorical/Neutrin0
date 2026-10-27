//! Durable raw evidence insertion and finalized reporter cleanup races.

use super::{ChainBackend, SLASHING_POOL_MAX_ENTRIES, state_sync_tests};
use neutrin0_consensus_engine::{Engine, ProposerKey, RetentionPolicy};
use neutrin0_consensus_types::{
    FinalityVoteData, FinalityVotePhase, IndexedVote, SlashingEvidence,
};
use neutrin0_proof_system::MockProofSystem;
use neutrin0_storage::{Batch, BatchOp, Column, ColumnSnapshot, Database, MemoryDatabase};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::Duration;

type Pause = (mpsc::Sender<()>, mpsc::Receiver<()>);
const PAUSE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Default)]
struct Hooks {
    fail_insert: AtomicBool,
    insert: Mutex<Option<Pause>>,
    delete: Mutex<Option<Pause>>,
}

struct FaultDatabase {
    inner: MemoryDatabase,
    hooks: Arc<Hooks>,
}

impl Database for FaultDatabase {
    type Error = &'static str;
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
        if column == Column::SlashingPool {
            pause_once(&self.hooks.delete);
        }
        self.inner.delete(column, key).unwrap();
        Ok(())
    }

    fn write_batch(&mut self, batch: Batch) -> Result<(), Self::Error> {
        pause_batch_deletions(&batch, &self.hooks.delete);
        self.inner.write_batch(batch).unwrap();
        Ok(())
    }

    fn write_batch_durable(&mut self, batch: Batch) -> Result<(), Self::Error> {
        if batch.operations().iter().any(|operation| {
            matches!(
                operation,
                BatchOp::Put {
                    column: Column::SlashingPool,
                    ..
                }
            )
        }) {
            pause_once(&self.hooks.insert);
            if self.hooks.fail_insert.load(Ordering::Acquire) {
                return Err("injected durable raw insertion failure");
            }
        }
        pause_batch_deletions(&batch, &self.hooks.delete);
        self.inner.write_batch_durable(batch).unwrap();
        Ok(())
    }

    fn iter_column(&self, column: Column) -> Result<ColumnSnapshot, Self::Error> {
        Ok(self.inner.iter_column(column).unwrap())
    }
}

fn pause_batch_deletions(batch: &Batch, hook: &Mutex<Option<Pause>>) {
    if batch.operations().iter().any(|operation| {
        matches!(
            operation,
            BatchOp::Delete {
                column: Column::SlashingPool,
                ..
            }
        )
    }) {
        pause_once(hook);
    }
}

fn pause_once(hook: &Mutex<Option<Pause>>) {
    let pause = hook.lock().unwrap().take();
    if let Some((entered, resume)) = pause {
        entered.send(()).unwrap();
        resume
            .recv_timeout(PAUSE_TIMEOUT)
            .expect("paused database operation must be resumed");
    }
}

fn arm_pause(hook: &Mutex<Option<Pause>>) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    *hook.lock().unwrap() = Some((entered_tx, resume_rx));
    (entered_rx, resume_tx)
}

fn backend(hooks: Arc<Hooks>) -> ChainBackend<FaultDatabase, MockProofSystem> {
    let mut engine = Engine::genesis(
        state_sync_tests::spec(),
        FaultDatabase {
            inner: MemoryDatabase::new(),
            hooks,
        },
    )
    .unwrap();
    engine
        .set_retention_policy(RetentionPolicy::Reporter)
        .unwrap();
    ChainBackend::new(engine, MockProofSystem)
}

fn offence() -> SlashingEvidence {
    let signer = ProposerKey::from_ikm(&[6; 32], 0).unwrap();
    let domain = state_sync_tests::spec().consensus_domain();
    let vote = |tag| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 2,
            phase: FinalityVotePhase::Prevote,
            chunk_hash: [tag; 32],
            selection: [0; 32],
        };
        IndexedVote {
            signature: signer.sign_finality_vote(domain, &data),
            data,
        }
    };
    SlashingEvidence::DoublePrevote {
        validator_index: 0,
        vote_a: vote(1),
        vote_b: vote(2),
    }
}

#[test]
fn ordinary_and_durable_batch_deletions_trigger_the_pause_hook() {
    for durable in [false, true] {
        let hooks = Arc::new(Hooks::default());
        let mut database = FaultDatabase {
            inner: MemoryDatabase::new(),
            hooks: Arc::clone(&hooks),
        };
        database.put(Column::SlashingPool, &[1; 32], &[2]).unwrap();
        let (entered, resume) = arm_pause(&hooks.delete);
        let deletion = std::thread::spawn(move || {
            let mut batch = Batch::new();
            batch.delete(Column::SlashingPool, [1; 32]);
            if durable {
                database.write_batch_durable(batch).unwrap();
            } else {
                database.write_batch(batch).unwrap();
            }
            database
        });
        entered
            .recv_timeout(PAUSE_TIMEOUT)
            .expect("batch deletion must trigger the database pause hook");
        resume.send(()).unwrap();
        let database = deletion.join().unwrap();
        assert_eq!(database.get(Column::SlashingPool, &[1; 32]).unwrap(), None);
    }
}

#[test]
fn failed_durable_insert_does_not_poison_deduplication() {
    let hooks = Arc::new(Hooks::default());
    let backend = backend(Arc::clone(&hooks));
    let evidence = offence();
    hooks.fail_insert.store(true, Ordering::Release);
    assert!(!backend.insert_persistent(&evidence));
    assert_eq!(backend.slashing_pool_len(), 0);
    assert_eq!(
        backend.with_engine(|engine| engine.store().iter_slashing_evidence().unwrap()),
        [] as [(neutrin0_primitives::Hash, SlashingEvidence); 0]
    );
    hooks.fail_insert.store(false, Ordering::Release);
    assert!(backend.insert_persistent(&evidence));
    assert!(!backend.insert_persistent(&evidence));
    assert_eq!(backend.slashing_pool_len(), 1);
    assert_eq!(
        backend
            .with_engine(|engine| engine.store().iter_slashing_evidence().unwrap())
            .len(),
        1
    );
}

#[test]
fn finalized_cleanup_cannot_be_undone_by_a_stale_computed_offence() {
    let hooks = Arc::new(Hooks::default());
    let backend = Arc::new(backend(Arc::clone(&hooks)));
    let evidence = offence();
    let (entered, resume) = arm_pause(&hooks.insert);
    let inserting = Arc::clone(&backend);
    let input = evidence.clone();
    let insert = std::thread::spawn(move || inserting.insert_persistent(&input));
    entered
        .recv_timeout(PAUSE_TIMEOUT)
        .expect("durable insertion must trigger the database pause hook");
    // No cleanup can see an insertion before its durable outcome is known.
    assert!(backend.slashing_pool.try_lock().is_err());
    let cleaning = Arc::clone(&backend);
    let cleanup = std::thread::spawn(move || {
        cleaning.with_raw_pool(|pool, engine| {
            let removed = engine.set_reporter_eligible(&[]).unwrap();
            pool.forget(&removed);
        });
    });
    resume.send(()).unwrap();
    assert!(insert.join().unwrap());
    cleanup.join().unwrap();
    assert_eq!(backend.slashing_pool_len(), 0);
    assert!(!backend.insert_persistent(&evidence));
    assert_eq!(
        backend.with_engine(|engine| engine.store().iter_slashing_evidence().unwrap()),
        [] as [(neutrin0_primitives::Hash, SlashingEvidence); 0]
    );
}

#[test]
fn drain_keeps_pool_locked_until_the_old_disk_row_is_deleted() {
    let hooks = Arc::new(Hooks::default());
    let backend = Arc::new(backend(Arc::clone(&hooks)));
    let evidence = offence();
    assert!(backend.insert_persistent(&evidence));
    let (entered, resume) = arm_pause(&hooks.delete);
    let draining = Arc::clone(&backend);
    let drain = std::thread::spawn(move || draining.drain_slashing_pool(1));
    entered
        .recv_timeout(PAUSE_TIMEOUT)
        .expect("raw pool drain must trigger the database deletion pause hook");
    assert!(backend.slashing_pool.try_lock().is_err());
    resume.send(()).unwrap();
    assert_eq!(drain.join().unwrap(), vec![evidence.clone()]);
    assert!(backend.insert_persistent(&evidence));
    assert_eq!(backend.slashing_pool_len(), 1);
    assert_eq!(
        backend
            .with_engine(|engine| engine.store().iter_slashing_evidence().unwrap())
            .len(),
        1
    );
}

/// Delete raw rows the way finalized retention does: one engine-side observed
/// batch that never passes through the node's pool.
fn delete_raw_rows_outside_the_pool<DB, P>(backend: &ChainBackend<DB, P>, keys: &[[u8; 32]])
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: neutrin0_proof_system::ProofSystem + Send + Sync + 'static,
{
    backend.with_engine_mut(|engine| {
        let mut batch = Batch::new();
        for key in keys {
            batch.delete(Column::SlashingPool, *key);
        }
        engine
            .store_mut()
            .write_observed_batch(batch, false)
            .unwrap();
    });
}

fn raw_key(evidence: &SlashingEvidence) -> [u8; 32] {
    neutrin0_primitives::blake3_256(&borsh::to_vec(evidence).unwrap())
}

#[test]
fn relays_never_pool_reports_against_a_tombstoned_identity() {
    // Non-reporters relay reports they can attribute, but once retention has
    // released a report whose offender consensus already ejected forever, the
    // same report must not be pooled and gossiped again.
    let relay = |tombstoned: bool| {
        let mut engine = Engine::genesis(
            state_sync_tests::spec(),
            FaultDatabase {
                inner: MemoryDatabase::new(),
                hooks: Arc::new(Hooks::default()),
            },
        )
        .unwrap();
        if tombstoned {
            let accused = engine.active_validator_set()[0].pubkey;
            engine
                .store_mut()
                .db_mut()
                .put(Column::FinalizedSlashes, &accused, &[1])
                .unwrap();
        }
        ChainBackend::new(engine, MockProofSystem)
    };
    assert!(relay(false).insert_persistent(&offence()));
    assert!(!relay(true).insert_persistent(&offence()));
}

#[test]
fn engine_side_raw_deletion_releases_pool_membership() {
    let backend = backend(Arc::new(Hooks::default()));
    let evidence = offence();
    assert!(backend.insert_persistent(&evidence));
    assert_eq!(backend.slashing_pool_len(), 1);
    delete_raw_rows_outside_the_pool(&backend, &[raw_key(&evidence)]);
    assert_eq!(backend.slashing_pool_len(), 0);
    // A stale key no longer deduplicates the released report.
    assert!(backend.insert_persistent(&evidence));
    assert_eq!(backend.slashing_pool_len(), 1);
}

/// Distinct raw reports; insertion pools them without verifying signatures.
/// They accuse an index no committee seats, so no per-identity cap applies.
fn numbered_offence(number: u16) -> SlashingEvidence {
    let SlashingEvidence::DoublePrevote { vote_a, vote_b, .. } = accusing(0, number) else {
        unreachable!("accusing builds a double prevote");
    };
    SlashingEvidence::DoublePrevote {
        validator_index: u32::MAX,
        vote_a,
        vote_b,
    }
}

/// A distinct raw report against the validator at `validator_index`.
fn accusing(validator_index: u32, number: u16) -> SlashingEvidence {
    let vote = |chunk_hash| IndexedVote {
        signature: [0; 96],
        data: FinalityVoteData {
            chunk_id: 0,
            round: 0,
            phase: FinalityVotePhase::Prevote,
            chunk_hash,
            selection: [0; 32],
        },
    };
    let mut conflicting = [0; 32];
    conflicting[..2].copy_from_slice(&number.to_be_bytes());
    SlashingEvidence::DoublePrevote {
        validator_index,
        vote_a: vote([0xFF; 32]),
        vote_b: vote(conflicting),
    }
}

#[test]
fn one_identity_cannot_hold_more_than_its_share_of_the_pool() {
    let backend = ChainBackend::new(
        Engine::genesis(state_sync_tests::spec(), MemoryDatabase::new()).unwrap(),
        MockProofSystem,
    );
    let share = u16::try_from(super::raw_pool::MAX_REPORTS_PER_IDENTITY).unwrap();
    for number in 0..share {
        assert!(backend.insert_persistent(&accusing(0, number)));
    }
    assert!(!backend.insert_persistent(&accusing(0, share)));
    assert_eq!(backend.slashing_pool_len(), usize::from(share));
    // Draining frees the identity's share again.
    backend.drain_slashing_pool(1);
    assert!(backend.insert_persistent(&accusing(0, share)));
}

#[test]
fn engine_side_raw_deletion_does_not_cause_a_premature_cap_eviction() {
    let backend = ChainBackend::new(
        Engine::genesis(state_sync_tests::spec(), MemoryDatabase::new()).unwrap(),
        MockProofSystem,
    );
    let full = u16::try_from(SLASHING_POOL_MAX_ENTRIES).unwrap();
    for number in 0..full {
        assert!(backend.insert_persistent(&numbered_offence(number)));
    }
    // Retention releases one report, which leaves room for another.
    delete_raw_rows_outside_the_pool(&backend, &[raw_key(&numbered_offence(1))]);
    assert!(backend.insert_persistent(&numbered_offence(full)));
    let rows = backend.with_engine(|engine| {
        engine
            .store()
            .db()
            .iter_column(Column::SlashingPool)
            .unwrap()
    });
    assert_eq!(rows.len(), SLASHING_POOL_MAX_ENTRIES);
    let oldest = raw_key(&numbered_offence(0));
    assert!(rows.iter().any(|(key, _)| key.as_slice() == oldest));
    assert_eq!(
        backend
            .metrics
            .reporter
            .pool_evictions
            .load(Ordering::Relaxed),
        0
    );
    assert_eq!(backend.slashing_pool_len(), SLASHING_POOL_MAX_ENTRIES);
}
