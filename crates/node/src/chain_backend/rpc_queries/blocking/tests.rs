use std::sync::{Arc, mpsc};
use std::time::Duration;

use neutrin0_consensus_engine::Engine;
use neutrin0_proof_system::MockProofSystem;
use neutrin0_rpc::RpcBackend;
use neutrin0_storage::MemoryDatabase;
use tokio::sync::{Semaphore, oneshot};

use crate::chain_backend::{ChainBackend, state_sync_tests};

type Backend = ChainBackend<MemoryDatabase, MockProofSystem>;

fn backend() -> Arc<Backend> {
    let engine = Engine::genesis(state_sync_tests::spec(), MemoryDatabase::new()).unwrap();
    let mut backend = ChainBackend::new(engine, MockProofSystem::new());
    backend.query_slots = Arc::new(Semaphore::new(1));
    Arc::new(backend)
}

#[tokio::test]
async fn waiting_for_the_engine_does_not_block_the_rpc_deadline() {
    let backend = backend();
    let engine = Arc::clone(&backend.engine);
    let (started, ready) = oneshot::channel();
    let holder = std::thread::spawn(move || {
        let _engine = engine.lock().unwrap();
        started.send(()).unwrap();
        // Release independently of the async executor so the regression cannot
        // deadlock the test when a reader incorrectly blocks its only worker.
        std::thread::sleep(Duration::from_millis(250));
    });
    ready.await.unwrap();
    let query = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.head().await })
    };
    let mut query = query;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut query)
            .await
            .is_err()
    );
    assert_eq!(query.await.unwrap().unwrap().height, 0);
    holder.join().unwrap();
}

#[tokio::test]
async fn cancelling_a_read_keeps_its_slot_until_the_blocking_work_finishes() {
    let backend = backend();
    let (started, ready) = oneshot::channel();
    let (release, wait) = mpsc::channel();
    let running = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move {
            backend
                .rpc_blocking(move || {
                    started.send(()).unwrap();
                    wait.recv_timeout(Duration::from_secs(2)).unwrap();
                })
                .await;
        })
    };
    ready.await.unwrap();
    running.abort();
    assert!(running.await.unwrap_err().is_cancelled());
    assert_eq!(backend.query_slots.available_permits(), 0);
    let (second_started, second_ready) = oneshot::channel();
    let second = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move {
            backend
                .rpc_blocking(move || second_started.send(()).unwrap())
                .await;
        })
    };
    let mut second_ready = second_ready;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut second_ready)
            .await
            .is_err()
    );
    release.send(()).unwrap();
    second_ready.await.unwrap();
    second.await.unwrap();
    assert_eq!(backend.query_slots.available_permits(), 1);
}
