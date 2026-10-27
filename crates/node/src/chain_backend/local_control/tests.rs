//! Exercise the real management transport and its engine serialization barrier.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_proof_system::MockProofSystem;
use neutrin0_rpc::management::{
    ManagementRequest, ManagementResponse, management_call, read_frame, validate_peer, write_frame,
};
use neutrin0_storage::MemoryDatabase;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

use super::super::state_sync_tests;
use crate::ChainBackend;

type Backend = ChainBackend<MemoryDatabase, MockProofSystem>;

fn backend() -> Arc<Backend> {
    let backend = ChainBackend::new(
        Engine::genesis(state_sync_tests::spec(), MemoryDatabase::new()).unwrap(),
        MockProofSystem,
    );
    backend.set_local_voter(ProposerKey::from_ikm(&[6; 32], 0).unwrap());
    Arc::new(backend)
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let path = root.join(format!(
            "neutrin0-management-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn socket(&self) -> PathBuf {
        self.0.join("node.sock")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn status(
    socket: &std::path::Path,
    request: ManagementRequest,
) -> neutrin0_rpc::management::ManagementStatus {
    match management_call(socket, request, Duration::from_secs(5))
        .await
        .unwrap()
    {
        ManagementResponse::Ok { status } => status,
        ManagementResponse::Exported { .. } => panic!("a control reported an export"),
        ManagementResponse::Error { message } => panic!("{message}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_socket_left_by_an_unclean_exit_is_replaced() {
    let directory = Directory::new();
    let socket = directory.socket();
    // A std listener leaves its path behind when dropped, as a killed node does.
    drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
    let bound = crate::management::bind(&socket).unwrap();
    assert!(crate::management::bind(&socket).is_err());
    drop(bound);
    std::fs::write(&socket, b"not a socket").unwrap();
    assert!(crate::management::bind(&socket).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socket_controls_are_independent_persistent_and_shutdown_is_acknowledged() {
    let directory = Directory::new();
    let socket = directory.socket();
    let bound = crate::management::bind(&socket).unwrap();
    assert_eq!(std::fs::metadata(&socket).unwrap().mode() & 0o7777, 0o600);
    assert!(crate::management::bind(&socket).is_err());
    let backend = backend();
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let task = tokio::spawn(crate::management::serve(
        bound,
        Arc::clone(&backend),
        Arc::clone(&shutdown),
    ));
    assert!(
        status(&socket, ManagementRequest::Status)
            .await
            .validator_active
    );
    assert!(
        status(&socket, ManagementRequest::PauseSigning)
            .await
            .signing_paused
    );
    let reply = status(&socket, ManagementRequest::ResumeProduction).await;
    assert!(reply.signing_paused);
    assert!(!reply.production_paused);
    let reply = status(&socket, ManagementRequest::PauseProduction).await;
    assert!(reply.production_paused);
    let reply = status(&socket, ManagementRequest::ResumeSigning).await;
    assert!(!reply.signing_paused);
    assert!(reply.production_paused);
    let db = backend.with_engine_mut_for_test(|engine| engine.store().db().clone());
    let restored = Engine::open(state_sync_tests::spec(), db).unwrap();
    assert!(restored.local_signing_policy().production_paused);
    assert!(status(&socket, ManagementRequest::Shutdown).await.stopping);
    tokio::time::timeout(Duration::from_secs(1), shutdown.notified())
        .await
        .unwrap();
    assert!(matches!(
        management_call(
            &socket,
            ManagementRequest::ResumeSigning,
            Duration::from_secs(1)
        )
        .await
        .unwrap(),
        ManagementResponse::Error { .. }
    ));
    task.abort();
    let _ = task.await;
    assert!(!socket.exists());
}

#[tokio::test]
async fn unsafe_paths_foreign_credentials_and_invalid_frames_are_refused() {
    let directory = Directory::new();
    let socket = directory.socket();
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(crate::management::bind(&socket).is_err());
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(&socket, b"do not replace").unwrap();
    assert!(crate::management::bind(&socket).is_err());
    assert_eq!(std::fs::read(&socket).unwrap(), b"do not replace");
    std::fs::remove_file(&socket).unwrap();
    let target = directory.0.join("target");
    std::os::unix::fs::symlink(&target, &socket).unwrap();
    assert!(crate::management::bind(&socket).is_err());
    std::fs::remove_file(&socket).unwrap();
    let bound = crate::management::bind(&socket).unwrap();
    let task = tokio::spawn(crate::management::serve(
        bound,
        backend(),
        Arc::new(tokio::sync::Notify::new()),
    ));
    let mut stream = UnixStream::connect(&socket).await.unwrap();
    let wrong_uid = stream.peer_cred().unwrap().uid().wrapping_add(1);
    assert!(validate_peer(&stream, wrong_uid).is_err());
    stream.write_u32(4097).await.unwrap();
    assert!(read_frame(&mut stream, 65_536).await.is_err());
    let mut stream = UnixStream::connect(&socket).await.unwrap();
    write_frame(&mut stream, b"{\"operation\":\"export_private_key\"}")
        .await
        .unwrap();
    let reply = read_frame(&mut stream, 65_536).await.unwrap();
    assert!(matches!(
        serde_json::from_slice::<ManagementResponse>(&reply).unwrap(),
        ManagementResponse::Error { .. }
    ));
    assert!(
        !status(&socket, ManagementRequest::Status)
            .await
            .signing_paused
    );
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(
        management_call(
            &socket,
            ManagementRequest::PauseSigning,
            Duration::from_secs(1)
        )
        .await
        .is_err()
    );
    task.abort();
    let _ = task.await;
}

#[test]
fn pause_acknowledgment_waits_for_the_engine_mutex() {
    let backend = backend();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let holder = Arc::clone(&backend);
    let hold = std::thread::spawn(move || {
        holder.with_engine_mut_for_test(|_engine| {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
    });
    entered_rx.recv().unwrap();
    let (ack_tx, ack_rx) = mpsc::channel();
    let controller = Arc::clone(&backend);
    let control = std::thread::spawn(move || {
        ack_tx
            .send(controller.apply_management(&ManagementRequest::PauseSigning))
            .unwrap();
    });
    assert!(matches!(
        ack_rx.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    release_tx.send(()).unwrap();
    assert!(
        ack_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .unwrap()
            .signing_paused
    );
    hold.join().unwrap();
    control.join().unwrap();
}

#[test]
fn persisted_pause_is_loaded_after_closing_and_reopening_rocksdb() {
    let directory = Directory::new();
    let path = directory.0.join("db");
    let mut engine = Engine::genesis(
        state_sync_tests::spec(),
        crate::NodeDb::open_rocks(&path).unwrap(),
    )
    .unwrap();
    engine
        .set_local_signing_policy(neutrin0_consensus_engine::LocalSigningPolicy {
            signing_paused: true,
            production_paused: true,
        })
        .unwrap();
    drop(engine);
    let engine = Engine::open(
        state_sync_tests::spec(),
        crate::NodeDb::open_rocks(&path).unwrap(),
    )
    .unwrap();
    assert!(engine.local_signing_policy().signing_paused);
    assert!(engine.local_signing_policy().production_paused);
    assert!(!engine.local_production_enabled());
}
