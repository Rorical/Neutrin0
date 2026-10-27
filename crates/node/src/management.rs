//! Private, owner-authenticated Unix management service with bounded requests.

use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use neutrin0_proof_system::ProofSystem;
use neutrin0_rpc::management::{
    ManagementRequest, ManagementResponse, SnapshotReport, read_frame, validate_directory,
    validate_peer, write_frame,
};
use neutrin0_storage::Database;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;
use tokio::task::JoinSet;

use crate::ChainBackend;

/// A bound socket whose pathname is removed when its service is stopped.
pub struct ManagementListener {
    listener: UnixListener,
    path: PathBuf,
    owner: u32,
    inode: u64,
    device: u64,
}

impl Drop for ManagementListener {
    fn drop(&mut self) {
        if std::fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| metadata.ino() == self.inode && metadata.dev() == self.device)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Bind a private endpoint without replacing an existing file or socket.
///
/// # Errors
/// Refuses noncanonical paths, unsafe ownership/permissions and existing sockets.
pub fn bind(socket: &Path) -> io::Result<ManagementListener> {
    let parent = socket
        .parent()
        .ok_or_else(|| io::Error::other("missing management directory"))?;
    if !socket.is_absolute() || socket.file_name().is_none() {
        return Err(io::Error::other(
            "management socket must have an absolute file path",
        ));
    }
    match std::fs::symlink_metadata(parent) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(0o700).create(parent)?;
        }
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    let owner = validate_directory(parent)?;
    clear_stale_socket(socket, owner)?;
    let listener = UnixListener::bind(socket)?;
    let metadata = std::fs::symlink_metadata(socket)?;
    let bound = ManagementListener {
        listener,
        path: socket.to_owned(),
        owner,
        inode: metadata.ino(),
        device: metadata.dev(),
    };
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    Ok(bound)
}

/// Remove a socket an unclean exit left at `socket`: one `owner` owns that no
/// process accepts on. Anything else at the path, a live socket included,
/// is kept and refused.
fn clear_stale_socket(socket: &Path, owner: u32) -> io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    let metadata = match std::fs::symlink_metadata(socket) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        metadata => metadata?,
    };
    let stale = metadata.file_type().is_socket()
        && metadata.uid() == owner
        && std::os::unix::net::UnixStream::connect(socket)
            .is_err_and(|error| error.kind() == io::ErrorKind::ConnectionRefused);
    if !stale {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "management socket path already exists",
        ));
    }
    std::fs::remove_file(socket)
}

/// Serve up to sixteen concurrent owner-authenticated connections.
///
/// Each connection accepts exactly one request (at most 4 KiB) with a ten-second
/// read deadline. Mutations finish even if the caller disconnects; shutdown is
/// requested after attempting its response. Dropping the service cancels its
/// owned connection tasks and removes the socket.
///
/// # Errors
/// Returns listener errors. Malformed or disconnected clients cannot stop the service.
pub async fn serve<DB, P>(
    bound: ManagementListener,
    backend: Arc<ChainBackend<DB, P>>,
    shutdown: Arc<Notify>,
) -> io::Result<()>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    let mut clients = JoinSet::new();
    let controls = Arc::new(tokio::sync::Mutex::new(()));
    loop {
        tokio::select! {
            accepted = bound.listener.accept(), if clients.len() < 16 => {
                let (stream, _) = accepted?;
                if validate_peer(&stream, bound.owner).is_err() {
                    continue;
                }
                let backend = Arc::clone(&backend);
                let shutdown = Arc::clone(&shutdown);
                let controls = Arc::clone(&controls);
                clients.spawn(async move { connection(stream, backend, shutdown, controls).await });
            }
            _ = clients.join_next(), if !clients.is_empty() => {}
        }
    }
}

async fn connection<DB, P>(
    mut stream: UnixStream,
    backend: Arc<ChainBackend<DB, P>>,
    shutdown: Arc<Notify>,
    controls: Arc<tokio::sync::Mutex<()>>,
) where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    let Ok(Ok(bytes)) =
        tokio::time::timeout(Duration::from_secs(10), read_frame(&mut stream, 4096)).await
    else {
        return;
    };
    let request = serde_json::from_slice::<ManagementRequest>(&bytes);
    let mut stop = false;
    let response = match request {
        Ok(ManagementRequest::ExportSnapshot {
            path,
            anchor_chunks,
        }) => export_snapshot(&backend, path, anchor_chunks).await,
        Ok(request) => {
            let _control = controls.lock().await;
            let worker = Arc::clone(&backend);
            let control = request.clone();
            match tokio::task::spawn_blocking(move || worker.apply_management(&control)).await {
                Ok(Ok(status)) => {
                    stop = request == ManagementRequest::Shutdown;
                    if request == ManagementRequest::ResumeSigning
                        && let Err(message) = backend.resume_bft_sessions().await
                    {
                        // A partially recovered session must never resume automatically.
                        let worker = Arc::clone(&backend);
                        let _ = tokio::task::spawn_blocking(move || {
                            worker.apply_management(&ManagementRequest::PauseSigning)
                        })
                        .await;
                        return send_error(&mut stream, message).await;
                    }
                    ManagementResponse::Ok { status }
                }
                Ok(Err(message)) => ManagementResponse::Error { message },
                Err(error) => ManagementResponse::Error {
                    message: error.to_string(),
                },
            }
        }
        Err(_) => ManagementResponse::Error {
            message: "invalid management request".into(),
        },
    };
    if let Ok(bytes) = serde_json::to_vec(&response) {
        let _ =
            tokio::time::timeout(Duration::from_secs(2), write_frame(&mut stream, &bytes)).await;
    }
    if stop {
        shutdown.notify_one();
    }
}

/// Export the latest finalized endpoint off the async workers. Only the
/// socket's owner can ask, and the file must be new.
async fn export_snapshot<DB, P>(
    backend: &Arc<ChainBackend<DB, P>>,
    path: String,
    anchor_chunks: Option<u64>,
) -> ManagementResponse
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return ManagementResponse::Error {
            message: "snapshot path must be absolute".into(),
        };
    }
    let worker = Arc::clone(backend);
    match tokio::task::spawn_blocking(move || worker.export_snapshot(&path, anchor_chunks)).await {
        Ok(Ok(summary)) => ManagementResponse::Exported {
            snapshot: SnapshotReport {
                endpoint: neutrin0_rpc::HashHex(summary.endpoint),
                chunks: summary.chunks,
                objects: summary.objects,
                programs_left_out: summary.programs_left_out,
                bytes: summary.bytes,
            },
        },
        Ok(Err(message)) => ManagementResponse::Error { message },
        Err(error) => ManagementResponse::Error {
            message: error.to_string(),
        },
    }
}

async fn send_error(stream: &mut UnixStream, message: String) {
    if let Ok(bytes) = serde_json::to_vec(&ManagementResponse::Error { message }) {
        let _ = tokio::time::timeout(Duration::from_secs(2), write_frame(stream, &bytes)).await;
    }
}
