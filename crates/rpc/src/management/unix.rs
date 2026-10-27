//! Bounded framing and owner-authenticated Unix socket client.

use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::{ManagementRequest, ManagementResponse};

/// Validate an absolute, canonical, private socket directory owned by this user.
///
/// # Errors
/// Refuses symlink components, foreign ownership and modes other than `0700`.
pub fn validate_directory(path: &Path) -> io::Result<u32> {
    if !path.is_absolute() || std::fs::canonicalize(path)? != path {
        return Err(io::Error::other(
            "management directory must be absolute and canonical",
        ));
    }
    let metadata = std::fs::symlink_metadata(path)?;
    // macOS needs the peer endpoint alive while reading its credentials.
    let (local, _peer) = UnixStream::pair()?;
    if !metadata.is_dir()
        || metadata.mode() & 0o7777 != 0o700
        || metadata.uid() != local.peer_cred()?.uid()
    {
        return Err(io::Error::other(
            "management directory must be owned by this user with mode 0700",
        ));
    }
    Ok(metadata.uid())
}

/// Require the connected process to have the expected socket owner's Unix UID.
///
/// # Errors
/// Refuses peers with a different UID or unavailable credentials.
pub fn validate_peer(stream: &UnixStream, owner: u32) -> io::Result<()> {
    if stream.peer_cred()?.uid() != owner {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "management peer has a different owner",
        ));
    }
    Ok(())
}

/// Read one length-prefixed frame, checking the limit before allocation.
///
/// # Errors
/// Returns I/O errors and refuses empty or oversized frames.
pub async fn read_frame(stream: &mut UnixStream, limit: u32) -> io::Result<Vec<u8>> {
    let size = stream.read_u32().await?;
    if size == 0 || size > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid management frame length",
        ));
    }
    let mut bytes = vec![0; usize::try_from(size).expect("u32 fits usize")];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

/// Write one length-prefixed frame.
///
/// # Errors
/// Returns I/O errors or rejects payloads that exceed the length field.
pub async fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> io::Result<()> {
    let size =
        u32::try_from(bytes.len()).map_err(|_| io::Error::other("management frame too large"))?;
    stream.write_u32(size).await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}

/// Execute one management request on a private local socket with a total timeout.
///
/// # Errors
/// Refuses unsafe socket paths, foreign peers, malformed replies and timeouts.
/// A timeout after sending a mutation has an unknown outcome: query status before
/// retrying. The client never automatically retries a mutation.
pub async fn management_call(
    socket: &Path,
    request: ManagementRequest,
    timeout: Duration,
) -> io::Result<ManagementResponse> {
    tokio::time::timeout(timeout, async {
        let parent = socket
            .parent()
            .ok_or_else(|| io::Error::other("missing socket directory"))?;
        let owner = validate_directory(parent)?;
        let metadata = std::fs::symlink_metadata(socket)?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != owner
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(io::Error::other(
                "management socket must be owned by this user with mode 0600",
            ));
        }
        let mut stream = UnixStream::connect(socket).await?;
        validate_peer(&stream, owner)?;
        let bytes = serde_json::to_vec(&request).map_err(io::Error::other)?;
        write_frame(&mut stream, &bytes).await?;
        let response = read_frame(&mut stream, 65_536).await?;
        serde_json::from_slice(&response).map_err(io::Error::other)
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "management request timed out; query status before retrying a mutation",
        )
    })?
}
