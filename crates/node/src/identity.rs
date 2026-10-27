//! Persistent libp2p identity, published atomically without replacing a key.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use neutrin0_network::libp2p::identity::Keypair;

use crate::config::NodeConfig;

/// A local identity is small; cap reads even if a configured file grows.
const MAX_KEY_BYTES: u64 = 64 * 1024;

/// Failure to load or safely persist a configured network identity.
#[derive(Debug, thiserror::Error)]
pub enum NetworkIdentityError {
    /// Filesystem operation failed; the original identity is never replaced.
    #[error("network identity `{path}`: {source}")]
    Io {
        /// File or directory involved in the failed operation.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: io::Error,
    },
    /// Existing bytes do not decode as a bounded libp2p private key.
    #[error("network identity `{path}` is not a valid libp2p private key")]
    InvalidKey {
        /// Configured key file.
        path: PathBuf,
    },
    /// The key path names a symlink, directory or other special file.
    #[error("network identity `{path}` must be a regular file, not a symlink or special file")]
    NotRegular {
        /// Configured key file.
        path: PathBuf,
    },
    /// A Unix key file does not have the required private access mode.
    #[error("network identity `{path}` has mode {mode:o}; required mode is 600")]
    Permissions {
        /// Configured key file.
        path: PathBuf,
        /// Observed Unix permission bits.
        mode: u32,
    },
    /// The locally generated key could not be encoded.
    #[error("could not encode the generated libp2p network identity")]
    Encoding,
}

fn io_error(path: &Path, source: io::Error) -> NetworkIdentityError {
    NetworkIdentityError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Load a persistent identity, or atomically create it on the first startup.
///
/// An explicit key path takes precedence over `data_dir/p2p-key`. With neither
/// configured, generate a temporary identity and warn that it changes on restart.
/// A completed staging file is hard-linked into place: competing creators load
/// the winner, and readers never see a partially written destination.
///
/// # Errors
/// Refuses invalid existing keys, unsafe permissions and filesystem failures.
/// An existing key is never overwritten or silently regenerated.
#[allow(
    clippy::redundant_pub_crate,
    reason = "the identity startup API is intentionally restricted to this crate"
)]
pub(crate) fn load_network_identity(config: &NodeConfig) -> Result<Keypair, NetworkIdentityError> {
    let Some(path) = config.network_key_path.clone().or_else(|| {
        config
            .data_dir
            .as_ref()
            .map(|directory| directory.join("p2p-key"))
    }) else {
        tracing::warn!(
            "no network_key_path or data_dir configured; temporary P2P identity changes on restart"
        );
        return Ok(Keypair::generate_ed25519());
    };
    if let Some(key) = read_identity(&path)? {
        return Ok(key);
    }
    create_identity(&path)
}

/// Peer ID of the identity at `path`, creating the identity when the file is
/// absent, so an operator can publish a node's bootnode address before its
/// first start.
///
/// # Errors
/// Refuses invalid existing keys, unsafe permissions and filesystem failures.
pub fn ensure_peer_id(path: &Path) -> Result<String, NetworkIdentityError> {
    let key = match read_identity(path)? {
        Some(key) => key,
        None => create_identity(path)?,
    };
    Ok(key.public().to_peer_id().to_string())
}

/// Peer ID of an existing identity at `path`, or `None` when it is absent.
///
/// # Errors
/// Refuses invalid keys, unsafe permissions and filesystem failures.
pub fn read_peer_id(path: &Path) -> Result<Option<String>, NetworkIdentityError> {
    Ok(read_identity(path)?.map(|key| key.public().to_peer_id().to_string()))
}

fn read_identity(path: &Path) -> Result<Option<Keypair>, NetworkIdentityError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(path, error)),
    };
    if !metadata.is_file() {
        return Err(NetworkIdentityError::NotRegular {
            path: path.to_path_buf(),
        });
    }
    check_permissions(path, &metadata)?;
    let file = File::open(path).map_err(|error| io_error(path, error))?;
    let metadata = file.metadata().map_err(|error| io_error(path, error))?;
    if !metadata.is_file() {
        return Err(NetworkIdentityError::NotRegular {
            path: path.to_path_buf(),
        });
    }
    check_permissions(path, &metadata)?;
    let mut bytes = Vec::new();
    file.take(MAX_KEY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(path, error))?;
    if bytes.len() > usize::try_from(MAX_KEY_BYTES).expect("key bound fits usize") {
        return Err(NetworkIdentityError::InvalidKey {
            path: path.to_path_buf(),
        });
    }
    Keypair::from_protobuf_encoding(&bytes)
        .map(Some)
        .map_err(|_| NetworkIdentityError::InvalidKey {
            path: path.to_path_buf(),
        })
}

#[cfg(unix)]
fn check_permissions(path: &Path, metadata: &fs::Metadata) -> Result<(), NetworkIdentityError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o7777;
    if mode != 0o600 {
        return Err(NetworkIdentityError::Permissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path, _metadata: &fs::Metadata) -> Result<(), NetworkIdentityError> {
    Ok(())
}

/// Close the staging handle before cleaning up, including on failed writes.
struct StagedIdentity {
    path: PathBuf,
    file: Option<File>,
}

impl Drop for StagedIdentity {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Err(error) = fs::remove_file(&self.path) {
            tracing::warn!(path = %self.path.display(), %error, "could not remove identity staging file");
        }
    }
}

fn create_identity(path: &Path) -> Result<Keypair, NetworkIdentityError> {
    let parent = path
        .parent()
        .filter(|directory| !directory.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| io_error(parent, error))?;
    let key = Keypair::generate_ed25519();
    let bytes = key
        .to_protobuf_encoding()
        .map_err(|_| NetworkIdentityError::Encoding)?;
    // A fresh public identity makes concurrent creators' staging paths distinct
    // without exposing private bytes in paths or error messages.
    let temporary = parent.join(format!(
        ".p2p-key-{}-{}.tmp",
        std::process::id(),
        key.public().to_peer_id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&temporary)
        .map_err(|error| io_error(&temporary, error))?;
    let mut staged = StagedIdentity {
        path: temporary,
        file: Some(file),
    };
    let file = staged.file.as_mut().expect("new staging handle is present");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| io_error(&staged.path, error))?;
    }
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error(&staged.path, error))?;
    drop(staged.file.take());
    match fs::hard_link(&staged.path, path) {
        Ok(()) => {
            sync_directory(parent)?;
            Ok(key)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            // Publication never replaces another writer's complete key. If a
            // winner is corrupt or unsafe, propagate that failure unchanged.
            let key = read_identity(path)?.ok_or_else(|| {
                io_error(
                    path,
                    io::Error::new(io::ErrorKind::NotFound, "published identity disappeared"),
                )
            })?;
            // A loser may observe publication before the winner syncs the
            // directory, so it must complete durability before returning too.
            sync_directory(parent)?;
            Ok(key)
        }
        Err(error) => Err(io_error(path, error)),
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), NetworkIdentityError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error(path, error))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), NetworkIdentityError> {
    Ok(())
}

#[cfg(test)]
mod tests;
