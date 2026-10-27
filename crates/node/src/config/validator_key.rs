//! Validator key sources (design 19): the remote signer, keystore password
//! and IKM resolution, and doppelganger protection.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::{KEYSTORE_PASSWORD_ENV, NodeConfig, PROPOSER_IKM_ENV};

/// A `neutrin0-signer` holding the validator's key (`[remote_signer]`): on
/// this host through `unix_socket`, or at `address` over mutually
/// authenticated TLS.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteSignerConfig {
    /// Unix socket of a signer on this host.
    #[serde(default)]
    pub unix_socket: Option<PathBuf>,
    /// `host:port` of a signer reached over TLS.
    #[serde(default)]
    pub address: Option<String>,
    /// Name the signer's certificate carries.
    #[serde(default)]
    pub server_name: Option<String>,
    /// Authority that issued the signer's certificate.
    #[serde(default)]
    pub ca_path: Option<PathBuf>,
    /// This node's client certificate.
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    /// This node's client key.
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    /// Key to sign with; required when the signer holds several.
    #[serde(default)]
    pub public_key_hex: Option<String>,
    /// The validator's next key, which the signer must hold too: a key
    /// rotation seats it in place of `public_key_hex` (design 19).
    #[serde(default)]
    pub next_public_key_hex: Option<String>,
}

impl RemoteSignerConfig {
    /// Where the signer listens.
    ///
    /// # Errors
    /// Refuses both or neither of `unix_socket` and `address`, TLS without
    /// all of its names and files, and invalid PEM files.
    pub fn endpoint(&self) -> Result<neutrin0_signer::Endpoint, String> {
        match (&self.unix_socket, &self.address) {
            #[cfg(unix)]
            (Some(path), None) => Ok(neutrin0_signer::Endpoint::Unix(path.clone())),
            (None, Some(address)) => {
                let (Some(server_name), Some(ca), Some(cert), Some(key)) = (
                    &self.server_name,
                    &self.ca_path,
                    &self.cert_path,
                    &self.key_path,
                ) else {
                    return Err(
                        "remote_signer.address needs server_name, ca_path, cert_path and key_path"
                            .into(),
                    );
                };
                neutrin0_signer::Endpoint::tls(address.clone(), server_name, ca, cert, key)
            }
            _ => Err("remote_signer needs exactly one of unix_socket and address".into()),
        }
    }
}

/// Doppelganger protection (`[doppelganger]`).
///
/// A validator signs nothing for `quiet_chunks` chunks of slots after it
/// starts, so another process signing with its key shows itself first; at
/// every time a message by its key that its journal did not reserve pauses
/// signing and production.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct DoppelgangerConfig {
    /// Chunks of slots without signing after startup; 0 starts at once.
    pub quiet_chunks: u64,
}

impl Default for DoppelgangerConfig {
    fn default() -> Self {
        Self { quiet_chunks: 2 }
    }
}

/// Where the validator IKM was read from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposerIkmSource {
    /// [`PROPOSER_IKM_ENV`].
    Environment,
    /// `proposer_ikm_path`.
    File,
    /// `proposer_ikm_hex` inline in the config file.
    Inline,
}

/// Failure to obtain the validator IKM from the configured sources.
#[derive(Debug, thiserror::Error)]
pub enum ProposerIkmError {
    /// The key file could not be read.
    #[error("failed to read proposer_ikm_path `{path}`: {source}")]
    Read {
        /// Configured path.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The key file is readable by group or others.
    #[error("proposer_ikm_path `{path}` has mode {mode:o}; it must not be group or world readable")]
    Permissions {
        /// Configured path.
        path: String,
        /// Observed permission bits.
        mode: u32,
    },
    /// The environment variable is set but not valid UTF-8.
    #[error("{PROPOSER_IKM_ENV} is not valid UTF-8")]
    Environment,
    /// More than one of the environment, the key file and the inline hex
    /// names an IKM.
    #[error(
        "configure one validator IKM: {PROPOSER_IKM_ENV}, proposer_ikm_path or proposer_ikm_hex"
    )]
    MultipleSources,
}

impl NodeConfig {
    /// Resolve the validator IKM hex from the one source that names it: the
    /// environment, the key file or the inline hex.
    ///
    /// Returns `Ok(None)` when no source is configured.
    ///
    /// # Errors
    /// Returns [`ProposerIkmError`] when more than one source is set, a
    /// configured source is unreadable or the key file is too permissive.
    pub fn resolve_proposer_ikm_hex(
        &self,
    ) -> Result<Option<(String, ProposerIkmSource)>, ProposerIkmError> {
        let environment = match std::env::var(PROPOSER_IKM_ENV) {
            Ok(value) if !value.trim().is_empty() => Some(value.trim().to_owned()),
            Err(std::env::VarError::NotUnicode(_)) => return Err(ProposerIkmError::Environment),
            _ => None,
        };
        // A stale variable or a leftover inline key must not silently
        // replace the configured identity.
        let sources = usize::from(environment.is_some())
            + usize::from(self.proposer_ikm_path.is_some())
            + usize::from(self.proposer_ikm_hex.is_some());
        if sources > 1 {
            return Err(ProposerIkmError::MultipleSources);
        }
        if let Some(value) = environment {
            return Ok(Some((value, ProposerIkmSource::Environment)));
        }
        if let Some(path) = &self.proposer_ikm_path {
            let hex = read_secret_file(path)?;
            return Ok(Some((hex, ProposerIkmSource::File)));
        }
        Ok(self
            .proposer_ikm_hex
            .as_ref()
            .map(|hex| (hex.trim().to_owned(), ProposerIkmSource::Inline)))
    }

    /// The keystore password: [`KEYSTORE_PASSWORD_ENV`], then
    /// `proposer_keystore_password_path`.
    ///
    /// # Errors
    /// Refuses neither being set and a password file other users could read.
    pub fn resolve_keystore_password(&self) -> Result<zeroize::Zeroizing<String>, String> {
        if let Ok(password) = std::env::var(KEYSTORE_PASSWORD_ENV) {
            return Ok(zeroize::Zeroizing::new(password));
        }
        let path = self
            .proposer_keystore_password_path
            .as_ref()
            .ok_or_else(|| {
                format!("set proposer_keystore_password_path or {KEYSTORE_PASSWORD_ENV}")
            })?;
        neutrin0_keystore::read_password_file(path)
    }
}

/// Read a single-line hex secret from a bounded regular file that other users
/// cannot read; a symlink could redirect the node to another user's file.
fn read_secret_file(path: &Path) -> Result<String, ProposerIkmError> {
    use std::io::Read as _;
    let display = path.display().to_string();
    let read_error = |source| ProposerIkmError::Read {
        path: display.clone(),
        source,
    };
    let metadata = std::fs::symlink_metadata(path).map_err(read_error)?;
    if !metadata.is_file() {
        return Err(read_error(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file (symlinks are refused)",
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(ProposerIkmError::Permissions {
                path: display.clone(),
                mode,
            });
        }
    }
    let mut raw = String::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(4097).read_to_string(&mut raw))
        .map_err(read_error)?;
    if raw.len() > 4096 {
        return Err(read_error(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "key file exceeds 4096 bytes",
        )));
    }
    Ok(raw.trim().to_owned())
}
