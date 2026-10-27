//! `neutrin0-signer` binary.
//!
//! Usage:
//! ```text
//! neutrin0-signer --config /path/to/signer.toml
//! ```
//!
//! ```toml
//! chain_id = 1
//! chain_spec_hash_hex = "<the chain specification's hash>"
//! data_dir = "/var/lib/neutrin0-signer"
//! keystores = ["/etc/neutrin0/v0.keystore.json"]
//! password_path = "/etc/neutrin0/keystore.password"  # or NEUTRIN0_KEYSTORE_PASSWORD
//! unix_socket = "/run/neutrin0/signer.sock"
//!
//! [tcp]  # optional, mutually authenticated TLS
//! listen = "0.0.0.0:9700"
//! cert_path = "/etc/neutrin0/signer.crt"
//! key_path = "/etc/neutrin0/signer.key"
//! client_ca_path = "/etc/neutrin0/nodes-ca.crt"
//!
//! [[tcp.clients]]  # each node certificate and the keys it may use
//! certificate_sha256 = "<SHA-256 of the certificate's DER, hex or colon-separated>"
//! public_keys_hex = ["<48-byte BLS public key>"]
//! ```
//!
//! The Unix socket's directory must be accessible to this user only.

#![deny(unsafe_code)]

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use neutrin0_keystore::Keystore;
use neutrin0_primitives::{ConsensusDomain, PriorDomains};
use neutrin0_signer::Signer;
use serde::Deserialize;
use zeroize::Zeroizing;

/// Environment variable holding the keystores' password.
const PASSWORD_ENV: &str = "NEUTRIN0_KEYSTORE_PASSWORD";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    chain_id: u64,
    chain_spec_hash_hex: String,
    data_dir: PathBuf,
    keystores: Vec<PathBuf>,
    password_path: Option<PathBuf>,
    unix_socket: Option<PathBuf>,
    tcp: Option<Tcp>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tcp {
    listen: SocketAddr,
    cert_path: PathBuf,
    key_path: PathBuf,
    client_ca_path: PathBuf,
    clients: Vec<TlsClient>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsClient {
    certificate_sha256: String,
    public_keys_hex: Vec<String>,
}

/// The keys each listed client certificate may use.
fn tls_clients(clients: &[TlsClient]) -> Result<neutrin0_signer::TlsClients, String> {
    let mut listed = neutrin0_signer::TlsClients::new();
    for client in clients {
        let mut fingerprint = [0; 32];
        hex::decode_to_slice(client.certificate_sha256.replace(':', ""), &mut fingerprint)
            .map_err(|_| "certificate_sha256 must be 32 bytes of hex".to_owned())?;
        let keys = client
            .public_keys_hex
            .iter()
            .map(|key| {
                let mut bytes = [0; 48];
                hex::decode_to_slice(key.trim_start_matches("0x"), &mut bytes)
                    .map(|()| bytes)
                    .map_err(|_| format!("public key {key} must be 48 bytes of hex"))
            })
            .collect::<Result<_, _>>()?;
        if listed.insert(fingerprint, keys).is_some() {
            return Err(format!(
                "client certificate {} is listed twice",
                client.certificate_sha256
            ));
        }
    }
    Ok(listed)
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "neutrin0-signer failed");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let (Some("--config"), Some(path), None) = (args.next().as_deref(), args.next(), args.next())
    else {
        return Err("usage: neutrin0-signer --config <signer.toml>".into());
    };
    let text = std::fs::read_to_string(&path).map_err(|error| format!("{path}: {error}"))?;
    let config: Config = toml::from_str(&text).map_err(|error| format!("{path}: {error}"))?;
    let mut chain_spec_hash = [0; 32];
    hex::decode_to_slice(
        config.chain_spec_hash_hex.trim_start_matches("0x"),
        &mut chain_spec_hash,
    )
    .map_err(|_| "chain_spec_hash_hex must be 32 bytes of hex".to_owned())?;
    // A signer signs only chunks of its own specification, which verify
    // under exactly this domain.
    let domain = ConsensusDomain {
        chain_id: config.chain_id,
        chain_spec_hash,
        prior: PriorDomains::NONE,
    };
    let password = match &config.password_path {
        Some(path) => neutrin0_keystore::read_password_file(path)?,
        None => Zeroizing::new(
            std::env::var(PASSWORD_ENV)
                .map_err(|_| format!("set password_path or {PASSWORD_ENV}"))?,
        ),
    };
    let mut keys = Vec::new();
    for keystore in &config.keystores {
        let key = Keystore::from_file(keystore)?
            .decrypt(&password)
            .map_err(|error| format!("{}: {error}", keystore.display()))?;
        tracing::info!(
            key = %hex::encode(key.public_key().to_bytes()),
            keystore = %keystore.display(),
            "key loaded"
        );
        keys.push(key);
    }
    if keys.is_empty() {
        return Err("no keystores configured".into());
    }
    let db = neutrin0_storage::RocksDbDatabase::open(&config.data_dir)
        .map_err(|error| format!("{}: {error}", config.data_dir.display()))?;
    let signer = Arc::new(Signer::new(domain, keys, db));

    let tcp = match &config.tcp {
        Some(tcp) => {
            let tls = neutrin0_signer::tls::server_config(
                &tcp.cert_path,
                &tcp.key_path,
                &tcp.client_ca_path,
            )?;
            let clients = Arc::new(tls_clients(&tcp.clients)?);
            let listener = TcpListener::bind(tcp.listen)
                .map_err(|error| format!("{}: {error}", tcp.listen))?;
            tracing::info!(listen = %tcp.listen, "serving mutually authenticated TLS");
            Some((listener, tls, clients))
        }
        None => None,
    };
    match (&config.unix_socket, tcp) {
        (None, None) => Err("configure unix_socket or [tcp]".into()),
        (None, Some((listener, tls, clients))) => signer
            .serve_tls(&listener, &tls, &clients)
            .map_err(|error| error.to_string()),
        (Some(path), tcp) => serve_unix(&signer, path, tcp),
    }
}

type Signing = Arc<Signer<neutrin0_storage::RocksDbDatabase>>;
type Tls = (
    TcpListener,
    Arc<rustls::ServerConfig>,
    Arc<neutrin0_signer::TlsClients>,
);

/// Serve the Unix socket at `path` and `tcp` beside it on its own thread.
/// The socket's directory must belong to this user and be closed to every
/// other, so no other user can reach the socket even before its own mode is
/// narrowed.
#[cfg(unix)]
fn serve_unix(signer: &Signing, path: &PathBuf, tcp: Option<Tls>) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let metadata = std::fs::symlink_metadata(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(format!(
            "{} must be a directory (not a symlink) of this user, closed to group and others (mode 700)",
            directory.display()
        ));
    }
    clear_stale_socket(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let listener = std::os::unix::net::UnixListener::bind(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    tracing::info!(socket = %path.display(), "serving the Unix socket");
    if let Some((tcp, tls, clients)) = tcp {
        let tcp_signer = Arc::clone(signer);
        std::thread::spawn(move || {
            if let Err(error) = tcp_signer.serve_tls(&tcp, &tls, &clients) {
                tracing::error!(%error, "TLS listener stopped");
            }
        });
    }
    signer
        .serve_unix(&listener)
        .map_err(|error| error.to_string())
}

/// Remove a socket an unclean exit left at `path`: one this user owns that no
/// process accepts on. Anything else at the path is kept, and binding fails.
#[cfg(unix)]
fn clear_stale_socket(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    let metadata = match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        metadata => metadata?,
    };
    if metadata.file_type().is_socket()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && std::os::unix::net::UnixStream::connect(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::ConnectionRefused)
    {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn serve_unix(_: &Signing, _: &PathBuf, _: Option<Tls>) -> Result<(), String> {
    Err("unix_socket needs a Unix host".into())
}
