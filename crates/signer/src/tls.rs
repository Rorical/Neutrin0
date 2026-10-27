//! Mutually authenticated TLS between a node and a remote signer: each side
//! trusts only the certificate authority its operator names.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    CertificateDer::pem_file_iter(path)
        .and_then(Iterator::collect)
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn private_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::from_pem_file(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn roots(path: &Path) -> Result<Arc<RootCertStore>, String> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates(path)? {
        roots
            .add(certificate)
            .map_err(|error| format!("{}: {error}", path.display()))?;
    }
    Ok(Arc::new(roots))
}

/// The signer's side: its certificate chain and key, accepting only clients
/// whose certificates `client_ca` issued.
///
/// # Errors
/// Returns unreadable or invalid PEM files.
pub fn server_config(
    certificate: &Path,
    key: &Path,
    client_ca: &Path,
) -> Result<Arc<ServerConfig>, String> {
    let verifier = WebPkiClientVerifier::builder_with_provider(roots(client_ca)?, provider())
        .build()
        .map_err(|error| error.to_string())?;
    ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates(certificate)?, private_key(key)?)
        .map(Arc::new)
        .map_err(|error| error.to_string())
}

/// The node's side: trusting signers whose certificates `server_ca` issued
/// and presenting its own certificate chain and key.
///
/// # Errors
/// Returns unreadable or invalid PEM files.
pub fn client_config(
    server_ca: &Path,
    certificate: &Path,
    key: &Path,
) -> Result<Arc<ClientConfig>, String> {
    ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_root_certificates(roots(server_ca)?)
        .with_client_auth_cert(certificates(certificate)?, private_key(key)?)
        .map(Arc::new)
        .map_err(|error| error.to_string())
}
