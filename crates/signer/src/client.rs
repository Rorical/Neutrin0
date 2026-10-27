//! A node's connection to its signer.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use neutrin0_consensus_engine::{RemoteSigner, SignRequest};
use neutrin0_primitives::{BlsPublicKey, BlsSignature};

use crate::protocol::{Request, Response, read_frame, write_frame};

/// How long one request may take, connection included.
const TIMEOUT: Duration = Duration::from_secs(5);

/// How long a failed signer is refused without being contacted. Signing
/// runs under the engine lock, so an unreachable signer costs that lock one
/// timed-out attempt per backoff rather than one per signature.
const BACKOFF: Duration = Duration::from_secs(10);

/// Where the signer listens.
#[derive(Clone)]
pub enum Endpoint {
    /// A Unix socket on this host.
    #[cfg(unix)]
    Unix(PathBuf),
    /// A TCP address reached over mutually authenticated TLS.
    Tls {
        /// `host:port`.
        address: String,
        /// Name the signer's certificate must carry.
        server_name: rustls::pki_types::ServerName<'static>,
        /// Trust anchors and this node's client certificate.
        config: Arc<rustls::ClientConfig>,
    },
}

impl Endpoint {
    /// A signer at `address` over mutually authenticated TLS: its
    /// certificate must name `server_name` and come from `server_ca`; this
    /// node presents `certificate` and `key`.
    ///
    /// # Errors
    /// Returns an invalid server name and unreadable or invalid PEM files.
    pub fn tls(
        address: String,
        server_name: &str,
        server_ca: &Path,
        certificate: &Path,
        key: &Path,
    ) -> Result<Self, String> {
        Ok(Self::Tls {
            address,
            server_name: rustls::pki_types::ServerName::try_from(server_name.to_owned())
                .map_err(|error| format!("server name {server_name}: {error}"))?,
            config: crate::tls::client_config(server_ca, certificate, key)?,
        })
    }
}

impl core::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            #[cfg(unix)]
            Self::Unix(path) => write!(f, "unix:{}", path.display()),
            Self::Tls { address, .. } => write!(f, "tls:{address}"),
        }
    }
}

trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

/// A blocking client that reconnects once when its connection broke and
/// backs off after a failed request.
pub struct Client {
    endpoint: Endpoint,
    link: Mutex<Link>,
}

/// The open connection, and when a failed signer may be tried again.
struct Link {
    stream: Option<Box<dyn Stream>>,
    retry_at: Option<Instant>,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// A client of the signer at `endpoint`; it connects on first use.
    #[must_use]
    pub const fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            link: Mutex::new(Link {
                stream: None,
                retry_at: None,
            }),
        }
    }

    /// The public keys the signer holds.
    ///
    /// # Errors
    /// Returns connection failures and an unexpected answer.
    pub fn identities(&self) -> Result<Vec<BlsPublicKey>, String> {
        match self.call(&Request::Identities)? {
            Response::Identities(keys) => Ok(keys),
            other => Err(format!("unexpected signer answer {other:?}")),
        }
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "The connection carries one request and its answer at a time."
    )]
    fn call(&self, request: &Request) -> Result<Response, String> {
        let mut link = self.link.lock().expect("signer connection poisoned");
        if link.retry_at.is_some_and(|at| Instant::now() < at) {
            return Err(format!(
                "signer {:?} unavailable after a failed request",
                self.endpoint
            ));
        }
        let answer = self.exchange(&mut link, request);
        link.retry_at = answer.is_err().then(|| Instant::now() + BACKOFF);
        answer
    }

    /// One request and its answer. A connection the signer closed fails on
    /// first use; one fresh attempt follows before the request is reported
    /// failed.
    fn exchange(&self, link: &mut Link, request: &Request) -> Result<Response, String> {
        for attempt in 0..2 {
            if link.stream.is_none() {
                link.stream = Some(
                    self.connect()
                        .map_err(|error| format!("signer {:?}: {error}", self.endpoint))?,
                );
            }
            let stream = link.stream.as_mut().expect("connected above");
            match write_frame(stream, request).and_then(|()| read_frame(stream)) {
                Ok(response) => return Ok(response),
                Err(error) => {
                    link.stream = None;
                    if attempt == 1 {
                        return Err(format!("signer {:?}: {error}", self.endpoint));
                    }
                }
            }
        }
        unreachable!("the second attempt returns")
    }

    fn connect(&self) -> std::io::Result<Box<dyn Stream>> {
        match &self.endpoint {
            #[cfg(unix)]
            Endpoint::Unix(path) => {
                let stream = UnixStream::connect(path)?;
                stream.set_read_timeout(Some(TIMEOUT))?;
                stream.set_write_timeout(Some(TIMEOUT))?;
                Ok(Box::new(stream))
            }
            Endpoint::Tls {
                address,
                server_name,
                config,
            } => {
                let socket = address.to_socket_addrs()?.next().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "address resolves to nothing")
                })?;
                let stream = TcpStream::connect_timeout(&socket, TIMEOUT)?;
                stream.set_read_timeout(Some(TIMEOUT))?;
                stream.set_write_timeout(Some(TIMEOUT))?;
                let connection =
                    rustls::ClientConnection::new(Arc::clone(config), server_name.clone())
                        .map_err(std::io::Error::other)?;
                Ok(Box::new(rustls::StreamOwned::new(connection, stream)))
            }
        }
    }
}

impl RemoteSigner for Client {
    fn sign(
        &self,
        identity: &BlsPublicKey,
        request: &SignRequest,
    ) -> Result<Vec<BlsSignature>, String> {
        let request = Request::Sign {
            identity: *identity,
            request: Box::new(request.clone()),
        };
        match self.call(&request)? {
            Response::Signatures(signatures) => Ok(signatures),
            Response::Refused(refusal) => Err(format!("signer refused: {refusal}")),
            Response::Identities(_) => Err("unexpected signer answer".into()),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn a_failed_signer_is_not_contacted_again_until_the_backoff_ends() {
        let client = Client::new(Endpoint::Unix(PathBuf::from(
            "/nonexistent/neutrin0-signer.sock",
        )));
        let first = client.identities().unwrap_err();
        assert!(!first.contains("unavailable"), "{first}");
        let second = client.identities().unwrap_err();
        assert!(second.contains("unavailable"), "{second}");
        client.link.lock().unwrap().retry_at = Some(Instant::now());
        assert!(!client.identities().unwrap_err().contains("unavailable"));
    }
}
