//! The signing service: the keys, the journal and the connections nodes
//! open to it.
//!
//! A connection may use only the keys its client is permitted: every key the
//! signer holds over the Unix socket, which only the signer's user can open,
//! and over TLS the keys listed for the client's certificate, refusing
//! certificates not listed. TLS handshakes run under their own small cap and
//! deadline before a connection takes one of the served slots, and a
//! connection idle past [`IDLE`] is closed; the node reconnects on demand.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use neutrin0_crypto::bls::SecretKey;
use neutrin0_primitives::{BlsPublicKey, ConsensusDomain, Hash};
use neutrin0_storage::Database;

use crate::journal::Journal;
use crate::protocol::{Refusal, Request, Response, read_frame, write_frame};

/// Connections served at once on each listener; one node needs one.
const MAX_CONNECTIONS: usize = 64;
/// TLS handshakes in progress at once.
const MAX_HANDSHAKES: usize = 16;
/// Time a TLS client has to complete its handshake.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// Time a connection may stay silent before it is closed.
pub const IDLE: Duration = Duration::from_secs(300);

/// The keys TLS clients may use, by the SHA-256 of their certificate's DER.
pub type TlsClients = BTreeMap<Hash, BTreeSet<BlsPublicKey>>;

/// The keys one connection may use.
#[derive(Clone, Debug)]
pub enum Access {
    /// Every key the signer holds.
    All,
    /// Only these keys.
    Only(BTreeSet<BlsPublicKey>),
}

impl Access {
    fn permits(&self, identity: &BlsPublicKey) -> bool {
        match self {
            Self::All => true,
            Self::Only(keys) => keys.contains(identity),
        }
    }
}

/// Keys of one chain and the journal that protects them.
#[derive(Debug)]
pub struct Signer<DB> {
    domain: ConsensusDomain,
    keys: BTreeMap<BlsPublicKey, SecretKey>,
    journal: Mutex<Journal<DB>>,
}

/// A held place under a cap, released on drop.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(counter: &Arc<AtomicUsize>, cap: usize) -> Option<Self> {
        if counter.fetch_add(1, Ordering::AcqRel) >= cap {
            counter.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Self(Arc::clone(counter)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A stream every read and write of which may take only the time left
/// until `deadline`, however the peer paces its bytes.
struct Deadline<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}

impl Deadline<'_> {
    fn bound(&self) -> std::io::Result<()> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| std::io::Error::from(ErrorKind::TimedOut))?;
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.set_write_timeout(Some(remaining))
    }
}

impl Read for Deadline<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.bound()?;
        self.stream.read(buffer)
    }
}

impl Write for Deadline<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.bound()?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.bound()?;
        self.stream.flush()
    }
}

impl<DB: Database> Signer<DB>
where
    DB::Error: core::fmt::Display,
{
    /// A signer of `keys` for the chain `domain` binds, journaling into `db`.
    pub fn new(domain: ConsensusDomain, keys: Vec<SecretKey>, db: DB) -> Self {
        Self {
            domain,
            keys: keys
                .into_iter()
                .map(|key| (key.public_key().to_bytes(), key))
                .collect(),
            journal: Mutex::new(Journal::new(db)),
        }
    }

    /// Answer one request from a connection permitted `access`.
    ///
    /// # Panics
    /// Panics if a thread panicked while holding the journal.
    pub fn handle(&self, request: &Request, access: &Access) -> Response {
        match request {
            Request::Identities => Response::Identities(
                self.keys
                    .keys()
                    .filter(|key| access.permits(key))
                    .copied()
                    .collect(),
            ),
            Request::Sign { identity, request } => {
                if !access.permits(identity) {
                    return Response::Refused(Refusal::NotPermitted);
                }
                let Some(key) = self.keys.get(identity) else {
                    return Response::Refused(Refusal::UnknownIdentity);
                };
                // The reservation is the safety point: once it is durable,
                // signing needs no lock, and a conflicting request on another
                // connection is refused by the journal.
                let reserved = self
                    .journal
                    .lock()
                    .expect("signing journal poisoned")
                    .reserve(identity, request);
                if let Err(refusal) = reserved {
                    return Response::Refused(refusal);
                }
                Response::Signatures(
                    request.sign_with(self.domain, |message| key.sign(message).to_bytes()),
                )
            }
        }
    }

    /// Answer requests on `stream`, permitted `access`, until the node
    /// closes it or it stays idle past its read timeout.
    ///
    /// # Errors
    /// Returns read and write failures other than the node closing.
    pub fn serve(&self, mut stream: impl Read + Write, access: &Access) -> std::io::Result<()> {
        loop {
            let request: Request = match read_frame(&mut stream) {
                Ok(request) => request,
                Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(error),
            };
            write_frame(&mut stream, &self.handle(&request, access))?;
        }
    }

    /// Serve every connection to `listener`, a Unix socket only the signer's
    /// user may open, each on its own thread with every key.
    ///
    /// # Errors
    /// Returns a failure to accept.
    #[cfg(unix)]
    pub fn serve_unix(self: &Arc<Self>, listener: &UnixListener) -> std::io::Result<()>
    where
        DB: Send + 'static,
    {
        let served = Arc::new(AtomicUsize::new(0));
        for stream in listener.incoming() {
            let stream = stream?;
            let Some(slot) = Slot::take(&served, MAX_CONNECTIONS) else {
                tracing::warn!("Unix connection refused: too many open connections");
                continue;
            };
            let signer = Arc::clone(self);
            std::thread::spawn(move || {
                let _slot = slot;
                let result = stream
                    .set_read_timeout(Some(IDLE))
                    .and_then(|()| signer.serve(&stream, &Access::All));
                if let Err(error) = result {
                    tracing::warn!(%error, "connection closed");
                }
            });
        }
        Ok(())
    }

    /// Serve every TLS connection to `listener` whose client presents a
    /// certificate `config` accepts and `clients` lists, with the keys listed
    /// for it, each on its own thread.
    ///
    /// # Errors
    /// Returns a failure to accept.
    pub fn serve_tls(
        self: &Arc<Self>,
        listener: &TcpListener,
        config: &Arc<rustls::ServerConfig>,
        clients: &Arc<TlsClients>,
    ) -> std::io::Result<()>
    where
        DB: Send + 'static,
    {
        let handshakes = Arc::new(AtomicUsize::new(0));
        let served = Arc::new(AtomicUsize::new(0));
        for stream in listener.incoming() {
            let stream = stream?;
            let Some(handshake) = Slot::take(&handshakes, MAX_HANDSHAKES) else {
                tracing::warn!("TLS connection refused: too many handshakes in progress");
                continue;
            };
            let (signer, config, clients, served) = (
                Arc::clone(self),
                Arc::clone(config),
                Arc::clone(clients),
                Arc::clone(&served),
            );
            std::thread::spawn(move || {
                let result =
                    signer.serve_tls_connection(stream, config, &clients, handshake, &served);
                if let Err(error) = result {
                    tracing::warn!(%error, "TLS connection closed");
                }
            });
        }
        Ok(())
    }

    /// Complete the handshake by [`HANDSHAKE`] after it began, however the
    /// client paces its bytes, then serve the client its listed keys in a
    /// served slot.
    fn serve_tls_connection(
        &self,
        mut stream: TcpStream,
        config: Arc<rustls::ServerConfig>,
        clients: &TlsClients,
        handshake: Slot,
        served: &Arc<AtomicUsize>,
    ) -> std::io::Result<()> {
        let mut connection =
            rustls::ServerConnection::new(config).map_err(std::io::Error::other)?;
        let mut bounded = Deadline {
            stream: &mut stream,
            deadline: Instant::now() + HANDSHAKE,
        };
        while connection.is_handshaking() {
            connection.complete_io(&mut bounded)?;
        }
        let keys = connection
            .peer_certificates()
            .and_then(<[_]>::first)
            .and_then(|certificate| clients.get(&neutrin0_crypto::hash::sha256(certificate)))
            .cloned()
            .ok_or_else(|| std::io::Error::other("client certificate is not listed"))?;
        drop(handshake);
        let Some(_slot) = Slot::take(served, MAX_CONNECTIONS) else {
            return Err(std::io::Error::other("too many open connections"));
        };
        stream.set_read_timeout(Some(IDLE))?;
        stream.set_write_timeout(Some(IDLE))?;
        self.serve(
            rustls::StreamOwned::new(connection, stream),
            &Access::Only(keys),
        )
    }
}
