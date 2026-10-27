//! Client identity and connection admission for the RPC listener.
//!
//! A client is its TCP peer's address, an IPv4 address or the IPv6 /64 a
//! subscriber is usually handed, except behind a configured trusted proxy,
//! whose connections name the client as the last hop of `X-Forwarded-For`.
//! The listener holds a bounded number of TCP connections; each client may
//! hold a bounded share of them, trusted proxies being exempt since they
//! multiplex many clients, and WebSocket sessions, whose buffered responses
//! outlive a request, take one of a separate, smaller set of slots for the
//! life of their connection. Rate limits key on the client (see `governor`).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// The client a request comes from, attached to its extensions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct ClientIp(pub(super) IpAddr);

impl ClientIp {
    /// The client `address` belongs to: itself for IPv4 (also when mapped
    /// into IPv6), its /64 for IPv6, so one subscriber's many addresses
    /// share one client's limits.
    fn of(address: IpAddr) -> Self {
        match address.to_canonical() {
            IpAddr::V6(address) => Self(IpAddr::V6(Ipv6Addr::from(
                u128::from(address) & (u128::MAX << 64),
            ))),
            IpAddr::V4(address) => Self(IpAddr::V4(address)),
        }
    }
}

/// The listener's connection slots, per-client connection counts and the
/// WebSocket session slots.
pub(super) struct Clients {
    trusted_proxies: Vec<IpAddr>,
    connections: Arc<Semaphore>,
    per_client: usize,
    open: Mutex<HashMap<ClientIp, usize>>,
    websockets: Arc<Semaphore>,
}

/// One admitted TCP connection, or the WebSocket session it became;
/// releases its slot and its client's count on drop.
pub(super) struct Admission {
    clients: Arc<Clients>,
    client: Option<ClientIp>,
    _connection: OwnedSemaphorePermit,
}

impl Drop for Admission {
    fn drop(&mut self) {
        let Some(client) = self.client else {
            return;
        };
        let mut open = self
            .clients
            .open
            .lock()
            .expect("rpc client counts poisoned");
        if let Some(count) = open.get_mut(&client) {
            *count -= 1;
            if *count == 0 {
                open.remove(&client);
            }
        }
    }
}

impl Clients {
    pub(super) fn new(
        trusted_proxies: &[IpAddr],
        connections: u32,
        per_client: u32,
        websockets: u32,
    ) -> Arc<Self> {
        let slots = |count: u32| usize::try_from(count).unwrap_or(usize::MAX);
        Arc::new(Self {
            trusted_proxies: trusted_proxies.iter().map(IpAddr::to_canonical).collect(),
            connections: Arc::new(Semaphore::new(slots(connections.max(1)))),
            per_client: slots(per_client.max(1)),
            open: Mutex::new(HashMap::new()),
            websockets: Arc::new(Semaphore::new(slots(websockets))),
        })
    }

    /// Admit a TCP connection from `peer`, or refuse one past the listener's
    /// or its client's bound. Trusted proxies count only toward the
    /// listener's.
    pub(super) fn admit(self: &Arc<Self>, peer: IpAddr) -> Option<Admission> {
        let connection = Arc::clone(&self.connections).try_acquire_owned().ok()?;
        let peer = peer.to_canonical();
        if self.trusted_proxies.contains(&peer) {
            return Some(Admission {
                clients: Arc::clone(self),
                client: None,
                _connection: connection,
            });
        }
        let client = ClientIp::of(peer);
        let mut open = self.open.lock().expect("rpc client counts poisoned");
        let count = open.entry(client).or_insert(0);
        if *count >= self.per_client {
            return None;
        }
        *count += 1;
        drop(open);
        Some(Admission {
            clients: Arc::clone(self),
            client: Some(client),
            _connection: connection,
        })
    }

    /// The client behind a request from `peer` carrying `headers`.
    pub(super) fn client(&self, peer: IpAddr, headers: &http::HeaderMap) -> ClientIp {
        let peer = peer.to_canonical();
        if !self.trusted_proxies.contains(&peer) {
            return ClientIp::of(peer);
        }
        // The proxy appends the address it received the request from; that
        // last hop is the only entry it vouches for.
        let forwarded = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .last()
            .and_then(|hop| hop.trim().parse().ok());
        ClientIp::of(forwarded.unwrap_or(peer))
    }

    /// A WebSocket session slot, if one is free; the session holds it until
    /// it closes.
    pub(super) fn websocket(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.websockets).try_acquire_owned().ok()
    }
}

/// A bounded pool of long-lived slots (subscriptions, polling filters) of
/// which one client holds at most `per_client`, so a single client cannot
/// take every slot.
pub(super) struct ClientSlots {
    total: Arc<Semaphore>,
    per_client: usize,
    held: Arc<Mutex<HashMap<ClientIp, usize>>>,
}

/// One held slot; releases it and its client's count on drop.
pub(super) struct ClientSlot {
    held: Arc<Mutex<HashMap<ClientIp, usize>>>,
    client: Option<ClientIp>,
    _total: OwnedSemaphorePermit,
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        let Some(client) = self.client else {
            return;
        };
        let mut held = self.held.lock().expect("rpc client slots poisoned");
        if let Some(count) = held.get_mut(&client) {
            *count -= 1;
            if *count == 0 {
                held.remove(&client);
            }
        }
    }
}

impl ClientSlots {
    pub(super) fn new(total: usize, per_client: usize) -> Self {
        Self {
            total: Arc::new(Semaphore::new(total)),
            per_client,
            held: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// A slot for `client`, if the pool and its share both have room. A
    /// request without a known client counts only toward the pool.
    pub(super) fn acquire(&self, client: Option<ClientIp>) -> Option<ClientSlot> {
        let total = Arc::clone(&self.total).try_acquire_owned().ok()?;
        if let Some(client) = client {
            let mut held = self.held.lock().expect("rpc client slots poisoned");
            let count = held.entry(client).or_insert(0);
            if *count >= self.per_client {
                return None;
            }
            *count += 1;
        }
        Some(ClientSlot {
            held: Arc::clone(&self.held),
            client,
            _total: total,
        })
    }
}

#[cfg(test)]
mod tests;
