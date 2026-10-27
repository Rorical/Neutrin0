//! Peer discovery beyond the configured bootnodes (design 21).
//!
//! While the node has fewer outbound connections than [`TARGET_OUTBOUND`],
//! a periodic Kademlia walk asks connected peers for others, and the node
//! dials a few of the addresses it learned. Outbound connections are the ones
//! an attacker filling inbound slots cannot choose, so they bound eclipse.
//! The book of learned addresses is bounded, keeps few entries per network
//! prefix and is never retried persistently: a learned peer is dialed at most
//! once per [`REDIAL_AFTER`] and forgotten when that dial fails, and only the
//! operator's bootnodes have reconnect schedules.

use crate::kademlia::is_local;
use libp2p::{Multiaddr, PeerId, multiaddr::Protocol, swarm::ConnectionId};
use std::{collections::HashMap, net::IpAddr, time::Duration};
use tokio::time::Instant;

/// Outbound connections below which the node walks the DHT and dials
/// learned peers; the swarm accepts at most 24 untrusted outbound ones.
pub(super) const TARGET_OUTBOUND: usize = 16;
/// Interval between walks while below the target.
#[cfg(not(test))]
pub(super) const WALK_INTERVAL: Duration = Duration::from_secs(30);
/// Loopback tests walk quickly so a few seconds show discovery working.
#[cfg(test)]
pub(super) const WALK_INTERVAL: Duration = Duration::from_secs(1);
/// Learned peers retained; the oldest entry is forgotten first.
const MAX_LEARNED: usize = 256;
/// Learned peers retained per IPv4 /24 or IPv6 /48, so one operator's
/// addresses cannot fill the book and steer every outbound dial.
const MAX_LEARNED_PER_PREFIX: usize = 4;
/// Addresses kept per learned peer.
const MAX_ADDRESSES_PER_PEER: usize = 4;
/// A learned peer is not dialed again sooner than this.
const REDIAL_AFTER: Duration = Duration::from_secs(600);
/// Dials started per walk, bounding what a forged reply can make this node do.
pub(super) const DIALS_PER_WALK: usize = 4;

struct Learned {
    addresses: Vec<Multiaddr>,
    since: Instant,
    dialed_at: Option<Instant>,
}

/// One learned entry: a peer's addresses inside one network prefix.
type EntryKey = (PeerId, [u8; 6]);

/// A learned entry chosen for a dial: the peer and the prefix of the
/// addresses dialed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ConnectionTarget(EntryKey);

impl ConnectionTarget {
    pub(super) const fn peer(&self) -> PeerId {
        self.0.0
    }
}

/// Bounded book of addresses learned from DHT replies, one entry per peer
/// and prefix: a reply can add addresses or a new entry under its own prefix
/// quota, but never replace or remove what another reply taught.
#[derive(Default)]
pub(super) struct Discovery {
    learned: HashMap<EntryKey, Learned>,
    /// Dials of learned entries in flight, to forget an entry whose dial fails.
    dials: HashMap<ConnectionId, EntryKey>,
    /// Local (loopback or private) targets are dialable only when the
    /// operator's own bootnodes are local: a development or private network.
    local_network: bool,
}

/// Network prefix of the first IP an address names: IPv4 /24, IPv6 /48.
fn prefix(address: &Multiaddr) -> Option<[u8; 6]> {
    address.iter().find_map(|part| match part {
        Protocol::Ip4(value) => {
            let [a, b, c, _] = value.octets();
            Some([0, 0, 0, a, b, c])
        }
        Protocol::Ip6(value) => value.to_ipv4_mapped().map_or_else(
            || value.octets()[..6].try_into().ok(),
            |v4| {
                let [a, b, c, _] = v4.octets();
                Some([0, 0, 0, a, b, c])
            },
        ),
        _ => None,
    })
}

/// Only a concrete unicast IP address with a transport port is dialable; a
/// reply cannot direct dials at broadcast, multicast or unspecified targets,
/// nor, unless the node itself runs on a local network, at local ones.
fn dialable(address: &Multiaddr, local_network: bool) -> bool {
    let ip = address.iter().find_map(|part| match part {
        Protocol::Ip4(value) => Some(IpAddr::V4(value)),
        Protocol::Ip6(value) => Some(IpAddr::V6(value)),
        _ => None,
    });
    let port = address
        .iter()
        .any(|part| matches!(part, Protocol::Tcp(_) | Protocol::Udp(_)));
    address.len() <= 256
        && port
        && ip.is_some_and(|ip| {
            !ip.is_unspecified() && !ip.is_multicast() && (local_network || !is_local(ip))
        })
        && !matches!(ip, Some(IpAddr::V4(value)) if value.is_broadcast())
}

impl Discovery {
    /// Permit local targets, for development and private networks.
    pub(super) const fn allow_local(&mut self, allow: bool) {
        self.local_network = allow;
    }

    /// Record what a DHT reply says about `peer`. Addresses naming another
    /// identity, undialable ones and addresses outside the first one's
    /// prefix are dropped. The rest join the peer's entry for that prefix up
    /// to [`MAX_ADDRESSES_PER_PEER`], or start a new entry while the prefix
    /// is below its bound; nothing a reply says replaces an existing address.
    pub(super) fn learn(
        &mut self,
        local: &PeerId,
        peer: PeerId,
        addresses: impl IntoIterator<Item = Multiaddr>,
        now: Instant,
    ) {
        if peer == *local {
            return;
        }
        let mut addresses: Vec<_> = addresses
            .into_iter()
            .filter(|address| {
                dialable(address, self.local_network)
                    && address
                        .iter()
                        .all(|part| !matches!(part, Protocol::P2p(identity) if identity != peer))
            })
            .collect();
        let Some(prefix) = addresses.first().and_then(self::prefix) else {
            return;
        };
        addresses.retain(|address| self::prefix(address) == Some(prefix));
        if let Some(entry) = self.learned.get_mut(&(peer, prefix)) {
            for address in addresses {
                if entry.addresses.len() < MAX_ADDRESSES_PER_PEER
                    && !entry.addresses.contains(&address)
                {
                    entry.addresses.push(address);
                }
            }
            return;
        }
        if self
            .learned
            .keys()
            .filter(|(_, other)| *other == prefix)
            .count()
            >= MAX_LEARNED_PER_PREFIX
        {
            return;
        }
        if self.learned.len() >= MAX_LEARNED
            && let Some(oldest) = self
                .learned
                .iter()
                .min_by_key(|(_, entry)| entry.since)
                .map(|(key, _)| *key)
        {
            self.learned.remove(&oldest);
        }
        addresses.dedup();
        addresses.truncate(MAX_ADDRESSES_PER_PEER);
        self.learned.insert(
            (peer, prefix),
            Learned {
                addresses,
                since: now,
                dialed_at: None,
            },
        );
    }

    /// Up to `limit` learned entries to dial now: peer not connected, entry
    /// not dialed within [`REDIAL_AFTER`], at most one entry per peer and
    /// per prefix in this round.
    pub(super) fn due(
        &mut self,
        connected: impl Fn(&PeerId) -> bool,
        limit: usize,
        now: Instant,
    ) -> Vec<(ConnectionTarget, Vec<Multiaddr>)> {
        let mut candidates: Vec<_> = self
            .learned
            .iter()
            .filter(|((peer, _), entry)| {
                !connected(peer)
                    && entry
                        .dialed_at
                        .is_none_or(|dialed| now.duration_since(dialed) >= REDIAL_AFTER)
            })
            .map(|(key, entry)| (*key, entry.dialed_at))
            .collect();
        // Never-dialed entries first, then the longest-waiting.
        candidates.sort_by_key(|((peer, prefix), dialed)| (*dialed, *peer, *prefix));
        let mut peers = Vec::new();
        let mut prefixes = Vec::new();
        let mut due = Vec::new();
        for (key, _) in candidates {
            if due.len() >= limit {
                break;
            }
            if peers.contains(&key.0) || prefixes.contains(&key.1) {
                continue;
            }
            peers.push(key.0);
            prefixes.push(key.1);
            if let Some(entry) = self.learned.get_mut(&key) {
                entry.dialed_at = Some(now);
                due.push((ConnectionTarget(key), entry.addresses.clone()));
            }
        }
        due
    }

    /// Remember that `connection` dials the learned entry `target`.
    pub(super) fn dialing(&mut self, connection: ConnectionId, target: ConnectionTarget) {
        self.dials.insert(connection, target.0);
    }

    /// A dial ended: a failed one forgets only the entry it dialed, whose
    /// addresses did not lead to the peer; a successful one keeps it.
    pub(super) fn dial_ended(&mut self, connection: ConnectionId, failed: bool) {
        if let Some(key) = self.dials.remove(&connection)
            && failed
        {
            self.learned.remove(&key);
        }
    }

    /// Learned peers currently retained.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.learned.len()
    }
}

#[cfg(test)]
mod tests;
