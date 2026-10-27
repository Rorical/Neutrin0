//! Shared connection, handshake and request budgets across all protocols.

use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use std::{collections::HashMap, net::IpAddr, time::Duration};
use tokio::time::Instant;

const WINDOW: Duration = Duration::from_secs(5);
const QUARANTINE: Duration = Duration::from_secs(300);
/// Strikes one address may collect within a minute across all its peer
/// identities before the address itself is quarantined; fresh identities
/// from it do not reset the count.
const IP_STRIKES: u8 = 6;

struct Peer {
    ip: Option<IpAddr>,
    connected: Instant,
    compatible: bool,
    trusted: bool,
    window: Instant,
    requests: u32,
    messages: u32,
    bytes: usize,
    invalid: u8,
    invalid_since: Instant,
}

struct GroupTraffic {
    since: Instant,
    requests: u32,
    messages: u32,
    bytes: usize,
}

#[derive(Default)]
pub(super) struct Guard {
    peers: HashMap<PeerId, Peer>,
    quarantine: HashMap<PeerId, Instant>,
    /// Strikes per address in the current minute, and quarantined addresses.
    ip_strikes: HashMap<IpAddr, (u8, Instant)>,
    ip_quarantine: HashMap<IpAddr, Instant>,
    groups: HashMap<[u8; 6], GroupTraffic>,
    pub(super) chain: Option<(u64, [u8; 32])>,
}

fn ip(address: &Multiaddr) -> Option<IpAddr> {
    address.iter().find_map(|part| match part {
        Protocol::Ip4(value) => Some(IpAddr::V4(value)),
        Protocol::Ip6(value) => Some(value.to_ipv4_mapped().map_or(IpAddr::V6(value), IpAddr::V4)),
        _ => None,
    })
}

/// The [`super::HostGroup`] of a remote address; `None` on loopback, which
/// local development networks share.
pub(super) fn host_group(address: &Multiaddr) -> Option<super::HostGroup> {
    ip(address).filter(|ip| !ip.is_loopback()).map(group)
}

fn group(address: IpAddr) -> [u8; 6] {
    match address {
        IpAddr::V4(value) => {
            let [a, b, c, _] = value.octets();
            [0, 0, 0, a, b, c]
        }
        IpAddr::V6(value) => value.octets()[..6].try_into().expect("six-byte prefix"),
    }
}

impl Guard {
    pub(super) fn connect(
        &mut self,
        peer: PeerId,
        address: &Multiaddr,
        trusted: bool,
        now: Instant,
    ) -> bool {
        self.quarantine.retain(|_, until| *until > now);
        if self.quarantine.contains_key(&peer) {
            return false;
        }
        if self.peers.contains_key(&peer) {
            return true;
        }
        self.ip_quarantine.retain(|_, until| *until > now);
        if !trusted && ip(address).is_some_and(|address| self.ip_quarantine.contains_key(&address))
        {
            return false;
        }
        if self.peers.len() >= 64 {
            return false;
        }
        let address = ip(address);
        // Local development networks intentionally share loopback. Configured,
        // identity-pinned bootnodes retain reserved outbound access behind NAT.
        if !trusted && !address.is_some_and(|ip| ip.is_loopback()) {
            let same_ip = self
                .peers
                .values()
                .filter(|entry| entry.ip == address)
                .count();
            let same_group = self
                .peers
                .values()
                .filter(|entry| entry.ip.map(group) == address.map(group))
                .count();
            if same_ip >= 4 || same_group >= 8 {
                return false;
            }
        }
        self.peers.insert(
            peer,
            Peer {
                ip: address,
                connected: now,
                compatible: self.chain.is_none(),
                trusted,
                window: now,
                requests: 0,
                messages: 0,
                bytes: 0,
                invalid: 0,
                invalid_since: now,
            },
        );
        true
    }

    pub(super) fn has_peer(&self, peer: &PeerId) -> bool {
        self.peers.contains_key(peer)
    }

    pub(super) fn disconnect(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
    }

    pub(super) fn ready(&self, peer: &PeerId) -> bool {
        self.chain.is_none() || self.peers.get(peer).is_some_and(|entry| entry.compatible)
    }

    pub(super) fn status(&mut self, peer: PeerId, chain: (u64, [u8; 32])) -> bool {
        if self.chain.is_some_and(|expected| expected != chain) {
            return false;
        }
        if let Some(entry) = self.peers.get_mut(&peer) {
            entry.compatible = true;
        }
        true
    }

    pub(super) fn expired(&self, now: Instant) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(_, entry)| {
                !entry.compatible
                    && now.saturating_duration_since(entry.connected) >= Duration::from_secs(30)
            })
            .map(|(peer, _)| *peer)
            .collect()
    }

    pub(super) fn admit(
        &mut self,
        peer: PeerId,
        request: bool,
        bytes: usize,
        now: Instant,
    ) -> bool {
        let Some(entry) = self.peers.get_mut(&peer) else {
            return self.chain.is_none();
        };
        if now.saturating_duration_since(entry.window) >= WINDOW {
            entry.window = now;
            entry.requests = 0;
            entry.messages = 0;
            entry.bytes = 0;
        }
        if entry.bytes.saturating_add(bytes) > 32 * 1024 * 1024
            || (request && entry.requests >= 16)
            || (!request && entry.messages >= 128)
        {
            return false;
        }
        if !entry.trusted && !entry.ip.is_some_and(|address| address.is_loopback()) {
            self.groups
                .retain(|_, quota| now.saturating_duration_since(quota.since) < WINDOW);
            let key = entry.ip.map_or([0; 6], group);
            if self.groups.len() >= 512 && !self.groups.contains_key(&key) {
                return false;
            }
            let quota = self.groups.entry(key).or_insert(GroupTraffic {
                since: now,
                requests: 0,
                messages: 0,
                bytes: 0,
            });
            if quota.bytes.saturating_add(bytes) > 128 * 1024 * 1024
                || (request && quota.requests >= 64)
                || (!request && quota.messages >= 512)
            {
                return false;
            }
            quota.bytes += bytes;
            if request {
                quota.requests += 1;
            } else {
                quota.messages += 1;
            }
        }
        entry.bytes += bytes;
        if request {
            entry.requests += 1;
        } else {
            entry.messages += 1;
        }
        true
    }

    /// Add `bytes` a response sent to `peer` to its and its group's byte
    /// budgets for the current window; requests are refused once spent.
    pub(super) fn charge(&mut self, peer: PeerId, bytes: usize, now: Instant) {
        let Some(entry) = self.peers.get_mut(&peer) else {
            return;
        };
        if now.saturating_duration_since(entry.window) >= WINDOW {
            entry.window = now;
            entry.requests = 0;
            entry.messages = 0;
            entry.bytes = 0;
        }
        entry.bytes = entry.bytes.saturating_add(bytes);
        if entry.trusted || entry.ip.is_some_and(|address| address.is_loopback()) {
            return;
        }
        let key = entry.ip.map_or([0; 6], group);
        if let Some(quota) = self.groups.get_mut(&key)
            && now.saturating_duration_since(quota.since) < WINDOW
        {
            quota.bytes = quota.bytes.saturating_add(bytes);
        }
    }

    pub(super) fn invalid(&mut self, peer: PeerId, now: Instant) -> bool {
        let Some(entry) = self.peers.get_mut(&peer) else {
            return false;
        };
        if now.saturating_duration_since(entry.invalid_since) >= Duration::from_secs(60) {
            entry.invalid = 0;
            entry.invalid_since = now;
        }
        entry.invalid = entry.invalid.saturating_add(1);
        let peer_struck = entry.invalid >= 3;
        let address = entry
            .ip
            .filter(|address| !entry.trusted && !address.is_loopback());
        let address_struck = address.is_some_and(|address| self.strike_address(address, now));
        if !peer_struck && !address_struck {
            return false;
        }
        self.quarantine.retain(|_, until| *until > now);
        if self.quarantine.len() >= 256
            && let Some(oldest) = self
                .quarantine
                .iter()
                .min_by_key(|(_, until)| **until)
                .map(|(peer, _)| *peer)
        {
            self.quarantine.remove(&oldest);
        }
        self.quarantine.insert(peer, now + QUARANTINE);
        true
    }

    /// Count a strike against `address`; quarantine it once it reaches
    /// [`IP_STRIKES`] within a minute. Both maps stay bounded.
    fn strike_address(&mut self, address: IpAddr, now: Instant) -> bool {
        self.ip_strikes.retain(|_, (_, since)| {
            now.saturating_duration_since(*since) < Duration::from_secs(60)
        });
        if self.ip_strikes.len() >= 1024 && !self.ip_strikes.contains_key(&address) {
            return false;
        }
        let (count, _) = self.ip_strikes.entry(address).or_insert((0, now));
        *count = count.saturating_add(1);
        if *count < IP_STRIKES {
            return false;
        }
        self.ip_strikes.remove(&address);
        self.ip_quarantine.retain(|_, until| *until > now);
        if self.ip_quarantine.len() < 256 {
            self.ip_quarantine.insert(address, now + QUARANTINE);
        }
        true
    }

    pub(super) fn advertised_address(
        &self,
        peer: PeerId,
        address: &Multiaddr,
        trusted: bool,
    ) -> bool {
        if address.len() > 2048
            || address
                .iter()
                .any(|part| matches!(part, Protocol::P2p(identity) if identity != peer))
        {
            return false;
        }
        let Some(value) = ip(address) else {
            return trusted;
        };
        if value.is_unspecified() || value.is_multicast() {
            return false;
        }
        trusted
            || self
                .peers
                .get(&peer)
                .is_some_and(|entry| entry.ip == Some(value))
    }
}

#[cfg(test)]
mod tests;
