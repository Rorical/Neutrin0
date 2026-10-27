//! Kademlia restricted to dialable targets.
//!
//! A Kademlia query dials the peers that replies name, at the addresses the
//! replies give. On a public node those must never be loopback or private
//! hosts, or any peer could aim this node's connections at its own internal
//! network. This wrapper filters the addresses Kademlia supplies for a dial;
//! everything else delegates unchanged.

use libp2p::{
    Multiaddr, PeerId,
    core::{Endpoint, transport::PortUse},
    kad::{self, store::MemoryStore},
    multiaddr::Protocol,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm,
    },
};
use std::{
    net::IpAddr,
    ops::{Deref, DerefMut},
    task::{Context, Poll},
};

/// Whether `ip` is reachable only inside a host or private network: loopback,
/// private, link-local, shared (CGNAT) or unique-local space.
pub(crate) fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => {
            let [first, second, ..] = value.octets();
            value.is_loopback()
                || value.is_private()
                || value.is_link_local()
                || (first == 100 && (64..128).contains(&second))
        }
        IpAddr::V6(value) => value.to_ipv4_mapped().map_or_else(
            || value.is_loopback() || value.is_unique_local() || value.is_unicast_link_local(),
            |mapped| is_local(IpAddr::V4(mapped)),
        ),
    }
}

/// Whether `address` names a local IP.
pub(crate) fn is_local_address(address: &Multiaddr) -> bool {
    address.iter().any(|part| match part {
        Protocol::Ip4(value) => is_local(IpAddr::V4(value)),
        Protocol::Ip6(value) => is_local(IpAddr::V6(value)),
        _ => false,
    })
}

/// Kademlia whose dial addresses exclude local targets unless the node itself
/// runs on a local network (its configured bootnodes are local).
pub struct FilteredKademlia {
    inner: kad::Behaviour<MemoryStore>,
    allow_local: bool,
}

impl FilteredKademlia {
    pub(crate) const fn new(inner: kad::Behaviour<MemoryStore>) -> Self {
        Self {
            inner,
            allow_local: false,
        }
    }

    /// Permit local dial targets, for development and private networks.
    pub(crate) const fn allow_local(&mut self, allow: bool) {
        self.allow_local = allow;
    }
}

impl Deref for FilteredKademlia {
    type Target = kad::Behaviour<MemoryStore>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for FilteredKademlia {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl NetworkBehaviour for FilteredKademlia {
    type ConnectionHandler = <kad::Behaviour<MemoryStore> as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = kad::Event;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let mut supplied = self.inner.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )?;
        if !self.allow_local {
            supplied.retain(|address| !is_local_address(address));
        }
        Ok(supplied)
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
        self.inner.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner
            .on_connection_handler_event(peer_id, connection_id, event);
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.inner.poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_space_is_recognised_in_every_form() {
        for local in [
            "/ip4/127.0.0.1/tcp/1",
            "/ip4/10.1.2.3/tcp/1",
            "/ip4/172.16.0.1/tcp/1",
            "/ip4/192.168.1.1/tcp/1",
            "/ip4/169.254.0.1/tcp/1",
            "/ip4/100.64.0.1/tcp/1",
            "/ip6/::1/tcp/1",
            "/ip6/fd00::1/tcp/1",
            "/ip6/fe80::1/tcp/1",
            "/ip6/::ffff:10.0.0.1/tcp/1",
        ] {
            assert!(is_local_address(&local.parse().unwrap()), "{local}");
        }
        for public in [
            "/ip4/198.51.100.1/tcp/1",
            "/ip4/100.128.0.1/tcp/1",
            "/ip6/2001:db8::1/tcp/1",
        ] {
            assert!(!is_local_address(&public.parse().unwrap()), "{public}");
        }
    }
}
