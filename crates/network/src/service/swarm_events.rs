//! Swarm event handling: connection lifecycle, identify, ping, gossip
//! admission and Kademlia results.

use super::{NetworkEvent, NetworkService};
use crate::behaviour::Neutrin0BehaviourEvent;
use crate::metrics::GuardAction;
use crate::topic::Topic;
use libp2p::{
    PeerId,
    core::ConnectedPoint,
    gossipsub, identify, kad, ping,
    swarm::{ConnectionError, ConnectionId, DialError, SwarmEvent},
};
use tracing::{debug, info, warn};

impl NetworkService {
    pub(super) fn promote_addresses(&mut self, peer: PeerId) {
        if !self.guard.ready(&peer) {
            return;
        }
        if let Some(addresses) = self.identified_addresses.get(&peer) {
            for address in addresses {
                self.swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer, address.clone());
            }
        }
    }

    pub(super) fn maintain_guard(&mut self) {
        let now = tokio::time::Instant::now();
        for peer in self.guard.expired(now) {
            self.metrics.guard_action(GuardAction::Handshake);
            warn!(%peer, "disconnecting peer after chain handshake deadline");
            let _ = self.swarm.disconnect_peer_id(peer);
        }
    }

    pub(super) fn handle_swarm_event(&mut self, event: SwarmEvent<Neutrin0BehaviourEvent>) {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                self.bootnodes.local_address(&address);
                info!(%address, "listening on new address");
                self.queue_control(NetworkEvent::NewListenAddr(address));
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => self.on_connection_established(peer_id, connection_id, &endpoint),
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                endpoint,
                cause,
                ..
            } => self.on_connection_closed(peer_id, connection_id, &endpoint, cause.as_ref()),
            SwarmEvent::OutgoingConnectionError {
                connection_id,
                peer_id,
                error,
            } => self.on_outgoing_connection_error(connection_id, peer_id, &error),
            SwarmEvent::Behaviour(Neutrin0BehaviourEvent::Identify(
                identify::Event::Received { peer_id, info, .. },
            )) => self.on_identify_received(peer_id, info),
            SwarmEvent::Behaviour(Neutrin0BehaviourEvent::Ping(ping::Event {
                peer,
                result,
                ..
            })) => match result {
                Ok(rtt) => {
                    self.metrics.ping(Some(rtt));
                    debug!(%peer, ?rtt, "ping success");
                }
                Err(err) => {
                    self.metrics.ping(None);
                    warn!(%peer, ?err, "ping failed");
                }
            },
            SwarmEvent::Behaviour(Neutrin0BehaviourEvent::Gossipsub(
                gossipsub::Event::Message {
                    propagation_source,
                    message,
                    message_id,
                },
            )) => self.on_gossip_message(propagation_source, message, message_id),
            SwarmEvent::Behaviour(Neutrin0BehaviourEvent::Gossipsub(
                gossipsub::Event::Subscribed { peer_id, topic },
            )) => debug!(%peer_id, %topic, "peer subscribed"),
            SwarmEvent::Behaviour(Neutrin0BehaviourEvent::Gossipsub(
                gossipsub::Event::Unsubscribed { peer_id, topic },
            )) => debug!(%peer_id, %topic, "peer unsubscribed"),
            SwarmEvent::Behaviour(Neutrin0BehaviourEvent::Kademlia(
                kad::Event::OutboundQueryProgressed {
                    result: kad::QueryResult::GetClosestPeers(Ok(found)),
                    ..
                },
            )) => {
                let local = *self.swarm.local_peer_id();
                let now = tokio::time::Instant::now();
                for info in found.peers {
                    self.discovery.learn(&local, info.peer_id, info.addrs, now);
                }
            }
            SwarmEvent::Behaviour(Neutrin0BehaviourEvent::Kademlia(event)) => {
                debug!(?event, "kademlia event");
            }
            SwarmEvent::Behaviour(event) => self.handle_rpc_event(event),
            _ => {}
        }
    }

    fn on_connection_established(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        endpoint: &ConnectedPoint,
    ) {
        self.discovery.dial_ended(connection_id, false);
        let trusted = self.bootnodes.trusted_peer(peer_id);
        let outgoing_full = endpoint.is_dialer()
            && !trusted
            && self
                .accepted_connections
                .values()
                .filter(|(_, dialer)| *dialer)
                .count()
                >= 24;
        if outgoing_full
            || self.control_events.len() >= 256
            || !self.guard.connect(
                peer_id,
                endpoint.get_remote_address(),
                trusted,
                tokio::time::Instant::now(),
            )
        {
            self.metrics.guard_action(GuardAction::Connection);
            // The transport connected, so no OutgoingConnectionError
            // will release a configured dial's pending reservation.
            self.bootnodes
                .failed(connection_id, tokio::time::Instant::now(), false);
            self.swarm.close_connection(connection_id);
            return;
        }
        let first = !self
            .accepted_connections
            .values()
            .any(|(peer, _)| *peer == peer_id);
        self.accepted_connections
            .insert(connection_id, (peer_id, endpoint.is_dialer()));
        self.metrics.connected(endpoint.is_dialer(), first);
        self.bootnodes
            .connected(peer_id, connection_id, endpoint.get_remote_address());
        info!(%peer_id, ?endpoint, "connection established");
        if first {
            if let Some(host) =
                super::guard::host_group(endpoint.get_remote_address()).filter(|_| !trusted)
            {
                self.queue_control(NetworkEvent::PeerHost {
                    peer: peer_id,
                    host,
                });
            }
            self.queue_control(NetworkEvent::PeerConnected(peer_id));
        }
    }

    fn on_connection_closed(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        endpoint: &ConnectedPoint,
        cause: Option<&ConnectionError>,
    ) {
        // Rejected connections have no corresponding host-side connect.
        if self.accepted_connections.remove(&connection_id).is_none() {
            return;
        }
        let num_established = u32::try_from(
            self.accepted_connections
                .values()
                .filter(|(peer, _)| *peer == peer_id)
                .count(),
        )
        .expect("bounded connections");
        self.metrics
            .disconnected(endpoint.is_dialer(), num_established == 0);
        self.bootnodes
            .disconnected(peer_id, num_established, tokio::time::Instant::now());
        info!(%peer_id, ?cause, "connection closed");
        if num_established == 0 {
            self.guard.disconnect(&peer_id);
            self.identified_addresses.remove(&peer_id);
            self.swarm.behaviour_mut().kademlia.remove_peer(&peer_id);
            self.queue_control(NetworkEvent::PeerDisconnected(peer_id));
        }
    }

    fn on_outgoing_connection_error(
        &mut self,
        connection_id: ConnectionId,
        peer_id: Option<PeerId>,
        error: &DialError,
    ) {
        self.discovery.dial_ended(connection_id, true);
        if self.bootnodes.failed(
            connection_id,
            tokio::time::Instant::now(),
            matches!(error, DialError::LocalPeerId { .. }),
        ) {
            self.metrics.bootnode_failure(error);
        }
        debug!(?peer_id, %error, "outgoing connection failed");
    }

    fn on_identify_received(&mut self, peer_id: PeerId, info: identify::Info) {
        debug!(%peer_id, listen_addrs = ?info.listen_addrs, "identify received");
        if self.guard.has_peer(&peer_id) {
            let addresses = info
                .listen_addrs
                .into_iter()
                .take(8)
                .filter(|address| {
                    let allowed = self.guard.advertised_address(
                        peer_id,
                        address,
                        self.bootnodes.trusted_peer(peer_id),
                    );
                    if !allowed {
                        self.metrics.guard_action(GuardAction::Address);
                    }
                    allowed
                })
                .collect();
            self.identified_addresses.insert(peer_id, addresses);
            self.promote_addresses(peer_id);
        }
    }

    fn on_gossip_message(
        &mut self,
        propagation_source: PeerId,
        message: gossipsub::Message,
        message_id: gossipsub::MessageId,
    ) {
        self.metrics.gossip_received(message.data.len());
        if let Some(topic) = self.topics.get(&message.topic).copied() {
            let consensus = matches!(
                topic,
                Topic::BftMessages
                    | Topic::FinalityVotesPrevote
                    | Topic::FinalityVotesPrecommit
                    | Topic::AggregateFinalityVotes(_)
            );
            let bytes_used = if consensus {
                self.consensus_gossip_bytes
            } else {
                self.gossip_bytes - self.consensus_gossip_bytes
            };
            let byte_limit = if consensus { 8 } else { 24 } * 1024 * 1024;
            let allowed = self.guard.ready(&propagation_source)
                && self.guard.admit(
                    propagation_source,
                    false,
                    message.data.len(),
                    tokio::time::Instant::now(),
                )
                && !self.gossip_pending.contains_key(&message_id)
                && self.gossip_pending.len() < (if consensus { 128 } else { 96 })
                && bytes_used.saturating_add(message.data.len()) <= byte_limit;
            let size = message.data.len();
            if !allowed
                || self
                    .event_tx
                    .try_send(NetworkEvent::GossipMessage {
                        propagation_source,
                        topic,
                        data: message.data,
                        message_id: message_id.clone(),
                    })
                    .is_err()
            {
                self.metrics.guard_action(GuardAction::Gossip);
                self.metrics
                    .gossip_validation(gossipsub::MessageAcceptance::Ignore);
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .report_message_validation_result(
                        &message_id,
                        &propagation_source,
                        gossipsub::MessageAcceptance::Ignore,
                    );
            } else {
                self.gossip_bytes += size;
                if consensus {
                    self.consensus_gossip_bytes += size;
                }
                self.gossip_pending.insert(message_id, (size, consensus));
            }
        } else {
            self.metrics
                .gossip_validation(gossipsub::MessageAcceptance::Reject);
            warn!(topic = %message.topic, "received gossip on unknown topic; rejecting");
            // An unknown topic from a connected peer is a
            // protocol violation; drop the message and let the
            // scorer count it against them.
            let _ = self
                .swarm
                .behaviour_mut()
                .gossipsub
                .report_message_validation_result(
                    &message_id,
                    &propagation_source,
                    gossipsub::MessageAcceptance::Reject,
                );
        }
    }
}
