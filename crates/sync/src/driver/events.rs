//! Network event intake: peer membership, gossip routing to the topic
//! handlers and inbound RPC service.

use alloc::sync::Arc;
use core::time::Duration;

use neutrin0_network::rpc::{RpcInboundId, RpcRequest, RpcResponse};
use neutrin0_network::service::{NetworkCommand, NetworkEvent};
use neutrin0_network::sync::SyncEvent;
use tracing::debug;

use super::{
    SyncDriver, availability, bft, bootstrap, candidates, full_chunk, inbound, metadata,
    transactions,
};

/// Inbound data queries served at once. The network admits each peer's
/// requests at a bounded rate; this bounds the engine work they start.
pub(super) const INBOUND_QUERY_SLOTS: usize = 4;

/// Longest an inbound query waits for its peer's slot and a shared one
/// before it is refused as busy, well inside a requester's timeout.
const INBOUND_QUERY_WAIT: Duration = Duration::from_secs(5);

impl SyncDriver {
    pub(super) async fn handle_network_event(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::PeerConnected(peer) => {
                debug!(%peer, "peer connected, dispatching FSM event");
                let new_peer = self.connected_peers.insert(peer);
                if new_peer {
                    full_chunk::on_connect(self, peer);
                    bootstrap::on_connect(self, peer);
                    candidates::on_connect(self, peer);
                    bft::on_connect(self, peer);
                    availability::on_connect(self, peer);
                    transactions::on_connect(self, peer);
                }
                let cmds = self.fsm.on_event(SyncEvent::PeerConnected(peer));
                self.dispatch_sync_commands(cmds).await;
                if new_peer {
                    metadata::on_connect(self, peer).await;
                }
            }
            NetworkEvent::PeerHost { peer, host } => {
                self.fsm.on_event(SyncEvent::PeerHost { peer, host });
            }
            NetworkEvent::PeerDisconnected(peer) => {
                debug!(%peer, "peer disconnected");
                self.connected_peers.remove(&peer);
                transactions::on_disconnect(self, peer);
                metadata::on_disconnect(self, peer);
                let interrupted_history = self
                    .active_history_request
                    .is_some_and(|request| request.peer == peer);
                if interrupted_history {
                    self.active_history_request = None;
                }
                self.deferred_history_status.remove(&peer);
                full_chunk::on_disconnect(self, peer);
                candidates::on_disconnect(self, peer).await;
                bft::on_disconnect(self, peer);
                availability::on_disconnect(self, peer).await;
                bootstrap::on_disconnect(self, peer).await;
                let cmds = self.fsm.on_event(SyncEvent::PeerDisconnected(peer));
                self.dispatch_sync_commands(cmds).await;
                if interrupted_history {
                    self.resume_deferred_history_status().await;
                }
                self.try_next_history_provider().await;
            }
            NetworkEvent::NewListenAddr(addr) => {
                debug!(%addr, "node listening on new address");
            }
            NetworkEvent::GossipMessage {
                topic,
                data,
                propagation_source,
                message_id,
            } => {
                let verdict = self.handle_gossip(topic, data, propagation_source).await;
                let _ = self
                    .cmd_tx
                    .send(NetworkCommand::ReportGossipValidation {
                        message_id,
                        propagation_source,
                        acceptance: verdict,
                    })
                    .await;
            }
            NetworkEvent::RpcRequestReceived {
                peer,
                inbound_id,
                request,
            } => {
                self.handle_inbound_rpc(peer, inbound_id, request).await;
            }
        }
    }

    /// Force the FSM back to `Init` and re-handshake every still-connected peer
    /// so the next [`rpc::Status`] response advances from the newly installed
    /// local boundary. Only the local, atomically installed bootstrap calls
    /// this; a peer's gossip can never reset the FSM.
    pub(super) async fn reset_and_rehandshake(&mut self) {
        self.active_history_request = None;
        self.deferred_history_status.clear();
        let cmds = self.fsm.on_event(SyncEvent::Reset);
        self.dispatch_sync_commands(cmds).await;
        let peers: Vec<_> = self.connected_peers.iter().copied().collect();
        for peer in peers {
            let cmds = self.fsm.on_event(SyncEvent::PeerConnected(peer));
            self.dispatch_sync_commands(cmds).await;
        }
    }

    /// Answer a peer's request. Handshake and liveness queries are cheap and
    /// answered here; data queries run off this task, so a slow one never
    /// stalls gossip, votes or sync. At most [`INBOUND_QUERY_SLOTS`] run at
    /// once and each peer runs one at a time, so no peer starves the others;
    /// a query waits for both in arrival order and is refused as busy after
    /// [`INBOUND_QUERY_WAIT`] rather than queued past its requester's timeout.
    async fn handle_inbound_rpc(
        &mut self,
        peer: neutrin0_network::PeerId,
        inbound_id: RpcInboundId,
        request: RpcRequest,
    ) {
        debug!(
            %peer,
            protocol = ?inbound_id.protocol,
            "serving inbound RPC"
        );
        if matches!(
            request,
            RpcRequest::Status(_) | RpcRequest::Metadata(_) | RpcRequest::Ping(_)
        ) {
            let response = inbound::response(self.backend.as_ref(), request).await;
            let _ = self
                .cmd_tx
                .send(NetworkCommand::SendRpcResponse {
                    inbound_id,
                    response,
                })
                .await;
            return;
        }
        // A peer's slot outlives its connection while its queries run, so
        // reconnecting never grants a second one; idle slots of departed
        // peers are dropped, bounding the map.
        let connected = &self.connected_peers;
        self.inbound_peer_slots
            .retain(|peer, slot| connected.contains(peer) || Arc::strong_count(slot) > 1);
        if !connected.contains(&peer) {
            let _ = self
                .cmd_tx
                .send(NetworkCommand::SendRpcResponse {
                    inbound_id,
                    response: RpcResponse::Error {
                        protocol: inbound_id.protocol,
                        error: neutrin0_network::rpc::RpcFailure::Unavailable(
                            "peer is not connected".into(),
                        ),
                    },
                })
                .await;
            return;
        }
        let own = Arc::clone(
            self.inbound_peer_slots
                .entry(peer)
                .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(1))),
        );
        let shared = Arc::clone(&self.inbound_slots);
        let backend = Arc::clone(&self.backend);
        let cmd_tx = self.cmd_tx.clone();
        tokio::spawn(async move {
            let slots = async { (own.acquire_owned().await, shared.acquire_owned().await) };
            let response = match tokio::time::timeout(INBOUND_QUERY_WAIT, slots).await {
                Ok((Ok(own), Ok(shared))) => {
                    let response = inbound::response(backend.as_ref(), request).await;
                    drop((own, shared));
                    response
                }
                _ => RpcResponse::Error {
                    protocol: inbound_id.protocol,
                    error: neutrin0_network::rpc::RpcFailure::Unavailable(
                        "query capacity is busy".into(),
                    ),
                },
            };
            let _ = cmd_tx
                .send(NetworkCommand::SendRpcResponse {
                    inbound_id,
                    response,
                })
                .await;
        });
    }
}
