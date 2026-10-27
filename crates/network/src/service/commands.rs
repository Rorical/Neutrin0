//! Execution of host [`NetworkCommand`]s: dialing, gossip, RPC dispatch
//! and peer-score queries.

use super::rpc_dispatch::{response_len, send_rpc_request, send_rpc_response};
use super::{NetworkCommand, NetworkService};
use crate::metrics::GuardAction;
use crate::rpc::{RpcError, RpcInboundId, RpcProtocol, RpcRequest, RpcResponse};
use libp2p::{PeerId, gossipsub, swarm::dial_opts::DialOpts};
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

impl NetworkService {
    pub(super) fn handle_command(&mut self, command: NetworkCommand) {
        match command {
            NetworkCommand::Dial(addr) => {
                if let Some(index) = self.bootnodes.manual_target(&addr) {
                    self.dial_bootnode(index, DialOpts::from(addr));
                    return;
                }
                info!(%addr, "dialing peer");
                if let Err(err) = self.swarm.dial(addr) {
                    error!(?err, "dial failed");
                }
            }
            NetworkCommand::Subscribe(topic) => {
                let ident = topic.to_ident();
                match self.swarm.behaviour_mut().gossipsub.subscribe(&ident) {
                    Ok(true) => info!(%topic, "subscribed to topic"),
                    Ok(false) => debug!(%topic, "already subscribed to topic"),
                    Err(err) => error!(%topic, ?err, "subscribe failed"),
                }
            }
            NetworkCommand::Publish { topic, data } => {
                let ident = topic.to_ident();
                let result = self.swarm.behaviour_mut().gossipsub.publish(ident, data);
                self.metrics.gossip_publish(&result);
                match result {
                    Ok(msg_id) => debug!(%topic, %msg_id, "published"),
                    Err(gossipsub::PublishError::Duplicate) => {
                        debug!(%topic, "exact gossip content already published");
                    }
                    Err(err) => warn!(%topic, ?err, "publish failed"),
                }
            }
            NetworkCommand::SendRpcRequest {
                peer,
                request,
                response_tx,
            } => self.dispatch_outbound_request(peer, request, response_tx),
            NetworkCommand::SendRpcResponse {
                inbound_id,
                response,
            } => self.dispatch_outbound_response(inbound_id, response),
            NetworkCommand::QueryPeerScores { response_tx } => {
                let gossipsub = &self.swarm.behaviour().gossipsub;
                let mut snapshot = Vec::new();
                for peer in gossipsub.all_peers().map(|(peer_id, _)| *peer_id) {
                    if let Some(score) = gossipsub.peer_score(&peer) {
                        snapshot.push((peer, score));
                    }
                }
                let _ = response_tx.send(snapshot);
            }
            NetworkCommand::ReportGossipValidation {
                message_id,
                propagation_source,
                acceptance,
            } => self.report_gossip_validation(&message_id, propagation_source, acceptance),
        }
    }

    fn report_gossip_validation(
        &mut self,
        message_id: &gossipsub::MessageId,
        propagation_source: PeerId,
        acceptance: gossipsub::MessageAcceptance,
    ) {
        if let Some((bytes, consensus)) = self.gossip_pending.remove(message_id) {
            self.gossip_bytes = self.gossip_bytes.saturating_sub(bytes);
            if consensus {
                self.consensus_gossip_bytes = self.consensus_gossip_bytes.saturating_sub(bytes);
            }
        }
        if matches!(acceptance, gossipsub::MessageAcceptance::Reject)
            && self
                .guard
                .invalid(propagation_source, tokio::time::Instant::now())
        {
            self.metrics.guard_action(GuardAction::Quarantine);
            let _ = self.swarm.disconnect_peer_id(propagation_source);
        }
        self.metrics.gossip_validation(acceptance);
        let _ = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(message_id, &propagation_source, acceptance);
    }

    pub(super) fn dispatch_outbound_request(
        &mut self,
        peer: PeerId,
        request: RpcRequest,
        response_tx: oneshot::Sender<Result<RpcResponse, RpcError>>,
    ) {
        let protocol = request.protocol();
        if let RpcRequest::Status(status) = &request {
            self.local_status = Some(*status);
        }
        let control = protocol.is_control();
        let peer_pending = self
            .rpc
            .pending_outbound
            .iter()
            .filter(|((protocol, _), entry)| {
                entry.peer == peer
                    && control
                        == matches!(
                            protocol,
                            RpcProtocol::Status | RpcProtocol::Ping | RpcProtocol::Metadata
                        )
            })
            .count();
        let pending_bytes: u64 = self
            .rpc
            .pending_outbound
            .iter()
            .filter(|((protocol, _), _)| !protocol.is_control())
            .map(|(_, entry)| entry.reserved_bytes)
            .sum();
        let bulk = self
            .rpc
            .pending_outbound
            .keys()
            .filter(|(protocol, _)| !protocol.is_control())
            .count();
        let auxiliary = self
            .rpc
            .pending_outbound
            .keys()
            .filter(|(protocol, _)| !protocol.is_control() && !protocol.is_chain_data())
            .count();
        let auxiliary_bytes: u64 = self
            .rpc
            .pending_outbound
            .iter()
            .filter(|((protocol, _), _)| !protocol.is_control() && !protocol.is_chain_data())
            .map(|(_, entry)| entry.reserved_bytes)
            .sum();
        if peer_pending >= if control { 1 } else { 4 }
            // One tiny control request per permitted identity must fit even
            // when every connection handshakes together and bulk work is full.
            || (control && self.rpc.pending_outbound.len().saturating_sub(bulk) >= 64)
            || (!control && bulk >= 8)
            || (!control && !protocol.is_chain_data() && auxiliary >= 6)
            || (!control
                && !protocol.is_chain_data()
                && auxiliary_bytes.saturating_add(protocol.size_limits().1) > 64 * 1024 * 1024)
            || (!control
                && pending_bytes.saturating_add(protocol.size_limits().1) > 128 * 1024 * 1024)
        {
            self.metrics.guard_action(GuardAction::OutboundRpc);
            let _ = response_tx.send(Err(RpcError::LocalOverloaded));
            return;
        }
        let id = send_rpc_request(self.swarm.behaviour_mut(), &peer, request);
        self.rpc.record_outbound(peer, protocol, id, response_tx);
    }

    pub(super) fn dispatch_outbound_response(
        &mut self,
        inbound_id: RpcInboundId,
        response: RpcResponse,
    ) {
        if response.protocol() != inbound_id.protocol {
            warn!(
                inbound = ?inbound_id,
                response = ?response.protocol(),
                "rejecting mismatched RPC response"
            );
            return;
        }

        self.rpc.response_outcome(inbound_id, &response);
        // A request is admitted against its request cap; what it pulls is
        // charged here, so later requests wait once a peer's egress is spent.
        if let Some(peer) = self.rpc.inbound_peer(inbound_id) {
            self.guard
                .charge(peer, response_len(&response), tokio::time::Instant::now());
        }
        let delivered = self
            .rpc
            .take_inbound_channel(inbound_id)
            .is_some_and(|channel| {
                send_rpc_response(self.swarm.behaviour_mut(), channel, response)
            });

        if !delivered {
            self.rpc.response_delivery_failed(inbound_id);
            warn!(?inbound_id, "failed to deliver RPC response (timed out?)");
        }
    }
}
