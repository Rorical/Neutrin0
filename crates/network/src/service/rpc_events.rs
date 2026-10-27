//! Request/response behaviour events: inbound admission and handshake
//! gating, outbound completion and malformed-peer quarantine.

use super::rpc_dispatch::{InboundChannel, send_rpc_response};
use super::{NetworkEvent, NetworkService};
use crate::metrics::GuardAction;
use crate::rpc::{self, RpcError, RpcProtocol, RpcRequest, RpcResponse};
use libp2p::{
    PeerId,
    request_response::{
        self, InboundRequestId, OutboundFailure, OutboundRequestId, ResponseChannel,
    },
};
use std::io;
use tracing::{debug, warn};

impl NetworkService {
    /// Shared handling for one protocol's request/response events. The
    /// constructors tag the decoded request, its response channel and the
    /// peer's reply with this protocol's host-facing variants.
    pub(super) fn handle_rpc<Req: Send + borsh::BorshSerialize, Resp: Send>(
        &mut self,
        protocol: RpcProtocol,
        event: request_response::Event<Req, rpc::RpcResult<Resp>>,
        wrap_request: impl FnOnce(Req) -> RpcRequest + Send,
        wrap_channel: impl FnOnce(ResponseChannel<rpc::RpcResult<Resp>>) -> InboundChannel + Send,
        wrap_response: impl FnOnce(Resp) -> RpcResponse + Send,
    ) {
        self.rpc.observe_event(protocol, &event);
        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request_id,
                        request,
                        channel,
                    },
                ..
            } => {
                self.handle_rpc_request(
                    peer,
                    protocol,
                    request_id,
                    wrap_request(request),
                    wrap_channel(channel),
                );
            }
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(tx) = self.rpc.take_outbound(protocol, request_id) {
                    let response = response.map(wrap_response).map_err(RpcError::Remote);
                    if let Ok(RpcResponse::Status(status)) = &response
                        && !self
                            .guard
                            .status(peer, (status.chain_id, status.chain_spec_hash))
                    {
                        self.metrics.guard_action(GuardAction::Handshake);
                        let _ = self.swarm.disconnect_peer_id(peer);
                        let _ = tx.send(Err(RpcError::Outbound("peer chain mismatch".into())));
                        return;
                    }
                    self.promote_addresses(peer);
                    let _ = tx.send(response);
                }
            }
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                // Timeouts include remote/local scheduling and transport delay;
                // they are availability failures, not objective invalid input.
                let abusive = matches!(&error, OutboundFailure::Io(error) if error.kind() == io::ErrorKind::InvalidData);
                if abusive && self.guard.invalid(peer, tokio::time::Instant::now()) {
                    self.metrics.guard_action(GuardAction::Quarantine);
                    warn!(%peer, ?protocol, ?error, "quarantining malformed RPC responder");
                    let _ = self.swarm.disconnect_peer_id(peer);
                }
                self.complete_outbound_failure(protocol, request_id, &error);
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                // A request is small and sent at once: a stream that announced
                // nothing or stalled its body past the read deadline is abuse,
                // unlike a response timeout, which is ordinary availability.
                let abusive = matches!(
                    &error,
                    request_response::InboundFailure::Io(error)
                        if matches!(error.kind(), io::ErrorKind::InvalidData | io::ErrorKind::TimedOut)
                );
                if abusive && self.guard.invalid(peer, tokio::time::Instant::now()) {
                    self.metrics.guard_action(GuardAction::Quarantine);
                    warn!(%peer, ?protocol, ?error, "quarantining malformed RPC requester");
                    let _ = self.swarm.disconnect_peer_id(peer);
                }
                warn!(%peer, ?protocol, ?error, "inbound RPC failure");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    fn handle_rpc_request(
        &mut self,
        peer: PeerId,
        protocol: RpcProtocol,
        request_id: InboundRequestId,
        request: RpcRequest,
        channel: InboundChannel,
    ) {
        let Some(channel) = self.admit_rpc_request(peer, protocol, &request, channel) else {
            return;
        };
        self.forward_rpc_request(peer, protocol, request_id, request, channel);
    }

    /// Rate-limit the peer, gate on its chain handshake and answer control
    /// requests locally; the channel comes back only when the host must reply.
    fn admit_rpc_request(
        &mut self,
        peer: PeerId,
        protocol: RpcProtocol,
        request: &RpcRequest,
        channel: InboundChannel,
    ) -> Option<InboundChannel> {
        if !self.guard.admit(
            peer,
            true,
            usize::try_from(protocol.size_limits().0).unwrap_or(usize::MAX),
            tokio::time::Instant::now(),
        ) {
            send_rpc_response(
                self.swarm.behaviour_mut(),
                channel,
                RpcResponse::Error {
                    protocol,
                    error: rpc::RpcFailure::Unavailable("peer RPC rate limit".into()),
                },
            );
            return None;
        }
        if let RpcRequest::Status(status) = request {
            if !self
                .guard
                .status(peer, (status.chain_id, status.chain_spec_hash))
            {
                let _ = self.swarm.disconnect_peer_id(peer);
                return None;
            }
            self.promote_addresses(peer);
            if let Some(status) = self.local_status {
                send_rpc_response(
                    self.swarm.behaviour_mut(),
                    channel,
                    RpcResponse::Status(status),
                );
                return None;
            }
        } else if !self.guard.ready(&peer) {
            send_rpc_response(
                self.swarm.behaviour_mut(),
                channel,
                RpcResponse::Error {
                    protocol,
                    error: rpc::RpcFailure::Unavailable("chain handshake required".into()),
                },
            );
            return None;
        }
        if self.local_status.is_some()
            && let RpcRequest::Ping(payload) = request
        {
            send_rpc_response(
                self.swarm.behaviour_mut(),
                channel,
                RpcResponse::Ping(*payload),
            );
            return None;
        }
        Some(channel)
    }

    fn forward_rpc_request(
        &mut self,
        peer: PeerId,
        protocol: RpcProtocol,
        request_id: InboundRequestId,
        request: RpcRequest,
        channel: InboundChannel,
    ) {
        let allowed = self.allow_inbound_host_request(peer, protocol);
        let inbound_id = self.rpc.next_inbound_id(protocol, request_id);
        self.rpc.inbound_channels.insert(inbound_id.raw, channel);
        if !allowed
            || self
                .event_tx
                .try_send(NetworkEvent::RpcRequestReceived {
                    peer,
                    inbound_id,
                    request,
                })
                .is_err()
        {
            self.metrics.guard_action(GuardAction::InboundRpc);
            self.dispatch_outbound_response(
                inbound_id,
                RpcResponse::Error {
                    protocol,
                    error: rpc::RpcFailure::Unavailable(
                        "shared inbound RPC budget exhausted".into(),
                    ),
                },
            );
        } else if let Some(pending) = self
            .rpc
            .inbound_observations
            .get_mut(&(protocol, request_id))
        {
            pending.admitted = true;
        }
    }

    fn allow_inbound_host_request(&self, peer: PeerId, protocol: RpcProtocol) -> bool {
        let mut total = 0;
        let mut bulk = 0;
        let mut auxiliary = 0;
        let mut peer_bulk = 0;
        let mut peer_control = 0;
        let mut peer_auxiliary = 0;
        for ((kind, _), pending) in &self.rpc.inbound_observations {
            if !pending.admitted {
                continue;
            }
            total += 1;
            if pending.peer == peer {
                peer_control += usize::from(kind.is_control());
                peer_bulk += usize::from(!kind.is_control());
                peer_auxiliary += usize::from(!kind.is_control() && !kind.is_chain_data());
            }
            if !kind.is_control() {
                bulk += 1;
                auxiliary += usize::from(!kind.is_chain_data());
            }
        }
        let control = protocol.is_control();
        total < 20
            && (if control {
                total - bulk < 4 && peer_control < 1
            } else {
                bulk < 16 && peer_bulk < 4
            })
            && (control || protocol.is_chain_data() || (auxiliary < 14 && peer_auxiliary < 3))
    }

    fn complete_outbound_failure(
        &mut self,
        protocol: RpcProtocol,
        request_id: OutboundRequestId,
        error: &OutboundFailure,
    ) {
        self.metrics.outbound_failure(protocol, error);
        if let Some(tx) = self.rpc.take_outbound(protocol, request_id) {
            tx.fail(error);
        } else {
            debug!(?protocol, ?error, "outbound failure for unknown request id");
        }
    }
}
