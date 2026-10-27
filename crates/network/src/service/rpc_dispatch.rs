//! In-flight RPC bookkeeping across the independent request/response
//! behaviours, and the table-driven per-protocol plumbing.

use super::NetworkService;
use crate::behaviour::{Neutrin0Behaviour, Neutrin0BehaviourEvent};
use crate::metrics::{Direction, NetworkMetrics, RpcObservation, RpcOutcome};
use crate::rpc::{self, RpcError, RpcInboundId, RpcProtocol, RpcRequest, RpcResponse};
use libp2p::{
    PeerId,
    request_response::{
        self, InboundRequestId, OutboundFailure, OutboundRequestId, ResponseChannel,
    },
};
use std::{collections::HashMap, io, sync::Arc};
use tokio::sync::oneshot;

pub(super) struct PendingOutbound {
    tx: oneshot::Sender<Result<RpcResponse, RpcError>>,
    observation: RpcObservation,
    pub(super) reserved_bytes: u64,
    pub(super) peer: PeerId,
}

impl PendingOutbound {
    pub(super) fn send(self, result: Result<RpcResponse, RpcError>) -> bool {
        let Self {
            tx,
            mut observation,
            ..
        } = self;
        let outcome = match &result {
            Ok(_) => RpcOutcome::Ok,
            Err(RpcError::Remote(_)) => RpcOutcome::RemoteError,
            Err(_) => RpcOutcome::DeliveryFailed,
        };
        let delivered = tx.send(result).is_ok();
        observation.complete(if delivered {
            outcome
        } else {
            RpcOutcome::DeliveryFailed
        });
        delivered
    }

    pub(super) fn fail(self, error: &OutboundFailure) {
        let Self {
            tx,
            mut observation,
            ..
        } = self;
        observation.complete(RpcOutcome::outbound(error));
        let error = if matches!(error, OutboundFailure::Io(error) if error.kind() == io::ErrorKind::WouldBlock)
        {
            RpcError::LocalOverloaded
        } else {
            RpcError::Outbound(format!("{error:?}"))
        };
        let _ = tx.send(Err(error));
    }
}

pub(super) struct PendingInbound {
    observation: RpcObservation,
    response_outcome: RpcOutcome,
    /// Host-facing wire id, assigned once the request is forwarded.
    raw: Option<u64>,
    pub(super) peer: PeerId,
    /// Charged through wire delivery, excluding automatic overload replies.
    pub(super) admitted: bool,
}

/// Tracks in-flight RPC state across the independent
/// `request_response::Behaviour` instances.
///
/// libp2p's `OutboundRequestId` is unique only per Behaviour, so outbound
/// state is keyed by `(protocol, id)`. Inbound state is keyed by one
/// service-local monotonic id shared by every protocol, because libp2p does
/// not expose a public constructor for `InboundRequestId` and so its id
/// cannot round-trip through the host API.
#[derive(Default)]
pub(super) struct RpcDispatch {
    pub(super) next_inbound_raw: u64,
    pub(super) metrics: Arc<NetworkMetrics>,
    pub(super) inbound_observations: HashMap<(RpcProtocol, InboundRequestId), PendingInbound>,
    pub(super) inbound_wire_ids: HashMap<u64, (RpcProtocol, InboundRequestId)>,
    /// Response channels awaiting the host's reply, by raw inbound id.
    pub(super) inbound_channels: HashMap<u64, InboundChannel>,
    pub(super) pending_outbound: HashMap<(RpcProtocol, OutboundRequestId), PendingOutbound>,
}

impl RpcDispatch {
    pub(super) fn observe_event<Q, R>(
        &mut self,
        protocol: RpcProtocol,
        event: &request_response::Event<Q, R>,
    ) {
        match event {
            request_response::Event::Message {
                peer,
                message: request_response::Message::Request { request_id, .. },
                ..
            } => {
                self.inbound_observations.insert(
                    (protocol, *request_id),
                    PendingInbound {
                        observation: self.metrics.rpc_start(protocol, Direction::Inbound),
                        response_outcome: RpcOutcome::Ok,
                        raw: None,
                        peer: *peer,
                        admitted: false,
                    },
                );
            }
            request_response::Event::InboundFailure {
                request_id, error, ..
            } => {
                let outcome = self.metrics.inbound_failure(protocol, error);
                self.finish_inbound(protocol, *request_id, outcome);
            }
            request_response::Event::ResponseSent { request_id, .. } => {
                if let Some(pending) = self.inbound_observations.get(&(protocol, *request_id)) {
                    let outcome = pending.response_outcome;
                    self.finish_inbound(protocol, *request_id, outcome);
                }
            }
            _ => {}
        }
    }

    pub(super) fn response_outcome(&mut self, inbound_id: RpcInboundId, response: &RpcResponse) {
        if let Some(key) = self.inbound_wire_ids.get(&inbound_id.raw)
            && let Some(pending) = self.inbound_observations.get_mut(key)
        {
            pending.response_outcome = if matches!(response, RpcResponse::Error { .. }) {
                RpcOutcome::RemoteError
            } else {
                RpcOutcome::Ok
            };
        }
    }

    /// The peer whose request `inbound_id` answers, while it is in flight.
    pub(super) fn inbound_peer(&self, inbound_id: RpcInboundId) -> Option<PeerId> {
        let key = self.inbound_wire_ids.get(&inbound_id.raw)?;
        self.inbound_observations
            .get(key)
            .map(|pending| pending.peer)
    }

    pub(super) fn response_delivery_failed(&mut self, inbound_id: RpcInboundId) {
        if let Some(&(protocol, request_id)) = self.inbound_wire_ids.get(&inbound_id.raw) {
            self.finish_inbound(protocol, request_id, RpcOutcome::DeliveryFailed);
        }
    }

    fn finish_inbound(
        &mut self,
        protocol: RpcProtocol,
        request_id: InboundRequestId,
        outcome: RpcOutcome,
    ) {
        let Some(mut pending) = self.inbound_observations.remove(&(protocol, request_id)) else {
            return;
        };
        pending.observation.complete(outcome);
        if let Some(raw) = pending.raw {
            self.inbound_wire_ids.remove(&raw);
            // A timeout can precede the host's reply; release its stale channel too.
            self.inbound_channels.remove(&raw);
        }
    }

    pub(super) fn next_inbound_id(
        &mut self,
        protocol: RpcProtocol,
        request_id: InboundRequestId,
    ) -> RpcInboundId {
        let raw = self.next_inbound_raw;
        self.next_inbound_raw = self.next_inbound_raw.wrapping_add(1);
        if let Some(pending) = self.inbound_observations.get_mut(&(protocol, request_id)) {
            pending.raw = Some(raw);
        }
        self.inbound_wire_ids.insert(raw, (protocol, request_id));
        RpcInboundId { protocol, raw }
    }

    /// Remove a reply channel only when `inbound_id` also names its protocol;
    /// a forged protocol tag leaves the real request's channel in place.
    pub(super) fn take_inbound_channel(
        &mut self,
        inbound_id: RpcInboundId,
    ) -> Option<InboundChannel> {
        if self.inbound_channels.get(&inbound_id.raw)?.protocol() != inbound_id.protocol {
            return None;
        }
        self.inbound_channels.remove(&inbound_id.raw)
    }

    pub(super) fn record_outbound(
        &mut self,
        peer: PeerId,
        protocol: RpcProtocol,
        id: OutboundRequestId,
        tx: oneshot::Sender<Result<RpcResponse, RpcError>>,
    ) {
        let pending = PendingOutbound {
            tx,
            observation: self.metrics.rpc_start(protocol, Direction::Outbound),
            reserved_bytes: protocol.size_limits().1,
            peer,
        };
        self.pending_outbound.insert((protocol, id), pending);
    }

    pub(super) fn take_outbound(
        &mut self,
        protocol: RpcProtocol,
        id: OutboundRequestId,
    ) -> Option<PendingOutbound> {
        self.pending_outbound.remove(&(protocol, id))
    }
}

/// Moves a payload between its wire type and its possibly boxed
/// [`RpcResponse`] field.
trait Unbox<T> {
    /// Wrap a decoded wire payload for the host-facing response.
    fn wrap(payload: T) -> Self;
    /// Recover the wire payload from the host-facing response.
    fn unbox(self) -> T;
    /// Borrow the wire payload.
    fn payload(&self) -> &T;
}

impl<T> Unbox<T> for T {
    fn wrap(payload: T) -> Self {
        payload
    }

    fn unbox(self) -> T {
        self
    }

    fn payload(&self) -> &T {
        self
    }
}

impl<T> Unbox<T> for Box<T> {
    fn wrap(payload: T) -> Self {
        Self::new(payload)
    }

    fn unbox(self) -> T {
        *self
    }

    fn payload(&self) -> &T {
        self
    }
}

/// Generates the per-protocol plumbing from one table row per protocol:
/// `Variant => behaviour field, behaviour event variant, response payload;`.
/// `Variant` names the matching [`RpcProtocol`], [`RpcRequest`],
/// [`RpcResponse`] and `InboundChannel` variants.
macro_rules! rpc_protocols {
    ($($variant:ident => $field:ident, $event:ident, $payload:ty;)+) => {
        /// A pending inbound reply channel, tagged by its protocol.
        pub(super) enum InboundChannel {
            $($variant(ResponseChannel<rpc::RpcResult<$payload>>),)+
        }

        impl InboundChannel {
            const fn protocol(&self) -> RpcProtocol {
                match self {
                    $(Self::$variant(_) => RpcProtocol::$variant,)+
                }
            }
        }

        /// Send `request` on its protocol's behaviour.
        pub(super) fn send_rpc_request(
            behaviour: &mut Neutrin0Behaviour,
            peer: &PeerId,
            request: RpcRequest,
        ) -> OutboundRequestId {
            match request {
                $(RpcRequest::$variant(request) => behaviour.$field.send_request(peer, request),)+
            }
        }

        /// Encoded size of a host response's payload, which the requester's
        /// egress budget is charged; an error reply is negligible.
        pub(super) fn response_len(response: &RpcResponse) -> usize {
            let length = match response {
                $(RpcResponse::$variant(payload) => {
                    borsh::object_length(<_ as Unbox<$payload>>::payload(payload))
                })+
                RpcResponse::Error { .. } => Ok(0),
            };
            length.unwrap_or(usize::MAX)
        }

        /// Deliver `response` on `channel`; a payload for another protocol is not sent.
        pub(super) fn send_rpc_response(
            behaviour: &mut Neutrin0Behaviour,
            channel: InboundChannel,
            response: RpcResponse,
        ) -> bool {
            match (channel, response) {
                $(
                    (InboundChannel::$variant(channel), RpcResponse::$variant(payload)) => behaviour
                        .$field
                        .send_response(channel, Ok(Unbox::unbox(payload)))
                        .is_ok(),
                    (InboundChannel::$variant(channel), RpcResponse::Error { error, .. }) => {
                        behaviour.$field.send_response(channel, Err(error)).is_ok()
                    }
                )+
                _ => false,
            }
        }

        impl NetworkService {
            /// Route a request/response behaviour event; other events are ignored.
            pub(super) fn handle_rpc_event(&mut self, event: Neutrin0BehaviourEvent) {
                match event {
                    $(Neutrin0BehaviourEvent::$event(event) => {
                        self.handle_rpc(
                            RpcProtocol::$variant,
                            event,
                            RpcRequest::$variant,
                            InboundChannel::$variant,
                            |payload| RpcResponse::$variant(Unbox::wrap(payload)),
                        );
                    })+
                    _ => {}
                }
            }
        }
    };
}

rpc_protocols! {
    Status => rpc_status, RpcStatus, rpc::Status;
    Metadata => rpc_metadata, RpcMetadata, rpc::Metadata;
    Ping => rpc_ping, RpcPing, rpc::PingPayload;
    BlocksByRange => rpc_blocks_by_range, RpcBlocksByRange, rpc::BlocksByRangeResponse;
    StateByRoot => rpc_state_by_root, RpcStateByRoot, rpc::StateByRootResponse;
    ChunkProofById => rpc_chunk_proof_by_id, RpcChunkProofById, rpc::ChunkProofByIdResponse;
    HistoryProof => rpc_history_proof, RpcHistoryProof, rpc::HistoryProofResponse;
    FinalityCertByChunk =>
        rpc_finality_cert_by_chunk, RpcFinalityCertByChunk, rpc::FinalityCertByChunkResponse;
    WitnessByBlock => rpc_witness_by_block, RpcWitnessByBlock, rpc::WitnessByBlockResponse;
    ReceiptsByHash => rpc_receipts_by_hash, RpcReceiptsByHash, rpc::ReceiptsByHashResponse;
    CandidateByChunk =>
        rpc_candidate_by_chunk, RpcCandidateByChunk, rpc::CandidateByChunkResponse;
    SignedArtifactById =>
        rpc_signed_artifact_by_id, RpcSignedArtifactById, rpc::SignedArtifactByIdResponse;
    SignedArtifactInventoryByChunk =>
        rpc_signed_artifact_inventory_by_chunk,
        RpcSignedArtifactInventoryByChunk,
        rpc::SignedArtifactInventoryByChunkResponse;
    BftRoundByChunk =>
        rpc_bft_round_by_chunk, RpcBftRoundByChunk, rpc::BftRoundByChunkResponse;
    TransactionInventory =>
        rpc_transaction_inventory, RpcTransactionInventory, rpc::TransactionInventoryResponse;
    TransactionsByHash =>
        rpc_transactions_by_hash, RpcTransactionsByHash, rpc::TransactionsByHashResponse;
}
