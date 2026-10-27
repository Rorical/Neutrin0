//! Outbound side: FSM command dispatch, budgeted RPC sending and routing
//! of RPC results back to the phase that issued them.

use alloc::vec::Vec;
use core::time::Duration;

use neutrin0_network::rpc::{RpcProtocol, RpcRequest, RpcResponse};
use neutrin0_network::service::NetworkCommand;
use neutrin0_network::sync::{SyncCommand, SyncEvent};
use tokio::sync::oneshot;
use tracing::{info, warn};

use super::{
    HistoryRequest, HistoryTarget, SyncDriver, availability, bft, bootstrap, candidates,
    full_chunk, metadata, programs, reporter_paths, transactions,
};

/// Upper bound on waiting for one outbound RPC result, so a vanished peer
/// eventually surfaces as a timeout.
const RPC_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

impl SyncDriver {
    pub(super) async fn dispatch_sync_commands(&mut self, cmds: Vec<SyncCommand>) {
        for cmd in cmds {
            self.dispatch_one(cmd).await;
        }
    }

    pub(super) async fn dispatch_one(&mut self, cmd: SyncCommand) {
        match cmd {
            SyncCommand::RequestStatus(peer) => {
                let local = match self.backend.local_status().await {
                    Ok(status) => status,
                    Err(error) => {
                        warn!(%error, "cannot read local status");
                        return;
                    }
                };
                self.send_rpc(peer, RpcRequest::Status(local), |peer, response| {
                    OutboundOutcome::StatusResponse { peer, response }
                })
                .await;
            }
            SyncCommand::RequestHistoryProof {
                peer,
                anchor_chunks,
                end_chunks,
                checkpoint_hash,
            } => {
                self.request_history(
                    peer,
                    HistoryTarget {
                        anchor_chunks,
                        end_chunks,
                        checkpoint_hash,
                    },
                )
                .await;
            }
            SyncCommand::CheckHistoryConflict {
                peer,
                end_chunks,
                checkpoint_hash,
            } => {
                self.request_conflict_side(
                    peer,
                    HistoryTarget {
                        anchor_chunks: 0,
                        end_chunks,
                        checkpoint_hash,
                    },
                )
                .await;
            }
            SyncCommand::Subscribe(topic) => {
                let _ = self.cmd_tx.send(NetworkCommand::Subscribe(topic)).await;
            }
            SyncCommand::EnterFollowing => {
                info!("sync FSM entered Following");
            }
        }
    }

    /// Reserve one slot and the byte units one `protocol` reply may occupy,
    /// or nothing when the local outbound budget cannot admit it now.
    fn reserve_outbound_budget(
        &self,
        protocol: RpcProtocol,
    ) -> Option<(
        tokio::sync::OwnedSemaphorePermit,
        tokio::sync::OwnedSemaphorePermit,
    )> {
        let units = u32::try_from(protocol.size_limits().1.div_ceil(1024))
            .unwrap_or(u32::MAX)
            .max(1);
        let control = protocol.is_control();
        let bytes = if control {
            &self.outbound_control_bytes
        } else {
            &self.outbound_bytes
        };
        let slots = if control {
            &self.outbound_control_slots
        } else {
            &self.outbound_slots
        };
        // Each admitted identity can handshake without waiting for another
        // peer's callback. Discovery still leaves two full chain replies free.
        let eligible = control
            || protocol.is_chain_data()
            || bytes.available_permits()
                >= usize::try_from(units)
                    .unwrap_or(usize::MAX)
                    .saturating_add(64 * 1024);
        eligible.then_some(()).and_then(|()| {
            slots.clone().try_acquire_owned().ok().and_then(|slots| {
                bytes
                    .clone()
                    .try_acquire_many_owned(units)
                    .ok()
                    .map(|bytes| (slots, bytes))
            })
        })
    }

    /// Convenience: send an outbound RPC, spawning a forwarder task that
    /// translates the `oneshot` result into an [`OutboundOutcome`].
    pub(super) async fn send_rpc<F>(
        &self,
        peer: neutrin0_network::PeerId,
        request: RpcRequest,
        wrap: F,
    ) -> bool
    where
        F: FnOnce(
                neutrin0_network::PeerId,
                Result<RpcResponse, neutrin0_network::rpc::RpcError>,
            ) -> OutboundOutcome
            + Send
            + 'static,
    {
        let Some(budget) = self.reserve_outbound_budget(request.protocol()) else {
            return self
                .outbound_tx
                .try_send(OutboundEnvelope {
                    value: wrap(peer, Err(neutrin0_network::rpc::RpcError::LocalOverloaded)),
                    budget: None,
                })
                .is_ok();
        };
        let (resp_tx, resp_rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(NetworkCommand::SendRpcRequest {
                peer,
                request,
                response_tx: resp_tx,
            })
            .await
            .is_err()
        {
            warn!(%peer, "command channel closed; cannot send RPC");
            return false;
        }
        let outbound_tx = self.outbound_tx.clone();
        tokio::spawn(async move {
            // Bound the wait so a vanished peer eventually surfaces.
            let result = match tokio::time::timeout(RPC_RESPONSE_TIMEOUT, resp_rx).await {
                Ok(Ok(r)) => r,
                Ok(Err(_canceled)) => Err(neutrin0_network::rpc::RpcError::ResponseDeliveryFailed),
                Err(_elapsed) => Err(neutrin0_network::rpc::RpcError::Outbound(
                    "timeout".to_owned(),
                )),
            };
            let _ = outbound_tx
                .send(OutboundEnvelope {
                    value: wrap(peer, result),
                    budget: Some(budget),
                })
                .await;
        });
        true
    }

    /// Release the FSM's matching in-flight request and dispatch any retry.
    pub(super) async fn handle_rpc_failure(
        &mut self,
        protocol: RpcProtocol,
        peer: neutrin0_network::PeerId,
    ) {
        let commands = self.fsm.on_event(SyncEvent::RpcFailed { protocol, peer });
        self.dispatch_sync_commands(commands).await;
    }

    pub(super) async fn handle_outbound_outcome(&mut self, outcome: OutboundOutcome) {
        match outcome {
            OutboundOutcome::Transactions { request, response } => {
                transactions::on_response(self, request, response).await;
            }
            OutboundOutcome::ProgramFragment { request, response } => {
                programs::on_response(self, request, response).await;
            }
            OutboundOutcome::ReporterPath { request, response } => {
                reporter_paths::on_response(self, request, response).await;
            }
            OutboundOutcome::Metadata { peer, response } => {
                metadata::on_response(self, peer, &response);
            }
            OutboundOutcome::SignedArtifact { request, response } => {
                availability::on_response(self, request, response).await;
            }
            OutboundOutcome::BftRound { request, response } => {
                bft::on_response(self, request, response).await;
            }
            OutboundOutcome::BftArtifacts { request, response } => {
                bft::on_artifact_response(self, request, response).await;
            }
            OutboundOutcome::Candidate { request, response } => {
                candidates::on_response(self, request, response).await;
            }
            OutboundOutcome::Bootstrap {
                peer,
                nonce,
                request,
                response,
            } => bootstrap::on_response(self, peer, nonce, request, response).await,
            OutboundOutcome::Consensus {
                peer,
                connection,
                step,
                response,
            } => {
                full_chunk::on_response(self, peer, connection, step, response).await;
            }
            OutboundOutcome::StatusResponse { peer, response } => {
                self.handle_status_response(peer, response).await;
            }
            OutboundOutcome::HistoryProof { request, response } => {
                self.complete_history_request(request, response).await;
            }
            OutboundOutcome::HistoryConflict {
                peer,
                target,
                response,
            } => {
                self.complete_conflict_side(peer, target, response).await;
            }
        }
    }
}

/// Result of one outbound RPC, forwarded from a spawned waiter task back
/// into the main driver loop.
#[derive(Debug)]
pub(super) struct OutboundEnvelope {
    pub(super) value: OutboundOutcome,
    // Lifetime covers the response waiter, queue and final application handling.
    pub(super) budget: Option<(
        tokio::sync::OwnedSemaphorePermit,
        tokio::sync::OwnedSemaphorePermit,
    )>,
}

#[derive(Debug)]
pub(super) enum OutboundOutcome {
    Transactions {
        request: transactions::Request,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    },
    ProgramFragment {
        request: programs::Request,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    },
    ReporterPath {
        request: reporter_paths::Request,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    },
    Metadata {
        peer: neutrin0_network::PeerId,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    },
    SignedArtifact {
        request: availability::Request,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    },
    BftRound {
        request: bft::Request,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    },
    BftArtifacts {
        request: bft::ArtifactRequest,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    },
    Candidate {
        request: candidates::Request,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    },
    Bootstrap {
        peer: neutrin0_network::PeerId,
        nonce: u64,
        request: bootstrap::Request,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    },
    Consensus {
        peer: neutrin0_network::PeerId,
        connection: u64,
        step: full_chunk::Step,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    },
    StatusResponse {
        peer: neutrin0_network::PeerId,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    },
    HistoryProof {
        request: HistoryRequest,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    },
    HistoryConflict {
        peer: neutrin0_network::PeerId,
        target: HistoryTarget,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    },
}
