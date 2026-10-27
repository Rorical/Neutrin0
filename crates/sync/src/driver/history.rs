//! Light-client History proof retrieval: provider rounds, conflict
//! sampling and proof import.

use neutrin0_network::rpc::{HistoryProofRequest, RpcProtocol, RpcRequest, RpcResponse};
use neutrin0_network::sync::{SyncCommand, SyncEvent, SyncMode};
use tracing::{debug, error, warn};

use crate::backend::SyncBackendError;

use super::{HISTORY_PROVIDER_ATTEMPT_LIMIT, OutboundOutcome, SyncDriver};

/// Conflict sides fetched or verified at once; further sides wait for a
/// later status.
const HISTORY_CONFLICT_CHECK_LIMIT: usize = 16;

/// The exact endpoint a light-client History request names.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct HistoryTarget {
    pub(super) anchor_chunks: u64,
    pub(super) end_chunks: u64,
    pub(super) checkpoint_hash: neutrin0_primitives::Hash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct HistoryRequest {
    pub(super) peer: neutrin0_network::PeerId,
    pub(super) target: HistoryTarget,
    pub(super) nonce: u64,
    pub(super) notice_generation: u64,
}

impl SyncDriver {
    pub(super) async fn request_history(
        &mut self,
        peer: neutrin0_network::PeerId,
        target: HistoryTarget,
    ) {
        if self.active_history_request.is_some() {
            return;
        }
        if self.history_attempt_target != Some(target) {
            self.history_attempt_target = Some(target);
            self.history_attempts.clear();
        }
        if self.history_attempts.len() >= HISTORY_PROVIDER_ATTEMPT_LIMIT
            || !self.history_attempts.insert(peer)
        {
            let _ = self.fsm.on_event(SyncEvent::RpcFailed {
                protocol: RpcProtocol::HistoryProof,
                peer,
            });
            return;
        }
        let notice_generation = self
            .history_announcement
            .map_or(0, |(generation, _)| generation);
        let Some(nonce) = self.next_history_nonce.checked_add(1) else {
            let _ = self.fsm.on_event(SyncEvent::RpcFailed {
                protocol: RpcProtocol::HistoryProof,
                peer,
            });
            return;
        };
        self.next_history_nonce = nonce;
        let request = HistoryRequest {
            peer,
            target,
            nonce,
            notice_generation,
        };
        self.active_history_request = Some(request);
        let sent = self
            .send_rpc(
                peer,
                RpcRequest::HistoryProof(HistoryProofRequest {
                    anchor_chunks: target.anchor_chunks,
                    end_chunks: target.end_chunks,
                    checkpoint_hash: target.checkpoint_hash,
                    bootstrap: false,
                }),
                move |_, response| OutboundOutcome::HistoryProof { request, response },
            )
            .await;
        if !sent {
            self.active_history_request = None;
            let _ = self.fsm.on_event(SyncEvent::RpcFailed {
                protocol: RpcProtocol::HistoryProof,
                peer,
            });
        }
    }

    /// Fetch one side of a sampled conflict, once per endpoint. Checks
    /// below the client's own endpoint are forgotten, and a full table
    /// forgets settled checks, lowest count first, before it refuses one:
    /// a settled check is only a cache, and a stale table must never stop
    /// the client from judging a new conflict.
    pub(super) async fn request_conflict_side(
        &mut self,
        peer: neutrin0_network::PeerId,
        target: HistoryTarget,
    ) {
        let local = self.fsm.progress().finalized_chunks();
        // An in-flight check stays until its response settles it.
        self.conflict_checks
            .retain(|checked, settled| checked.end_chunks >= local || !*settled);
        if self.conflict_checks.contains_key(&target) {
            return;
        }
        if self.conflict_checks.len() >= HISTORY_CONFLICT_CHECK_LIMIT
            && let Some(settled) = self
                .conflict_checks
                .iter()
                .filter(|(_, settled)| **settled)
                .map(|(checked, _)| *checked)
                .min_by_key(|checked| checked.end_chunks)
        {
            self.conflict_checks.remove(&settled);
        }
        if self.conflict_checks.len() >= HISTORY_CONFLICT_CHECK_LIMIT {
            return;
        }
        self.conflict_checks.insert(target, false);
        let sent = self
            .send_rpc(
                peer,
                RpcRequest::HistoryProof(HistoryProofRequest {
                    anchor_chunks: 0,
                    end_chunks: target.end_chunks,
                    checkpoint_hash: target.checkpoint_hash,
                    bootstrap: false,
                }),
                move |peer, response| OutboundOutcome::HistoryConflict {
                    peer,
                    target,
                    response,
                },
            )
            .await;
        if !sent {
            self.conflict_checks.remove(&target);
        }
    }

    /// Verify a fetched conflict side. A peer that cannot back its
    /// advertisement with a valid proof stops counting as a sample.
    pub(super) async fn complete_conflict_side(
        &mut self,
        peer: neutrin0_network::PeerId,
        target: HistoryTarget,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    ) {
        let proof = match response {
            Ok(RpcResponse::HistoryProof(payload))
                if payload.proof.end_checkpoint().hash() == target.checkpoint_hash
                    && payload.proof.end().next_chunk_id == target.end_chunks =>
            {
                payload.proof
            }
            _ => {
                self.conflict_checks.remove(&target);
                let commands = self.fsm.on_event(SyncEvent::SampleRejected(peer));
                self.dispatch_sync_commands(commands).await;
                return;
            }
        };
        match self.backend.verify_history_conflict(proof).await {
            Ok(true) => {
                self.conflict_checks.insert(target, true);
                error!(
                    chunks = target.end_chunks,
                    "two verified History proofs disagree; light client halted until a new trusted checkpoint is configured"
                );
                self.active_history_request = None;
                let _ = self.fsm.on_event(SyncEvent::HistoryConflict);
            }
            Ok(false) => {
                self.conflict_checks.insert(target, true);
            }
            Err(SyncBackendError::Rejected(reason)) => {
                warn!(%peer, %reason, "conflicting History proof is invalid");
                self.conflict_checks.remove(&target);
                let commands = self.fsm.on_event(SyncEvent::SampleRejected(peer));
                self.dispatch_sync_commands(commands).await;
            }
            Err(error) => {
                debug!(%peer, %error, "conflicting History proof not checked yet");
                self.conflict_checks.remove(&target);
            }
        }
    }

    pub(super) async fn complete_history_request(
        &mut self,
        request: HistoryRequest,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    ) {
        if self.active_history_request != Some(request) {
            return;
        }
        self.active_history_request = None;
        self.handle_history_rpc_response(request.peer, request.target, response)
            .await;
        if let Some((generation, source)) = self.history_announcement
            && generation != request.notice_generation
        {
            self.dispatch_one(SyncCommand::RequestStatus(source)).await;
        }
        self.resume_deferred_history_status().await;
        self.try_next_history_provider().await;
    }

    pub(super) async fn try_next_history_provider(&mut self) {
        if self.fsm.mode() != SyncMode::LightClient || self.active_history_request.is_some() {
            return;
        }
        let agreeing = self.fsm.history_providers();
        let Some(peer) = agreeing
            .iter()
            .chain(self.connected_peers.iter())
            .filter(|peer| self.connected_peers.contains(peer))
            .find(|peer| !self.history_attempts.contains(peer))
            // A target can change while the last request is pending. Let the
            // request gate observe that new range even after the old round was
            // exhausted; an unchanged range emits no network request.
            .or_else(|| self.connected_peers.iter().next())
            .copied()
        else {
            return;
        };
        let commands = self.fsm.retry_history_from(peer);
        self.dispatch_sync_commands(commands).await;
    }

    async fn handle_history_rpc_response(
        &mut self,
        peer: neutrin0_network::PeerId,
        target: HistoryTarget,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    ) {
        match response {
            Ok(RpcResponse::HistoryProof(payload)) => {
                self.handle_history_proof_response(peer, payload.proof, payload.anchor, target)
                    .await;
            }
            Ok(other) => {
                warn!(?other, "unexpected response type for HistoryProof RPC");
                self.handle_rpc_failure(RpcProtocol::HistoryProof, peer)
                    .await;
            }
            Err(_) => {
                self.handle_rpc_failure(RpcProtocol::HistoryProof, peer)
                    .await;
            }
        }
    }

    async fn handle_history_proof_response(
        &mut self,
        peer: neutrin0_network::PeerId,
        proof: neutrin0_consensus_types::HistoryProof,
        anchor: Option<neutrin0_consensus_types::AnchorOpening>,
        target: HistoryTarget,
    ) {
        if proof.end_checkpoint().hash() != target.checkpoint_hash
            || proof.end().next_chunk_id != target.end_chunks
        {
            self.handle_rpc_failure(RpcProtocol::HistoryProof, peer)
                .await;
            return;
        }
        match self.backend.verify_and_import_history(proof, anchor).await {
            Ok(cp) => {
                let cmds = self.fsm.on_event(SyncEvent::CheckpointsAdvanced {
                    new_finalized_index: cp.new_finalized_index,
                    new_finalized_hash: cp.new_finalized_hash,
                    new_finalized_state_root: cp.new_finalized_state_root,
                    new_finalized_height: cp.new_finalized_height,
                    new_finalized_block_hash: cp.new_finalized_block_hash,
                });
                self.dispatch_sync_commands(cmds).await;
            }
            Err(err) => {
                warn!(?err, "rejected History proof");
                if self.backend.history_halted().await {
                    let _ = self.fsm.on_event(SyncEvent::HistoryConflict);
                    return;
                }
                if matches!(err, SyncBackendError::Rejected(_)) {
                    let commands = self.fsm.on_event(SyncEvent::SampleRejected(peer));
                    self.dispatch_sync_commands(commands).await;
                }
                self.handle_rpc_failure(RpcProtocol::HistoryProof, peer)
                    .await;
            }
        }
    }
}
