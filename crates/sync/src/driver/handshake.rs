//! Status handshake responses: phase fan-out and the bounded queue of
//! status hints deferred behind an active History request.

use neutrin0_network::rpc::{RpcProtocol, RpcResponse};
use neutrin0_network::sync::SyncEvent;
use tracing::warn;

use super::{
    HISTORY_PROVIDER_ATTEMPT_LIMIT, SyncDriver, availability, bft, bootstrap, candidates,
    full_chunk, transactions,
};

impl SyncDriver {
    pub(super) async fn handle_status_response(
        &mut self,
        peer: neutrin0_network::PeerId,
        response: Result<RpcResponse, neutrin0_network::rpc::RpcError>,
    ) {
        if !self.connected_peers.contains(&peer) {
            return;
        }
        match response {
            Ok(RpcResponse::Status(status)) => {
                if self.active_history_request.is_some() {
                    let local = self.fsm.progress();
                    if status.chain_id == local.chain_id
                        && status.chain_spec_hash == local.chain_spec_hash
                        && status.finalized_chunks() > local.finalized_chunks()
                        && (self.deferred_history_status.len() < HISTORY_PROVIDER_ATTEMPT_LIMIT
                            || self.deferred_history_status.contains_key(&peer))
                    {
                        self.deferred_history_status.insert(peer, status);
                    }
                    // The sample still counts, and a conflict is checked at
                    // once; the active request keeps its provider.
                    let commands = self.fsm.on_event(SyncEvent::PeerStatus { peer, status });
                    self.dispatch_sync_commands(commands).await;
                    return;
                }
                if bootstrap::on_status(self, peer, status).await {
                    return;
                }
                // Reserve the chain request before discovery allocates its
                // bounded auxiliary work for this same provider.
                let full_sync = full_chunk::on_status(self, peer, status).await;
                transactions::on_status(self, peer, status).await;
                candidates::on_status(self, peer, status).await;
                bft::on_status(self, peer, status).await;
                availability::on_status(self, peer, status).await;
                if full_sync {
                    return;
                }
                let commands = self.fsm.on_event(SyncEvent::PeerStatus { peer, status });
                self.dispatch_sync_commands(commands).await;
            }
            Ok(other) => warn!(?other, "unexpected response type for Status RPC"),
            Err(_) => self.handle_rpc_failure(RpcProtocol::Status, peer).await,
        }
        self.try_next_history_provider().await;
    }

    pub(super) async fn resume_deferred_history_status(&mut self) {
        // Consume only already-received, bounded hints. An exhausted provider
        // must not prevent the next queued target from making progress.
        while self.active_history_request.is_none() {
            let Some((peer, status)) = self.take_deferred_history_status() else {
                break;
            };
            self.handle_status_response(peer, Ok(RpcResponse::Status(status)))
                .await;
        }
    }

    fn take_deferred_history_status(
        &mut self,
    ) -> Option<(neutrin0_network::PeerId, neutrin0_network::rpc::Status)> {
        let local = self.fsm.progress().finalized_chunks();
        self.deferred_history_status
            .retain(|_, status| status.finalized_chunks() > local);
        let selected = self.deferred_history_cursor.and_then(|cursor| {
            self.deferred_history_status
                .range((
                    core::ops::Bound::Excluded(cursor),
                    core::ops::Bound::Unbounded,
                ))
                .next()
        });
        let (&peer, &status) = selected.or_else(|| self.deferred_history_status.iter().next())?;
        self.deferred_history_cursor = Some(peer);
        self.deferred_history_status.remove(&peer);
        Some((peer, status))
    }
}
