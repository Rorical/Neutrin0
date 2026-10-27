//! The driver's event loop: the retry tick and fair intake of network
//! events and outbound RPC results.

use core::time::Duration;

use neutrin0_network::rpc::RpcRequest;
use neutrin0_network::service::NetworkEvent;
use neutrin0_network::sync::{SyncEvent, SyncMode};
use neutrin0_network::topic::Topic;
use tracing::{error, info, warn};

use super::{
    OutboundOutcome, RETRY_INTERVAL, SyncDriver, availability, bft, programs, reporter_paths,
    transactions,
};

impl SyncDriver {
    /// Drive the loop until the network event channel closes.
    pub async fn run(mut self) {
        // A conflict halt persists across restarts until trust is replaced.
        if self.fsm.mode() == SyncMode::LightClient && self.backend.history_halted().await {
            error!(
                "light client halted on conflicting History proofs; configure a new trusted checkpoint"
            );
            let _ = self.fsm.on_event(SyncEvent::HistoryConflict);
        }
        // A full backend must retry even if no first handshake ever completed.
        let reconcile_status = self.fsm.mode() == SyncMode::LightClient
            || !matches!(self.backend.consensus_sync_target().await, Ok(None));
        let mut retry =
            tokio::time::interval_at(tokio::time::Instant::now() + RETRY_INTERVAL, RETRY_INTERVAL);
        loop {
            // Reflect the state left by the previous iteration before blocking.
            self.publish_status().await;
            tokio::select! {
                _ = retry.tick() => {
                    transactions::on_retry(&mut self).await;
                    programs::on_retry(&mut self).await;
                    reporter_paths::on_retry(&mut self).await;
                    availability::on_retry(&mut self).await;
                    bft::on_retry(&mut self).await;
                    if self.active_history_request.is_none() && tokio::time::Instant::now() >= self.history_retry_at {
                        self.history_attempts.clear();
                        self.history_retry_at = tokio::time::Instant::now() + Duration::from_secs(30);
                        self.try_next_history_provider().await;
                    }
                    if !self.full_chunks.enabled && !reconcile_status { continue; }
                    let count = self.connected_peers.len();
                    let index = self.full_chunks.retry_cursor.checked_rem(count).unwrap_or(0);
                    self.full_chunks.retry_cursor = self.full_chunks.retry_cursor.wrapping_add(1);
                    if let Some(peer) = self.connected_peers.iter().nth(index).copied() {
                        let Ok(status) = self.backend.local_status().await else { continue; };
                        self.send_rpc(peer, RpcRequest::Status(status),
                            |peer, response| OutboundOutcome::StatusResponse { peer, response }).await;
                    }
                }
                () = std::future::ready(()), if !self.event_backlog.is_empty() => {
                    let index = self.event_backlog.iter().position(priority_event).unwrap_or(0);
                    let event = self.event_backlog.remove(index).expect("nonempty backlog");
                    self.handle_network_event(event).await;
                }
                event = self.event_rx.recv(), if self.event_backlog.len() < 128 => {
                    let Some(event) = event else {
                        info!("network event channel closed, sync driver stopping");
                        return;
                    };
                    self.event_backlog.push_back(event);
                    while self.event_backlog.len() < 128 {
                        let Ok(event) = self.event_rx.try_recv() else { break; };
                        self.event_backlog.push_back(event);
                    }
                }
                outcome = self.outbound_rx.recv() => {
                    let Some(outcome) = outcome else {
                        // Cannot happen: we hold a sender alive.
                        warn!("outbound outcome channel closed unexpectedly");
                        return;
                    };
                    self.handle_outbound_outcome(outcome.value).await;
                    drop(outcome.budget);
                }
            }
        }
    }
}

/// Control and consensus intake precede queued bulk verification. The main
/// select remains fair between this bounded queue, retries and RPC completions.
const fn priority_event(event: &NetworkEvent) -> bool {
    match event {
        NetworkEvent::PeerConnected(_)
        | NetworkEvent::PeerHost { .. }
        | NetworkEvent::PeerDisconnected(_)
        | NetworkEvent::NewListenAddr(_) => true,
        NetworkEvent::GossipMessage { topic, .. } => matches!(
            topic,
            Topic::BftMessages
                | Topic::FinalityVotesPrevote
                | Topic::FinalityVotesPrecommit
                | Topic::AggregateFinalityVotes(_)
        ),
        NetworkEvent::RpcRequestReceived { request, .. } => matches!(
            request,
            RpcRequest::Status(_) | RpcRequest::Ping(_) | RpcRequest::Metadata(_)
        ),
    }
}
