//! Peer retention discovery through the `Metadata` RPC (designs 21 and 17).
//!
//! A node that needs old history asks each connection once what complete
//! history it still serves. A pruned provider is then never asked for a chunk
//! below its floor, and work
//! that needs history older than every full node's window (an archive's
//! source sync, a reporter's old dormant paths) is directed to peers that
//! advertise the `ARCHIVE` role. Advertisements are advisory: a provider that
//! claims more than it serves still answers `Pruned` and is skipped then.

use super::{OutboundOutcome, SyncDriver};
use neutrin0_network::{
    PeerId,
    rpc::{Metadata, MetadataRequest, RpcError, RpcRequest, RpcResponse, role_flags},
};

/// Ask a new connection for its retention when this node needs history a
/// pruned provider may lack: an archive syncing sources, or a reporter with
/// dormant paths. Others learn floors from `Pruned` answers.
pub(super) async fn on_connect(driver: &SyncDriver, peer: PeerId) {
    if driver.fsm.mode() != neutrin0_network::SyncMode::Archive
        && driver.backend.dormant_reporter_path().await.is_none()
    {
        return;
    }
    driver
        .send_rpc(
            peer,
            RpcRequest::Metadata(MetadataRequest),
            |peer, response| OutboundOutcome::Metadata { peer, response },
        )
        .await;
}

pub(super) fn on_disconnect(driver: &mut SyncDriver, peer: PeerId) {
    driver.peer_metadata.remove(&peer);
}

pub(super) fn on_response(
    driver: &mut SyncDriver,
    peer: PeerId,
    response: &Result<RpcResponse, RpcError>,
) {
    let Ok(RpcResponse::Metadata(metadata)) = response else {
        return;
    };
    if !driver.connected_peers.contains(&peer) {
        return;
    }
    if let Some(floor) = metadata.retained_from_chunk {
        super::full_chunk::record_retention(driver, peer, floor);
    }
    driver.peer_metadata.insert(peer, *metadata);
}

/// Whether `peer` advertised complete history from genesis.
pub(super) fn is_archive(driver: &SyncDriver, peer: &PeerId) -> bool {
    driver
        .peer_metadata
        .get(peer)
        .is_some_and(|metadata: &Metadata| metadata.role_flags & role_flags::ARCHIVE != 0)
}
