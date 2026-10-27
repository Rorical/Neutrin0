//! Service construction and event waits shared by the service test modules.

use super::{Keypair, Multiaddr, NetworkCommand, NetworkEvent, NetworkService, PeerId};
use std::time::Duration;
use tokio::{sync::mpsc, time::timeout};

/// A constructed service that is not yet running, with its host channel ends.
pub(super) struct TestNode {
    pub(super) service: NetworkService,
    pub(super) commands: mpsc::Sender<NetworkCommand>,
    pub(super) events: mpsc::Receiver<NetworkEvent>,
}

pub(super) fn test_node(key: Keypair, commands: usize, events: usize) -> TestNode {
    let (command_tx, command_rx) = mpsc::channel(commands);
    let (event_tx, event_rx) = mpsc::channel(events);
    TestNode {
        service: NetworkService::new(key, command_rx, event_tx).unwrap(),
        commands: command_tx,
        events: event_rx,
    }
}

/// The next address a running service advertises, within five seconds.
pub(super) async fn next_listen_addr(events: &mut mpsc::Receiver<NetworkEvent>) -> Multiaddr {
    timeout(Duration::from_secs(5), async {
        loop {
            if let NetworkEvent::NewListenAddr(addr) =
                events.recv().await.expect("network service remains live")
            {
                return addr;
            }
        }
    })
    .await
    .expect("listener advertised an address")
}

/// Wait up to five seconds until each side reports its expected peer.
#[allow(clippy::similar_names)]
pub(super) async fn wait_connected(
    events_a: &mut mpsc::Receiver<NetworkEvent>,
    peer_seen_by_a: PeerId,
    events_b: &mut mpsc::Receiver<NetworkEvent>,
    peer_seen_by_b: PeerId,
) {
    timeout(Duration::from_secs(5), async {
        let mut connected_a = false;
        let mut connected_b = false;
        loop {
            tokio::select! {
                Some(ev) = events_a.recv() => {
                    if matches!(ev, NetworkEvent::PeerConnected(p) if p == peer_seen_by_a) {
                        connected_a = true;
                    }
                }
                Some(ev) = events_b.recv() => {
                    if matches!(ev, NetworkEvent::PeerConnected(p) if p == peer_seen_by_b) {
                        connected_b = true;
                    }
                }
            }
            if connected_a && connected_b {
                break;
            }
        }
    })
    .await
    .expect("connection both ways");
}
