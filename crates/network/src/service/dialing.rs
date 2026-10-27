//! Bootnode reconnects and DHT-driven outbound dialing.

use super::{NetworkError, NetworkService, discovery};
use crate::bootnodes::Bootnodes;
use libp2p::{
    Multiaddr, PeerId,
    swarm::{DialError, dial_opts::DialOpts},
};
use tracing::{debug, info};

impl NetworkService {
    /// Configure persistent reconnects for at most 64 bootstrap addresses.
    ///
    /// Call before [`Self::run`]. Only these operator-supplied addresses are
    /// retried: peer discovery cannot grow this set. Each address has one dial
    /// in flight, known peer aliases share that restriction, and failures use
    /// exponential backoff with identity/address-specific jitter (1–60 seconds).
    /// A successful connection resets backoff; retries resume only when its last
    /// connection closes. Bare addresses permit a changed remote identity, while
    /// an explicit `/p2p/` suffix continues to authenticate the configured peer.
    ///
    /// # Errors
    /// Rejects empty/oversized addresses, more than 64 entries and the local
    /// peer identity. Validation leaves the previous configuration intact.
    pub fn configure_bootnodes(&mut self, addresses: Vec<Multiaddr>) -> Result<(), NetworkError> {
        let configured = addresses.clone();
        let mut bootnodes = Bootnodes::configured(
            *self.swarm.local_peer_id(),
            addresses,
            tokio::time::Instant::now(),
        )
        .map_err(NetworkError::Bootnodes)?;
        for address in self.swarm.listeners() {
            bootnodes.local_address(address);
        }
        let local = configured.iter().any(crate::kademlia::is_local_address);
        self.discovery.allow_local(local);
        self.swarm.behaviour_mut().kademlia.allow_local(local);
        self.bootnodes = bootnodes;
        self.publish_bootnode_metrics();
        Ok(())
    }

    pub(super) fn publish_bootnode_metrics(&self) {
        self.metrics
            .bootnode_states(self.bootnodes.states(tokio::time::Instant::now()));
    }

    /// Below the outbound target, walk the DHT from a random key and dial a
    /// few learned peers; configured bootnodes alone would make every node a
    /// spoke of the same few seeds.
    pub(super) fn discover_peers(&mut self) {
        let outbound = self
            .accepted_connections
            .values()
            .filter(|(_, dialer)| *dialer)
            .count();
        if outbound >= discovery::TARGET_OUTBOUND {
            return;
        }
        if self.accepted_connections.is_empty() {
            return;
        }
        self.swarm
            .behaviour_mut()
            .kademlia
            .get_closest_peers(PeerId::random());
        let limit = discovery::DIALS_PER_WALK.min(discovery::TARGET_OUTBOUND - outbound);
        let now = tokio::time::Instant::now();
        let connected = &self.accepted_connections;
        let due = self.discovery.due(
            |peer| connected.values().any(|(connected, _)| connected == peer),
            limit,
            now,
        );
        for (target, addresses) in due {
            let peer = target.peer();
            debug!(%peer, "dialing a peer learned from the DHT");
            let options = DialOpts::peer_id(peer).addresses(addresses).build();
            let connection = options.connection_id();
            match self.swarm.dial(options) {
                Ok(()) => self.discovery.dialing(connection, target),
                Err(error) => debug!(%peer, %error, "learned peer dial not started"),
            }
        }
    }

    pub(super) fn dial_due_bootnodes(&mut self) {
        let now = tokio::time::Instant::now();
        while let Some(index) = self.bootnodes.next_due(now) {
            let address = self.bootnodes.address(index).clone();
            let options = self.bootnodes.expected_peer(index).map_or_else(
                || DialOpts::unknown_peer_id().address(address.clone()).build(),
                |peer| {
                    DialOpts::peer_id(peer)
                        .addresses(vec![address.clone()])
                        .build()
                },
            );
            self.dial_bootnode(index, options);
        }
    }

    pub(super) fn dial_bootnode(&mut self, index: usize, options: DialOpts) {
        let connection = options.connection_id();
        if !self.bootnodes.start(index, connection) {
            return;
        }
        self.metrics.bootnode_attempt();
        info!(address = %self.bootnodes.address(index), "dialing configured bootnode");
        if let Err(error) = self.swarm.dial(options) {
            self.metrics.bootnode_failure(&error);
            self.bootnodes.failed(
                connection,
                tokio::time::Instant::now(),
                matches!(error, DialError::LocalPeerId { .. }),
            );
            debug!(%error, "bootnode dial deferred");
        }
    }
}

pub(super) async fn wait_for_bootnode_retry(at: Option<tokio::time::Instant>) {
    if let Some(at) = at {
        tokio::time::sleep_until(at).await;
    } else {
        std::future::pending::<()>().await;
    }
}
