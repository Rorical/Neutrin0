//! Light-client endpoint sampling: a light client moves only to an
//! endpoint a quorum of sampled peers advertise identically (design 14).

use super::{PeerStatus, SyncCommand, SyncMachine, SyncMode, SyncStallReason, SyncState};
use crate::rpc;
use libp2p::PeerId;
use neutrin0_light_client::sampling::{self, Advertisement, Decision};
use neutrin0_primitives::{BlockHash, CheckpointIndex, Hash, Height, StateRoot};

impl SyncMachine {
    /// Peers whose latest advertisement is the endpoint currently being
    /// fetched: the providers a light client may ask for it.
    #[must_use]
    pub fn history_providers(&self) -> Vec<PeerId> {
        let Some(target) = self.sync_peer else {
            return Vec::new();
        };
        let target = advertisement(&target.status);
        self.samples
            .iter()
            .filter(|sample| advertisement(&sample.status) == target)
            .map(|sample| sample.peer)
            .collect()
    }

    /// Retry the same anchored endpoint from another provider after unavailability.
    /// The driver bounds provider attempts; changing provider never changes the
    /// requested endpoint or treats that provider as a new trust anchor.
    pub fn retry_history_from(&mut self, peer: PeerId) -> Vec<SyncCommand> {
        if self.mode != SyncMode::LightClient {
            return Vec::new();
        }
        let SyncState::HistoryFetch {
            local_finalized_index,
            target_index,
            in_flight: false,
        } = self.state
        else {
            return Vec::new();
        };
        let Some(target) = self.sync_peer.as_mut() else {
            return Vec::new();
        };
        if target.status.finalized_chunks() <= local_finalized_index {
            return Vec::new();
        }
        target.peer = peer;
        self.state = SyncState::HistoryFetch {
            local_finalized_index,
            target_index,
            in_flight: true,
        };
        self.emit_checkpoint_fetch(peer, local_finalized_index)
    }

    /// Record a light peer's advertisement and act on the samples. Genesis is
    /// trusted locally, so a status claiming no finalized chunk is not a
    /// sample; it can still confirm a client that is itself at genesis.
    pub(super) fn on_light_status(
        &mut self,
        peer: PeerId,
        status: &rpc::Status,
    ) -> Vec<SyncCommand> {
        if matches!(self.state, SyncState::Stalled { .. }) {
            return Vec::new();
        }
        if status.finalized_chunk_id.is_some() {
            // One sample per host: identities one machine or network runs
            // cannot make up a quorum between them.
            let host = self.peer_hosts.get(&peer).copied();
            self.samples
                .retain(|sample| sample.peer != peer && (host.is_none() || sample.host != host));
            self.samples.push_back(PeerStatus {
                peer,
                host,
                status: *status,
            });
            while self.samples.len() > self.light_sampling.peers.max(1) {
                self.samples.pop_front();
            }
        }
        let confirms = status.finalized_chunks() == self.progress.finalized_chunks()
            && status.checkpoint_hash == self.progress.checkpoint_hash;
        self.light_step(Some(peer), confirms)
    }

    /// Decide from the current samples: check a conflict, fetch the highest
    /// endpoint a quorum advertises, or follow once a peer confirms the
    /// current one. `preferred` is the peer whose status triggered this step.
    fn light_step(&mut self, preferred: Option<PeerId>, confirms: bool) -> Vec<SyncCommand> {
        let current = Advertisement {
            chunks: self.progress.finalized_chunks(),
            checkpoint_hash: self.progress.checkpoint_hash,
        };
        let adverts: Vec<_> = self
            .samples
            .iter()
            .map(|sample| advertisement(&sample.status))
            .collect();
        // An endpoint a lone peer advertises against the rest is checked
        // alongside whatever the samples decide, so it can still halt the
        // client once verified without holding it back meanwhile.
        // Below its own endpoint nothing a lone peer claims can move the
        // client, so only disagreements from there up are checked.
        let mut checks: Vec<_> = sampling::disagreements(current, &adverts)
            .into_iter()
            .filter(|disagreement| !disagreement.backed && disagreement.chunks >= current.chunks)
            .flat_map(|disagreement| {
                self.conflict_checks(
                    current,
                    disagreement.chunks,
                    [disagreement.first, disagreement.second],
                )
            })
            .collect();
        match sampling::decide(current, &adverts, self.light_sampling.quorum) {
            Decision::Conflict {
                chunks,
                first,
                second,
            } => self.conflict_checks(current, chunks, [first, second]),
            Decision::Advance(target) => {
                if matches!(
                    self.state,
                    SyncState::HistoryFetch {
                        in_flight: true,
                        ..
                    }
                ) {
                    // The active request owns its provider until it settles.
                    return checks;
                }
                let Some(provider) = preferred
                    .and_then(|peer| self.samples.iter().find(|sample| sample.peer == peer))
                    .filter(|sample| advertisement(&sample.status) == target)
                    .or_else(|| {
                        self.samples
                            .iter()
                            .rev()
                            .find(|sample| advertisement(&sample.status) == target)
                    })
                    .copied()
                else {
                    return checks;
                };
                self.sync_peer = Some(provider);
                self.state = SyncState::HistoryFetch {
                    local_finalized_index: current.chunks,
                    target_index: target.chunks,
                    in_flight: true,
                };
                checks.extend(self.emit_checkpoint_fetch(provider.peer, current.chunks));
                checks
            }
            Decision::Wait => {
                checks.extend(match self.state {
                    SyncState::Init if confirms => self.enter_following(),
                    SyncState::HistoryFetch {
                        in_flight: false, ..
                    } => self.enter_following(),
                    _ => Vec::new(),
                });
                checks
            }
        }
    }

    /// Fetch each side of a disagreement at `chunks` that is not the
    /// current endpoint, already verified locally.
    fn conflict_checks(
        &self,
        current: Advertisement,
        chunks: CheckpointIndex,
        sides: [Hash; 2],
    ) -> Vec<SyncCommand> {
        sides
            .into_iter()
            .filter(|hash| chunks != current.chunks || *hash != current.checkpoint_hash)
            .filter_map(|hash| {
                self.sample_peer(chunks, hash)
                    .map(|peer| SyncCommand::CheckHistoryConflict {
                        peer,
                        end_chunks: chunks,
                        checkpoint_hash: hash,
                    })
            })
            .collect()
    }

    /// The most recently heard sampled peer advertising this endpoint.
    fn sample_peer(&self, chunks: CheckpointIndex, hash: Hash) -> Option<PeerId> {
        self.samples
            .iter()
            .rev()
            .find(|sample| {
                sample.status.finalized_chunks() == chunks && sample.status.checkpoint_hash == hash
            })
            .map(|sample| sample.peer)
    }

    pub(super) fn on_history_conflict(&mut self) -> Vec<SyncCommand> {
        if self.mode == SyncMode::LightClient {
            self.sync_peer = None;
            self.state = SyncState::Stalled {
                reason: SyncStallReason::HistoryConflict,
            };
        }
        Vec::new()
    }

    pub(super) fn on_sample_rejected(&mut self, peer: PeerId) -> Vec<SyncCommand> {
        if self.mode != SyncMode::LightClient || matches!(self.state, SyncState::Stalled { .. }) {
            return Vec::new();
        }
        self.samples.retain(|sample| sample.peer != peer);
        self.light_step(None, false)
    }

    fn emit_checkpoint_fetch(
        &self,
        peer: PeerId,
        local_finalized_index: CheckpointIndex,
    ) -> Vec<SyncCommand> {
        let Some(target) = self.sync_peer else {
            return Vec::new();
        };
        if target.status.finalized_chunks() <= local_finalized_index {
            return Vec::new();
        }
        // The latest proof proves its chain from genesis; the client also
        // asks for the opening of its own endpoint, which a provider supplies
        // when it still can (design 13).
        vec![SyncCommand::RequestHistoryProof {
            peer,
            anchor_chunks: local_finalized_index,
            end_chunks: target.status.finalized_chunks(),
            checkpoint_hash: target.status.checkpoint_hash,
        }]
    }

    pub(super) fn on_checkpoints_advanced(
        &mut self,
        new_finalized_index: CheckpointIndex,
        new_finalized_hash: Hash,
        new_finalized_state_root: StateRoot,
        new_finalized_height: Height,
        new_finalized_block_hash: BlockHash,
    ) -> Vec<SyncCommand> {
        // Full-node finality comes from the backend, never from a History
        // proof imported by a light-client flow.
        if self.mode != SyncMode::LightClient {
            return Vec::new();
        }
        if !matches!(self.state, SyncState::HistoryFetch { .. }) {
            return Vec::new();
        }
        if new_finalized_index <= self.progress.finalized_chunks() {
            return Vec::new();
        }
        self.progress.finalized_chunk_id = new_finalized_index.checked_sub(1);
        self.progress.checkpoint_hash = new_finalized_hash;
        self.progress.finalized_state_root = new_finalized_state_root;
        self.progress.finalized_height = new_finalized_height;
        self.progress.finalized_block_hash = new_finalized_block_hash;
        // Continue to a higher endpoint the samples agree on, or follow.
        self.set_in_flight(false);
        self.light_step(None, true)
    }
}

/// The endpoint a status advertises.
const fn advertisement(status: &rpc::Status) -> Advertisement {
    Advertisement {
        chunks: match status.finalized_chunk_id {
            Some(id) => id.saturating_add(1),
            None => 0,
        },
        checkpoint_hash: status.checkpoint_hash,
    }
}
