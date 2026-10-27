//! The driver protocol: events the driver feeds the machine and the
//! commands it executes in return.

use crate::{
    rpc::{self, RpcProtocol},
    topic::Topic,
};
use libp2p::PeerId;
use neutrin0_primitives::{BlockHash, CheckpointIndex, Hash, Height, Slot, StateRoot};

/// Pseudo-events the driver feeds to the FSM after performing verification
/// and storage.
#[derive(Clone, Copy, Debug)]
pub enum SyncEvent {
    /// A peer just became reachable.
    PeerConnected(PeerId),
    /// The network a connected peer reached this node from; light-client
    /// sampling keeps one sample per host.
    PeerHost {
        /// The connected peer.
        peer: PeerId,
        /// Its address prefix.
        host: crate::service::HostGroup,
    },
    /// A peer disconnected.
    PeerDisconnected(PeerId),
    /// Peer responded to the [`rpc::Status`] handshake.
    ///
    /// The FSM compares chain ids and finalized cursors to decide whether
    /// this peer is a useful sync target.
    PeerStatus {
        /// Peer that produced the status.
        peer: PeerId,
        /// Reported status payload.
        status: rpc::Status,
    },
    /// Driver verified and accepted a light-client History proof. The new
    /// local endpoint is reported back as part of the event.
    CheckpointsAdvanced {
        /// Chunk count at the newly authenticated endpoint.
        new_finalized_index: CheckpointIndex,
        /// Hash of the newly authenticated endpoint.
        new_finalized_hash: Hash,
        /// New `end_state_root`.
        new_finalized_state_root: StateRoot,
        /// New `end_height`.
        new_finalized_height: Height,
        /// New `end_block_hash`.
        new_finalized_block_hash: BlockHash,
    },
    /// Driver imported and verified a batch of headers / blocks.
    HeadersAdvanced {
        /// New highest header height.
        new_head_height: Height,
        /// Hash of the new head.
        new_head_hash: BlockHash,
        /// Slot of the new head.
        new_head_slot: Slot,
    },
    /// Two verified History proofs disagree at one chunk count; the backend
    /// has durably halted the light client.
    HistoryConflict,
    /// A sampled peer could not back its advertised endpoint with a valid
    /// History proof; its advertisement no longer counts.
    SampleRejected(PeerId),
    /// An outstanding RPC failed.
    ///
    /// The light-client history fetch clears its `in_flight` bit and waits for
    /// a fresh notification; full-node downloads retry in the driver.
    RpcFailed {
        /// The RPC that failed.
        protocol: RpcProtocol,
        /// Peer that failed to serve the request.
        peer: PeerId,
    },
    /// Reset the FSM to [`crate::sync::SyncState::Init`] (driver-initiated).
    Reset,
}

/// Outputs the FSM emits for the driver to execute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncCommand {
    /// Send a [`rpc::Status`] handshake to the given peer.
    RequestStatus(PeerId),
    /// Fetch the History proof of the peer's endpoint.
    RequestHistoryProof {
        /// Peer to query.
        peer: PeerId,
        /// Chunk count whose boundary the provider must open under the
        /// endpoint; zero (none) for light clients, which trust the latest
        /// proof alone.
        anchor_chunks: CheckpointIndex,
        /// Chunk count of the requested peer endpoint.
        end_chunks: CheckpointIndex,
        /// Exact requested peer endpoint.
        checkpoint_hash: Hash,
    },
    /// Fetch and verify one side of a conflict between sampled endpoints,
    /// without accepting it.
    CheckHistoryConflict {
        /// Peer advertising this side.
        peer: PeerId,
        /// Chunk count both sides claim.
        end_chunks: CheckpointIndex,
        /// This side's endpoint.
        checkpoint_hash: Hash,
    },
    /// Subscribe to a gossip topic.
    Subscribe(Topic),
    /// Reached [`crate::sync::SyncState::Following`]; the driver should now treat the
    /// node as caught up.
    EnterFollowing,
}
