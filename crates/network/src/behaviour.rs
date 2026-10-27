#![allow(missing_docs)]

use crate::rpc::{
    BlocksByRangeBehaviour, CandidateByChunkBehaviour, ChunkProofByIdBehaviour,
    FinalityCertByChunkBehaviour, HistoryProofBehaviour, MetadataBehaviour, PingBehaviour,
    ReceiptsByHashBehaviour, StateByRootBehaviour, StatusBehaviour, WitnessByBlockBehaviour,
};
use libp2p::{connection_limits, gossipsub, identify, ping, swarm::NetworkBehaviour};

/// Gossip behaviour restricted to the finite protocol topic registry.
pub type GossipBehaviour = gossipsub::Behaviour<
    gossipsub::IdentityTransform,
    gossipsub::MaxCountSubscriptionFilter<gossipsub::WhitelistSubscriptionFilter>,
>;

/// The composed libp2p `NetworkBehaviour` for Neutrin0.
///
/// Combines:
/// - [`gossipsub::Behaviour`] — pub/sub for blocks, txs, proofs, votes (design 21).
/// - Kademlia with an in-memory routing store — peer discovery.
/// - [`identify::Behaviour`] — protocol negotiation and listen-addr exchange.
/// - [`ping::Behaviour`] — keepalive and RTT estimation.
/// - [`connection_limits::Behaviour`] — DoS resistance via hard caps.
/// - Independent `request_response::Behaviour` instances, one per RPC: the
///   core protocols (`status`, `metadata`, `ping` reply, `blocks_by_range`
///   serving complete publications, `state_by_root`) plus retrieval endpoints
///   for chunk and History proofs, candidates and signed artifacts.
#[derive(NetworkBehaviour)]
pub struct Neutrin0Behaviour {
    /// Connection limits to prevent resource exhaustion.
    pub connection_limits: connection_limits::Behaviour,
    /// Identify protocol for peer capability and address exchange.
    pub identify: identify::Behaviour,
    /// Ping protocol to keep connections alive and measure RTT.
    pub ping: ping::Behaviour,
    /// Gossipsub v1.1 for topic-based broadcast.
    pub gossipsub: GossipBehaviour,
    /// Kademlia DHT for peer discovery, never dialing local targets on a
    /// public node.
    pub kademlia: crate::kademlia::FilteredKademlia,
    /// `/neutrin0/req/status` request/response.
    pub rpc_status: StatusBehaviour,
    /// `/neutrin0/req/metadata` request/response.
    pub rpc_metadata: MetadataBehaviour,
    /// `/neutrin0/req/ping` request/response.
    pub rpc_ping: PingBehaviour,
    /// `/neutrin0/req/blocks_by_range` request/response.
    pub rpc_blocks_by_range: BlocksByRangeBehaviour,
    /// `/neutrin0/req/state_by_root` request/response.
    pub rpc_state_by_root: StateByRootBehaviour,
    /// `/neutrin0/req/chunk_proof_by_id` request/response.
    pub rpc_chunk_proof_by_id: ChunkProofByIdBehaviour,
    /// `/neutrin0/req/history_proof` request/response.
    pub rpc_history_proof: HistoryProofBehaviour,
    /// `/neutrin0/req/finality_cert_by_chunk` request/response.
    pub rpc_finality_cert_by_chunk: FinalityCertByChunkBehaviour,
    /// `/neutrin0/req/witness_by_block` request/response.
    pub rpc_witness_by_block: WitnessByBlockBehaviour,
    /// `/neutrin0/req/receipts_by_hash` request/response.
    pub rpc_receipts_by_hash: ReceiptsByHashBehaviour,
    /// Bounded SignedArtifactById RPC.
    pub rpc_signed_artifact_by_id: crate::rpc::SignedArtifactByIdBehaviour,
    /// Bounded SignedArtifactInventoryByChunk RPC.
    pub rpc_signed_artifact_inventory_by_chunk: crate::rpc::SignedArtifactInventoryByChunkBehaviour,
    /// Bounded BftRoundByChunk RPC.
    pub rpc_bft_round_by_chunk: crate::rpc::BftRoundByChunkBehaviour,
    /// Pending transaction hash discovery.
    pub rpc_transaction_inventory: crate::rpc::TransactionInventoryBehaviour,
    /// Pending transaction body retrieval.
    pub rpc_transactions_by_hash: crate::rpc::TransactionsByHashBehaviour,
    /// Proven next-chunk candidate discovery.
    pub rpc_candidate_by_chunk: CandidateByChunkBehaviour,
}
