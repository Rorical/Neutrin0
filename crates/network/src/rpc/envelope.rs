//! Host-facing umbrella request/response enums and the RPC failure types.

use super::{
    BftRoundByChunkRequest, BftRoundByChunkResponse, BlocksByRangeRequest, BlocksByRangeResponse,
    CandidateByChunkRequest, CandidateByChunkResponse, ChunkProofByIdRequest,
    ChunkProofByIdResponse, FinalityCertByChunkRequest, FinalityCertByChunkResponse,
    HistoryProofRequest, HistoryProofResponse, Metadata, MetadataRequest, PingPayload,
    ReceiptsByHashRequest, ReceiptsByHashResponse, RpcProtocol, SignedArtifactByIdRequest,
    SignedArtifactByIdResponse, SignedArtifactInventoryByChunkRequest,
    SignedArtifactInventoryByChunkResponse, StateByRootRequest, StateByRootResponse, Status,
    TransactionInventoryRequest, TransactionInventoryResponse, TransactionsByHashRequest,
    TransactionsByHashResponse, WitnessByBlockRequest, WitnessByBlockResponse,
};
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{ChunkId, Height};
use thiserror::Error;

/// Host-facing umbrella request enum used by the command surface.
///
/// Never serialized to the wire — each variant maps to a different
/// [`libp2p::request_response::Behaviour`] which serializes only the inner type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcRequest {
    /// Status handshake.
    Status(Status),
    /// Metadata query.
    Metadata(MetadataRequest),
    /// Ping with a nonce.
    Ping(PingPayload),
    /// Block backfill by height range.
    BlocksByRange(BlocksByRangeRequest),
    /// State trie node fetch.
    StateByRoot(StateByRootRequest),
    /// Chunk proof fetch by chunk id.
    ChunkProofById(ChunkProofByIdRequest),
    /// Anchored History proof by endpoint identity.
    HistoryProof(HistoryProofRequest),
    /// Finality certificate fetch by chunk id.
    FinalityCertByChunk(FinalityCertByChunkRequest),
    /// Execution witness fetch by block hash.
    WitnessByBlock(WitnessByBlockRequest),
    /// `ReceiptsByHash` request.
    ReceiptsByHash(ReceiptsByHashRequest),
    /// Discover a proven candidate branch.
    CandidateByChunk(CandidateByChunkRequest),
    /// SignedArtifactById request.
    SignedArtifactById(SignedArtifactByIdRequest),
    /// SignedArtifactInventoryByChunk request.
    SignedArtifactInventoryByChunk(SignedArtifactInventoryByChunkRequest),
    /// BftRoundByChunk request.
    BftRoundByChunk(BftRoundByChunkRequest),
    /// Discover pending transaction hashes.
    TransactionInventory(TransactionInventoryRequest),
    /// Retrieve exact pending transaction bodies.
    TransactionsByHash(TransactionsByHashRequest),
}

impl RpcRequest {
    /// Which protocol the variant maps to.
    #[must_use]
    pub const fn protocol(&self) -> RpcProtocol {
        match self {
            Self::Status(_) => RpcProtocol::Status,
            Self::Metadata(_) => RpcProtocol::Metadata,
            Self::Ping(_) => RpcProtocol::Ping,
            Self::BlocksByRange(_) => RpcProtocol::BlocksByRange,
            Self::StateByRoot(_) => RpcProtocol::StateByRoot,
            Self::ChunkProofById(_) => RpcProtocol::ChunkProofById,
            Self::HistoryProof(_) => RpcProtocol::HistoryProof,
            Self::FinalityCertByChunk(_) => RpcProtocol::FinalityCertByChunk,
            Self::WitnessByBlock(_) => RpcProtocol::WitnessByBlock,
            Self::ReceiptsByHash(_) => RpcProtocol::ReceiptsByHash,
            Self::CandidateByChunk(_) => RpcProtocol::CandidateByChunk,
            Self::SignedArtifactById(_) => RpcProtocol::SignedArtifactById,
            Self::SignedArtifactInventoryByChunk(_) => RpcProtocol::SignedArtifactInventoryByChunk,
            Self::BftRoundByChunk(_) => RpcProtocol::BftRoundByChunk,
            Self::TransactionInventory(_) => RpcProtocol::TransactionInventory,
            Self::TransactionsByHash(_) => RpcProtocol::TransactionsByHash,
        }
    }
}

/// Host-facing umbrella response enum used by the event surface.
///
/// [`crate::rpc::HistoryProofResponse`] carries a statement and a bounded receipt;
/// it is boxed here so the enum
/// stays small and equally cheap to move regardless of variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpcResponse {
    /// Explicit remote failure for the tagged protocol.
    Error {
        /// Protocol whose request could not be served.
        protocol: RpcProtocol,
        /// Reason data could not be served.
        error: RpcFailure,
    },
    /// Status handshake reply.
    Status(Status),
    /// Metadata reply.
    Metadata(Metadata),
    /// Ping reply.
    Ping(PingPayload),
    /// `BlocksByRange` reply.
    BlocksByRange(BlocksByRangeResponse),
    /// `StateByRoot` reply.
    StateByRoot(StateByRootResponse),
    /// `ChunkProofById` reply.
    ChunkProofById(ChunkProofByIdResponse),
    /// `HistoryProof` reply (boxed to keep the enum compact).
    HistoryProof(Box<HistoryProofResponse>),
    /// `FinalityCertByChunk` reply.
    FinalityCertByChunk(FinalityCertByChunkResponse),
    /// `WitnessByBlock` reply.
    WitnessByBlock(WitnessByBlockResponse),
    /// `ReceiptsByHash` reply.
    ReceiptsByHash(ReceiptsByHashResponse),
    /// Candidate availability reply.
    CandidateByChunk(Box<CandidateByChunkResponse>),
    /// SignedArtifactById response.
    SignedArtifactById(Box<SignedArtifactByIdResponse>),
    /// SignedArtifactInventoryByChunk response.
    SignedArtifactInventoryByChunk(Box<SignedArtifactInventoryByChunkResponse>),
    /// BftRoundByChunk response.
    BftRoundByChunk(Box<BftRoundByChunkResponse>),
    /// Pending hash inventory.
    TransactionInventory(TransactionInventoryResponse),
    /// Exact pending bodies.
    TransactionsByHash(TransactionsByHashResponse),
}

impl RpcResponse {
    /// Which protocol the variant maps to.
    #[must_use]
    pub const fn protocol(&self) -> RpcProtocol {
        match self {
            Self::Error { protocol, .. } => *protocol,
            Self::Status(_) => RpcProtocol::Status,
            Self::Metadata(_) => RpcProtocol::Metadata,
            Self::Ping(_) => RpcProtocol::Ping,
            Self::BlocksByRange(_) => RpcProtocol::BlocksByRange,
            Self::StateByRoot(_) => RpcProtocol::StateByRoot,
            Self::ChunkProofById(_) => RpcProtocol::ChunkProofById,
            Self::HistoryProof(_) => RpcProtocol::HistoryProof,
            Self::FinalityCertByChunk(_) => RpcProtocol::FinalityCertByChunk,
            Self::WitnessByBlock(_) => RpcProtocol::WitnessByBlock,
            Self::ReceiptsByHash(_) => RpcProtocol::ReceiptsByHash,
            Self::CandidateByChunk(_) => RpcProtocol::CandidateByChunk,
            Self::SignedArtifactById(_) => RpcProtocol::SignedArtifactById,
            Self::SignedArtifactInventoryByChunk(_) => RpcProtocol::SignedArtifactInventoryByChunk,
            Self::BftRoundByChunk(_) => RpcProtocol::BftRoundByChunk,
            Self::TransactionInventory(_) => RpcProtocol::TransactionInventory,
            Self::TransactionsByHash(_) => RpcProtocol::TransactionsByHash,
        }
    }
}

/// Errors surfaced to RPC callers.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RpcError {
    /// Local processing could not reserve resources; this does not blame the peer.
    #[error("local RPC capacity exhausted")]
    LocalOverloaded,
    /// Peer explicitly reported missing data, storage failure or invalid parameters.
    #[error("remote RPC failure: {0}")]
    Remote(RpcFailure),
    /// libp2p reported an outbound request failure.
    #[error("outbound failure: {0}")]
    Outbound(String),
    /// libp2p rejected the response: peer disconnected before delivery.
    #[error("failed to deliver response to peer")]
    ResponseDeliveryFailed,
}

impl RpcError {
    /// Whether the exchange failed in transport rather than with a peer answer.
    #[must_use]
    pub const fn is_transport(&self) -> bool {
        matches!(self, Self::Outbound(_) | Self::ResponseDeliveryFailed)
    }
}

/// Canonical wire failure shared by request/response protocols.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Error, Eq, PartialEq)]
pub enum RpcFailure {
    /// Requested data is not retained or not yet produced by this peer.
    #[error("data unavailable: {0}")]
    Unavailable(String),
    /// Payload was deliberately removed below the finalized retention window.
    #[error(
        "data pruned; retained chunks start at {retained_from_chunk}, blocks at {retained_from_height}"
    )]
    Pruned {
        /// Actual persisted retention watermark, not a requested policy.
        retained_from_chunk: ChunkId,
        /// First block payload height above that watermark.
        retained_from_height: Height,
    },
    /// Local storage failed or contained inconsistent authenticated data.
    #[error("storage failure: {0}")]
    Storage(String),
    /// Request parameters do not describe a supported bounded query.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

/// Every protocol returns either its payload or an explicit wire failure.
pub type RpcResult<T> = Result<T, RpcFailure>;

/// Stable, protocol-namespaced inbound request identifier.
///
/// libp2p's `InboundRequestId` is only unique within a single
/// [`libp2p::request_response::Behaviour`], so we tag each id with the originating
/// [`RpcProtocol`] before exposing it to host code.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RpcInboundId {
    /// Protocol that produced the underlying libp2p id.
    pub protocol: RpcProtocol,
    /// Raw libp2p inbound request id, unique per protocol.
    pub raw: u64,
}
