//! Request/response RPC for Neutrin0, per design 21 §"Request/response protocols".
//!
//! Implements the **core** RPC family every full node supports. Block data
//! travels only as complete `ProvenBlock` publications, by anchored range:
//!
//! | Protocol id                                | Request → Response                                       |
//! |--------------------------------------------|----------------------------------------------------------|
//! | `/neutrin0/req/status`                   | [`crate::rpc::Status`] → [`crate::rpc::Status`]                                  |
//! | `/neutrin0/req/metadata`                 | [`crate::rpc::MetadataRequest`] → [`crate::rpc::Metadata`]                       |
//! | `/neutrin0/req/ping`                     | [`crate::rpc::PingPayload`] → [`crate::rpc::PingPayload`]                        |
//! | `/neutrin0/req/blocks_by_range`          | [`crate::rpc::BlocksByRangeRequest`] → [`crate::rpc::BlocksByRangeResponse`]     |
//! | `/neutrin0/req/state_by_root`            | [`crate::rpc::StateByRootRequest`]   → [`crate::rpc::StateByRootResponse`]       |
//! | `/neutrin0/req/chunk_proof_by_id`        | [`crate::rpc::ChunkProofByIdRequest`] → [`crate::rpc::ChunkProofByIdResponse`]   |
//! | `/neutrin0/req/history_proof`            | [`crate::rpc::HistoryProofRequest`] → [`crate::rpc::HistoryProofResponse`]       |
//!
//! Responses encode `RpcResult<Payload>` with explicit remote failures.
//! Every request and response is canonically encoded with `borsh`, matching
//! the wire format used by gossip and on-disk consensus types.
//!
//! Each protocol runs as its own [`libp2p::request_response::Behaviour`] so per-protocol
//! peer scoring, rate limits, and size caps can be tuned independently. The
//! umbrella [`RpcRequest`] and [`RpcResponse`] enums exist only at the
//! crate-internal command/event boundary; they are never serialized to the wire.

use libp2p::StreamProtocol;
use std::time::Duration;

mod codec;
mod envelope;
mod messages;
mod transactions;

pub use codec::*;
pub use envelope::*;
pub use messages::*;
pub use transactions::*;

/// Status RPC protocol id.
pub const PROTOCOL_STATUS: &str = "/neutrin0/req/status";
/// Metadata RPC protocol id.
pub const PROTOCOL_METADATA: &str = "/neutrin0/req/metadata";
/// Ping RPC protocol id.
pub const PROTOCOL_PING: &str = "/neutrin0/req/ping";
/// `BlocksByRange` RPC protocol id.
pub const PROTOCOL_BLOCKS_BY_RANGE: &str = "/neutrin0/req/blocks_by_range";
/// `StateByRoot` RPC protocol id, including independently fetched execution programs.
pub const PROTOCOL_STATE_BY_ROOT: &str = "/neutrin0/req/state_by_root";
/// `ChunkProofById` RPC protocol id.
pub const PROTOCOL_CHUNK_PROOF_BY_ID: &str = "/neutrin0/req/chunk_proof_by_id";
/// `HistoryProof` RPC protocol id.
pub const PROTOCOL_HISTORY_PROOF: &str = "/neutrin0/req/history_proof";
/// `FinalityCertByChunk` RPC protocol id.
pub const PROTOCOL_FINALITY_CERT_BY_CHUNK: &str = "/neutrin0/req/finality_cert_by_chunk";
/// `WitnessByBlock` RPC protocol id.
pub const PROTOCOL_WITNESS_BY_BLOCK: &str = "/neutrin0/req/witness_by_block";
/// `ReceiptsByHash` RPC protocol id.
pub const PROTOCOL_RECEIPTS_BY_HASH: &str = "/neutrin0/req/receipts_by_hash";

/// `CandidateByChunk` RPC protocol id.
pub const PROTOCOL_CANDIDATE_BY_CHUNK: &str = "/neutrin0/req/candidate_by_chunk";
/// SignedArtifactById RPC protocol.
pub const PROTOCOL_SIGNED_ARTIFACT_BY_ID: &str = "/neutrin0/req/signed_artifact_by_id";
/// SignedArtifactInventoryByChunk RPC protocol.
pub const PROTOCOL_SIGNED_ARTIFACT_INVENTORY_BY_CHUNK: &str =
    "/neutrin0/req/signed_artifact_inventory_by_chunk";
/// BftRoundByChunk RPC protocol.
pub const PROTOCOL_BFT_ROUND_BY_CHUNK: &str = "/neutrin0/req/bft_round_by_chunk";

/// Default maximum request payload size in bytes (1 MiB).
pub const DEFAULT_MAX_REQUEST_SIZE: u64 = 1024 * 1024;
/// Default maximum response payload size in bytes (32 MiB).
pub const DEFAULT_MAX_RESPONSE_SIZE: u64 = 32 * 1024 * 1024;
/// Request cap for the fixed-size identity queries `SignedArtifactById`,
/// `SignedArtifactInventoryByChunk` and `BftRoundByChunk`.
pub const MAX_IDENTITY_REQUEST_SIZE: u64 = 64;
/// Response cap for one exact `SignedArtifactById` source.
pub const MAX_SIGNED_ARTIFACT_RESPONSE_SIZE: u64 = 8_388_624;
/// Response cap for one `SignedArtifactInventoryByChunk` page.
pub const MAX_SIGNED_ARTIFACT_INVENTORY_RESPONSE_SIZE: u64 = 2048;
/// Response cap for one `BftRoundByChunk` reply.
pub const MAX_BFT_ROUND_RESPONSE_SIZE: u64 = 8_388_608;

/// Maximum number of proven blocks returned in a single `BlocksByRange`
/// response. The provider also stops a page before it would exceed
/// [`DEFAULT_MAX_RESPONSE_SIZE`], since one publication can approach 18 MiB.
pub const MAX_BLOCKS_PER_RESPONSE: u64 = 16;
/// Maximum number of chunk proofs returned in one response.
pub const MAX_CHUNK_PROOFS_PER_RESPONSE: u64 = 2;
/// Maximum number of finality certificates returned in one response.
pub const MAX_FINALITY_CERTS_PER_RESPONSE: u64 = 16;
/// Maximum number of block witnesses returned in one response.
///
/// Witnesses are large; the cap keeps a single response under
/// [`DEFAULT_MAX_RESPONSE_SIZE`] even for fully populated blocks.
pub const MAX_WITNESSES_PER_RESPONSE: u64 = 4;
/// Maximum block receipts per `ReceiptsByHash` response.
pub const MAX_RECEIPTS_PER_RESPONSE: u64 = 16;

/// Identifies one of the core RPC protocols defined by design 21.
///
/// Used to namespace per-protocol request IDs across the independent
/// [`libp2p::request_response::Behaviour`] instances.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RpcProtocol {
    /// Design 21 `/neutrin0/req/status`.
    Status,
    /// Design 21 `/neutrin0/req/metadata`.
    Metadata,
    /// Design 21 `/neutrin0/req/ping`.
    Ping,
    /// Design 21 `/neutrin0/req/blocks_by_range`.
    BlocksByRange,
    /// Design 21 `/neutrin0/req/state_by_root`.
    StateByRoot,
    /// Design 21 `/neutrin0/req/chunk_proof_by_id`.
    ChunkProofById,
    /// Design 21 `/neutrin0/req/history_proof`.
    HistoryProof,
    /// Design 21 `/neutrin0/req/finality_cert_by_chunk`.
    FinalityCertByChunk,
    /// Design 21 `/neutrin0/req/witness_by_block`.
    WitnessByBlock,
    /// Design 21 `/neutrin0/req/receipts_by_hash`.
    ReceiptsByHash,
    /// Query a fully proven next-chunk candidate.
    CandidateByChunk,
    /// Bounded SignedArtifactById transport.
    SignedArtifactById,
    /// Bounded SignedArtifactInventoryByChunk transport.
    SignedArtifactInventoryByChunk,
    /// Bounded BftRoundByChunk transport.
    BftRoundByChunk,
    /// Discover pending transaction hashes.
    TransactionInventory,
    /// Retrieve pending transaction bodies.
    TransactionsByHash,
}

impl RpcProtocol {
    /// Small control replies have a separate reader and response budget.
    pub const fn is_control(self) -> bool {
        matches!(self, Self::Status | Self::Metadata | Self::Ping)
    }

    /// Bulk chain/state data whose retrieval must survive discovery traffic.
    pub const fn is_chain_data(self) -> bool {
        matches!(
            self,
            Self::BlocksByRange
                | Self::StateByRoot
                | Self::ChunkProofById
                | Self::HistoryProof
                | Self::FinalityCertByChunk
                | Self::WitnessByBlock
                | Self::ReceiptsByHash
        )
    }

    /// Every protocol in declaration order, so `protocol as usize` indexes it.
    pub const ALL: [Self; 16] = [
        Self::Status,
        Self::Metadata,
        Self::Ping,
        Self::BlocksByRange,
        Self::StateByRoot,
        Self::ChunkProofById,
        Self::HistoryProof,
        Self::FinalityCertByChunk,
        Self::WitnessByBlock,
        Self::ReceiptsByHash,
        Self::CandidateByChunk,
        Self::SignedArtifactById,
        Self::SignedArtifactInventoryByChunk,
        Self::BftRoundByChunk,
        Self::TransactionInventory,
        Self::TransactionsByHash,
    ];

    /// Outbound request timeout configured on this protocol's behaviour.
    #[must_use]
    pub const fn request_timeout(self) -> Duration {
        Duration::from_secs(match self {
            Self::Status
            | Self::Metadata
            | Self::Ping
            | Self::FinalityCertByChunk
            | Self::CandidateByChunk
            | Self::SignedArtifactById
            | Self::SignedArtifactInventoryByChunk
            | Self::BftRoundByChunk
            | Self::TransactionInventory
            | Self::TransactionsByHash => 15,
            Self::BlocksByRange
            | Self::StateByRoot
            | Self::ChunkProofById
            | Self::HistoryProof
            | Self::ReceiptsByHash => 30,
            Self::WitnessByBlock => 60,
        })
    }

    /// `(request, response)` payload byte caps enforced by this protocol's codec.
    #[must_use]
    pub const fn size_limits(self) -> (u64, u64) {
        match self {
            Self::Status => (161, 1024),
            Self::Metadata => (0, 1024),
            Self::Ping => (8, 1024),
            Self::TransactionInventory => (33, 4101),
            Self::TransactionsByHash => (516, 4_194_373),
            Self::SignedArtifactById => {
                (MAX_IDENTITY_REQUEST_SIZE, MAX_SIGNED_ARTIFACT_RESPONSE_SIZE)
            }
            Self::SignedArtifactInventoryByChunk => (
                MAX_IDENTITY_REQUEST_SIZE,
                MAX_SIGNED_ARTIFACT_INVENTORY_RESPONSE_SIZE,
            ),
            Self::BftRoundByChunk => (MAX_IDENTITY_REQUEST_SIZE, MAX_BFT_ROUND_RESPONSE_SIZE),
            Self::BlocksByRange
            | Self::StateByRoot
            | Self::ChunkProofById
            | Self::HistoryProof
            | Self::FinalityCertByChunk
            | Self::WitnessByBlock
            | Self::ReceiptsByHash
            | Self::CandidateByChunk => (DEFAULT_MAX_REQUEST_SIZE, DEFAULT_MAX_RESPONSE_SIZE),
        }
    }

    /// Canonical wire protocol id.
    #[must_use]
    pub const fn protocol_id(self) -> &'static str {
        match self {
            Self::Status => PROTOCOL_STATUS,
            Self::Metadata => PROTOCOL_METADATA,
            Self::Ping => PROTOCOL_PING,
            Self::BlocksByRange => PROTOCOL_BLOCKS_BY_RANGE,
            Self::StateByRoot => PROTOCOL_STATE_BY_ROOT,
            Self::ChunkProofById => PROTOCOL_CHUNK_PROOF_BY_ID,
            Self::HistoryProof => PROTOCOL_HISTORY_PROOF,
            Self::FinalityCertByChunk => PROTOCOL_FINALITY_CERT_BY_CHUNK,
            Self::WitnessByBlock => PROTOCOL_WITNESS_BY_BLOCK,
            Self::ReceiptsByHash => PROTOCOL_RECEIPTS_BY_HASH,
            Self::CandidateByChunk => PROTOCOL_CANDIDATE_BY_CHUNK,
            Self::SignedArtifactById => PROTOCOL_SIGNED_ARTIFACT_BY_ID,
            Self::SignedArtifactInventoryByChunk => PROTOCOL_SIGNED_ARTIFACT_INVENTORY_BY_CHUNK,
            Self::BftRoundByChunk => PROTOCOL_BFT_ROUND_BY_CHUNK,
            Self::TransactionInventory => "/neutrin0/req/transaction_inventory",
            Self::TransactionsByHash => "/neutrin0/req/transactions_by_hash",
        }
    }

    /// Build a [`StreamProtocol`] from the protocol id.
    #[must_use]
    pub const fn stream_protocol(self) -> StreamProtocol {
        StreamProtocol::new(self.protocol_id())
    }
}

#[cfg(test)]
mod codec_tests;

#[cfg(test)]
mod tests;
