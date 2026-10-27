//! Keyset page edges and connections of every listing.
use super::{Block, Chunk, Log, PageInfo, Proof, TokenTransfer, TransactionRecord};
use async_graphql::SimpleObject;

/// One block page edge.
#[derive(SimpleObject)]
pub struct BlockEdge {
    /// Opaque generation/filter-bound cursor.
    pub cursor: String,
    /// Indexed record.
    pub node: Block,
}
/// Bounded block connection.
#[derive(SimpleObject)]
pub struct BlockConnection {
    /// Ordered edges.
    pub edges: Vec<BlockEdge>,
    /// Continuation metadata.
    pub page_info: PageInfo,
}

/// One transaction page edge.
#[derive(SimpleObject)]
pub struct TransactionEdge {
    /// Opaque generation/filter-bound cursor.
    pub cursor: String,
    /// Indexed record.
    pub node: TransactionRecord,
}
/// Bounded transaction connection.
#[derive(SimpleObject)]
pub struct TransactionConnection {
    /// Ordered edges.
    pub edges: Vec<TransactionEdge>,
    /// Continuation metadata.
    pub page_info: PageInfo,
}

/// One log page edge.
#[derive(SimpleObject)]
pub struct LogEdge {
    /// Opaque generation/filter-bound cursor.
    pub cursor: String,
    /// Indexed record.
    pub node: Log,
}
/// Bounded log connection.
#[derive(SimpleObject)]
pub struct LogConnection {
    /// Ordered edges.
    pub edges: Vec<LogEdge>,
    /// Continuation metadata.
    pub page_info: PageInfo,
}

/// One transfer page edge.
#[derive(SimpleObject)]
pub struct TransferEdge {
    /// Opaque generation/filter-bound cursor.
    pub cursor: String,
    /// Indexed record.
    pub node: TokenTransfer,
}
/// Bounded transfer connection.
#[derive(SimpleObject)]
pub struct TransferConnection {
    /// Ordered edges.
    pub edges: Vec<TransferEdge>,
    /// Continuation metadata.
    pub page_info: PageInfo,
}

/// One chunk page edge.
#[derive(SimpleObject)]
pub struct ChunkEdge {
    /// Opaque generation/filter-bound cursor.
    pub cursor: String,
    /// Indexed record.
    pub node: Chunk,
}
/// Bounded chunk connection.
#[derive(SimpleObject)]
pub struct ChunkConnection {
    /// Ordered edges.
    pub edges: Vec<ChunkEdge>,
    /// Continuation metadata.
    pub page_info: PageInfo,
}

/// One proof page edge.
#[derive(SimpleObject)]
pub struct ProofEdge {
    /// Opaque generation/filter-bound cursor.
    pub cursor: String,
    /// Indexed record.
    pub node: Proof,
}
/// Bounded proof connection.
#[derive(SimpleObject)]
pub struct ProofConnection {
    /// Ordered edges.
    pub edges: Vec<ProofEdge>,
    /// Continuation metadata.
    pub page_info: PageInfo,
}
