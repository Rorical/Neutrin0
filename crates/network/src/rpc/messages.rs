//! Request and response payloads of the core RPC protocols.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::{BftCandidate, ChunkProof, FinalityCert, HistoryProof};
use neutrin0_primitives::{BlockHash, ChainId, ChunkId, Hash, Height, Slot, StateRoot};

/// Status handshake exchanged on every new connection.
///
/// Used by peers to detect chain mismatches and as input to the sync FSM
/// described in design 21 §"Sync state machine".
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Status {
    /// Chain identifier; mismatching peers should be disconnected.
    pub chain_id: ChainId,
    /// Canonical hash of the local chain spec.
    pub chain_spec_hash: Hash,
    /// Latest proof-finalized chunk; `None` at trusted genesis.
    pub finalized_chunk_id: Option<ChunkId>,
    /// Hash of that chunk, or zero when no chunk has finalized.
    pub finalized_chunk_hash: Hash,
    /// [`neutrin0_consensus_types::Checkpoint`] hash of the boundary that
    /// chunk ends in, whose History proof this peer serves; the genesis
    /// checkpoint before any chunk finalizes.
    pub checkpoint_hash: Hash,
    /// Hash of the materialized head selecting the canonical height index.
    pub head_block_hash: BlockHash,
    /// Slot of the current head.
    pub head_slot: Slot,
    /// Height of the current head.
    pub head_height: Height,
}

impl Status {
    /// Chunk count of the finalized endpoint this peer reports.
    #[must_use]
    pub fn finalized_chunks(&self) -> u64 {
        self.finalized_chunk_id.map_or(0, |id| id.saturating_add(1))
    }
}

/// Empty metadata request marker.
///
/// Borsh deserializes a zero-byte payload as the unit struct, matching the
/// `() → Metadata` shape in design 21.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MetadataRequest;

/// Self-declared peer capabilities.
///
/// `role_flags` is a bitmask of [`role_flags`].
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Metadata {
    /// Self-declared role flags, see [`role_flags`].
    pub role_flags: u32,
    /// Earliest complete chunk payload still served; `None` makes no availability claim.
    pub retained_from_chunk: Option<ChunkId>,
    /// Earliest complete block payload still served; genesis is not a block payload.
    pub retained_from_height: Option<Height>,
}

/// Self-declared role bits a peer advertises in [`crate::rpc::Metadata`].
///
/// Roles are advisory only — misbehaviour is detected by application-level
/// scoring, not enforced cryptographically.
pub mod role_flags {
    /// Honest full node serving any other full node.
    pub const FULL_NODE: u32 = 1 << 0;
    /// Light client; verifier-only.
    pub const LIGHT_CLIENT: u32 = 1 << 1;
    /// Archive provider retaining complete history from genesis without a pruning gap.
    pub const ARCHIVE: u32 = 1 << 2;
}

/// Ping payload — a free-form 64-bit nonce.
///
/// Per design 21 the ping protocol is `u64 → u64`. Senders generally echo the
/// nonce; receivers may return anything.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PingPayload {
    /// Free-form 64-bit nonce.
    pub nonce: u64,
}

/// `BlocksByRange` request: stream proven blocks at
/// `[start_height, start_height + count)` along one advertised branch.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct BlocksByRangeRequest {
    /// Branch anchor from the peer status; all heights refer to its ancestry.
    pub head_block_hash: BlockHash,
    /// First block height to include.
    pub start_height: Height,
    /// Number of blocks to include; clamped to [`crate::rpc::MAX_BLOCKS_PER_RESPONSE`]
    /// and further by the response byte cap.
    pub count: u64,
}

/// `BlocksByRange` response: proven blocks in height order, then the
/// candidates that follow them on the branch (design 08).
///
/// The proven page ends where the provider holds no receipt yet or where the
/// next block would exceed the response byte cap; candidates continue from
/// the first block without a receipt while the provider holds a write set. A
/// page never places a proven block after a candidate, and a short page is
/// partial.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct BlocksByRangeResponse {
    /// Complete publications in canonical height order.
    pub blocks: Vec<neutrin0_consensus_types::ProvenBlock>,
    /// Candidates in canonical height order after the last proven block.
    pub candidates: Vec<neutrin0_consensus_types::CandidateBlock>,
}

/// Request bounded content-addressed fragments under one authenticated state root.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct StateByRootRequest {
    /// Immutable target state root.
    pub state_root: StateRoot,
    /// Exact typed node/value hashes and byte offsets.
    pub items: neutrin0_consensus_types::bootstrap::StateItems,
}

/// Bounded state fragments, in exact request order.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct StateByRootResponse {
    /// Each fragment is independently framed; hashes are checked after assembly.
    pub entries: neutrin0_consensus_types::bootstrap::StateEntries,
}

/// `ChunkProofById` request: fetch chunk proofs by chunk id.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct ChunkProofByIdRequest {
    /// Chunk ids whose proofs are requested.
    pub chunk_ids: Vec<ChunkId>,
    /// Empty for each chunk's canonical proof. Otherwise one statement key per
    /// id, selecting the retained proof of that chunk with that key, canonical
    /// or alternative: a voter fetches a proof a ratification list names
    /// (design 08).
    pub statement_keys: Vec<Hash>,
}

/// `ChunkProofById` response carrying requested chunk proofs.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ChunkProofByIdResponse {
    /// Chunk proofs in the same order as requested ids; entries omitted when unknown.
    pub proofs: Vec<ChunkProof>,
}

/// Request the History proof of an exact endpoint, anchored at a boundary the
/// requester already trusts.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct HistoryProofRequest {
    /// Chunk count of the requester's trusted boundary; the provider opens it
    /// under the endpoint unless it is genesis or the endpoint itself.
    pub anchor_chunks: u64,
    /// Chunk count of the requested endpoint.
    pub end_chunks: u64,
    /// Exact [`neutrin0_consensus_types::Checkpoint`] hash of that endpoint;
    /// a provider on another fork refuses rather than substituting its own.
    pub checkpoint_hash: Hash,
    /// Include authenticated full-node bootstrap context for the endpoint.
    pub bootstrap: bool,
}

/// One endpoint's History proof, or an explicit unavailable RPC error.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct HistoryProofResponse {
    /// The endpoint's chunk receipt, which proves the chain from the
    /// specification's start (genesis or a hard fork's start).
    pub proof: HistoryProof,
    /// Opening of the requested anchor under the endpoint's history root.
    pub anchor: Option<neutrin0_consensus_types::AnchorOpening>,
    /// Full-node context for this same endpoint, requested explicitly.
    pub bootstrap: Option<neutrin0_consensus_types::bootstrap::BootstrapData>,
}

/// Lightweight availability announcement of a newly finalized endpoint;
/// never accepted as a proof or trust anchor.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointAnnouncement {
    /// Chunk count of the endpoint, whose History proof covers every chunk below it.
    pub chunk_count: u64,
    /// Endpoint identity; receivers request and verify its History proof.
    pub checkpoint_hash: Hash,
}

/// `FinalityCertByChunk` request: fetch the BFT finality certificate
/// for one or more chunk ids.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct FinalityCertByChunkRequest {
    /// Chunk ids whose finality certificates are requested.
    pub chunk_ids: Vec<ChunkId>,
}

/// `FinalityCertByChunk` response carrying requested finality
/// certificates in request order. A certificate may precede its complete
/// Chunk proof and does not by itself authenticate finalized state.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct FinalityCertByChunkResponse {
    /// Finality certificates in request order.
    pub certs: Vec<FinalityCert>,
}

/// `WitnessByBlock` request: fetch execution witnesses for blocks.
///
/// Any node holding a requested block's execution witness serves it, for
/// provers outside the node; a node holding none returns an empty response.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct WitnessByBlockRequest {
    /// Block header hashes whose witnesses are requested.
    pub block_hashes: Vec<BlockHash>,
}

/// `WitnessByBlock` response carrying opaque witness bytes.
///
/// Entries are in request order; missing entries indicate the local
/// node has no witness for that block. Consumers should treat a
/// short response as partial and re-request from another peer.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct WitnessByBlockResponse {
    /// Opaque witness blobs in request order.
    pub witnesses: Vec<Vec<u8>>,
}

/// `ReceiptsByHash` request: the retained receipts of up to
/// [`crate::rpc::MAX_RECEIPTS_PER_RESPONSE`] blocks by header hash.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct ReceiptsByHashRequest {
    /// Block header hashes whose receipts are requested.
    pub block_hashes: Vec<BlockHash>,
}

/// `ReceiptsByHash` response: every retained receipt of the requested blocks,
/// in request order, the canonical receipt of each block first.
///
/// A block keeps several valid receipts with distinct statement keys (design
/// 08), and a voter fetches the one a proposal names. Unknown or unproven
/// blocks are omitted. A short response is partial; the requester asks
/// another peer for the rest.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ReceiptsByHashResponse {
    /// Retained receipts in request order.
    pub receipts: Vec<neutrin0_consensus_types::BlockReceipt>,
}

/// Discover the current candidate, or an exact target referenced by a vote.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateByChunkRequest {
    /// Only the provider's next unfinalized chunk is served.
    pub chunk_id: ChunkId,
    /// Exact semantic target, or `None` to discover the active candidate.
    pub chunk_hash: Option<Hash>,
}

/// A bounded candidate hint; branch data is fetched through ordinary anchored RPCs.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct CandidateByChunkResponse {
    /// Fully verified provider branch and optional prior-round quorum.
    pub candidate: BftCandidate,
}

/// Retrieve one exact immutable source, including alternative proof encodings.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedArtifactByIdRequest {
    /// Exact canonical source identity.
    pub id: Hash,
}
/// Exact bounded original source; receivers authenticate it independently.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Eq, PartialEq)]
pub struct SignedArtifactByIdResponse {
    /// Exact requested vote, quorum or block-proof envelope.
    pub artifact: neutrin0_consensus_types::signed_artifacts::SignedArtifact,
}
/// Paginate original sources for one authenticated source chunk.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedArtifactInventoryByChunkRequest {
    /// Source chunk; not an assertion of finality.
    pub chunk_id: ChunkId,
    /// Exclusive immutable content-hash cursor.
    pub after: Option<Hash>,
}
/// At most 32 source references in immutable increasing order.
pub type SignedArtifactInventoryByChunkResponse =
    neutrin0_consensus_types::signed_artifacts::SignedArtifactInventory;
/// Fetch current signed leader and pacemaker information for a chunk.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct BftRoundByChunkRequest {
    /// Exact unfinalized consensus height.
    pub chunk_id: ChunkId,
}
/// Availability response; all declarations require independent authentication.
#[derive(BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct BftRoundByChunkResponse {
    /// Current signed proposal, when available.
    pub proposal: Option<neutrin0_consensus_types::BftProposal>,
    /// Independently signed higher-round catch-up certificate.
    pub round_change: Option<neutrin0_consensus_types::RoundChangeCertificate>,
}

impl BorshDeserialize for BftRoundByChunkResponse {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let proposal = match u8::deserialize_reader(reader)? {
            0 => None,
            1 => Some(neutrin0_consensus_types::bft::read_proposal(reader)?),
            _ => {
                return Err(borsh::io::Error::new(
                    borsh::io::ErrorKind::InvalidData,
                    "proposal option",
                ));
            }
        };
        let round_change = match u8::deserialize_reader(reader)? {
            0 => None,
            1 => Some(neutrin0_consensus_types::bft::read_round_change_certificate(reader)?),
            _ => {
                return Err(borsh::io::Error::new(
                    borsh::io::ErrorKind::InvalidData,
                    "round certificate option",
                ));
            }
        };
        Ok(Self {
            proposal,
            round_change,
        })
    }
}
