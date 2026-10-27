//! Retained consensus artifacts and recoverable local chain observations.
use super::{BytesHex, HashHex};
use serde::{Deserialize, Serialize};
/// Canonical finalized chunk, with independently reported artifact availability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChunkJson {
    /// Canonical Chunk commitment, independent of receipt encoding.
    pub hash: HashHex,
    /// Consensus Chunk field `chunk_id`.
    pub chunk_id: u64,
    /// Consensus Chunk field `start_height`.
    pub start_height: u64,
    /// Consensus Chunk field `end_height`.
    pub end_height: u64,
    /// Consensus Chunk field `start_state_root`.
    pub start_state_root: HashHex,
    /// Consensus Chunk field `end_state_root`.
    pub end_state_root: HashHex,
    /// Consensus Chunk field `start_block_hash`.
    pub start_block_hash: HashHex,
    /// Consensus Chunk field `end_block_hash`.
    pub end_block_hash: HashHex,
    /// Consensus Chunk field `block_hash_root`.
    pub block_hash_root: HashHex,
    /// Consensus Chunk field `block_proof_root`.
    pub block_proof_root: HashHex,
    /// Consensus Chunk field `vrf_proof_root`.
    pub vrf_proof_root: HashHex,
    /// Consensus Chunk field `active_validator_set_root`.
    pub active_validator_set_root: HashHex,
    /// Consensus Chunk field `next_validator_set_root`.
    pub next_validator_set_root: HashHex,
    /// Consensus Chunk field `next_identity_sanctions_root`.
    pub next_identity_sanctions_root: HashHex,
    /// Consensus Chunk field `da_root`.
    pub da_root: HashHex,
    /// Whether exact complete consensus receipt bytes are locally available.
    pub proof_available: bool,
    /// Whether the complete accountability certificate is locally available.
    pub certificate_available: bool,
}
impl ChunkJson {
    /// Project a persisted finalized chunk without serializing proof bytes.
    #[must_use]
    pub fn new(
        chunk: &neutrin0_consensus_types::Chunk,
        proof_available: bool,
        certificate_available: bool,
    ) -> Self {
        Self {
            hash: HashHex(chunk.hash()),
            chunk_id: chunk.chunk_id,
            start_height: chunk.start_height,
            end_height: chunk.end_height,
            start_state_root: HashHex(chunk.start_state_root),
            end_state_root: HashHex(chunk.end_state_root),
            start_block_hash: HashHex(chunk.start_block_hash),
            end_block_hash: HashHex(chunk.end_block_hash),
            block_hash_root: HashHex(chunk.block_hash_root),
            block_proof_root: HashHex(chunk.block_proof_root),
            vrf_proof_root: HashHex(chunk.vrf_proof_root),
            active_validator_set_root: HashHex(chunk.active_validator_set_root),
            next_validator_set_root: HashHex(chunk.next_validator_set_root),
            next_identity_sanctions_root: HashHex(chunk.next_identity_sanctions_root),
            da_root: HashHex(chunk.da_root),
            proof_available,
            certificate_available,
        }
    }
}
/// Exact artifact locator; finalized chunk numbers and native block hashes are explicit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactIdJson {
    /// Block execution proof envelope.
    BlockProof {
        /// Exact native block identifier.
        block: HashHex,
    },
    /// Complete consensus proof envelope.
    ChunkProof {
        /// Finalized chunk identifier.
        chunk: u64,
    },
    /// Mandatory finality certificate.
    Certificate {
        /// Finalized chunk identifier.
        chunk: u64,
    },
}
/// Metadata for canonical Borsh artifact downloads; it does not replace verification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactInfoJson {
    /// Exact locator.
    pub id: ArtifactIdJson,
    /// BLAKE3 of the complete Borsh envelope, including proof bytes.
    pub artifact_hash: HashHex,
    /// Complete envelope length in bytes.
    pub encoded_bytes: u64,
    /// Opaque backend receipt length, zero for certificates.
    pub proof_bytes: u64,
    /// Exact Borsh public statement/inputs, absent for certificates.
    pub public_values: Option<BytesHex>,
}
/// Bounded slice of the exact artifact pinned by its envelope hash.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactSliceJson {
    /// Exact envelope commitment.
    pub artifact_hash: HashHex,
    /// Total Borsh envelope length.
    pub encoded_bytes: u64,
    /// Requested byte offset.
    pub offset: u64,
    /// At most 1 MiB of exact canonical Borsh bytes.
    pub bytes: BytesHex,
}
/// Inspectable certificate summary. Exact signatures and declarations are downloadable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CertificateJson {
    /// Finalized chunk identifier.
    pub chunk_id: u64,
    /// Canonical finalized chunk commitment.
    pub chunk_hash: HashHex,
    /// Certified BFT round.
    pub round: u32,
    /// Validator-set commitment used to weight both phases.
    pub active_validator_set_root: HashHex,
    /// Selected signed leader's authenticated committee index.
    pub leader_index: u32,
    /// Exact Borsh signed leader proposal, including its round-change certificate.
    pub proposal: BytesHex,
    /// Authenticated prevote participants.
    pub prevote_signers: Vec<u32>,
    /// Authenticated precommit participants.
    pub precommit_signers: Vec<u32>,
    /// Aggregate prevote BLS signature.
    pub prevote_signature: BytesHex,
    /// Aggregate precommit BLS signature.
    pub precommit_signature: BytesHex,
    /// Individual prevote declarations retained in the exact downloadable certificate.
    pub prevote_attestations: u32,
    /// Individual precommit declarations retained in the exact downloadable certificate.
    pub precommit_attestations: u32,
    /// Exact ordered proof-envelope hash lists declared by precommit signers.
    pub proof_manifests: Vec<Vec<HashHex>>,
    /// Download locator, commitment and byte size for the complete certificate.
    pub artifact: ArtifactInfoJson,
}
/// Canonical endpoint sufficient to locate a header or backfill ancestry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainPointJson {
    /// Native canonical block hash.
    pub hash: HashHex,
    /// Canonical block height.
    pub height: u64,
}
/// Last durably consumed sequence. A cursor is scoped to one database-local stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainCursorJson {
    /// Random, durable stream identity; a new database gets a new identity.
    pub stream_id: HashHex,
    /// Last consumed sequence as a decimal string (lossless in JavaScript).
    pub sequence: String,
}
/// Atomic chain snapshot with the event journal's durable bounds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainEventStatusJson {
    /// Full chain specification commitment; transport observations are not light-client proofs.
    pub chain_spec_hash: HashHex,
    /// Current canonical execution head.
    pub head: ChainPointJson,
    /// Complete-chunk finalized endpoint.
    pub finalized: ChainPointJson,
    /// Number of finalized chunks.
    pub finalized_chunks: u64,
    /// Last retained sequence, usable to subscribe only to future transitions.
    pub latest: ChainCursorJson,
    /// Cursor immediately before the first retained event, usable to replay the window.
    pub replay_from: ChainCursorJson,
    /// Maximum retained transition count, independent of payload retention.
    pub retention_events: u64,
}
/// One durably ordered local canonical transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainEventJson {
    /// Resume cursor after this event.
    pub cursor: ChainCursorJson,
    /// snapshot, head, reorg, finalized or checkpoint (the latter requires backfill).
    pub kind: String,
    /// Previous head; absent only for stream initialization.
    pub previous_head: Option<ChainPointJson>,
    /// New canonical execution head.
    pub head: ChainPointJson,
    /// Exact common ancestor; absent when checkpoint/source limits prevent reconstruction.
    pub common_ancestor: Option<ChainPointJson>,
    /// Previous finalized endpoint.
    pub previous_finalized: ChainPointJson,
    /// New complete-chunk finalized endpoint.
    pub finalized: ChainPointJson,
    /// Previous finalized chunk count.
    pub previous_finalized_chunks: u64,
    /// New finalized chunk count.
    pub finalized_chunks: u64,
}
/// Bounded replay page. The returned snapshot and all events share one engine read lock.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChainEventPageJson {
    /// Current journal bounds and chain snapshot.
    pub status: ChainEventStatusJson,
    /// Ordered transitions strictly after the supplied cursor.
    pub events: Vec<ChainEventJson>,
    /// Cursor after the last event, or the input cursor for an empty page.
    pub next: ChainCursorJson,
    /// More transitions were already committed at the captured snapshot.
    pub has_more: bool,
}
/// Subscription notification, including a recoverable terminal replay failure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChainNotificationJson {
    /// Initial atomic observation; the resume cursor precedes any replayed events.
    Snapshot {
        /// Current snapshot and replay bounds.
        status: ChainEventStatusJson,
        /// Cursor used to begin this subscription.
        after: ChainCursorJson,
    },
    /// One durable transition; reconnect after this cursor for at-least-once delivery.
    Event {
        /// Transition payload.
        event: ChainEventJson,
    },
    /// This subscription cannot safely continue; use the supplied snapshot to recover.
    ResetRequired {
        /// Stable reason code.
        reason: String,
        /// Current atomic snapshot when available.
        status: Option<ChainEventStatusJson>,
    },
}

/// Header-bound opaque execution data, decoded without replay by consumers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockArtifactsJson {
    /// Exact native block identifier.
    pub block_hash: HashHex,
    /// Historical runtime artifact that produced these receipts.
    pub runtime_code_hash: HashHex,
    /// Canonical Borsh `ExecutionArtifacts`, including IDs, receipts and metadata.
    pub artifacts: BytesHex,
}
