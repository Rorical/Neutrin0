//! Column-family names shared by all storage backends.

/// Named storage column.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Column {
    /// Authenticated trie nodes, keyed by node hash.
    TrieNodes,
    /// Content-addressed state values, keyed by value hash.
    StateValues,
    /// Block bodies, keyed by block hash.
    Blocks,
    /// Runtime transaction identifiers plus block hash; value is height and transaction index.
    ExecutionTransactions,
    /// Block headers, keyed by block hash.
    Headers,
    /// Canonical block hash by height, keyed by big-endian or
    /// little-endian height bytes chosen by the caller.
    HeaderByHeight,
    /// One or more block hashes by slot, keyed by caller-encoded slot.
    HeaderBySlot,
    /// Finalized chunks, keyed by chunk id.
    Chunks,
    /// Per-block preferred receipt, keyed by block hash.
    BlockProofs,
    /// Every retained receipt of a block, keyed by block hash then statement
    /// key (design 08).
    BlockReceipts,
    /// Per-block consensus FSM state, keyed by block hash.
    BlockStates,
    /// Per-chunk proof artifacts, keyed by chunk id.
    ChunkProofs,
    /// Verified chunk proofs retained for ratification, keyed by chunk id
    /// then statement key (design 08).
    ChunkReceipts,
    /// Execution witnesses, keyed by block hash.
    Witnesses,
    /// Per-block execution state diffs served to proof-following nodes,
    /// keyed by block hash.
    StateDiffs,
    /// Validator-set snapshots, keyed by the index at which each set takes effect.
    ValidatorSetSnapshots,
    /// Chain pointers such as `tip`, `finalized_head`, `latest_chunk_id` and
    /// `chain_spec_hash`.
    Finalized,
    /// Node-local raw misconduct reports awaiting an evidence proof. Key is
    /// BLAKE3 of the borsh-encoded `SlashingEvidence`; value is the
    /// borsh-encoded evidence itself, so a node that crashes after
    /// detecting an offence still proves it after restart.
    SlashingPool,
    /// Node-local metadata such as chain-spec hash.
    Meta,
    /// Immutable compact statements of finalized chunks.
    ChunkStatements,
    /// Canonical consensus boundaries, keyed by covered chunk count.
    ConsensusBoundaries,
    /// Finalized historical records, keyed by chunk ID.
    HistoricalChunks,
    /// Archive-only content-addressed immutable binary history nodes.
    HistoryNodes,
    /// Bounded append frontiers, keyed by covered chunk count.
    HistoryFrontiers,
    /// Bounded authenticated history openings, keyed by count and leaf index.
    HistoryPaths,
    /// Offence admissions authenticated by finalized block proofs.
    FinalizedOffences,
    /// BLS identities whose safety sanction finalized blocks have admitted.
    FinalizedSlashes,
    /// Verified offence reports and locally authenticated path anchors,
    /// keyed by program-scoped statement ID.
    EvidenceProofs,
    /// Durable local signing intents and monotonic signing watermarks.
    SigningJournal,
    /// Unfinalized BFT sessions, including local votes and quorum certificates.
    BftSessions,
    /// Durable exact signed sources and proof envelopes for delayed accountability.
    SignedArtifacts,
    /// Bounded metadata index for exact signed sources and proof dependencies.
    SignedArtifactIndex,
    /// Selectively retained historical contexts and continuously refreshed openings.
    ReporterHistory,
    /// Exact accountability sources owned by slashable tracked identities.
    ReporterSources,
    /// Signed headers and compact proof-input dependencies for reporter discovery.
    ReporterHeaders,
    /// Compact historical program boundaries used to authenticate retained proof sources.
    ReporterBoundaries,
    /// Finalized-runtime-authorized slashable identities and withdrawal addresses.
    ReporterValidators,
    /// Compact exact-identity indexes into selective reporter sources and headers.
    ReporterIndex,
    /// Reference counts of stored trie nodes and state values, keyed by kind
    /// byte then content hash: parent edges plus pins that reach each entry.
    StateRefs,
    /// State roots the node keeps readable, keyed by what pins them.
    StatePins,
    /// Persistent queue of released references, drained in bounded slices.
    StateReleases,
    /// Signed headers of stale candidates that rooted their stale subtree,
    /// kept for abandonment detection, keyed by big-endian height then hash.
    AbandonedHeaders,
}

/// Every storage column in deterministic order.
pub const ALL_COLUMNS: [Column; 42] = [
    Column::TrieNodes,
    Column::StateValues,
    Column::Blocks,
    Column::ExecutionTransactions,
    Column::Headers,
    Column::HeaderByHeight,
    Column::HeaderBySlot,
    Column::Chunks,
    Column::BlockProofs,
    Column::BlockReceipts,
    Column::BlockStates,
    Column::ChunkProofs,
    Column::ChunkReceipts,
    Column::Witnesses,
    Column::StateDiffs,
    Column::ValidatorSetSnapshots,
    Column::Finalized,
    Column::SlashingPool,
    Column::Meta,
    Column::ChunkStatements,
    Column::ConsensusBoundaries,
    Column::HistoricalChunks,
    Column::HistoryNodes,
    Column::HistoryFrontiers,
    Column::HistoryPaths,
    Column::FinalizedOffences,
    Column::FinalizedSlashes,
    Column::EvidenceProofs,
    Column::SigningJournal,
    Column::BftSessions,
    Column::SignedArtifacts,
    Column::SignedArtifactIndex,
    Column::ReporterHistory,
    Column::ReporterSources,
    Column::ReporterHeaders,
    Column::ReporterBoundaries,
    Column::ReporterValidators,
    Column::ReporterIndex,
    Column::StateRefs,
    Column::StatePins,
    Column::StateReleases,
    Column::AbandonedHeaders,
];

impl Column {
    /// Returns the stable RocksDB column-family name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TrieNodes => "trie_nodes",
            Self::StateValues => "state_values",
            Self::Blocks => "blocks",
            Self::ExecutionTransactions => "execution_transactions",
            Self::Headers => "headers",
            Self::HeaderByHeight => "header_by_height",
            Self::HeaderBySlot => "header_by_slot",
            Self::Chunks => "chunks",
            Self::BlockProofs => "block_proofs",
            Self::BlockReceipts => "block_receipts",
            Self::BlockStates => "block_states",
            Self::ChunkProofs => "chunk_proofs",
            Self::ChunkReceipts => "chunk_receipts",
            Self::Witnesses => "witnesses",
            Self::StateDiffs => "state_diffs",
            Self::ValidatorSetSnapshots => "validator_set_snap",
            Self::Finalized => "finalized",
            Self::SlashingPool => "slashing_pool",
            Self::Meta => "meta",
            Self::ChunkStatements => "chunk_statements",
            Self::ConsensusBoundaries => "consensus_boundaries",
            Self::HistoricalChunks => "historical_chunks",
            Self::HistoryNodes => "history_nodes",
            Self::HistoryFrontiers => "history_frontiers",
            Self::HistoryPaths => "history_paths",
            Self::FinalizedOffences => "finalized_offences",
            Self::FinalizedSlashes => "finalized_slashes",
            Self::EvidenceProofs => "evidence_proofs",
            Self::SigningJournal => "signing_journal",
            Self::BftSessions => "bft_sessions",
            Self::SignedArtifacts => "signed_artifacts",
            Self::SignedArtifactIndex => "signed_artifact_index",
            Self::ReporterHistory => "reporter_history",
            Self::ReporterSources => "reporter_sources",
            Self::ReporterHeaders => "reporter_headers",
            Self::ReporterBoundaries => "reporter_boundaries",
            Self::ReporterValidators => "reporter_validators",
            Self::ReporterIndex => "reporter_index",
            Self::StateRefs => "state_refs",
            Self::StatePins => "state_pins",
            Self::StateReleases => "state_releases",
            Self::AbandonedHeaders => "abandoned_headers",
        }
    }
}

#[cfg(test)]
mod tests;
