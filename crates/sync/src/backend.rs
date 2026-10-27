//! Host-supplied backend abstraction for the sync driver.
//!
//! The driver remains storage-agnostic: it asks the backend for the data
//! needed to serve incoming RPCs, and hands the backend the data it
//! receives from peers for verification and persistence. Real nodes plug
//! in an implementation backed by `neutrin0-consensus-engine`'s
//! [`ChainStore`](https://docs.rs/neutrin0-consensus-engine); tests use a
//! lightweight in-memory mock.

use async_trait::async_trait;
use neutrin0_consensus_types::{
    AnchorOpening, BftCandidate, BlockReceipt, CandidateBlock, ChunkProof, FinalityVote,
    HistoryProof, ProvenBlock, SlashingEvidence,
};
use neutrin0_network::rpc::{
    BlocksByRangeResponse, CandidateByChunkResponse, ChunkProofByIdResponse,
    FinalityCertByChunkResponse, HistoryProofResponse, Metadata, ReceiptsByHashResponse,
    StateByRootResponse, Status, WitnessByBlockResponse, role_flags,
};
use neutrin0_network::sync::LocalProgress;
use neutrin0_primitives::{BlockHash, CheckpointIndex, ChunkId, Hash, Height, StateRoot};

mod types;

pub use types::{
    CheckpointsImported, ChunkProofImported, ConsensusSyncTarget, EvidenceProofAcceptance,
    HeadersImported, ProposalArtifacts, ReceiptsImported, StateProgress, SyncBackendError,
};

/// Host-supplied verification + storage adapter.
///
/// All methods take `&self`; implementations are expected to use interior
/// mutability (typically an `Arc<Mutex<…>>` over a `ChainStore`). The trait
/// is `async` to leave room for backends that need to defer to
/// [`tokio::task::spawn_blocking`] for sync storage backends like RocksDB.
#[async_trait]
pub trait SyncBackend: Send + Sync + 'static {
    /// Next chunk whose consensus certificate or complete proof is needed locally.
    async fn consensus_sync_target(&self) -> Result<Option<ConsensusSyncTarget>, SyncBackendError> {
        Ok(None)
    }
    /// Whether this backend supports current-program candidate branch synchronization.
    fn supports_bft_candidate_sync(&self) -> bool {
        false
    }
    /// Whether proven candidate backfill also fetches a complete BFT certificate.
    fn supports_certified_execution_sync(&self) -> bool {
        false
    }
    /// Last height authorized for execution by a complete native certificate.
    /// Finality downloads still target `consensus_sync_target` independently.
    async fn certified_execution_sync_height(&self) -> Option<Height> {
        None
    }
    /// Authenticate a complete certificate against locally verified Block receipts.
    /// This permits bounded execution only; it never publishes finality.
    async fn verify_and_import_execution_certificate(
        &self,
        _certificate: neutrin0_consensus_types::FinalityCert,
    ) -> Result<(), SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "execution certification is unsupported".into(),
        ))
    }
    /// Discover a fully proven next-chunk target, optionally by its exact hash.
    async fn bft_candidate(
        &self,
        _chunk_id: ChunkId,
        _hash: Option<Hash>,
    ) -> Result<CandidateByChunkResponse, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "candidate unavailable".into(),
        ))
    }
    /// Authenticate local boundary/range and any carried QC before caching a hint.
    async fn validate_bft_candidate_hint(&self, _candidate: &BftCandidate) -> bool {
        false
    }
    /// Whether an authenticated next-chunk vote needs exact candidate discovery.
    async fn bft_vote_needs_candidate(&self, _vote: &FinalityVote) -> bool {
        false
    }
    /// Whether every block of `candidate`'s branch is already held and proven
    /// locally, so discovery can consider it without downloading the range.
    async fn holds_bft_candidate_branch(&self, _candidate: &BftCandidate) -> bool {
        false
    }
    /// Independently authenticate a downloaded branch and apply local round/lock policy.
    async fn consider_bft_candidate(
        &self,
        _candidate: BftCandidate,
    ) -> Result<(), SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "candidate replacement unavailable".into(),
        ))
    }

    /// Whether the backend verifies the live leader/nil/pacemaker protocol.
    fn supports_bft_message_sync(&self) -> bool {
        false
    }
    /// The authenticated next source and local round, for bounded catchup queues.
    async fn current_bft_round(&self) -> Option<(ChunkId, u32)> {
        None
    }
    /// Fetch the current signed proposal and authenticated round-change quorum.
    async fn bft_round_by_chunk(
        &self,
        _chunk_id: ChunkId,
    ) -> Result<neutrin0_network::rpc::BftRoundByChunkResponse, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "BFT round unavailable".into(),
        ))
    }
    /// Verify proposal leadership, signatures and the authenticated source boundary.
    /// The candidate's block/proof branch may still need independent backfill.
    /// An unavailable local source is neutral, including a different finalized chunk.
    async fn validate_bft_proposal_hint(
        &self,
        _proposal: &neutrin0_consensus_types::BftProposal,
    ) -> Result<(), SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "BFT proposal context unavailable".into(),
        ))
    }
    /// Admit a signed live BFT message after verification and durable persistence.
    async fn ingest_bft_message(
        &self,
        _message: neutrin0_consensus_types::BftMessage,
    ) -> Result<(), SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "BFT protocol unavailable".into(),
        ))
    }

    /// Build a [`Status`] payload reflecting the local chain head.
    async fn local_status(&self) -> Result<Status, SyncBackendError>;

    /// Build a [`Metadata`] payload advertising local peer capabilities.
    async fn local_metadata(&self) -> Metadata {
        Metadata {
            role_flags: role_flags::FULL_NODE,
            retained_from_chunk: None,
            retained_from_height: None,
        }
    }

    /// Build a [`LocalProgress`] snapshot for the sync FSM.
    async fn local_progress(&self) -> Result<LocalProgress, SyncBackendError>;

    /// Build a response to `/neutrin0/req/history_proof`: the History proof
    /// of the canonical endpoint at `end` chunks whose checkpoint hash is
    /// `checkpoint`, and the opening of the boundary at `anchor` chunks under
    /// it unless that is the specification's start (genesis or a fork's
    /// start) or the endpoint. Refuses an opening it no longer retains, and a
    /// different endpoint rather than substituting its own.
    async fn history_proof(
        &self,
        anchor: CheckpointIndex,
        end: CheckpointIndex,
        checkpoint: Hash,
    ) -> Result<HistoryProofResponse, SyncBackendError>;

    /// Full-node bootstrap trust origin selected from local configuration or finality.
    async fn bootstrap_origin(&self) -> Option<neutrin0_consensus_types::Checkpoint> {
        None
    }
    /// Freeze local execution while an authenticated bootstrap target is fetched.
    async fn bootstrap_fetch(&self, _active: bool) {}
    /// Resume durable authenticated state/program reconstruction, if active.
    async fn bootstrap_state(
        &self,
    ) -> Result<
        Option<(
            StateRoot,
            Vec<neutrin0_consensus_types::bootstrap::StateItem>,
        )>,
        SyncBackendError,
    > {
        Ok(None)
    }
    /// Serve the bootstrap context of an exact finalized endpoint.
    async fn bootstrap_data(
        &self,
        _end: Hash,
    ) -> Result<neutrin0_consensus_types::bootstrap::BootstrapData, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "bootstrap context unavailable".into(),
        ))
    }
    /// Verify the receipt, the opening of the local trust anchor and the
    /// context before starting a state download.
    async fn begin_bootstrap(
        &self,
        _anchor: Option<AnchorOpening>,
        _data: neutrin0_consensus_types::bootstrap::BootstrapData,
    ) -> Result<StateProgress, SyncBackendError> {
        Err(SyncBackendError::NotAvailable("bootstrap disabled".into()))
    }

    /// Build a response to `/neutrin0/req/blocks_by_range`: complete
    /// publications along the advertised branch, ending the page where a
    /// receipt or write set is not retained yet.
    async fn blocks_by_range(
        &self,
        start: Height,
        count: u64,
        head: BlockHash,
    ) -> Result<BlocksByRangeResponse, SyncBackendError>;

    /// Build a response to `/neutrin0/req/state_by_root`, including bounded
    /// Runtime/Guest fragments requested under authenticated bootstrap identities.
    async fn state_nodes(
        &self,
        root: StateRoot,
        items: &[neutrin0_consensus_types::bootstrap::StateItem],
    ) -> Result<StateByRootResponse, SyncBackendError>;

    /// Build a response to `/neutrin0/req/chunk_proof_by_id`.
    async fn chunk_proofs_by_id(
        &self,
        chunk_ids: &[ChunkId],
    ) -> Result<ChunkProofByIdResponse, SyncBackendError>;

    /// Build a response to a `/neutrin0/req/chunk_proof_by_id` request naming
    /// statement keys: the retained proof of each chunk with that key,
    /// canonical or alternative, unknown entries omitted (design 08).
    async fn chunk_proofs_by_key(
        &self,
        _entries: &[(ChunkId, Hash)],
    ) -> Result<ChunkProofByIdResponse, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "keyed chunk proof retrieval is unsupported".to_owned(),
        ))
    }

    /// The receipts and chunk proofs a deferred leader proposal names that
    /// this node does not hold, so the driver can fetch them from the peer
    /// that relayed the proposal (design 08).
    async fn missing_proposal_artifacts(
        &self,
        _proposal: &neutrin0_consensus_types::BftProposal,
    ) -> ProposalArtifacts {
        ProposalArtifacts::default()
    }

    /// Build a response to `/neutrin0/req/finality_cert_by_chunk`.
    ///
    /// Backends retrieve persisted certificates or return an explicit error.
    async fn finality_certs_by_chunk(
        &self,
        _chunk_ids: &[ChunkId],
    ) -> Result<FinalityCertByChunkResponse, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "finality certificate retrieval is unsupported".to_owned(),
        ))
    }

    /// Build a response to `/neutrin0/req/witness_by_block`.
    ///
    /// Backends retrieve persisted witnesses or return an explicit error.
    async fn witnesses_by_block(
        &self,
        _block_hashes: &[BlockHash],
    ) -> Result<WitnessByBlockResponse, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "witness retrieval is unsupported".to_owned(),
        ))
    }

    /// Import complete publications in order (design 07): each block, the
    /// bytes of its receipt and the write set of its execution. A
    /// proof-following backend verifies the receipt and applies the writes;
    /// an executing backend re-executes the body, checks the receipt and
    /// requires its own write set to equal the published one. The first
    /// failure stops the batch. Returns the head afterwards.
    async fn verify_and_import_proven_blocks(
        &self,
        blocks: Vec<ProvenBlock>,
    ) -> Result<HeadersImported, SyncBackendError>;

    /// Import candidate publications in order (design 08): each signed block
    /// with the write set of its execution and no receipt. The backend admits
    /// the header and body, then requires the writes to reproduce the
    /// header's state root over the exact parent state, or re-executes the
    /// body when it executes. The first failure stops the batch. Returns the
    /// pending head afterwards.
    async fn verify_and_import_candidates(
        &self,
        _candidates: Vec<CandidateBlock>,
    ) -> Result<HeadersImported, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "candidate import is unsupported".to_owned(),
        ))
    }

    /// Verify block receipts from `source` against their retained headers
    /// (design 08). A receipt whose block is not held yet is kept for the
    /// orphan window and retried when the block arrives, attributed to its
    /// source; an invalid receipt fails the batch.
    async fn verify_and_import_receipts(
        &self,
        _receipts: Vec<BlockReceipt>,
        _source: neutrin0_network::PeerId,
    ) -> Result<ReceiptsImported, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "receipt import is unsupported".to_owned(),
        ))
    }

    /// Build a response to `/neutrin0/req/receipts_by_hash`: the retained
    /// receipts of the requested blocks, in request order, unknown or
    /// unproven blocks omitted.
    async fn receipts_by_hash(
        &self,
        _block_hashes: &[BlockHash],
    ) -> Result<ReceiptsByHashResponse, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "receipt retrieval is unsupported".to_owned(),
        ))
    }

    /// Verify a light client's History proof, which proves its chain from
    /// genesis, then persist its endpoint as the latest trusted one. The
    /// driver requests only an endpoint that a quorum of sampled peers
    /// advertise. `anchor`, when the provider could supply it, opens the
    /// client's current endpoint under the new one: a verified opening that
    /// places another boundary there halts the client like a conflict, and
    /// one that does not verify rejects the reply.
    ///
    /// Returns the new endpoint (or `Err` if verification or persistence
    /// failed, or the client is halted on a conflict).
    async fn verify_and_import_history(
        &self,
        proof: HistoryProof,
        anchor: Option<AnchorOpening>,
    ) -> Result<CheckpointsImported, SyncBackendError>;

    /// Verify one side of a conflict between sampled endpoints without
    /// accepting it. Returns `true` once two verified proofs end at different
    /// endpoints with one chunk count; the backend then durably halts the
    /// light client. A proof that fails verification is `Rejected`.
    async fn verify_history_conflict(
        &self,
        _proof: HistoryProof,
    ) -> Result<bool, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "History conflicts are checked only by light clients".to_owned(),
        ))
    }

    /// Whether a verified History conflict has halted this light client.
    async fn history_halted(&self) -> bool {
        false
    }

    /// Discard the staged fragments of the partly received `items`, which then
    /// restart from byte zero, so an object's bytes all come from the one
    /// provider that completes it.
    async fn restart_state_fragments(
        &self,
        _items: &[neutrin0_consensus_types::bootstrap::StateItem],
    ) -> Result<(), SyncBackendError> {
        Ok(())
    }

    /// Persist exact bounded fragments and discover authenticated child hashes.
    async fn import_state_nodes(
        &self,
        root: StateRoot,
        items: Vec<neutrin0_consensus_types::bootstrap::StateItem>,
        entries: Vec<neutrin0_consensus_types::bootstrap::StateEntry>,
    ) -> Result<StateProgress, SyncBackendError>;

    /// Admit a peer-supplied transaction (received via
    /// `/neutrin0/txs/borsh`) into the local mempool.
    ///
    /// Default impl drops the transaction; backends that maintain a
    /// mempool override it to feed into validation + insertion.
    /// Only objectively malformed or unauthentic data is rejected. Local policy
    /// limits, duplicates and state-dependent failures remain unavailable.
    async fn submit_transaction(&self, _bytes: Vec<u8>) -> Result<(), SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "transaction admission unavailable".into(),
        ))
    }

    /// Admit gossip under its publisher's exact execution runtime. Backends
    /// with governed runtimes must ignore messages for another program.
    async fn submit_transaction_in_runtime(
        &self,
        _runtime: Hash,
        bytes: Vec<u8>,
    ) -> Result<(), SyncBackendError> {
        self.submit_transaction(bytes).await
    }

    /// The next fragment of a program artifact the chain or specification
    /// names but this node lacks, requested from peers through the
    /// `StateByRoot` program namespaces (design 20).
    async fn wanted_program_fragment(
        &self,
    ) -> Option<neutrin0_consensus_types::bootstrap::StateItem> {
        None
    }

    /// Absorb a fetched fragment of the artifact `wanted_program_fragment`
    /// named. Returns `false` for a fragment that does not continue it.
    async fn import_program_fragment(
        &self,
        _entry: neutrin0_consensus_types::bootstrap::StateEntry,
    ) -> bool {
        false
    }

    /// A History request whose anchor is one watched reporter chunk with a
    /// dormant path and whose endpoint is this node's latest finalized
    /// checkpoint (design 18).
    async fn dormant_reporter_path(&self) -> Option<neutrin0_network::rpc::HistoryProofRequest> {
        None
    }

    /// Revive the dormant path `opening` opens. Returns `false` when it opens
    /// no watched record under the latest finalized root.
    async fn refresh_reporter_path(
        &self,
        _opening: neutrin0_consensus_types::AnchorOpening,
    ) -> bool {
        false
    }

    /// Whether this backend maintains an execution transaction pool.
    fn supports_transaction_sync(&self) -> bool {
        false
    }

    /// One sorted, exclusive-cursor page of pending BLAKE3 hashes.
    async fn transaction_inventory(&self, _after: Option<Hash>) -> Vec<Hash> {
        Vec::new()
    }

    /// Available bodies for a bounded exact-hash query.
    async fn pending_transactions(&self, _hashes: &[Hash]) -> Vec<Vec<u8>> {
        Vec::new()
    }

    /// Filter an inventory down to transactions absent from the local pool.
    async fn missing_transactions(&self, hashes: &[Hash]) -> Vec<Hash> {
        hashes.to_vec()
    }

    /// Verify + persist a chunk proof received via
    /// `/neutrin0/chunk_proofs/borsh`.
    ///
    /// The default implementation rejects every chunk proof so test
    /// backends that have no proof system stay safe. The production
    /// backend overrides this to call
    /// `Engine::import_chunk_proof`. `source` is the peer that sent it.
    async fn verify_and_import_chunk_proof(
        &self,
        _proof: ChunkProof,
        _source: neutrin0_network::PeerId,
    ) -> Result<ChunkProofImported, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "chunk proof import is not implemented by this backend".to_owned(),
        ))
    }

    /// Ingest a finality vote received via
    /// `/neutrin0/finality_votes_prevote/borsh` or
    /// `/neutrin0/finality_votes_precommit/borsh`.
    ///
    /// Default impl drops the vote. BFT backends override this
    /// to route the vote into the chunk-BFT state machine.
    async fn ingest_finality_vote(&self, _vote: FinalityVote) -> Result<(), SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "gossip admission unavailable".into(),
        ))
    }

    /// Ingest an aggregate finality vote received via
    /// `/neutrin0/aggregate_finality_votes_<subnet>/borsh`.
    ///
    /// Default impl drops the aggregate. BFT backends override
    /// this to merge the aggregate into the per-chunk vote
    /// accumulator.
    async fn ingest_aggregate_finality_vote(
        &self,
        _subnet: u8,
        _vote: FinalityVote,
    ) -> Result<(), SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "gossip admission unavailable".into(),
        ))
    }

    /// Ingest a slashing evidence record received via
    /// `/neutrin0/slashing_evidence/borsh`.
    ///
    /// Default impl drops the evidence. Slashing backends
    /// override this to buffer evidence for runtime application.
    async fn ingest_slashing_evidence(
        &self,
        _evidence: SlashingEvidence,
    ) -> Result<(), SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "gossip admission unavailable".into(),
        ))
    }

    /// Ingest an independently proven offence with its reporter-supplied history path.
    async fn ingest_evidence_proof(
        &self,
        _report: neutrin0_consensus_types::evidence::EvidenceReport,
    ) -> EvidenceProofAcceptance {
        EvidenceProofAcceptance::Deferred
    }

    /// Whether this backend serves durable original signed accountability sources.
    fn supports_signed_artifact_sync(&self) -> bool {
        false
    }

    /// Authenticate a source chunk against current or preceding-eight local history.
    async fn signed_artifact_source_known(&self, _chunk_id: ChunkId) -> bool {
        false
    }

    /// Bind returned bytes to the exact queried source, using local block-range policy.
    async fn signed_artifact_matches_source(
        &self,
        artifact: &neutrin0_consensus_types::signed_artifacts::SignedArtifact,
        chunk_id: ChunkId,
    ) -> bool {
        use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
        match artifact {
            SignedArtifact::BlockProof(_) => false,
            other => other.chunk_id(1) == Some(chunk_id),
        }
    }

    /// Retrieve an exact immutable vote, quorum or proof envelope.
    async fn signed_artifact_by_id(
        &self,
        _id: Hash,
    ) -> Result<neutrin0_network::rpc::SignedArtifactByIdResponse, SyncBackendError> {
        Err(SyncBackendError::NotAvailable(
            "signed source unavailable".into(),
        ))
    }

    /// Retrieve a stable bounded page of original-source identities.
    async fn signed_artifact_inventory(
        &self,
        _chunk_id: ChunkId,
        _after: Option<Hash>,
    ) -> Result<neutrin0_network::rpc::SignedArtifactInventoryByChunkResponse, SyncBackendError>
    {
        Err(SyncBackendError::NotAvailable(
            "signed source inventory unavailable".into(),
        ))
    }

    /// Recheck cryptographic context and persist fetched sources before detection.
    async fn ingest_signed_artifact(
        &self,
        _artifact: neutrin0_consensus_types::signed_artifacts::SignedArtifact,
    ) -> EvidenceProofAcceptance {
        EvidenceProofAcceptance::Deferred
    }

    /// Discover exact missing proof bytes named by authenticated precommit claims.
    async fn missing_vote_artifacts(
        &self,
        _vote: &FinalityVote,
    ) -> Vec<neutrin0_consensus_types::signed_artifacts::SignedArtifactRef> {
        Vec::new()
    }
}
