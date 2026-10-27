//! Read/write surface the RPC server consumes.
//!
//! [`RpcBackend`] is the only trait the JSON-RPC layer talks to; the
//! node binary's `ChainBackend` (or any other implementation a test
//! wants to wire up) implements it. The trait is deliberately small —
//! chain-agnostic queries (`chain_*`, `system_*`) operate on raw
//! engine state, runtime-specific queries go through
//! [`RpcBackend::runtime_call`] which calls into the runtime's
//! `_neutrin0_query` entrypoint.

use async_trait::async_trait;
use neutrin0_consensus_types::{Block, Header};
use neutrin0_primitives::{BlockHash, ChainId, Hash, Height, Validator};

mod errors;
mod views;

pub use errors::{QueryError, RuntimeCallError, SubmitError};
pub use views::{
    BlockId, FinalizedInfo, GenesisInfo, HeadInfo, HistoryRetention, RuntimeCallResponse,
};

/// Async trait the JSON-RPC server consumes.
///
/// Implementations must be cheap to clone (`Arc`-wrap if needed) since
/// every RPC handler holds a `&dyn RpcBackend` reference for the
/// duration of the call.
#[async_trait]
pub trait RpcBackend: Send + Sync + 'static {
    /// Read header-bound execution artifacts without executing the block.
    async fn block_artifacts(
        &self,
        _block: Hash,
    ) -> Result<Option<crate::types::BlockArtifactsJson>, QueryError> {
        Err(QueryError::StateUnavailable)
    }
    /// Retained finalized chunk, or latest finalized when omitted.
    async fn chunk(&self, _id: Option<u64>) -> Result<Option<crate::types::ChunkJson>, QueryError> {
        Err(QueryError::StateUnavailable)
    }
    /// Exact mandatory certificate summary and its downloadable envelope identity.
    async fn certificate(
        &self,
        _id: u64,
    ) -> Result<Option<crate::types::CertificateJson>, QueryError> {
        Err(QueryError::StateUnavailable)
    }
    /// Proof/certificate envelope identity, size and exact public values.
    async fn artifact(
        &self,
        _id: crate::types::ArtifactIdJson,
    ) -> Result<Option<crate::types::ArtifactInfoJson>, QueryError> {
        Err(QueryError::StateUnavailable)
    }
    /// Bounded exact Borsh envelope download pinned by content hash.
    async fn artifact_bytes(
        &self,
        _id: crate::types::ArtifactIdJson,
        _expected: Hash,
        _offset: u64,
        _length: u32,
    ) -> Result<crate::types::ArtifactSliceJson, QueryError> {
        Err(QueryError::StateUnavailable)
    }
    /// Read a consistent durable replay page; absent cursor captures only current snapshot.
    async fn chain_events(
        &self,
        _after: Option<crate::types::ChainCursorJson>,
        _limit: u32,
    ) -> Result<crate::types::ChainEventPageJson, QueryError> {
        Err(QueryError::StateUnavailable)
    }

    /// Local operational observations, without granting signing authority.
    async fn diagnostics(&self) -> Result<crate::types::DiagnosticsJson, QueryError> {
        Err(QueryError::StateUnavailable)
    }
    /// Immutable chain facts; unavailable when this backend has no chain binding.
    async fn genesis_info(&self) -> Result<Option<GenesisInfo>, QueryError> {
        Ok(None)
    }

    /// Report actual durable retention boundaries without changing client trust.
    async fn history_retention(&self) -> Result<HistoryRetention, QueryError> {
        Ok(HistoryRetention::default())
    }
    /// The History proof of the latest finalized endpoint, encoded with
    /// canonical Borsh: its chunk receipt, which proves the chain from genesis.
    async fn history_latest(&self) -> Result<Vec<u8>, QueryError> {
        Err(QueryError::StateUnavailable)
    }

    /// Chain id this node participates in.
    fn chain_id(&self) -> ChainId;

    /// Content hash of the attached runtime, or `None` when no runtime is installed.
    fn runtime_code_hash(&self) -> Option<neutrin0_primitives::Hash>;

    /// Whether a WASM runtime is attached and `runtime_call` is
    /// callable. Returned in `system_health` so clients can detect
    /// query-disabled nodes up front.
    fn runtime_available(&self) -> bool;

    /// Number of transactions currently buffered in the mempool.
    fn mempool_len(&self) -> usize;

    /// Number of currently connected peers. Backends without a network
    /// service report `0`.
    fn peer_count(&self) -> u64 {
        0
    }

    /// Program distribution and installation state (design 20, on-chain program distribution).
    fn programs_status(&self) -> crate::types::ProgramsStatusJson {
        crate::types::ProgramsStatusJson::default()
    }

    /// What this node proves and which account it names (design 08).
    fn proving_status(&self) -> crate::types::ProvingStatusJson {
        crate::types::ProvingStatusJson::default()
    }

    /// Whether the sync driver still trails the network. Backends without
    /// a sync driver report `false`.
    fn is_syncing(&self) -> bool {
        false
    }

    /// Current unfinalised head summary.
    async fn head(&self) -> Result<HeadInfo, QueryError>;

    /// Latest proof-finalized chunk boundary, or trusted genesis.
    async fn finalized(&self) -> Result<FinalizedInfo, QueryError>;

    /// Active validator set (the one the engine uses for proposer
    /// eligibility and BFT quorum weighting).
    async fn active_validator_set(&self) -> Vec<Validator>;

    /// Resolve a [`BlockId`] to a block hash, or `None` if the
    /// requested block is not known.
    async fn resolve_block_id(&self, id: &BlockId) -> Result<Option<BlockHash>, QueryError>;

    /// Fetch a header by block hash. `None` if the hash is unknown.
    async fn header_by_hash(&self, hash: BlockHash) -> Result<Option<Header>, QueryError>;

    /// Fetch a header from the selected head's ancestry by height.
    /// `None` if above the local head or no header is stored (trusted genesis).
    async fn header_by_height(&self, height: Height) -> Result<Option<Header>, QueryError>;

    /// Fetch a full block (header + body) by hash.
    async fn block_by_hash(&self, hash: BlockHash) -> Result<Option<Block>, QueryError>;

    /// Fetch a full block from the selected head's ancestry by height.
    async fn block_by_height(&self, height: Height) -> Result<Option<Block>, QueryError>;

    /// Read a raw value from the selected block's state. `None` means
    /// authenticated key absence; unavailable blocks/state return an error.
    async fn storage_at(&self, key: &[u8], at: &BlockId) -> Result<Option<Vec<u8>>, QueryError>;

    /// Submit a raw transaction to the local mempool.
    async fn submit_transaction(&self, bytes: Vec<u8>) -> Result<Hash, SubmitError>;

    /// Resolve a runtime transaction identifier on the canonical branch.
    /// If old locators were pruned, absence from the retained index cannot
    /// establish absence from the chain and returns [`QueryError::Pruned`].
    async fn execution_transaction(
        &self,
        _identifier: Hash,
    ) -> Result<Option<(Hash, u32)>, QueryError> {
        Err(QueryError::BodyUnavailable)
    }

    /// Lookup opaque local pending bytes by the runtime identifier.
    async fn pending_transaction(&self, _identifier: Hash) -> Option<Vec<u8>> {
        None
    }

    /// Bounded local transaction identifiers for polling pending-transaction filters.
    async fn pending_identifiers(&self) -> Vec<Hash> {
        Vec::new()
    }

    /// Next local sequence including contiguous runtime-admitted pending entries.
    /// `at` pins the state nonce and local dependency view to one canonical head.
    async fn pending_sequence(
        &self,
        _account: Hash,
        state_nonce: u64,
        _at: Hash,
    ) -> Result<u64, QueryError> {
        Ok(state_nonce)
    }

    /// Execute a node-derived pending query in a disposable runtime journal.
    async fn runtime_pending_call(
        &self,
        _method: String,
        _args: Vec<u8>,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        Err(RuntimeCallError::RuntimeNotConfigured)
    }

    /// Decode opaque artifacts with the selected block's own installed runtime.
    /// This operation has no state access and remains usable while state is pruned.
    async fn runtime_artifact_call(
        &self,
        _method: String,
        _args: Vec<u8>,
        _block: Hash,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        Err(RuntimeCallError::RuntimeNotConfigured)
    }

    /// Decode or inspect an admitted candidate using the runtime selected for
    /// the next height and the current immutable head state. This can differ
    /// from the head's historical runtime at a governed execution switch.
    async fn runtime_admission_call(
        &self,
        method: String,
        args: Vec<u8>,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        self.runtime_call(method, args, &BlockId::Latest).await
    }

    /// Invoke the runtime's read-only query entrypoint. `at` selects
    /// the immutable state root the query observes, including retained history.
    async fn runtime_call(
        &self,
        method: String,
        args: Vec<u8>,
        at: &BlockId,
    ) -> Result<RuntimeCallResponse, RuntimeCallError>;
}
