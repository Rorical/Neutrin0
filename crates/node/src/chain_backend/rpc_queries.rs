//! RPC views are selected by block hash and read from its committed state root.

mod diagnostics;
mod reads;
mod runtime_calls;
mod transactions;

use async_trait::async_trait;
use neutrin0_consensus_types::{Block, Body, Header};
use neutrin0_primitives::{BlockHash, ChainId, Hash, Height, Validator};
use neutrin0_proof_system::ProofSystem;
use neutrin0_rpc::{
    BlockId, FinalizedInfo, HeadInfo, HistoryRetention, QueryError, RpcBackend, RuntimeCallError,
    RuntimeCallResponse, SubmitError,
};
use neutrin0_storage::Database;

use super::ChainBackend;
use reads::{body_matches_header, readable_header, required_header, resolve_id, state_read_error};
pub(in crate::chain_backend) use reads::{
    checked_header, ensure_payload_height, finalized_info, read_state_at, retention_info,
    storage_error,
};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// A retained block, its header checked under the engine lock and its
    /// body read and checked against the header outside it. Clients take
    /// what RPC returns as is, so local corruption is caught here rather
    /// than served.
    pub(super) fn read_block(&self, hash: BlockHash) -> Result<Option<Block>, QueryError> {
        let Some(header) = self.with_engine(|engine| readable_header(engine, hash))? else {
            return Ok(None);
        };
        let bytes = self
            .reads
            .get(neutrin0_storage::Column::Blocks, &hash)
            .map_err(storage_error)?
            .ok_or(QueryError::BodyUnavailable)?;
        let body: Body = borsh::from_slice(&bytes).map_err(storage_error)?;
        if !body_matches_header(&header, &body) {
            return Err(storage_error(
                "stored body does not match the header commitment",
            ));
        }
        Ok(Some(Block { header, body }))
    }
}

#[async_trait]
impl<DB, P> RpcBackend for ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    async fn block_artifacts(
        &self,
        block: Hash,
    ) -> Result<Option<neutrin0_rpc::types::BlockArtifactsJson>, QueryError> {
        if self.is_light() {
            return Err(QueryError::StateUnavailable);
        }
        let Some(read) = self.read_block(block)? else {
            return Ok(None);
        };
        let runtime = self.with_engine(|engine| {
            engine
                .runtime_code_hash_for(read.header.height)
                .map_err(storage_error)
        })?;
        Ok(Some(neutrin0_rpc::types::BlockArtifactsJson {
            block_hash: neutrin0_rpc::HashHex(block),
            runtime_code_hash: neutrin0_rpc::HashHex(runtime),
            artifacts: neutrin0_rpc::BytesHex(
                borsh::to_vec(&read.body.artifacts).map_err(storage_error)?,
            ),
        }))
    }
    async fn chunk(
        &self,
        id: Option<u64>,
    ) -> Result<Option<neutrin0_rpc::types::ChunkJson>, QueryError> {
        self.query_chunk(id)
    }
    async fn certificate(
        &self,
        id: u64,
    ) -> Result<Option<neutrin0_rpc::types::CertificateJson>, QueryError> {
        self.query_certificate(id)
    }
    async fn artifact(
        &self,
        id: neutrin0_rpc::types::ArtifactIdJson,
    ) -> Result<Option<neutrin0_rpc::types::ArtifactInfoJson>, QueryError> {
        self.query_artifact(id)
    }
    async fn artifact_bytes(
        &self,
        id: neutrin0_rpc::types::ArtifactIdJson,
        expected: Hash,
        offset: u64,
        length: u32,
    ) -> Result<neutrin0_rpc::types::ArtifactSliceJson, QueryError> {
        self.query_artifact_bytes(&id, expected, offset, length)
    }
    async fn chain_events(
        &self,
        after: Option<neutrin0_rpc::types::ChainCursorJson>,
        limit: u32,
    ) -> Result<neutrin0_rpc::types::ChainEventPageJson, QueryError> {
        self.query_chain_events(after, limit)
    }
    async fn diagnostics(&self) -> Result<neutrin0_rpc::types::DiagnosticsJson, QueryError> {
        self.diagnostics_snapshot()
    }

    async fn history_retention(&self) -> Result<HistoryRetention, QueryError> {
        if let Some(checkpoint) = self.light_checkpoint() {
            return Ok(HistoryRetention {
                finalized_chunks: checkpoint.boundary.next_chunk_id,
                ..HistoryRetention::default()
            });
        }
        self.with_engine(retention_info)
    }

    async fn genesis_info(&self) -> Result<Option<neutrin0_rpc::backend::GenesisInfo>, QueryError> {
        Ok(Some(self.with_engine(|engine| {
            let spec = engine.chain_spec();
            neutrin0_rpc::backend::GenesisInfo {
                hash: spec.genesis_block_hash,
                state_root: spec.genesis_state_root,
                timestamp: spec.genesis_time,
                gas_limit: spec.genesis_gas_limit,
                seed: spec.genesis_seed,
            }
        })))
    }

    async fn history_latest(&self) -> Result<Vec<u8>, QueryError> {
        if self.is_light() {
            return borsh::to_vec(
                &self
                    .light_latest_proof()
                    .map_err(storage_error)?
                    .ok_or(QueryError::HistoryUnavailable)?,
            )
            .map_err(storage_error);
        }
        let proof = self
            .with_engine(neutrin0_consensus_engine::Engine::latest_history_proof)
            .map_err(storage_error)?
            .ok_or(QueryError::HistoryUnavailable)?;
        borsh::to_vec(&proof).map_err(storage_error)
    }

    fn chain_id(&self) -> ChainId {
        Self::chain_id(self)
    }

    fn runtime_code_hash(&self) -> Option<Hash> {
        self.block_executor_snapshot()?;
        self.with_engine(|engine| engine.runtime_code_hash_for(engine.head_height()).ok())
    }

    fn runtime_available(&self) -> bool {
        self.block_executor_snapshot().is_some()
    }

    fn mempool_len(&self) -> usize {
        Self::mempool_len(self)
    }

    fn peer_count(&self) -> u64 {
        self.sync_status().map_or(0, |status| status.peer_count())
    }

    fn programs_status(&self) -> neutrin0_rpc::ProgramsStatusJson {
        Self::programs_status(self)
    }

    fn proving_status(&self) -> neutrin0_rpc::ProvingStatusJson {
        Self::proving_status(self)
    }

    fn is_syncing(&self) -> bool {
        self.sync_status().is_some_and(|status| status.is_syncing())
    }

    async fn head(&self) -> Result<HeadInfo, QueryError> {
        if let Some(checkpoint) = self.light_checkpoint() {
            let boundary = checkpoint.boundary;
            return Ok(HeadInfo {
                height: boundary.height,
                hash: boundary.block_hash,
                slot: boundary.slot,
                state_root: boundary.state_root,
            });
        }
        self.with_engine(|engine| {
            let hash = engine.head_hash();
            let slot = if hash == engine.chain_spec().genesis_block_hash {
                0
            } else {
                let header = required_header(engine, hash)?;
                if header.height != engine.head_height()
                    || header.state_root != engine.head_state_root()
                {
                    return Err(storage_error(
                        "head metadata does not match the selected header",
                    ));
                }
                header.slot
            };
            Ok(HeadInfo {
                height: engine.head_height(),
                hash,
                slot,
                state_root: engine.head_state_root(),
            })
        })
    }

    async fn finalized(&self) -> Result<FinalizedInfo, QueryError> {
        if let Some(checkpoint) = self.light_checkpoint() {
            let boundary = checkpoint.boundary;
            return Ok(FinalizedInfo {
                chunk_id: boundary.next_chunk_id.checked_sub(1),
                block_hash: boundary.block_hash,
                height: boundary.height,
                state_root: boundary.state_root,
            });
        }
        self.with_engine(finalized_info)
    }

    async fn active_validator_set(&self) -> Vec<Validator> {
        if self.is_light() {
            return Vec::new();
        }
        self.with_engine(|engine| engine.active_validator_set().to_vec())
    }

    async fn resolve_block_id(&self, id: &BlockId) -> Result<Option<BlockHash>, QueryError> {
        if let Some(checkpoint) = self.light_checkpoint() {
            let boundary = checkpoint.boundary;
            return Ok(match id {
                BlockId::Latest | BlockId::Safe | BlockId::Finalized => Some(boundary.block_hash),
                BlockId::Hash(hash) if *hash == boundary.block_hash => Some(*hash),
                BlockId::Height(height) if *height == boundary.height => Some(boundary.block_hash),
                _ => None,
            });
        }
        self.with_engine(|engine| resolve_id(engine, id))
    }

    async fn header_by_hash(&self, hash: BlockHash) -> Result<Option<Header>, QueryError> {
        self.with_engine(|engine| checked_header(engine, hash))
    }

    async fn header_by_height(&self, height: Height) -> Result<Option<Header>, QueryError> {
        self.with_engine(|engine| {
            resolve_id(engine, &BlockId::Height(height))?
                .map(|hash| checked_header(engine, hash))
                .transpose()
                .map(Option::flatten)
        })
    }

    async fn block_by_hash(&self, hash: BlockHash) -> Result<Option<Block>, QueryError> {
        self.read_block(hash)
    }

    async fn block_by_height(&self, height: Height) -> Result<Option<Block>, QueryError> {
        let Some(hash) = self.with_engine(|engine| resolve_id(engine, &BlockId::Height(height)))?
        else {
            return Ok(None);
        };
        self.read_block(hash)
    }

    async fn storage_at(&self, key: &[u8], at: &BlockId) -> Result<Option<Vec<u8>>, QueryError> {
        self.rpc_state_snapshot(at)
            .await?
            .0
            .get(key)
            .map_err(state_read_error)
    }

    async fn submit_transaction(&self, bytes: Vec<u8>) -> Result<Hash, SubmitError> {
        self.rpc_submit_transaction(bytes).await
    }

    async fn execution_transaction(
        &self,
        identifier: Hash,
    ) -> Result<Option<(Hash, u32)>, QueryError> {
        self.rpc_execution_transaction(identifier)
    }

    // Pending reads answer from the last validated pool: revalidation runs
    // once per head off the head-update fence, never per request.
    async fn pending_transaction(&self, identifier: Hash) -> Option<Vec<u8>> {
        self.mempool
            .lock()
            .expect("ChainBackend mempool poisoned")
            .transaction(&identifier)
    }

    async fn pending_identifiers(&self) -> Vec<Hash> {
        self.mempool
            .lock()
            .expect("ChainBackend mempool poisoned")
            .iter()
            .take(8192)
            .map(|entry| {
                entry
                    .dependency
                    .map_or(entry.hash, |dependency| dependency.identifier)
            })
            .collect()
    }

    async fn pending_sequence(
        &self,
        account: Hash,
        state_nonce: u64,
        at: Hash,
    ) -> Result<u64, QueryError> {
        self.rpc_pending_sequence(account, state_nonce, at)
    }

    async fn runtime_pending_call(
        &self,
        method: String,
        args: Vec<u8>,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        self.pending_runtime_call(method, args).await
    }

    async fn runtime_artifact_call(
        &self,
        method: String,
        args: Vec<u8>,
        block: Hash,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        self.artifact_runtime_call(method, args, block).await
    }

    async fn runtime_admission_call(
        &self,
        method: String,
        args: Vec<u8>,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        self.admission_runtime_call(method, args).await
    }

    async fn runtime_call(
        &self,
        method: String,
        args: Vec<u8>,
        at: &BlockId,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        self.runtime_call_at(method, args, at).await
    }
}
