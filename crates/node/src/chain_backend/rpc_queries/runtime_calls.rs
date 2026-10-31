//! WASM runtime queries: bounded by query slots, run on the blocking pool.

use std::sync::Arc;

use neutrin0_consensus_engine::Engine;
use neutrin0_consensus_types::Body;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::{ErasedBlockExecutor, ProofSystem};
use neutrin0_rpc::{BlockId, QueryError, RuntimeCallError, RuntimeCallResponse};
use neutrin0_runtime_abi::{
    QueryRequest, QueryResponse, RuntimeBlockInput,
    ethereum::{PendingMode, PendingRequest},
};
use neutrin0_storage::Database;
use neutrin0_trie::Trie;

use super::super::pool_validation;
use super::{ChainBackend, reads::read_state, storage_error};

/// The selected state, the runtime that interprets it, the authenticated
/// next-block input when the chunk context allows one, and the pool
/// candidates frozen with them.
type PendingInputs = (Arc<Trie>, Hash, Option<RuntimeBlockInput>, Vec<Vec<u8>>);

/// The head-local pending block: the runtime's own environment record with
/// the frozen user candidates as its transactions.
fn head_local_block(
    executor: &dyn ErasedBlockExecutor,
    runtime: Hash,
    state: &Trie,
    candidates: &[Vec<u8>],
) -> Result<RuntimeBlockInput, RuntimeCallError> {
    let environment = executor
        .query(
            &QueryRequest {
                method: "evm:environment".into(),
                args: Vec::new(),
            },
            runtime,
            state,
        )
        .map_err(RuntimeCallError::Runtime)?;
    if !environment.is_ok() {
        return Err(RuntimeCallError::Runtime(
            "head-local pending environment unavailable".into(),
        ));
    }
    // The regular environment query reports an optional record;
    // a head without one cannot serve head-local simulations.
    let mut block = borsh::from_slice::<Option<RuntimeBlockInput>>(&environment.payload)
        .map_err(|error| RuntimeCallError::Decode(error.to_string()))?
        .ok_or_else(|| {
            RuntimeCallError::Runtime("head-local pending environment unavailable".into())
        })?;
    block.participation_acks.clear();
    block.transactions = candidates
        .iter()
        .map(|bytes| borsh::from_slice(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| RuntimeCallError::Decode(error.to_string()))?;
    block.transactions.retain(|transaction| {
        matches!(
            transaction,
            neutrin0_runtime_abi::RuntimeTransaction::User(_)
        )
    });
    Ok(block)
}

/// Run `method` inside the simulated pending `block`.
fn run_pending_query(
    executor: &dyn ErasedBlockExecutor,
    runtime: Hash,
    state: &Trie,
    mode: PendingMode,
    block: RuntimeBlockInput,
    method: String,
    args: Vec<u8>,
) -> Result<QueryResponse, RuntimeCallError> {
    let pending = PendingRequest {
        mode,
        block,
        query: QueryRequest { method, args },
    };
    let request = QueryRequest {
        method: "evm:pending".into(),
        args: borsh::to_vec(&pending)
            .map_err(|error| RuntimeCallError::Decode(error.to_string()))?,
    };
    executor
        .query(&request, runtime, state)
        .map_err(RuntimeCallError::Runtime)
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Run one WASM query on the blocking pool while holding a query slot.
    ///
    /// The RPC deadline only bounds the caller's wait and the fuel cap one
    /// query's work; the slots bound how many run at once. A slot is taken
    /// before the work starts, so a caller that times out while waiting costs
    /// nothing, and released only when the query returns.
    async fn run_query<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, RuntimeCallError> {
        let slot = Arc::clone(&self.query_slots)
            .acquire_owned()
            .await
            .map_err(|_| RuntimeCallError::Runtime("runtime query slots closed".into()))?;
        tokio::task::spawn_blocking(move || {
            let _slot = slot;
            work()
        })
        .await
        .map_err(|error| RuntimeCallError::Runtime(format!("query join error: {error}")))
    }

    /// State at `at` together with the runtime artifact that interprets it.
    pub(super) async fn rpc_state_snapshot(
        &self,
        at: &BlockId,
    ) -> Result<(Trie, Hash), QueryError> {
        if self.is_light() {
            return Err(QueryError::StateUnavailable);
        }
        let at = at.clone();
        self.rpc_engine(move |engine| {
            let (state, height) = read_state(engine, &at)?;
            let runtime = engine
                .runtime_code_hash_for(height)
                .map_err(|_| QueryError::StateUnavailable)?;
            Ok((state, runtime))
        })
        .await
    }

    /// The authenticated next-block input over the head state, or the head
    /// state alone when the next chunk's context is not finalized here.
    fn next_block_input(
        engine: &Engine<DB>,
        head_state: &pool_validation::HeadState,
        body: &Body,
    ) -> Result<(Arc<Trie>, Hash, Option<RuntimeBlockInput>), RuntimeCallError> {
        let height = engine
            .head_height()
            .checked_add(1)
            .ok_or_else(|| RuntimeCallError::Runtime("pending height exhausted".into()))?;
        let chunk = (height - 1) / engine.chain_spec().consensus.chunk_size;
        if engine.execution_boundary(chunk).is_err() {
            let runtime = engine
                .runtime_code_hash_for(engine.head_height())
                .map_err(storage_error)?;
            return Ok((
                pool_validation::head_state_snapshot(head_state, engine),
                runtime,
                None,
            ));
        }
        let parent = engine
            .store()
            .get_header(&engine.head_hash())
            .map_err(storage_error)?;
        let slot = parent
            .as_ref()
            .map_or(0, |header| header.slot)
            .checked_add(1)
            .ok_or_else(|| RuntimeCallError::Runtime("pending slot exhausted".into()))?;
        let parent_time = parent.as_ref().map_or_else(
            || engine.chain_spec().genesis_time,
            |header| header.timestamp,
        );
        let timestamp = engine.clock().timestamp_for(slot).max(
            parent_time
                .checked_add(1)
                .ok_or_else(|| RuntimeCallError::Runtime("pending timestamp exhausted".into()))?,
        );
        let finalized = engine.execution_boundary(chunk).map_err(storage_error)?;
        let anchor = engine
            .evidence_anchor(height)
            .map_err(RuntimeCallError::Runtime)?;
        let block = RuntimeBlockInput {
            context: neutrin0_consensus_types::runtime::ConsensusExecutionContext {
                slot,
                timestamp,
                parent_block_hash: engine.head_hash(),
                proposer_vrf_output: [0; 32],
                finalized,
            },
            evidence_anchor: anchor,
            chain_id: engine.chain_spec().chain_id,
            block_height: height,
            block_gas_limit: engine.chain_spec().genesis_gas_limit,
            proposer_address: [0; 32],
            active_validators: engine
                .validator_context_for_height(height)
                .map_err(storage_error)?
                .0,
            participation: engine
                .participation_for_next_block()
                .map_err(RuntimeCallError::Runtime)?,
            proving: None,
            participation_acks: Vec::new(),
            program_pieces: Vec::new(),
            transactions: body
                .transactions
                .iter()
                .map(|bytes| borsh::from_slice(bytes))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| RuntimeCallError::Decode(error.to_string()))?,
        };
        Ok((
            pool_validation::head_state_snapshot(head_state, engine),
            finalized.programs.runtime_code_hash,
            Some(block),
        ))
    }

    async fn pending_call_inputs(
        &self,
        executor: Arc<dyn ErasedBlockExecutor>,
    ) -> Result<PendingInputs, RuntimeCallError> {
        let updates = Arc::clone(&self.head_updates);
        let mempool = Arc::clone(&self.mempool);
        let engine = Arc::clone(&self.engine);
        let head_state = Arc::clone(&self.head_state);
        self.rpc_blocking(move || {
            // Freeze the head and validated pool together; no async worker
            // waits for the publication fence or performs evidence queries.
            let _update = updates.lock().expect("ChainBackend head update poisoned");
            let candidates = mempool
                .lock()
                .expect("ChainBackend mempool poisoned")
                .execution_candidates(super::super::DEFAULT_BODY_TX_BUDGET_BYTES)
                .into_iter()
                .map(|entry| entry.bytes)
                .collect::<Vec<_>>();
            let engine = engine.lock().expect("ChainBackend mutex poisoned");
            let head_local = engine
                .head_height()
                .checked_div(engine.chain_spec().consensus.chunk_size)
                .is_none_or(|chunk| engine.execution_boundary(chunk).is_err());
            let body = if head_local {
                Body::default()
            } else {
                super::super::evidence::selected_body(&engine, executor.as_ref(), &candidates).0
            };
            let (state, runtime, block) = Self::next_block_input(&engine, &head_state, &body)?;
            drop(engine);
            Ok((state, runtime, block, candidates))
        })
        .await
    }

    /// One selected-state snapshot chooses authenticated next-block or
    /// explicit head-local simulation.
    pub(super) async fn pending_runtime_call(
        &self,
        method: String,
        args: Vec<u8>,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        let executor = self
            .block_executor_snapshot()
            .ok_or(RuntimeCallError::RuntimeNotConfigured)?;
        let (state, runtime, block, candidates) =
            self.pending_call_inputs(Arc::clone(&executor)).await?;
        let response = self
            .run_query(move || -> Result<_, RuntimeCallError> {
                let (mode, block) = if let Some(block) = block {
                    (PendingMode::NextBlock, block)
                } else {
                    (
                        PendingMode::HeadLocal,
                        head_local_block(executor.as_ref(), runtime, &state, &candidates)?,
                    )
                };
                run_pending_query(
                    executor.as_ref(),
                    runtime,
                    &state,
                    mode,
                    block,
                    method,
                    args,
                )
            })
            .await??;
        Ok(RuntimeCallResponse {
            code: response.code,
            payload: response.payload,
            gas_used: 0,
        })
    }

    pub(super) async fn artifact_runtime_call(
        &self,
        method: String,
        args: Vec<u8>,
        block: Hash,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        let executor = self
            .block_executor_snapshot()
            .ok_or(RuntimeCallError::RuntimeNotConfigured)?;
        let runtime = self
            .rpc_engine(move |engine| {
                let header = engine
                    .store()
                    .get_header(&block)
                    .map_err(storage_error)?
                    .ok_or(QueryError::BlockNotFound)?;
                engine
                    .runtime_code_hash_for(header.height)
                    .map_err(storage_error)
            })
            .await?;
        let request = QueryRequest { method, args };
        let response = self
            .run_query(move || executor.query(&request, runtime, &Trie::default()))
            .await?
            .map_err(RuntimeCallError::Runtime)?;
        Ok(RuntimeCallResponse {
            code: response.code,
            payload: response.payload,
            gas_used: 0,
        })
    }

    pub(super) async fn admission_runtime_call(
        &self,
        method: String,
        args: Vec<u8>,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        let executor = self
            .block_executor_snapshot()
            .ok_or(RuntimeCallError::RuntimeNotConfigured)?;
        let head_state = Arc::clone(&self.head_state);
        let (state, runtime) = self
            .rpc_engine(move |engine| {
                let runtime = engine
                    .head_height()
                    .checked_add(1)
                    .and_then(|height| engine.runtime_code_hash_for(height).ok())
                    .or_else(|| engine.runtime_code_hash_for(engine.head_height()).ok())
                    .ok_or_else(|| {
                        RuntimeCallError::Runtime(
                            "transaction admission runtime unavailable".into(),
                        )
                    })?;
                Ok::<_, RuntimeCallError>((
                    pool_validation::head_state_snapshot(&head_state, engine),
                    runtime,
                ))
            })
            .await?;
        let request = QueryRequest { method, args };
        let response = self
            .run_query(move || executor.query(&request, runtime, &state))
            .await?
            .map_err(RuntimeCallError::Runtime)?;
        Ok(RuntimeCallResponse {
            code: response.code,
            payload: response.payload,
            gas_used: 0,
        })
    }

    pub(super) async fn runtime_call_at(
        &self,
        method: String,
        args: Vec<u8>,
        at: &BlockId,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        let executor = self
            .block_executor_snapshot()
            .ok_or(RuntimeCallError::RuntimeNotConfigured)?;
        let (state, runtime) = self.rpc_state_snapshot(at).await?;
        let request = QueryRequest { method, args };
        let response = self
            .run_query(move || executor.query(&request, runtime, &state))
            .await?
            .map_err(RuntimeCallError::Runtime)?;
        Ok(RuntimeCallResponse {
            code: response.code,
            payload: response.payload,
            gas_used: 0,
        })
    }
}
