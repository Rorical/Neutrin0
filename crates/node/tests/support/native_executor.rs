//! Native executor over the EVM runtime's state transition for fixtures
//! that seed engines without wasmtime: the same `execute_block` the Guest
//! proves, traced over a live copy of the engine's trie.
#![allow(dead_code)] // Each integration test binary uses a subset.

use neutrin0_consensus_types::Body;
use neutrin0_proof_system::{BlockExecutionContext, ErasedBlockExecutor, ExecutionOutcome};
use neutrin0_runtime_abi::{QueryRequest, QueryResponse, RuntimeBlockInput, TxValidity};
use neutrin0_runtime_core::host::{LiveTrie, TracingState};
use neutrin0_trie::Trie;

/// Execute the EVM runtime natively; witnesses are the traced input and
/// state witness, which no production prover accepts.
pub struct NativeExecutor;

/// The runtime input the engine's execution context describes for `body`.
///
/// # Errors
/// Returns the decode error of a malformed transaction.
pub fn runtime_input(
    context: &BlockExecutionContext,
    body: &Body,
) -> Result<RuntimeBlockInput, String> {
    Ok(RuntimeBlockInput {
        context: context.context,
        active_validators: context.active_validators.clone(),
        evidence_anchor: context.evidence_anchor,
        chain_id: context.chain_id,
        block_height: context.block_height,
        block_gas_limit: context.gas_limit,
        proposer_address: context.proposer_address,
        participation: context.participation.clone(),
        proving: context.proving.clone(),
        participation_acks: context.participation_acks.clone(),
        program_pieces: context.program_pieces.clone(),
        transactions: body
            .transactions
            .iter()
            .map(|bytes| borsh::from_slice(bytes).map_err(|error| error.to_string()))
            .collect::<Result<_, _>>()?,
    })
}

/// Run the EVM runtime over `state` for `input`, advancing `state` to the
/// post-state and returning the outcome with `witness_bytes` as the witness.
///
/// # Errors
/// Returns the tracer's error when `state` does not hold an accessed path.
pub fn execute_native(
    input: &RuntimeBlockInput,
    state: &mut Trie,
    witness_bytes: impl FnOnce(&neutrin0_runtime_abi::StateWitness) -> Result<Vec<u8>, String>,
) -> Result<ExecutionOutcome, String> {
    let live = LiveTrie::from_trie(state.clone());
    let mut tracing = TracingState::new(&live);
    let result = neutrin0_evm_runtime_core::execute_block(input, &mut tracing);
    let (post_state, witness, writes) = tracing
        .into_committed_witness_and_writes()
        .map_err(|error| error.to_string())?;
    let witness_bytes = witness_bytes(&witness)?;
    *state = post_state;
    Ok(ExecutionOutcome {
        artifacts: result.artifacts,
        state_root_after: result.output.post_state_root,
        runtime_extra: result.output.consensus_candidates_root,
        receipts_root: result.output.receipts_root,
        gas_used: result.output.gas_used,
        witness_bytes,
        state_writes: writes
            .into_iter()
            .map(|(key, value)| neutrin0_consensus_types::StateWrite { key, value })
            .collect(),
    })
}

impl ErasedBlockExecutor for NativeExecutor {
    fn execute_block(
        &self,
        context: &BlockExecutionContext,
        body: &Body,
        state: &mut Trie,
    ) -> Result<ExecutionOutcome, String> {
        let input = runtime_input(context, body)?;
        execute_native(&input, state, |witness| {
            borsh::to_vec(&(&input, witness)).map_err(|error| error.to_string())
        })
    }

    fn query(
        &self,
        request: &QueryRequest,
        _runtime: neutrin0_primitives::Hash,
        state: &Trie,
    ) -> Result<QueryResponse, String> {
        let live = LiveTrie::from_trie(state.clone());
        Ok(neutrin0_evm_runtime_core::query(
            request,
            &mut TracingState::new(&live),
        ))
    }

    fn validate_tx(
        &self,
        _bytes: &[u8],
        _chain_id: u64,
        _gas_limit: u64,
        _runtime: neutrin0_primitives::Hash,
        _state: &Trie,
    ) -> Result<TxValidity, String> {
        Err("native fixture executor does not admit transactions".into())
    }

    fn install_runtime(&self, _wasm: &[u8]) -> Result<neutrin0_primitives::Hash, String> {
        Err("native fixture executor installs no artifacts".into())
    }

    fn installed_runtimes(&self) -> Vec<neutrin0_primitives::Hash> {
        Vec::new()
    }
}
