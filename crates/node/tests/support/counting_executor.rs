//! The real WASM executor with a counter on body execution, so tests can
//! assert which nodes executed which blocks.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use neutrin0_consensus_types::Body;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::{BlockExecutionContext, BlockExecutor, ExecutionOutcome};
use neutrin0_runtime_abi::{QueryRequest, QueryResponse, TxValidity};
use neutrin0_runtime_host::WasmExecutor;
use neutrin0_trie::{Poseidon2Hasher, Trie};

/// Delegates everything to [`WasmExecutor`] and counts `execute_block` calls.
pub struct CountingExecutor {
    inner: WasmExecutor,
    executed: Arc<AtomicUsize>,
}

impl CountingExecutor {
    /// Wrap the embedded runtime.
    pub fn embedded() -> (Self, Arc<AtomicUsize>) {
        let executed = Arc::new(AtomicUsize::new(0));
        (
            Self {
                inner: WasmExecutor::embedded().expect("wasm runtime"),
                executed: Arc::clone(&executed),
            },
            executed,
        )
    }
}

impl BlockExecutor for CountingExecutor {
    type Error = <WasmExecutor as BlockExecutor>::Error;

    fn lease_runtimes(
        &self,
        runtimes: &[Hash],
    ) -> Result<neutrin0_proof_system::artifacts::ProgramLease, Self::Error> {
        self.inner.lease_runtimes(runtimes)
    }

    fn retain_programs(&self, retention: &neutrin0_proof_system::artifacts::ProgramRetention) {
        self.inner.retain_programs(retention);
    }

    fn set_artifact_loader(&self, loader: neutrin0_proof_system::artifacts::ProgramArtifactLoader) {
        self.inner.set_artifact_loader(loader);
    }

    fn execute_block(
        &self,
        ctx: &BlockExecutionContext,
        body: &Body,
        state: &mut Trie<Poseidon2Hasher>,
    ) -> Result<ExecutionOutcome, Self::Error> {
        self.executed.fetch_add(1, Ordering::SeqCst);
        self.inner.execute_block(ctx, body, state)
    }

    fn query(
        &self,
        request: &QueryRequest,
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<QueryResponse, Self::Error> {
        self.inner.query(request, runtime_code_hash, state)
    }

    fn runtime_artifact(&self, runtime_code_hash: &Hash) -> Option<Vec<u8>> {
        self.inner.runtime_artifact(runtime_code_hash)
    }

    fn validate_tx(
        &self,
        tx_bytes: &[u8],
        chain_id: u64,
        block_gas_limit: u64,
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, Self::Error> {
        self.inner.validate_tx(
            tx_bytes,
            chain_id,
            block_gas_limit,
            runtime_code_hash,
            state,
        )
    }

    fn install_runtime(&self, wasm: &[u8]) -> Result<Hash, Self::Error> {
        BlockExecutor::install_runtime(&self.inner, wasm)
    }

    fn installed_runtimes(&self) -> Vec<Hash> {
        self.inner.installed_runtimes()
    }
}
