//! A block executor wrapper that meters runtime traps and query latencies.

#![allow(clippy::redundant_pub_crate)] // Crate-internal helpers re-exported by the parent module.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use neutrin0_consensus_types::Body;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::{BlockExecutionContext, ErasedBlockExecutor, ExecutionOutcome};
use neutrin0_runtime_abi::{QueryRequest, QueryResponse, TxValidity};
use neutrin0_trie::{Poseidon2Hasher, Trie};

use super::RUNTIME_TRAP;
use crate::metrics::NodeMetrics;

pub(crate) struct MeteredExecutor<X> {
    inner: X,
    metrics: Arc<NodeMetrics>,
}
impl<X> MeteredExecutor<X> {
    pub(crate) const fn new(inner: X, metrics: Arc<NodeMetrics>) -> Self {
        Self { inner, metrics }
    }
}
impl<X: ErasedBlockExecutor> ErasedBlockExecutor for MeteredExecutor<X> {
    fn lease_runtimes(
        &self,
        runtimes: &[Hash],
    ) -> Result<neutrin0_proof_system::artifacts::ProgramLease, String> {
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
    ) -> Result<ExecutionOutcome, String> {
        let timer = self.metrics.execution.blocks.timer();
        let result = self.inner.execute_block(ctx, body, state);
        if let Ok(output) = &result {
            self.metrics
                .execution
                .gas
                .fetch_add(output.gas_used, Ordering::Relaxed);
            self.metrics.execution.transactions.fetch_add(
                u64::try_from(body.transactions.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
        timer.finish(result.is_ok());
        result
    }
    fn query(
        &self,
        request: &QueryRequest,
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<QueryResponse, String> {
        let timer = self.metrics.execution.queries.timer();
        let result = self.inner.query(request, runtime_code_hash, state);
        timer.finish(result.as_ref().is_ok_and(QueryResponse::is_ok));
        result
    }
    fn validate_tx(
        &self,
        bytes: &[u8],
        chain_id: u64,
        gas_limit: u64,
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, String> {
        let timer = self.metrics.execution.validation.timer();
        let result = self
            .inner
            .validate_tx(bytes, chain_id, gas_limit, runtime_code_hash, state);
        let code = result.as_ref().map_or(RUNTIME_TRAP, |validity| {
            usize::try_from(validity.code.as_u32()).expect("bounded validity code")
        });
        self.metrics.execution.validity_codes[code].fetch_add(1, Ordering::Relaxed);
        timer.finish(result.as_ref().is_ok_and(|validity| validity.is_valid()));
        result
    }
    fn runtime_artifact(&self, runtime_code_hash: &Hash) -> Option<Vec<u8>> {
        self.inner.runtime_artifact(runtime_code_hash)
    }

    fn runtime_fragment(
        &self,
        code_hash: &Hash,
        offset: u64,
        max_bytes: usize,
    ) -> Option<(u64, Vec<u8>)> {
        self.inner.runtime_fragment(code_hash, offset, max_bytes)
    }

    fn install_runtime(&self, wasm: &[u8]) -> Result<Hash, String> {
        self.inner.install_runtime(wasm)
    }
    fn installed_runtimes(&self) -> Vec<Hash> {
        self.inner.installed_runtimes()
    }
}
