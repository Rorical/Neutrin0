//! Dyn-friendly companion to [`BlockExecutor`].

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use neutrin0_consensus_types::Body;
use neutrin0_primitives::Hash;
use neutrin0_runtime_abi::{QueryRequest, QueryResponse, TxValidity};
use neutrin0_trie::{Poseidon2Hasher, Trie};

use super::{BlockExecutionContext, BlockExecutor, ExecutionOutcome};

/// Dyn-friendly companion to [`BlockExecutor`].
///
/// The consensus engine's block-production path stores its executor
/// behind a trait object so the engine type doesn't need a third
/// generic parameter. `ErasedBlockExecutor` collapses
/// [`BlockExecutor::Error`] to [`String`] so the dyn pointer carries
/// no associated types.
///
/// Every `BlockExecutor + Send + Sync` automatically implements this
/// via the blanket impl below.
pub trait ErasedBlockExecutor: Send + Sync {
    /// Type-erased counterpart to [`BlockExecutor::lease_runtimes`].
    /// # Errors
    /// Returns the underlying program/resource failure as text.
    fn lease_runtimes(&self, _runtimes: &[Hash]) -> Result<crate::artifacts::ProgramLease, String> {
        Ok(alloc::sync::Arc::new(()))
    }

    /// Type-erased counterpart to [`BlockExecutor::retain_programs`].
    fn retain_programs(&self, _retention: &crate::artifacts::ProgramRetention) {}

    /// Type-erased counterpart to [`BlockExecutor::set_artifact_loader`].
    fn set_artifact_loader(&self, _loader: crate::artifacts::ProgramArtifactLoader) {}

    /// Type-erased counterpart to [`BlockExecutor::execute_block`].
    ///
    /// # Errors
    /// Surfaces the underlying executor's error rendered as a
    /// human-readable string.
    fn execute_block(
        &self,
        ctx: &BlockExecutionContext,
        body: &Body,
        state: &mut Trie<Poseidon2Hasher>,
    ) -> Result<ExecutionOutcome, String>;

    /// Type-erased counterpart to [`BlockExecutor::query`].
    ///
    /// # Errors
    /// Surfaces the underlying executor's error rendered as a
    /// human-readable string.
    fn query(
        &self,
        request: &QueryRequest,
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<QueryResponse, String>;

    /// Exact installed runtime bytes for bounded bootstrap artifact serving.
    fn runtime_artifact(&self, _runtime_code_hash: &Hash) -> Option<Vec<u8>> {
        None
    }

    /// Type-erased counterpart to [`BlockExecutor::runtime_fragment`].
    fn runtime_fragment(
        &self,
        code_hash: &Hash,
        offset: u64,
        max_bytes: usize,
    ) -> Option<(u64, Vec<u8>)> {
        crate::artifacts::artifact_fragment(&self.runtime_artifact(code_hash)?, offset, max_bytes)
    }

    /// Type-erased counterpart to [`BlockExecutor::validate_tx`].
    ///
    /// # Errors
    /// Surfaces the underlying executor's error rendered as a
    /// human-readable string.
    fn validate_tx(
        &self,
        tx_bytes: &[u8],
        chain_id: u64,
        block_gas_limit: u64,
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, String>;

    /// Type-erased counterpart to [`BlockExecutor::install_runtime`].
    ///
    /// # Errors
    /// Surfaces the underlying executor's error rendered as a string.
    fn install_runtime(&self, wasm: &[u8]) -> Result<Hash, String>;

    /// Type-erased counterpart to [`BlockExecutor::installed_runtimes`].
    fn installed_runtimes(&self) -> Vec<Hash>;
}

impl<X> ErasedBlockExecutor for X
where
    X: BlockExecutor + Send + Sync,
{
    fn lease_runtimes(&self, runtimes: &[Hash]) -> Result<crate::artifacts::ProgramLease, String> {
        BlockExecutor::lease_runtimes(self, runtimes).map_err(|error| error.to_string())
    }

    fn retain_programs(&self, retention: &crate::artifacts::ProgramRetention) {
        BlockExecutor::retain_programs(self, retention);
    }

    fn set_artifact_loader(&self, loader: crate::artifacts::ProgramArtifactLoader) {
        BlockExecutor::set_artifact_loader(self, loader);
    }

    fn execute_block(
        &self,
        ctx: &BlockExecutionContext,
        body: &Body,
        state: &mut Trie<Poseidon2Hasher>,
    ) -> Result<ExecutionOutcome, String> {
        BlockExecutor::execute_block(self, ctx, body, state).map_err(|err| err.to_string())
    }

    fn query(
        &self,
        request: &QueryRequest,
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<QueryResponse, String> {
        BlockExecutor::query(self, request, runtime_code_hash, state).map_err(|err| err.to_string())
    }

    fn runtime_artifact(&self, runtime_code_hash: &Hash) -> Option<Vec<u8>> {
        BlockExecutor::runtime_artifact(self, runtime_code_hash)
    }

    fn runtime_fragment(
        &self,
        code_hash: &Hash,
        offset: u64,
        max_bytes: usize,
    ) -> Option<(u64, Vec<u8>)> {
        BlockExecutor::runtime_fragment(self, code_hash, offset, max_bytes)
    }

    fn validate_tx(
        &self,
        tx_bytes: &[u8],
        chain_id: u64,
        block_gas_limit: u64,
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, String> {
        BlockExecutor::validate_tx(
            self,
            tx_bytes,
            chain_id,
            block_gas_limit,
            runtime_code_hash,
            state,
        )
        .map_err(|err| err.to_string())
    }

    fn install_runtime(&self, wasm: &[u8]) -> Result<Hash, String> {
        BlockExecutor::install_runtime(self, wasm).map_err(|err| err.to_string())
    }

    fn installed_runtimes(&self) -> Vec<Hash> {
        BlockExecutor::installed_runtimes(self)
    }
}
