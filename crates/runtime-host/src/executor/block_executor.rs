//! The [`BlockExecutor`] trait implementation over the runtime cache.

use std::sync::Arc;

use borsh::BorshDeserialize;
use neutrin0_consensus_types::Body;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::artifacts::{ArtifactIdentity, ProgramArtifactLoader, ProgramRetention};
use neutrin0_proof_system::executor::{BlockExecutionContext, BlockExecutor, ExecutionOutcome};
use neutrin0_runtime_abi::{QueryRequest, QueryResponse, TxValidity};
use neutrin0_runtime_abi::{RuntimeBlockInput, RuntimeTransaction};
use neutrin0_trie::{Poseidon2Hasher, Trie};

use super::runtime_cache::RuntimeEntry;
use super::{ExecutorError, WasmExecutor, encode_witness_bundle};
use crate::DryRun;

impl BlockExecutor for WasmExecutor {
    type Error = ExecutorError;

    fn lease_runtimes(
        &self,
        runtimes: &[Hash],
    ) -> Result<neutrin0_proof_system::artifacts::ProgramLease, Self::Error> {
        let leases: Result<Vec<_>, _> = runtimes.iter().map(|hash| self.runtime(hash)).collect();
        Ok(Arc::new(leases?))
    }

    fn set_artifact_loader(&self, loader: ProgramArtifactLoader) {
        *self
            .artifact_loader
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(loader);
    }

    fn retain_programs(&self, retention: &ProgramRetention) {
        let mut cache = self
            .runtimes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.sources = retention
            .sources
            .iter()
            .filter_map(|identity| match identity {
                ArtifactIdentity::Runtime(hash) => Some(*hash),
                ArtifactIdentity::Guest(_) => None,
            })
            .collect();
        cache.warm = retention
            .warm
            .iter()
            .filter_map(|identity| match identity {
                ArtifactIdentity::Runtime(hash) => Some(*hash),
                ArtifactIdentity::Guest(_) => None,
            })
            .collect();
        let resumed: Vec<_> = cache
            .retired
            .iter()
            .filter_map(|(lease, bytes)| lease.upgrade().map(|runtime| (runtime, *bytes)))
            .filter(|(runtime, _)| cache.warm.contains(&runtime.code_hash()))
            .collect();
        let touched = cache.clock;
        for (runtime, bytes) in resumed {
            cache
                .entries
                .entry(runtime.code_hash())
                .or_insert(RuntimeEntry {
                    runtime,
                    touched,
                    bytes,
                });
        }
        let warm = cache.warm.clone();
        cache.retired.retain(|(lease, _)| {
            lease
                .upgrade()
                .is_some_and(|runtime| !warm.contains(&runtime.code_hash()))
        });
        let obsolete: Vec<_> = cache
            .entries
            .keys()
            .filter(|hash| !cache.sources.contains(*hash))
            .copied()
            .collect();
        for hash in obsolete {
            cache.remove(&hash);
        }
        cache.retired.retain(|(lease, _)| lease.strong_count() != 0);
    }

    fn execute_block(
        &self,
        ctx: &BlockExecutionContext,
        body: &Body,
        state: &mut Trie<Poseidon2Hasher>,
    ) -> Result<ExecutionOutcome, ExecutorError> {
        // Decode only the common envelope. User payloads belong to the runtime.
        // Strict decoding preserves the exact body bytes and transaction root;
        // silently omitting a malformed envelope would break proof bindings.
        let mut txs = Vec::with_capacity(body.transactions.len());
        for (idx, raw) in body.transactions.iter().enumerate() {
            let tx = <RuntimeTransaction as BorshDeserialize>::try_from_slice(raw.as_slice())
                .map_err(|err| {
                    ExecutorError::Codec(format!(
                        "body.transactions[{idx}] failed to decode as RuntimeTransaction: {err}",
                    ))
                })?;
            txs.push(tx);
        }
        let input = RuntimeBlockInput {
            context: ctx.context,
            evidence_anchor: ctx.evidence_anchor,
            chain_id: ctx.chain_id,
            block_height: ctx.block_height,
            block_gas_limit: ctx.gas_limit,
            proposer_address: ctx.proposer_address,
            participation: ctx.participation.clone(),
            proving: ctx.proving.clone(),
            active_validators: ctx.active_validators.clone(),
            participation_acks: ctx.participation_acks.clone(),
            program_pieces: ctx.program_pieces.clone(),
            transactions: txs,
        };

        // The runtime borrows the engine's authoritative trie as the
        // pre-state and applies writes to its own scratch copy, so
        // `state` stays untouched until the swap below.
        let DryRun {
            artifacts,
            output,
            witness,
            post_state,
            writes,
        } = self
            .runtime(&ctx.runtime_code_hash)?
            .dry_run(&input, state, &body.evidence_proofs)?;

        // Commit the dry-run's post-state into the engine's trie.
        // Read-only blocks fall back to a clone of `state`, so the
        // swap is unconditional and idempotent.
        // Persist attachments beside the semantic input and state witness.
        // The prover sends them through SP1's separate recursive proof stream.
        let witness_bytes = encode_witness_bundle(&input, &witness, &body.evidence_proofs)
            .map_err(|err| ExecutorError::Codec(err.to_string()))?;
        if !input.evidence_anchor.is_well_formed()
            || u64::try_from(witness_bytes.len()).unwrap_or(u64::MAX)
                > input.evidence_anchor.max_block_proving_input_bytes
        {
            return Err(ExecutorError::Codec(
                "block proving envelope exceeds authenticated allocation limit".into(),
            ));
        }
        *state = post_state;

        Ok(ExecutionOutcome {
            artifacts,
            state_root_after: output.post_state_root,
            runtime_extra: output.consensus_candidates_root,
            receipts_root: output.receipts_root,
            gas_used: output.gas_used,
            witness_bytes,
            state_writes: writes,
        })
    }

    fn query(
        &self,
        request: &QueryRequest,
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<QueryResponse, ExecutorError> {
        // The WasmRuntime's query path works on its own scratch copy
        // and discards it after the call so no mutation can leak back
        // into `state`.
        Ok(self.runtime(&runtime_code_hash)?.query(request, state)?)
    }

    fn runtime_artifact(&self, code_hash: &Hash) -> Option<Vec<u8>> {
        let cache = self
            .runtimes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = cache.entries.get(code_hash) {
            return Some(entry.runtime.artifact().to_vec());
        }
        if !cache.sources.contains(code_hash) {
            return None;
        }
        drop(cache);
        self.artifact_loader
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .and_then(|reader| reader(ArtifactIdentity::Runtime(*code_hash)))
    }

    fn runtime_fragment(
        &self,
        code_hash: &Hash,
        offset: u64,
        max_bytes: usize,
    ) -> Option<(u64, Vec<u8>)> {
        neutrin0_proof_system::artifacts::artifact_fragment(
            &self.runtime_artifact(code_hash)?,
            offset,
            max_bytes,
        )
    }

    fn validate_tx(
        &self,
        tx_bytes: &[u8],
        chain_id: u64,
        block_gas_limit: u64,
        runtime_code_hash: Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, ExecutorError> {
        Ok(self.runtime(&runtime_code_hash)?.validate_tx(
            tx_bytes,
            chain_id,
            block_gas_limit,
            state,
        )?)
    }

    fn install_runtime(&self, wasm: &[u8]) -> Result<Hash, ExecutorError> {
        Ok(Self::install_runtime(self, wasm)?)
    }

    fn installed_runtimes(&self) -> Vec<Hash> {
        self.runtime_hashes()
    }
}
