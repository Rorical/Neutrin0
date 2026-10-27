//! The runtime ABI calls: block dry-run, genesis, read-only queries and
//! transaction admission, each over a fresh host state.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_abi::{
    APPLY_BLOCK_ENTRYPOINT, QUERY_ENTRYPOINT, QueryRequest, QueryResponse, QueryStatus, TxValidity,
    VALIDATE_TX_ENTRYPOINT,
};
use neutrin0_runtime_core::host::witness_of;
use neutrin0_trie::{Poseidon2Hasher, Trie};

use super::host_state::HostState;
use super::{WasmError, WasmRuntime, codec_err};
use crate::DryRun;

impl WasmRuntime {
    /// Execute `apply_block` inside the WASM runtime against a tracing
    /// view of `live`, then materialise the witness the SP1 Guest needs
    /// to replay the same transition.
    ///
    /// `input.block_gas_limit` must be set by the caller to the
    /// header's `gas_limit`; the runtime stops applying transactions
    /// once their cumulative cost would exceed that ceiling.
    ///
    /// Equivalent in result to [`crate::dry_run`] but goes through the
    /// real wasmtime ABI used in production.
    ///
    /// # Errors
    /// Returns [`WasmError`] if instantiation or trap recovery fails.
    /// Codec errors during input/output encoding are surfaced the same
    /// way.
    pub fn dry_run(
        &self,
        input: &RuntimeBlockInput,
        live: &Trie<Poseidon2Hasher>,
        evidence_proofs: &[neutrin0_consensus_types::evidence::EvidenceArtifact],
    ) -> Result<DryRun, WasmError> {
        crate::evidence::verify_input_receipts(input, evidence_proofs).map_err(codec_err)?;
        let mut input_bytes = Vec::new();
        BorshSerialize::serialize(
            &neutrin0_runtime_abi::RuntimeCallInput::Block(input.clone().into()),
            &mut input_bytes,
        )
        .map_err(codec_err)?;
        let host = HostState::new(live, false, self.limits.block_memory_bytes);
        let (output_bytes, host) = self.invoke(
            APPLY_BLOCK_ENTRYPOINT,
            &input_bytes,
            host,
            self.limits.block_fuel,
        )?;
        let neutrin0_runtime_abi::RuntimeCallOutput::Block(result) =
            BorshDeserialize::try_from_slice(&output_bytes).map_err(codec_err)?
        else {
            return Err(codec_err("runtime returned a genesis result for a block"));
        };
        let output = result.output;
        if output.receipts_root
            != neutrin0_runtime_core::execution::artifacts_commitment(&result.artifacts)
        {
            return Err(codec_err(
                "runtime artifacts do not match receipt commitment",
            ));
        }

        if !neutrin0_runtime_core::execution::output_binds_input(
            input,
            &output,
            live.root(),
            host.scratch.root(),
        ) {
            return Err(codec_err(
                "runtime output does not bind execution input and state",
            ));
        }

        // Materialise the witness from the recorded accesses against
        // the live trie and return the post-state scratch trie so the
        // producer can swap it into the engine's authoritative state.
        let witness =
            witness_of(live, host.accessed).map_err(|error| WasmError::State(error.to_string()))?;
        Ok(DryRun {
            artifacts: result.artifacts,
            output,
            witness,
            post_state: host.scratch,
            writes: crate::state_writes(host.writes),
        })
    }

    /// Initialize the selected runtime against a fresh trie and authenticate its roots.
    /// # Errors
    /// Rejects traps, malformed outputs and inconsistent genesis commitments.
    pub fn init_genesis(
        &self,
        input: &neutrin0_runtime_abi::RuntimeGenesisInput,
    ) -> Result<
        (
            neutrin0_runtime_abi::RuntimeGenesisOutput,
            Trie<Poseidon2Hasher>,
        ),
        WasmError,
    > {
        let live = Trie::<Poseidon2Hasher>::default();
        let host = HostState::new(&live, false, self.limits.block_memory_bytes);
        let bytes = borsh::to_vec(&neutrin0_runtime_abi::RuntimeCallInput::Genesis(
            input.clone().into(),
        ))
        .map_err(codec_err)?;
        let (bytes, host) =
            self.invoke(APPLY_BLOCK_ENTRYPOINT, &bytes, host, self.limits.block_fuel)?;
        let neutrin0_runtime_abi::RuntimeCallOutput::Genesis(output) =
            borsh::from_slice(&bytes).map_err(codec_err)?
        else {
            return Err(codec_err("runtime returned block output for genesis"));
        };
        let candidates = host
            .scratch
            .get(neutrin0_consensus_types::runtime::CONSENSUS_CANDIDATES_KEY)
            .map_err(|error| WasmError::State(error.to_string()))?
            .map(|bytes| {
                borsh::from_slice::<neutrin0_consensus_types::runtime::ConsensusCandidates>(&bytes)
                    .map_err(codec_err)
            })
            .transpose()?
            .unwrap_or_default();
        if output.state_root != host.scratch.root()
            || !candidates
                .entries
                .windows(2)
                .all(|pair| pair[0].address < pair[1].address)
            || output.consensus_candidates_root != candidates.root()
        {
            return Err(codec_err("runtime genesis commitment mismatch"));
        }
        Ok((*output, host.scratch))
    }

    /// Execute a read-only query against `live`. The runtime's
    /// `_neutrin0_query` export is invoked with the borsh-encoded
    /// [`QueryRequest`]; the returned [`QueryResponse`] carries the
    /// runtime-defined result.
    ///
    /// The host runs the call in read-only mode: any `state_write`
    /// or `state_delete` from the guest is silently dropped and the
    /// response is replaced with
    /// [`QueryStatus::PermissionDenied`]. The scratch trie is
    /// discarded after the call so no overlay mutation can leak into
    /// `live`.
    ///
    /// # Errors
    /// Returns [`WasmError`] if instantiation or trap recovery fails.
    /// Codec errors during input/output encoding are surfaced the same
    /// way.
    pub fn query(
        &self,
        request: &QueryRequest,
        live: &Trie<Poseidon2Hasher>,
    ) -> Result<QueryResponse, WasmError> {
        let mut req_bytes = Vec::new();
        BorshSerialize::serialize(request, &mut req_bytes).map_err(codec_err)?;
        // Selection is a trusted block operation and must have the same resource
        // allowance as execution. Node RPC rejects client-supplied block context.
        let block_operation =
            request.method == neutrin0_runtime_abi::operational::QUERY_SELECT_TRANSACTIONS;
        let (fuel, memory) = if block_operation {
            (self.limits.block_fuel, self.limits.block_memory_bytes)
        } else {
            (self.limits.query_fuel, self.limits.query_memory_bytes)
        };
        let host = HostState::new(live, true, memory);
        let (resp_bytes, host) = self.invoke(QUERY_ENTRYPOINT, &req_bytes, host, fuel)?;
        let response: QueryResponse =
            BorshDeserialize::try_from_slice(&resp_bytes).map_err(codec_err)?;

        // The scratch trie is dropped with `host`; queries never
        // mutate `live`. Any write attempt poisons the response so the
        // caller cannot confuse a write-attempted query with a
        // successful one.
        if host.write_attempted {
            return Ok(QueryResponse::err(
                QueryStatus::PermissionDenied,
                b"runtime attempted state write during query".to_vec(),
            ));
        }

        Ok(response)
    }

    /// Run the runtime's `_neutrin0_validate_tx` entrypoint against a
    /// read-only view of `live`.
    ///
    /// The host writes the bound `chain_id` + `block_gas_limit` +
    /// raw transaction bytes into linear memory, invokes
    /// the runtime, and decodes the canonical 13-byte [`TxValidity`]
    /// result the runtime emitted. The scratch trie is discarded
    /// after the call so admission cannot mutate `live`; the host
    /// runs in read-only mode and forces
    /// `TxValidationCode::Unauthorized`-equivalent behavior at the
    /// WASM ABI boundary if the runtime attempts a write (it should
    /// not for a correctly-implemented runtime).
    ///
    /// # Errors
    /// Returns [`WasmError`] when instantiation or trap recovery
    /// fails; or [`WasmError::InvalidTxValidity`] when the runtime's
    /// response cannot be decoded as a [`TxValidity`].
    pub fn validate_tx(
        &self,
        tx_bytes: &[u8],
        chain_id: u64,
        block_gas_limit: u64,
        live: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, WasmError> {
        // Canonical admission envelope:
        //   8B chain_id || 8B block_gas_limit || tx_bytes
        // The runtime's _neutrin0_validate_tx decodes the prefix
        // before parsing the tx itself. Putting the gas limit on the
        // wire means a runtime that wraps multiple chain
        // configurations can pick the right one.
        let mut input_bytes = Vec::with_capacity(8 + 8 + tx_bytes.len());
        input_bytes.extend_from_slice(&chain_id.to_le_bytes());
        input_bytes.extend_from_slice(&block_gas_limit.to_le_bytes());
        input_bytes.extend_from_slice(tx_bytes);

        let host = HostState::new(live, true, self.limits.validate_tx_memory_bytes);
        let (out_bytes, host) = self.invoke(
            VALIDATE_TX_ENTRYPOINT,
            &input_bytes,
            host,
            self.limits.validate_tx_fuel,
        )?;

        if host.write_attempted {
            // A correctly-implemented runtime never writes during
            // admission, so a write attempt is a hard ABI violation;
            // we surface it as Unauthorized (the consensus-driven
            // rejection code) so callers cannot accidentally treat
            // the bytes as admissible.
            return Ok(TxValidity::invalid(
                neutrin0_runtime_abi::TxValidationCode::Unauthorized,
            ));
        }

        TxValidity::decode(&out_bytes).map_err(WasmError::InvalidTxValidity)
    }
}
