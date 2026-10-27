//! Engine integration for proof-gated finality. The backend here is explicitly
//! a native statement checker; real SP1 recursion is tested in runtime-host.
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use neutrin0_consensus_engine::{BftAction, BlockState, Engine, ProposerKey};
use neutrin0_consensus_types::{BlockProof, BlockProofPublicInputs, Body};
use neutrin0_evm_runtime_core::apply_block;
use neutrin0_proof_system::{
    BlockExecutionContext, ErasedBlockExecutor, ExecutionOutcome, ProofError, ProofSystem,
};
use neutrin0_prover_chunk::consensus::{ConsensusWitness, validate_consensus};
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_abi::{BlockReceiptStatement, RuntimeBlockOutput};
use neutrin0_runtime_abi::{QueryRequest, QueryResponse, TxValidity};
use neutrin0_runtime_core::host::{LiveTrie, TracingState};
use neutrin0_storage::MemoryDatabase;
use neutrin0_trie::{Poseidon2Hasher, Trie};

struct NativeConsensusBackend {
    reject: bool,
}

/// Execute the actual shared STF when materializing a proof-selected branch.
struct NativeReplayExecutor;

impl ErasedBlockExecutor for NativeReplayExecutor {
    fn execute_block(
        &self,
        context: &BlockExecutionContext,
        body: &Body,
        state: &mut Trie<Poseidon2Hasher>,
    ) -> Result<ExecutionOutcome, String> {
        let input = RuntimeBlockInput {
            active_validators: context.active_validators.clone(),
            participation_acks: context.participation_acks.clone(),
            program_pieces: context.program_pieces.clone(),
            context: context.context,
            evidence_anchor: context.evidence_anchor,
            chain_id: context.chain_id,
            block_height: context.block_height,
            block_gas_limit: context.gas_limit,
            proposer_address: context.proposer_address,
            participation: context.participation.clone(),
            proving: context.proving.clone(),
            transactions: body
                .transactions
                .iter()
                .map(|bytes| borsh::from_slice(bytes))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?,
        };
        let live = LiveTrie::from_trie(state.clone());
        let mut tracing = TracingState::new(&live);
        let result = neutrin0_evm_runtime_core::execute_block(&input, &mut tracing);
        let output = result.output;
        let (post_state, witness, writes) = tracing.into_committed_witness_and_writes().unwrap();
        *state = post_state;
        Ok(ExecutionOutcome {
            artifacts: result.artifacts,
            state_root_after: output.post_state_root,
            runtime_extra: output.consensus_candidates_root,
            receipts_root: output.receipts_root,
            gas_used: output.gas_used,
            witness_bytes: borsh::to_vec(&(input, witness)).map_err(|error| error.to_string())?,
            state_writes: writes
                .into_iter()
                .map(|(key, value)| neutrin0_consensus_types::StateWrite { key, value })
                .collect(),
        })
    }

    fn query(
        &self,
        request: &QueryRequest,
        _: neutrin0_primitives::Hash,
        state: &Trie<Poseidon2Hasher>,
    ) -> Result<QueryResponse, String> {
        let live = LiveTrie::from_trie(state.clone());
        Ok(neutrin0_evm_runtime_core::query(
            request,
            &mut TracingState::new(&live),
        ))
    }

    fn validate_tx(
        &self,
        _: &[u8],
        _: u64,
        _: u64,
        _: neutrin0_primitives::Hash,
        _: &Trie<Poseidon2Hasher>,
    ) -> Result<TxValidity, String> {
        Err(String::from(
            "transaction admission is outside this replay regression",
        ))
    }

    fn install_runtime(&self, _: &[u8]) -> Result<neutrin0_primitives::Hash, String> {
        Err(String::from(
            "runtime installation is outside this replay regression",
        ))
    }

    fn installed_runtimes(&self) -> Vec<neutrin0_primitives::Hash> {
        Vec::new()
    }
}

impl ProofSystem for NativeConsensusBackend {
    type BlockProof = BlockReceiptStatement;
    type ChunkProof = neutrin0_consensus_types::history_proof::ChunkReceiptStatement;

    fn prove_block(
        &self,
        bytes: &[u8],
        pi: &BlockProofPublicInputs,
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::BlockProof, ProofError> {
        let (input, witness): (RuntimeBlockInput, neutrin0_runtime_abi::StateWitness) =
            borsh::from_slice(bytes).map_err(|_| ProofError::InvalidWitness)?;
        let mut state = neutrin0_runtime_core::WitnessState::new(&witness)
            .map_err(|_| ProofError::InvalidWitness)?;
        let statement = BlockReceiptStatement {
            output: apply_block(&input, &mut state),
            prover_address,
        };
        self.verify_block(&statement, pi)?;
        Ok(statement)
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        pi: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        if proof.output.block_height != pi.height
            || proof.output.post_state_root != pi.state_root_after
        {
            return Err(ProofError::PublicInputMismatch);
        }
        Ok(())
    }

    fn programs(&self) -> Option<neutrin0_consensus_types::history_proof::GuestPrograms> {
        Some(neutrin0_consensus_types::history_proof::GuestPrograms {
            execution: support::programs([1; 8], [4; 32]).execution,
            chunk: support::chunk_program(),
        })
    }

    fn block_statement(
        &self,
        proof: &Self::BlockProof,
    ) -> Result<BlockReceiptStatement, ProofError> {
        Ok(proof.clone())
    }

    fn prove_consensus_chunk(
        &self,
        _: &[Self::BlockProof],
        _: &[Self::ChunkProof],
        witness: &ConsensusWitness,
        chunk_prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::ChunkProof, ProofError> {
        if self.reject {
            return Err(ProofError::BackendRejected);
        }
        validate_consensus(witness)
            .map(
                |statement| neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
                    statement,
                    chunk_prover_address,
                },
            )
            .map_err(|_| ProofError::InvalidWitness)
    }

    fn chunk_prover_address(
        &self,
        proof: &Self::ChunkProof,
    ) -> Result<neutrin0_primitives::Hash, ProofError> {
        Ok(proof.chunk_prover_address)
    }

    fn verify_consensus_chunk(
        &self,
        proof: &Self::ChunkProof,
        expected: &neutrin0_consensus_types::history_proof::ChunkReceiptStatement,
    ) -> Result<(), ProofError> {
        if self.reject || proof != expected {
            return Err(ProofError::BackendRejected);
        }
        Ok(())
    }

    fn history_domain(
        &self,
        spec: &neutrin0_primitives::ChainSpec,
    ) -> Result<neutrin0_consensus_types::history_proof::ProofDomain, ProofError> {
        Ok(neutrin0_consensus_types::history_proof::ProofDomain {
            chain: neutrin0_consensus_types::history_proof::ChainBinding::new(spec),
            chunk: spec.genesis_chunk,
            programs: support::programs([1; 8], [4; 32]),
        })
    }

    /// A native History receipt is the exact statement it proves.
    fn verify_history(
        &self,
        proof: &neutrin0_consensus_types::HistoryProof,
        chunk: &neutrin0_consensus_types::history_proof::VkDigest,
    ) -> Result<(), ProofError> {
        let receipt: Self::ChunkProof =
            borsh::from_slice(proof.receipt.as_slice()).map_err(|_| ProofError::BackendRejected)?;
        if self.reject || *chunk != support::chunk_program() || receipt != proof.statement {
            return Err(ProofError::BackendRejected);
        }
        Ok(())
    }
}

fn engine() -> (Engine<MemoryDatabase>, ConsensusWitness) {
    let (engine, witness, _) = engine_with_input();
    (engine, witness)
}

/// Execute the fixture block again as a sibling at `slot` under `engine`'s
/// chunk-zero boundary. The returned header, public inputs and output commit
/// the sibling's exact slot, timestamp, VRF output and committee, so the
/// Chunk Guest accepts the branch; the caller signs the header.
fn sibling_execution<DB: neutrin0_storage::Database>(
    engine: &Engine<DB>,
    input: &RuntimeBlockInput,
    base_header: &neutrin0_consensus_types::Header,
    base_inputs: &BlockProofPublicInputs,
    slot: u64,
    vrf_proof: neutrin0_primitives::BlsSignature,
    live: &LiveTrie,
) -> (
    neutrin0_consensus_types::Header,
    BlockProofPublicInputs,
    RuntimeBlockOutput,
    Body,
) {
    let spec = engine.chain_spec();
    let Ok((context, seed, _)) = engine.consensus_boundary(0) else {
        panic!("chunk-zero boundary is always available");
    };
    let boundary = neutrin0_prover_chunk::consensus::context_boundary(&context, seed).unwrap();
    let mut input = input.clone();
    input.active_validators = context.active_validators;
    input.context.finalized = boundary;
    input.context.slot = slot;
    input.context.timestamp = spec.genesis_time + slot * spec.consensus.slot_duration_secs;
    input.context.proposer_vrf_output = neutrin0_vrf::proof_output(&vrf_proof);
    let mut state = TracingState::new(live);
    let result = neutrin0_evm_runtime_core::execute_block(&input, &mut state);
    let output = result.output;
    // The sibling's own artifacts: its metadata commits its own context.
    let body = Body {
        artifacts: result.artifacts,
        ..Body::default()
    };
    let mut header = base_header.clone();
    header.slot = slot;
    header.timestamp = input.context.timestamp;
    header.vrf_proof = vrf_proof;
    header.state_root = output.post_state_root;
    header.transactions_root = output.transactions_root;
    header.receipts_root = output.receipts_root;
    header.da_root = neutrin0_prover_chunk::consensus::body_da_root(&body);
    header.gas_used = output.gas_used;
    header.runtime_extra = output.consensus_candidates_root;
    header.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
    header.signature = [0; 96];
    let mut public_inputs = base_inputs.clone();
    public_inputs.context = Box::new(input.context);
    public_inputs.block_hash = header.hash();
    public_inputs.state_root_before = output.pre_state_root;
    public_inputs.state_root_after = output.post_state_root;
    public_inputs.transactions_root = output.transactions_root;
    public_inputs.receipt_root = output.receipts_root;
    public_inputs.da_root = header.da_root;
    public_inputs.gas_used = output.gas_used;
    public_inputs.runtime_extra = output.consensus_candidates_root;
    public_inputs.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
    (header, public_inputs, output, body)
}

/// [`engine`] that also returns the executed block's runtime input, for tests
/// that derive sibling executions from it.
fn engine_with_input() -> (Engine<MemoryDatabase>, ConsensusWitness, RuntimeBlockInput) {
    let (mut witness, input, _) = support::fixture([1; 8], [4; 32]);
    let genesis = support::fixture_genesis_live([1; 8], [4; 32], 30_000_000);
    let mut engine = Engine::genesis(witness.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_programs(support::guests([1; 8], [4; 32]));
    engine
        .install_genesis_state(genesis.trie().clone())
        .unwrap();
    let block = &witness.blocks[0];
    let hash = block.header.hash();
    engine
        .import_block(
            &neutrin0_consensus_types::Block {
                header: block.header.clone(),
                body: support::executed_body(&genesis, &input),
            },
            &NativeReplayExecutor,
        )
        .unwrap();
    engine
        .store_mut()
        .put_block_state(&hash, BlockState::Proven)
        .unwrap();
    engine
        .store_mut()
        .put_block_proof(
            &hash,
            &BlockProof {
                prover_address: block.public_inputs.proposer_address,
                statement_key: neutrin0_consensus_types::evidence::commitment(&block.statement()),
                height: block.header.height,
                block_hash: hash,
                public_inputs: block.public_inputs.clone(),
                proof_bytes: borsh::to_vec(&block.statement()).unwrap(),
            },
        )
        .unwrap();
    let proof = engine.store().get_block_proof(&hash).unwrap().unwrap();
    let manifest = neutrin0_consensus_types::ProofManifest {
        proof_hashes: vec![neutrin0_consensus_types::evidence::commitment(&proof)],
    };
    let data = witness.finality_cert.precommit_vote().data;
    witness.finality_cert.precommit_attestations =
        vec![ProposerKey::from_ikm(&[42; 32], 0).unwrap().attest_vote(
            engine.chain_spec().consensus_domain(),
            data,
            manifest.proof_hashes.clone(),
            None,
        )];
    witness.finality_cert.proof_manifests = vec![manifest];
    (engine, witness, input)
}

#[test]
fn proof_failure_cannot_persist_empty_proof_or_advance_finality() {
    let (mut engine, input) = engine();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    assert!(
        engine
            .finalize_chunk(0, &NativeConsensusBackend { reject: true }, &voter)
            .is_err()
    );
    assert_eq!(engine.latest_finalized_chunk_id(), None);
    assert_eq!(engine.store().get_consensus_state().unwrap(), None);
    assert_eq!(engine.store().get_chunk_proof(0).unwrap(), None);
    assert_eq!(
        engine
            .store()
            .get_block_state(&input.blocks[0].header.hash())
            .unwrap(),
        Some(BlockState::Proven)
    );
}

#[test]
fn complete_finalization_persists_boundary_and_peer_import_checks_certificate() {
    let (mut producer, input) = engine();
    let backend = NativeConsensusBackend { reject: false };
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let outcome = producer.finalize_chunk(0, &backend, &voter).unwrap();
    assert_ne!(outcome.chunk_proof.proof_bytes, [] as [u8; 0]);
    assert_eq!(outcome.chunk_proof.finality_cert, outcome.finality_cert);
    let state = producer.store().get_consensus_state().unwrap().unwrap();
    assert_eq!(state.boundary, validate_consensus(&input).unwrap().end);
    assert_eq!(
        producer.active_validator_set(),
        state.next_context.active_validators
    );
    assert_eq!(state.frontier.count, 1);
    let restarted = Engine::open(input.chain_spec, producer.store().db().clone()).unwrap();
    assert_eq!(restarted.latest_finalized_chunk_id(), Some(0));
    assert_eq!(
        restarted.active_validator_set(),
        state.next_context.active_validators
    );
    assert_eq!(
        restarted.consensus_boundary(1).unwrap().0,
        state.next_context
    );

    let (mut follower, _) = engine();
    let mut bad = outcome.chunk_proof.clone();
    bad.finality_cert.precommit.signature[0] ^= 1;
    assert!(follower.import_chunk_proof(&bad, &backend).is_err());
    assert_eq!(follower.latest_finalized_chunk_id(), None);
    bad = outcome.chunk_proof.clone();
    bad.chunk_hash[0] ^= 1;
    assert!(follower.import_chunk_proof(&bad, &backend).is_err());
    follower
        .import_chunk_proof(&outcome.chunk_proof, &backend)
        .unwrap();
    assert_eq!(follower.store().get_consensus_state().unwrap(), Some(state));
    // An exact duplicate is idempotent; it cannot apply penalties twice.
    follower
        .import_chunk_proof(&outcome.chunk_proof, &backend)
        .unwrap();
}

/// This suite's explicit native checker verifies the complete signed statement;
/// real recursive proof acceptance remains in runtime-host's ignored gates.
fn commit_native_selection_fixture(
    engine: &mut Engine<MemoryDatabase>,
    mut witness: ConsensusWitness,
    keys: &[neutrin0_crypto::bls::SecretKey],
) -> ConsensusWitness {
    let backend = NativeConsensusBackend { reject: false };
    let mut proof_hashes = Vec::new();
    let mut proofs = Vec::new();
    for (executed, compact) in witness.blocks.iter().zip(&witness.bodies) {
        assert_eq!(
            compact.program_pieces,
            Vec::<neutrin0_consensus_types::ProgramPieceDescriptor>::new()
        );
        assert_eq!(executed.output.transaction_summary.transaction_count, 0);
        let body = support::executed_body_of(&executed.header);
        assert_eq!(
            neutrin0_prover_chunk::body::ConsensusBody::from_body(&body).unwrap(),
            *compact,
        );
        engine
            .import_block(
                &neutrin0_consensus_types::Block {
                    header: executed.header.clone(),
                    body,
                },
                &NativeReplayExecutor,
            )
            .unwrap();
        let receipt = engine
            .prove_block(&executed.header.hash(), &backend)
            .unwrap();
        let statement: BlockReceiptStatement =
            borsh::from_slice(&receipt.block_proof.proof_bytes).unwrap();
        assert_eq!(statement.output, executed.output);
        proof_hashes.push(neutrin0_consensus_types::evidence::commitment(
            &receipt.block_proof,
        ));
        proofs.push(statement);
    }
    // Bind genuine precommit attestations to the actual native block receipts,
    // rather than the support fixture's conditional cryptographic placeholders.
    let manifest = neutrin0_consensus_types::ProofManifest { proof_hashes };
    for claim in &mut witness.finality_cert.precommit_attestations {
        claim.proof_acceptance = Some(manifest.commitment());
        claim.signature = keys[usize::try_from(claim.validator_index).unwrap()]
            .sign(&claim.signing_message(witness.chain_spec.consensus_domain()))
            .to_bytes();
    }
    witness.finality_cert.proof_manifests = vec![manifest];
    let statement = backend
        .prove_consensus_chunk(&proofs, &[], &witness, [0; 32])
        .unwrap();
    engine
        .commit_consensus_chunk(&witness, &statement, &backend)
        .unwrap();
    witness
}

#[test]
#[allow(clippy::too_many_lines)]
fn branch_selected_participation_survives_different_local_certificates_and_restart() {
    let keys: Vec<_> = (42..46)
        .map(|byte| neutrin0_crypto::bls::SecretKey::key_gen(&[byte; 32], &[]).unwrap())
        .collect();
    let (mut first, input, _, post) =
        support::fixture_with_validator_keys_and_chunk_size([1; 8], [4; 32], &keys, 2);
    first.finality_cert = support::certificate_with_precommitters(&first, &keys, &[0, 1, 2]);
    let selected = first.finality_cert.carried_certificate();
    let mut alternate = first.clone();
    alternate.finality_cert = support::certificate_with_precommitters(&first, &keys, &[0, 1, 3]);
    let genesis = support::spec_genesis_live(&first);
    let mut a = Engine::genesis(first.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    let mut b = Engine::genesis(first.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    for engine in [&mut a, &mut b] {
        engine.set_programs(support::guests([1; 8], [4; 32]));
        engine
            .install_genesis_state(genesis.trie().clone())
            .unwrap();
    }
    let first = commit_native_selection_fixture(&mut a, first, &keys);
    let alternate = commit_native_selection_fixture(&mut b, alternate, &keys);
    assert_ne!(first.finality_cert, alternate.finality_cert);
    assert_eq!(
        a.store().get_consensus_state().unwrap(),
        b.store().get_consensus_state().unwrap()
    );
    assert_eq!(a.selected_participation_certificate(0).unwrap(), None);
    assert_eq!(b.selected_participation_certificate(0).unwrap(), None);

    let (next, next_input, _, next_post) =
        support::successor_with_participation(&first, &input, &post, &keys, selected.clone());
    let report = next_input.participation.as_ref().unwrap();
    let first_body = Body {
        participation: Some(selected.clone()),
        ..Body::default()
    };
    for engine in [&a, &b] {
        // The imported first block's committed choice, not the node's ABC/ABD
        // collection, determines execution on both nodes.
        assert_eq!(
            engine
                .participation_for_block(&next.blocks[0].header, &first_body)
                .unwrap(),
            Some(report.clone())
        );
    }
    let next_a = commit_native_selection_fixture(&mut a, next.clone(), &keys);
    let next_b = commit_native_selection_fixture(&mut b, next, &keys);
    assert_eq!(next_a.finality_cert, next_b.finality_cert);
    assert_eq!(
        a.store().get_consensus_state().unwrap(),
        b.store().get_consensus_state().unwrap()
    );
    assert_eq!(a.head_state_root(), next_post.state_root());
    assert_eq!(b.head_state_root(), next_post.state_root());
    for engine in [&a, &b] {
        assert_eq!(
            engine.selected_participation_certificate(0).unwrap(),
            Some(selected.quorum.clone())
        );
        for block in &next_a.blocks {
            assert_eq!(
                engine
                    .participation_for_height(block.header.height)
                    .unwrap(),
                Some(report.clone())
            );
            let bytes = engine
                .store()
                .get_witness(&block.header.hash())
                .unwrap()
                .unwrap();
            let (executed, _): (RuntimeBlockInput, neutrin0_runtime_abi::StateWitness) =
                borsh::from_slice(&bytes).unwrap();
            assert_eq!(executed.participation.as_ref(), Some(report));
        }
    }
    let mut restarted = Engine::open(first.chain_spec, b.store().db().clone()).unwrap();
    restarted.set_programs(support::guests([1; 8], [4; 32]));
    assert_eq!(
        restarted.selected_participation_certificate(0).unwrap(),
        Some(selected.quorum.clone())
    );
    // The carrier need not be the chunk's first block (design 08); the
    // selection is read from whichever canonical block carries it.
    let first_hash = next_a.blocks[0].header.hash();
    let second_hash = next_a.blocks[1].header.hash();
    let mut first_body = restarted.store().get_body(&first_hash).unwrap().unwrap();
    let mut carrier = restarted.store().get_body(&second_hash).unwrap().unwrap();
    carrier.participation = first_body.participation.take();
    restarted
        .store_mut()
        .put_body(&first_hash, &first_body)
        .unwrap();
    restarted
        .store_mut()
        .put_body(&second_hash, &carrier)
        .unwrap();
    assert_eq!(
        restarted.selected_participation_certificate(0).unwrap(),
        Some(selected.quorum)
    );
    assert_eq!(
        restarted
            .participation_for_height(next_a.blocks[1].header.height)
            .unwrap(),
        Some(report.clone())
    );
    assert!(restarted.participation_for_height(999).is_err());
    assert!(restarted.store().historical_chunk(0).unwrap().is_some());
    // A pruned selected body reports unavailability even while a different
    // locally retained full finality certificate remains available.
    neutrin0_storage::Database::delete(
        restarted.store_mut().db_mut(),
        neutrin0_storage::Column::Blocks,
        &next_a.blocks[0].header.hash(),
    )
    .unwrap();
    assert!(restarted.selected_participation_certificate(0).is_err());
    assert!(
        restarted
            .participation_for_height(next_a.blocks[1].header.height)
            .is_err()
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_snapshot_bootstrapped_node_imports_the_next_chunk_proof_after_restart() {
    let keys: Vec<_> = (42..46)
        .map(|byte| neutrin0_crypto::bls::SecretKey::key_gen(&[byte; 32], &[]).unwrap())
        .collect();
    let (mut first, input, _, post) =
        support::fixture_with_validator_keys_and_chunk_size([1; 8], [4; 32], &keys, 2);
    first.finality_cert = support::certificate_with_precommitters(&first, &keys, &[0, 1, 2]);
    let genesis = support::spec_genesis_live(&first);
    let backend = NativeConsensusBackend { reject: false };
    let spec = first.chain_spec.clone();
    let mut source = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    source.set_programs(support::guests([1; 8], [4; 32]));
    source
        .install_genesis_state(genesis.trie().clone())
        .unwrap();
    let selected = first.finality_cert.carried_certificate();
    let first = commit_native_selection_fixture(&mut source, first, &keys);
    let (mut second, second_input, _, second_post) =
        support::successor_with_participation(&first, &input, &post, &keys, selected);
    second.finality_cert = support::certificate_with_precommitters(&second, &keys, &[0, 1, 2]);
    let selected = second.finality_cert.carried_certificate();
    let second = commit_native_selection_fixture(&mut source, second, &keys);

    // Snapshot the source after two chunks, so the snapshot's start boundary
    // is not genesis and the next certificate ratifies a non-genesis proof.
    let statement = source.store().chunk_statement(1).unwrap().unwrap();
    let end = statement.end;
    let receipt = neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
        statement,
        chunk_prover_address: support::RATIFIED_CHUNK_PROVER,
    };
    let history = neutrin0_consensus_types::HistoryProof {
        statement: receipt.clone(),
        receipt: neutrin0_primitives::BoundedBytes::new(borsh::to_vec(&receipt).unwrap()).unwrap(),
    };
    let consensus = source.store().get_consensus_state().unwrap().unwrap();
    let header = source
        .store()
        .get_header_by_height(end.height)
        .unwrap()
        .unwrap();
    let recent: Vec<_> = (0..2)
        .map(|chunk| source.store().historical_opening(chunk, 2).unwrap())
        .collect();
    let state = source.state().detached().unwrap();
    assert_eq!(
        end.identity_sanctions_root,
        Trie::<Poseidon2Hasher>::new().root()
    );
    let directory = std::env::temp_dir().join(format!(
        "neutrin0-bootstrap-next-chunk-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    let mut target = Engine::genesis(
        spec.clone(),
        neutrin0_storage::RocksDbDatabase::open(&directory).unwrap(),
    )
    .unwrap();
    target
        .set_history_domain(backend.history_domain(&spec).unwrap())
        .unwrap();
    target
        .store_mut()
        .install_state_slice(
            &[end.state_root, end.identity_sanctions_root],
            &state,
            usize::MAX,
        )
        .unwrap();
    target
        .install_bootstrap(
            neutrin0_proof_system::verify_history_proof(&backend, &spec, history).unwrap(),
            None,
            neutrin0_consensus_types::Checkpoint {
                chain: receipt.statement.chain,
                boundary: neutrin0_consensus_types::history_proof::ConsensusBoundary::first(&spec),
            },
            &header,
            &consensus.next_context.active_validators,
            &consensus.frontier,
            &recent,
            None,
        )
        .unwrap();
    drop(target);
    let mut target = Engine::open(
        spec,
        neutrin0_storage::RocksDbDatabase::open(&directory).unwrap(),
    )
    .unwrap();
    target.set_programs(support::guests([1; 8], [4; 32]));
    // A running node prunes up to its bootstrap anchor; the latest finalized
    // chunk's proof, statement and start boundary must survive as the History
    // proof and as the proof the next certificate ratifies.
    target.prune_finalized_history().unwrap();

    // The source finalizes the next chunk; the restarted target imports its
    // block, the block's receipt and then the complete chunk proof.
    let (next, _, _, _) = support::successor_with_participation(
        &second,
        &second_input,
        &second_post,
        &keys,
        selected,
    );
    let next = commit_native_selection_fixture(&mut source, next, &keys);
    for block in &next.blocks {
        let hash = block.header.hash();
        target
            .import_block(
                &neutrin0_consensus_types::Block {
                    header: block.header.clone(),
                    body: source.store().get_body(&hash).unwrap().unwrap(),
                },
                &NativeReplayExecutor,
            )
            .unwrap();
        target
            .store_mut()
            .put_block_proof(
                &hash,
                &source.store().get_block_proof(&hash).unwrap().unwrap(),
            )
            .unwrap();
        target
            .store_mut()
            .put_block_state(&hash, BlockState::Proven)
            .unwrap();
    }
    let proof = source.store().get_chunk_proof(2).unwrap().unwrap();
    target.import_chunk_proof(&proof, &backend).unwrap();
    assert_eq!(target.latest_finalized_chunk_id(), Some(2));
    assert_eq!(target.head_state_root(), source.head_state_root());
    drop(target);
    std::fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn production_acknowledges_only_precommits_the_carried_certificate_omitted() {
    let keys: Vec<_> = (42..46)
        .map(|byte| neutrin0_crypto::bls::SecretKey::key_gen(&[byte; 32], &[]).unwrap())
        .collect();
    let (mut first, _, _, _) =
        support::fixture_with_validator_keys_and_chunk_size([1; 8], [4; 32], &keys, 2);
    let unsigned = first.clone();
    // This node finalized with 0, 1 and 3; the following chunk carries
    // another valid subset, 0, 1 and 2, which absence is charged against.
    let selected =
        support::certificate_with_precommitters(&first, &keys, &[0, 1, 2]).carried_certificate();
    first.finality_cert = support::certificate_with_precommitters(&first, &keys, &[0, 1, 3]);
    let genesis = support::spec_genesis_live(&first);
    let mut engine = Engine::genesis(first.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_programs(support::guests([1; 8], [4; 32]));
    engine
        .install_genesis_state(genesis.trie().clone())
        .unwrap();
    let committed = commit_native_selection_fixture(&mut engine, first, &keys);
    // Every validator's precommit is retained locally.
    let mut all = support::certificate_with_precommitters(&unsigned, &keys, &[0, 1, 2, 3]);
    let manifest = committed.finality_cert.proof_manifests[0].clone();
    for claim in &mut all.precommit_attestations {
        claim.proof_acceptance = Some(manifest.commitment());
        claim.signature = keys[usize::try_from(claim.validator_index).unwrap()]
            .sign(&claim.signing_message(committed.chain_spec.consensus_domain()))
            .to_bytes();
    }
    all.proof_manifests = vec![manifest];
    engine
        .retain_signed_artifact(
            &neutrin0_consensus_types::signed_artifacts::SignedArtifact::Vote(all.precommit_vote()),
            false,
        )
        .unwrap();

    let proposer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let start = committed.blocks.last().unwrap().header.slot + 1;
    let produced = (start..start + 64)
        .find_map(|slot| {
            engine
                .try_produce_block(
                    slot,
                    neutrin0_consensus_engine::ProductionConfig {
                        proposer: &proposer,
                    },
                    Body {
                        participation: Some(selected.clone()),
                        ..Body::default()
                    },
                    &NativeReplayExecutor,
                )
                .unwrap()
        })
        .expect("the proposer is eligible within the window");
    let body = engine
        .store()
        .get_body(&produced.block_hash)
        .unwrap()
        .unwrap();
    let acknowledged: Vec<u32> = body
        .participation_acks
        .iter()
        .map(|vote| vote.validator_index)
        .collect();
    assert_eq!(acknowledged, [3]);

    // Each source seat is acknowledged once per chunk: a repeat adds only
    // signature work, so neither one body nor a later block of the chunk on
    // this branch may hold it again.
    let header = engine
        .store()
        .get_header(&produced.block_hash)
        .unwrap()
        .unwrap();
    let twice = Body {
        participation_acks: [
            body.participation_acks.clone(),
            body.participation_acks.clone(),
        ]
        .concat(),
        ..Body::default()
    };
    assert!(
        engine
            .participation_acknowledgements(header.height, &twice)
            .is_err()
    );
    let next = header.height + 1;
    let chunk_size = engine.chain_spec().consensus.chunk_size;
    assert_eq!((next - 1) / chunk_size, (header.height - 1) / chunk_size);
    let block_key = engine.programs_for_height(next).unwrap().execution.block;
    let authorize = |body: &Body| {
        engine.authorize_consensus_body(
            next,
            produced.block_hash,
            body,
            header.gas_limit,
            &block_key,
        )
    };
    authorize(&Body::default()).unwrap();
    assert!(
        authorize(&Body {
            participation_acks: body.participation_acks,
            ..Body::default()
        })
        .is_err()
    );
}

#[test]
fn body_authorization_follows_candidate_ancestry_and_checks_the_boundary() {
    let (mut witness, _, _) = support::fixture([1; 8], [4; 32]);
    witness.chain_spec.consensus.chunk_size = 2;
    let mut engine = Engine::genesis(witness.chain_spec, MemoryDatabase::new()).unwrap();
    engine.set_programs(support::guests([1; 8], [4; 32]));
    let parent = &witness.blocks[0].header;
    let parent_hash = engine.store_mut().put_header(parent).unwrap();
    engine
        .store_mut()
        .put_body(&parent_hash, &neutrin0_consensus_types::Body::default())
        .unwrap();

    // A competing candidate may occupy the height index before its body arrives.
    // Authorization must open the selected parent's body, not that sibling.
    let mut sibling = parent.clone();
    sibling.slot += 1;
    engine.store_mut().put_header(&sibling).unwrap();
    let body = neutrin0_consensus_types::Body::default();
    assert!(
        engine
            .authorize_consensus_body(2, parent_hash, &body, parent.gas_limit, &[1; 8])
            .is_ok()
    );
    assert!(
        engine
            .authorize_consensus_body(2, sibling.hash(), &body, parent.gas_limit, &[1; 8])
            .is_err()
    );
    let mut foreign = parent.clone();
    foreign.parent_hash = [99; 32];
    let foreign_hash = engine.store_mut().put_header(&foreign).unwrap();
    engine.store_mut().put_body(&foreign_hash, &body).unwrap();
    assert!(
        engine
            .authorize_consensus_body(2, foreign_hash, &body, parent.gas_limit, &[1; 8])
            .is_err()
    );
}

thread_local! {
    /// Panics raised on this thread, including ones a callee caught.
    static PANICS: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
}

/// Panics raised so far on the calling thread. The release profile aborts on
/// panic, so a rejection that unwinds kills the node even if it is caught.
fn panics_on_this_thread() -> u32 {
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            PANICS.with(|count| count.set(count.get().saturating_add(1)));
            previous(info);
        }));
    });
    PANICS.with(core::cell::Cell::get)
}

#[test]
fn malformed_peer_evidence_is_rejected_without_unwinding() {
    use neutrin0_consensus_types::evidence::{
        EvidenceArtifact, EvidenceContext, EvidenceStatement, EvidenceSubmission, SanctionKind,
    };
    fn body_of(transactions: Vec<Vec<u8>>, evidence_proofs: Vec<EvidenceArtifact>) -> Body {
        Body {
            transactions,
            evidence_proofs,
            ..Body::default()
        }
    }

    let (mut witness, _, _) = support::fixture([1; 8], [4; 32]);
    witness.chain_spec.consensus.chunk_size = 2;
    let mut engine = Engine::genesis(witness.chain_spec, MemoryDatabase::new()).unwrap();
    engine.set_programs(support::guests([1; 8], [4; 32]));
    let parent = &witness.blocks[0].header;
    let parent_hash = engine.store_mut().put_header(parent).unwrap();
    engine
        .store_mut()
        .put_body(&parent_hash, &Body::default())
        .unwrap();
    let statement = EvidenceStatement {
        reporter: None,
        chain_id: engine.chain_spec().chain_id,
        chain_spec_hash: engine.chain_spec_hash(),
        block_guest_vk_digest: [1; 8],
        context: EvidenceContext {
            chunk_id: 0,
            chunk_hash: [3; 32],
            end_height: 1,
            validators_root: engine.chain_spec().genesis_validator_set_root,
            seed: [0; 32],
            source_block_guest_vk_digest: [1; 8],
            source_runtime_code_hash: [0; 32],
            start_boundary: [0; 32],
        },
        offender: witness.context.active_validators[0].clone(),
        kind: SanctionKind::Slash,
        offence_id: [5; 32],
        facts_commitment: [6; 32],
    };
    let evidence = borsh::to_vec(&neutrin0_runtime_abi::RuntimeTransaction::SubmitEvidence(
        Box::new(EvidenceSubmission {
            statement: statement.clone(),
            history: neutrin0_consensus_types::history::HistoryPath {
                index: 0,
                count: 0,
                siblings: vec![[0; 32]; 64],
            },
        }),
    ))
    .unwrap();
    let ordinary = borsh::to_vec(&support::transfer(0)).unwrap();
    let attachment = EvidenceArtifact {
        membership: neutrin0_consensus_types::evidence::EvidenceMembership::default(),
        evidence_guest_vk_digest: [2; 8],
        statement,
        proof_bytes: vec![1],
    };
    let authorize = |body: &Body| {
        engine.authorize_consensus_body(2, parent_hash, body, parent.gas_limit, &[1; 8])
    };

    // Ordinary transactions alone carry no admission to check.
    assert!(authorize(&body_of(vec![ordinary.clone()], Vec::new())).is_ok());
    // Evidence after an ordinary transaction, and evidence the block's anchor
    // cannot authenticate, trip assertions in the runtime's input validation.
    // A peer body must be rejected before reaching them: the release profile
    // aborts on panic, so a caught unwind still takes the whole node down.
    let panics = panics_on_this_thread();
    for rejected in [
        body_of(vec![ordinary, evidence.clone()], vec![attachment.clone()]),
        body_of(vec![evidence], vec![attachment]),
    ] {
        assert!(authorize(&rejected).is_err());
    }
    assert_eq!(panics_on_this_thread(), panics);
}

#[test]
fn successor_bft_uses_the_proven_validator_root() {
    let (mut engine, _) = engine();
    let backend = NativeConsensusBackend { reject: false };
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let outcome = engine.finalize_chunk(0, &backend, &voter).unwrap();
    let state = engine.store().get_consensus_state().unwrap().unwrap();
    // Rotation projects runtime stakes; with no stake change the proven next
    // set equals the current one, and the successor uses exactly that root.
    let root =
        neutrin0_consensus_types::evidence::commitment(&state.next_context.active_validators);
    assert_eq!(root, outcome.chunk.next_validator_set_root);
    let mut successor = outcome.chunk;
    successor.chunk_id = 1;
    successor.start_height = 2;
    successor.end_height = 2;
    successor.active_validator_set_root = root;
    engine.set_local_voter(voter.clone());
    let mut header = engine.store().get_header_by_height(1).unwrap().unwrap();
    let mut proof = engine
        .store()
        .get_block_proof(&header.hash())
        .unwrap()
        .unwrap();
    header.parent_hash = header.hash();
    header.height = 2;
    header.slot = 2;
    header.signature =
        voter.sign_proposer_message(engine.chain_spec().consensus_domain(), &header.hash());
    let hash = engine.store_mut().put_header(&header).unwrap();
    successor.start_block_hash = hash;
    successor.end_block_hash = hash;
    proof.height = 2;
    proof.block_hash = hash;
    proof.public_inputs.height = 2;
    proof.public_inputs.parent_block_hash = header.parent_hash;
    proof.public_inputs.block_hash = hash;
    let genesis = engine.chain_spec().genesis_block_hash;
    engine
        .store_mut()
        .commit_tip(hash, genesis, neutrin0_storage::Batch::new())
        .unwrap();
    engine.store_mut().put_block_proof(&hash, &proof).unwrap();
    engine.open_bft_session(successor).unwrap();
    let certificate = engine
        .bft_session(1)
        .unwrap()
        .chunk_bft()
        .try_finalize(root)
        .unwrap()
        .expect("successor quorum uses proven validator root");
    assert_eq!(certificate.active_validator_set_root, root);
}

#[test]
fn a_proof_under_another_valid_certificate_is_retained_and_rebuilds_its_statement() {
    use neutrin0_consensus_types::evidence::commitment;
    use neutrin0_consensus_types::history_proof::ChunkReceiptStatement;
    use neutrin0_consensus_types::{FinalityVoteData, FinalityVotePhase, QuorumCertificate};
    let (mut engine, _) = engine();
    let backend = NativeConsensusBackend { reject: false };
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let outcome = engine.finalize_chunk(0, &backend, &voter).unwrap();
    let domain = engine.chain_spec().consensus_domain();
    // Another certificate of the same chunk: the leader signed a later slot,
    // so every vote signs another payment selection (design 08). Nodes may
    // finalize under either; boundaries and History do not depend on which.
    let mut certificate = outcome.finality_cert.clone();
    certificate.proposal.proposal_slot += 1;
    certificate.proposal.signature = voter
        .sign_raw(&certificate.proposal.signing_message(domain))
        .to_bytes();
    let selection = certificate.proposal.selection();
    for (phase, aggregate) in [
        (FinalityVotePhase::Prevote, &mut certificate.prevote),
        (FinalityVotePhase::Precommit, &mut certificate.precommit),
    ] {
        aggregate.signature = voter.sign_finality_vote(
            domain,
            &FinalityVoteData {
                chunk_id: 0,
                round: certificate.round,
                chunk_hash: certificate.chunk_hash,
                selection,
                phase,
            },
        );
    }
    let prevote = certificate.prevote_vote();
    let hashes = neutrin0_consensus_types::proof_manifest_for(
        &certificate.proof_manifests,
        &certificate.precommit_attestations[0]
            .proof_acceptance
            .unwrap(),
    )
    .unwrap()
    .proof_hashes
    .clone();
    let unlock = QuorumCertificate {
        data: prevote.data.clone(),
        aggregate: certificate.prevote.clone(),
    };
    certificate.prevote_attestations =
        vec![voter.attest_vote(domain, prevote.data, Vec::new(), None)];
    certificate.precommit_attestations = vec![voter.attest_vote(
        domain,
        certificate.precommit_vote().data,
        hashes,
        Some(unlock),
    )];
    assert_ne!(commitment(&certificate), commitment(&outcome.finality_cert));

    // The statement under the other certificate differs from the local one
    // only in its certificate commitment.
    let local = engine.store().chunk_statement(0).unwrap().unwrap();
    let statement = engine
        .chunk_statement_under(0, commitment(&certificate))
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            statement.chain,
            statement.start,
            statement.end,
            &statement.chunk
        ),
        (local.chain, local.start, local.end, &local.chunk)
    );
    assert_eq!(statement.finality_cert_hash, commitment(&certificate));
    let receipt = ChunkReceiptStatement {
        statement,
        chunk_prover_address: [0x5a; 32],
    };
    let mut wire = outcome.chunk_proof;
    wire.finality_cert = certificate;
    wire.prover_address = receipt.chunk_prover_address;
    wire.proof_bytes = borsh::to_vec(&receipt).unwrap();

    // A proof of another chunk commitment is refused; the proof under the
    // other certificate is retained for ratification.
    let mut foreign = wire.clone();
    foreign.public_inputs.da_root[0] ^= 1;
    assert!(
        engine
            .import_alternative_chunk_proof(&foreign, &backend)
            .is_err()
    );
    assert!(
        engine
            .import_alternative_chunk_proof(&wire, &backend)
            .unwrap()
    );
    assert!(
        engine
            .store()
            .chunk_receipts(0)
            .unwrap()
            .iter()
            .any(|held| held.statement_key == receipt.statement_key())
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "Follows one certificate through restart and a validator rotation."
)]
fn persisted_certificate_restores_accountability_after_restart_and_rotation() {
    use neutrin0_consensus_types::{FinalityVoteData, FinalityVotePhase, SlashingEvidence};
    let (mut engine, input) = engine();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let outcome = engine
        .finalize_chunk(0, &NativeConsensusBackend { reject: false }, &voter)
        .unwrap();
    let mut rotated = engine.active_validator_set().to_vec();
    rotated[0].pubkey = *ProposerKey::from_ikm(&[43; 32], 0)
        .unwrap()
        .public_key_bytes();
    let mut restarted = Engine::open(input.chain_spec, engine.store().db().clone()).unwrap();
    // Native harness rotates after restoring a consistent proof-gated snapshot.
    restarted.set_active_validator_set(2, rotated).unwrap();
    let mut conflicting_chunk = outcome.chunk;
    conflicting_chunk.end_state_root[0] ^= 1;
    let mut certificate = outcome.finality_cert;
    certificate.round = 1;
    certificate.chunk_hash = conflicting_chunk.hash();
    certificate.proposal.chunk = conflicting_chunk.clone();
    certificate.proposal.round = 1;
    let mut report = neutrin0_consensus_types::RoundChange {
        chunk_id: 0,
        round: 1,
        validator_index: 0,
        highest_quorum: None,
        signature: [0; 96],
    };
    report.signature = voter
        .sign_raw(&report.signing_message(restarted.chain_spec().consensus_domain()))
        .to_bytes();
    certificate.proposal.round_change_certificate =
        Some(neutrin0_consensus_types::RoundChangeCertificate {
            chunk_id: 0,
            round: 1,
            reports: vec![report],
        });
    certificate.proposal.signature = voter
        .sign_raw(
            &certificate
                .proposal
                .signing_message(restarted.chain_spec().consensus_domain()),
        )
        .to_bytes();
    let selection = certificate.proposal.selection();
    for (phase, aggregate) in [
        (FinalityVotePhase::Prevote, &mut certificate.prevote),
        (FinalityVotePhase::Precommit, &mut certificate.precommit),
    ] {
        aggregate.signature = voter.sign_finality_vote(
            restarted.chain_spec().consensus_domain(),
            &FinalityVoteData {
                chunk_id: 0,
                round: 1,
                chunk_hash: certificate.chunk_hash,
                selection,
                phase,
            },
        );
    }
    certificate.precommit_attestations = vec![
        voter.attest_vote(
            restarted.chain_spec().consensus_domain(),
            certificate.precommit_vote().data,
            neutrin0_consensus_types::proof_manifest_for(
                &certificate.proof_manifests,
                &certificate.precommit_attestations[0]
                    .proof_acceptance
                    .unwrap(),
            )
            .unwrap()
            .proof_hashes
            .clone(),
            None,
        ),
    ];
    certificate.prevote_attestations = vec![voter.attest_vote(
        restarted.chain_spec().consensus_domain(),
        certificate.prevote_vote().data,
        Vec::new(),
        None,
    )];
    let evidence = restarted
        .observe_certificate_for_slashing(&conflicting_chunk, &certificate)
        .unwrap();
    assert_eq!(evidence.len(), 2);
    let mut phases = std::collections::BTreeSet::new();
    for item in &evidence {
        let SlashingEvidence::LockViolation {
            validator_index: 0,
            vote_b,
            ..
        } = item
        else {
            panic!("the historical validator's two phases remain attributable");
        };
        phases.insert(vote_b.data.phase);
        restarted.verify_slashing_evidence(item).unwrap();
    }
    assert_eq!(
        phases,
        std::collections::BTreeSet::from([
            FinalityVotePhase::Prevote,
            FinalityVotePhase::Precommit
        ])
    );
}

#[test]
fn historical_header_attribution_uses_its_authenticated_validator_set() {
    use neutrin0_consensus_engine::slashing::SlashingError;
    use neutrin0_consensus_types::SlashingEvidence;
    let (mut producer, input) = engine();
    let old_signer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    producer
        .finalize_chunk(0, &NativeConsensusBackend { reject: false }, &old_signer)
        .unwrap();
    assert_ne!(producer.finalized_seed(), input.chain_spec.genesis_seed);
    let mut restored = Engine::open(input.chain_spec, producer.store().db().clone()).unwrap();
    let new_signer = ProposerKey::from_ikm(&[43; 32], 0).unwrap();
    let mut current = restored.active_validator_set().to_vec();
    current[0].pubkey = *new_signer.public_key_bytes();
    restored.set_active_validator_set(2, current).unwrap();
    // The native harness changes the live identity; the historical context
    // remains authenticated by the complete chunk proof committed above.
    let historical = input.blocks[0].header.clone();
    assert!(
        restored
            .observe_header_for_slashing(&historical)
            .unwrap()
            .is_none()
    );
    let mut alternate = historical.clone();
    alternate.state_root[0] ^= 1;
    alternate.signature = old_signer
        .sign_proposer_message(restored.chain_spec().consensus_domain(), &alternate.hash());
    let offence = restored
        .observe_header_for_slashing(&alternate)
        .unwrap()
        .unwrap();
    restored.verify_slashing_evidence(&offence).unwrap();

    let mut live = historical.clone();
    live.height = 2;
    live.signature =
        new_signer.sign_proposer_message(restored.chain_spec().consensus_domain(), &live.hash());
    assert!(
        restored
            .observe_header_for_slashing(&live)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        restored.verify_slashing_evidence(&SlashingEvidence::DoubleProposal {
            proposer_index: 0,
            header_a: historical,
            header_b: live.clone(),
        }),
        Err(SlashingError::EvidenceFieldsInconsistent)
    );
    let mut conflicting = live;
    conflicting.state_root[0] ^= 2;
    conflicting.signature = new_signer.sign_proposer_message(
        restored.chain_spec().consensus_domain(),
        &conflicting.hash(),
    );
    let offence = restored
        .observe_header_for_slashing(&conflicting)
        .unwrap()
        .unwrap();
    let SlashingEvidence::DoubleProposal {
        header_a, header_b, ..
    } = &offence
    else {
        panic!("the new context must retain its own same-slot header pair");
    };
    assert_eq!(header_a.height, 2);
    assert_eq!(header_b.height, 2);
    restored.verify_slashing_evidence(&offence).unwrap();
}

#[test]
fn block_only_backend_cannot_finalize_a_chunk() {
    let (mut engine, _) = engine();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    assert!(matches!(
        engine.finalize_chunk(0, &neutrin0_proof_system::MockProofSystem::new(), &voter),
        Err(neutrin0_consensus_engine::FinalizeError::Backend(
            ProofError::Unsupported
        ))
    ));
    assert_eq!(engine.latest_finalized_chunk_id(), None);
    assert_eq!(engine.store().get_chunk_proof(0).unwrap(), None);
}

#[test]
fn local_proving_requires_a_persisted_execution_witness() {
    use neutrin0_storage::{Column, Database};
    let (mut engine, input) = engine();
    let hash = input.blocks[0].header.hash();
    engine
        .store_mut()
        .put_block_state(&hash, BlockState::BlockProduced)
        .unwrap();
    // The executed import retained a witness; a block whose witness is gone
    // cannot be proven locally.
    engine
        .store_mut()
        .db_mut()
        .delete(Column::Witnesses, &hash)
        .unwrap();
    assert!(
        matches!(engine.prove_block(&hash, &neutrin0_proof_system::MockProofSystem::new()),
        Err(neutrin0_consensus_engine::ProveError::MissingWitness(missing)) if missing == hash)
    );
}

#[test]
fn chunk_preparation_uses_the_materialized_branch_after_sibling_archival() {
    let (mut engine, witness) = engine();
    let mut sibling = witness.blocks[0].header.clone();
    sibling.slot += 1;
    engine.store_mut().put_header(&sibling).unwrap();
    let prepared = engine
        .prepare_consensus_chunk(0, &NativeConsensusBackend { reject: false })
        .unwrap();
    assert_eq!(prepared.witness.blocks, witness.blocks);
    assert_ne!(prepared.witness.blocks[0].header.hash(), sibling.hash());
}

#[test]
#[allow(clippy::too_many_lines)] // Follow the fixed signed target across branch change, restart and finality.
fn restored_bft_finalizes_its_signed_branch_after_the_canonical_head_changes() {
    let (mut engine, input, runtime_input) = engine_with_input();
    let backend = NativeConsensusBackend { reject: false };
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let mut original = engine.prepare_bft_consensus_chunk(0, &backend).unwrap();
    engine
        .certify_consensus_chunk(&mut original, &voter)
        .unwrap();
    let signed_hash = original.witness.finality_cert.chunk_hash;
    let original_header = &input.blocks[0].header;
    let signed_end = original_header.hash();
    let original_certificate = original.witness.finality_cert.clone();

    // A valid sibling has its own proposer signature and slot-bound BLS VRF.
    // Its STF transition is identical because neither block has transactions.
    let secret = neutrin0_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let vrf_proof = secret
        .sign(&neutrin0_vrf::vrf_message(
            input.chain_spec.consensus_domain(),
            &input.chain_spec.genesis_seed,
            2,
        ))
        .to_bytes();
    let (mut sibling, public_inputs, output, sibling_body) = sibling_execution(
        &engine,
        &runtime_input,
        original_header,
        &input.blocks[0].public_inputs,
        2,
        vrf_proof,
        &support::fixture_genesis_live([1; 8], [4; 32], 30_000_000),
    );
    sibling.signature =
        voter.sign_proposer_message(input.chain_spec.consensus_domain(), &sibling.hash());
    engine
        .import_block(
            &neutrin0_consensus_types::Block {
                header: sibling.clone(),
                body: sibling_body,
            },
            &NativeReplayExecutor,
        )
        .unwrap();
    let sibling_hash = sibling.hash();
    engine
        .store_mut()
        .put_block_state(&sibling_hash, BlockState::Proven)
        .unwrap();
    let statement = BlockReceiptStatement {
        output,
        prover_address: public_inputs.proposer_address,
    };
    engine
        .store_mut()
        .put_block_proof(
            &sibling_hash,
            &BlockProof {
                prover_address: statement.prover_address,
                statement_key: neutrin0_consensus_types::evidence::commitment(&statement),
                height: 1,
                block_hash: sibling_hash,
                public_inputs,
                proof_bytes: borsh::to_vec(&statement).unwrap(),
            },
        )
        .unwrap();
    // Publish a competing materialized head, just as ordinary fork-choice
    // replay does. Both branches have the same genuine native STF state.
    engine
        .store_mut()
        .commit_tip(
            sibling_hash,
            input.chain_spec.genesis_block_hash,
            neutrin0_storage::Batch::new(),
        )
        .unwrap();
    let database = engine.store().db().clone();
    drop(engine);

    let mut restored = Engine::open(input.chain_spec.clone(), database).unwrap();
    restored.set_programs(support::guests([1; 8], [4; 32]));
    restored.set_local_voter(voter.clone());
    assert_eq!(restored.head_hash(), sibling_hash);
    assert_eq!(restored.bft_session(0).unwrap().chunk_hash(), signed_hash);
    let mut canonical = restored.prepare_consensus_chunk(0, &backend).unwrap();
    assert_eq!(canonical.witness.blocks[0].header.hash(), sibling_hash);
    // A restart never permits a local vote or proof to retarget the session.
    assert!(
        restored
            .certify_consensus_chunk(&mut canonical, &voter)
            .is_err()
    );

    let mut prepared = restored.prepare_bft_consensus_chunk(0, &backend).unwrap();
    assert_eq!(prepared.witness.blocks[0].header.hash(), signed_end);
    let resumed = restored.resume_bft_actions().unwrap();
    assert!(resumed.iter().any(
        |action| matches!(action, BftAction::QuorumReached(identity) if identity.chunk_id == 0)
    ));
    restored
        .certify_consensus_chunk(&mut prepared, &voter)
        .unwrap();
    assert_eq!(prepared.witness.finality_cert, original_certificate);
    let statement = backend
        .prove_consensus_chunk(
            &prepared.proofs,
            &prepared.ratified,
            &prepared.witness,
            [0; 32],
        )
        .unwrap();
    let chunk = neutrin0_prover_chunk::consensus::as_chunk(&statement.statement.chunk);
    neutrin0_prover_chunk::finality::verify_finality(
        input.chain_spec.consensus_domain(),
        &input.chain_spec.consensus,
        &prepared.witness.context.active_validators,
        &prepared.witness.seed,
        &chunk,
        &prepared.witness.finality_cert,
    )
    .unwrap();
    // Rejected proofs and a missing replay executor leave head/finality intact.
    assert!(
        restored
            .commit_bft_consensus_chunk(
                &prepared.witness,
                &statement,
                &NativeConsensusBackend { reject: true },
                Some(&NativeReplayExecutor),
            )
            .is_err()
    );
    assert!(
        restored
            .commit_bft_consensus_chunk(&prepared.witness, &statement, &backend, None)
            .is_err()
    );
    assert_eq!(restored.head_hash(), sibling_hash);
    assert_eq!(restored.latest_finalized_chunk_id(), None);
    let outcome = restored
        .commit_bft_consensus_chunk(
            &prepared.witness,
            &statement,
            &backend,
            Some(&NativeReplayExecutor),
        )
        .unwrap();
    assert_eq!(outcome.chunk_hash, signed_hash);
    assert_eq!(restored.head_hash(), signed_end);
    assert_eq!(restored.fork_choice_finalized(), signed_end);
    assert_eq!(restored.latest_finalized_chunk_id(), Some(0));
    assert!(restored.bft_session(0).is_none());
    let restarted = Engine::open(input.chain_spec, restored.store().db().clone()).unwrap();
    assert_eq!(restarted.head_hash(), signed_end);
    assert_eq!(restarted.latest_finalized_chunk_id(), Some(0));
    assert!(restarted.bft_session(0).is_none());
}

#[test]
#[allow(clippy::too_many_lines)] // Authenticate registration, transition identity, produce and restart.
fn a_registered_key_produces_after_authenticated_activation_with_a_stale_index_hint() {
    use neutrin0_runtime_system::{ValidatorRegistration, registration_key};

    let newcomer = ProposerKey::from_ikm(&[43; 32], 99).unwrap();
    let address = support::credentials(12);
    let registration = ValidatorRegistration {
        address,
        bls_pubkey: *newcomer.public_key_bytes(),
        pop_signature: newcomer.prove_registration(&address).to_bytes(),
        registered_at_height: 0,
    };
    // Consensus reads only the candidate record the runtime projects from
    // these records; seed both exactly as the runtime would have left them.
    let mut candidates = neutrin0_consensus_types::runtime::ConsensusCandidates::default();
    candidates.upsert(neutrin0_consensus_types::runtime::ConsensusCandidate {
        address,
        stake: 100,
        identity: Some(neutrin0_consensus_types::runtime::BlsIdentity {
            pubkey: registration.bls_pubkey,
            pop_signature: registration.pop_signature,
        }),
    });
    let mut live = support::fixture_genesis_live([1; 8], [4; 32], 30_000_000);
    live.insert(
        &registration_key(&address),
        borsh::to_vec(&registration).unwrap(),
    );
    live.insert(
        neutrin0_consensus_types::runtime::CONSENSUS_CANDIDATES_KEY,
        borsh::to_vec(&candidates).unwrap(),
    );
    let (mut witness, mut input, _) =
        support::fixture_with_live([1; 8], [4; 32], Vec::new(), 30_000_000, &live);
    // Registration seats an inactive key at epoch 1, then the next verified
    // chunk activates it at epoch 2 under a valid positive protocol delay.
    witness.chain_spec.consensus.epoch_length_in_chunks = 1;
    witness.chain_spec.consensus.activation_delay_epochs = 1;
    input.evidence_anchor.chain_spec_hash = witness.chain_spec.hash();
    let signing_key = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let domain = witness.chain_spec.consensus_domain();
    // The changed specification changes the VRF domain; execution, header and
    // public inputs must all commit the proposer's actual VRF output.
    witness.blocks[0].header.vrf_proof = signing_key.vrf_eval(
        domain,
        &witness.chain_spec.genesis_seed,
        witness.blocks[0].header.slot,
    );
    input.context.proposer_vrf_output =
        neutrin0_vrf::proof_output(&witness.blocks[0].header.vrf_proof);
    let mut state = TracingState::new(&live);
    let result = neutrin0_evm_runtime_core::execute_block(&input, &mut state);
    witness.blocks[0].output = result.output;
    let body = Body {
        artifacts: result.artifacts,
        ..Body::default()
    };
    let output = witness.blocks[0].output.clone();
    let header = &mut witness.blocks[0].header;
    header.state_root = output.post_state_root;
    header.transactions_root = output.transactions_root;
    header.receipts_root = output.receipts_root;
    header.da_root = neutrin0_prover_chunk::consensus::body_da_root(&body);
    header.gas_used = output.gas_used;
    header.runtime_extra = output.consensus_candidates_root;
    header.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
    header.signature = signing_key.sign_proposer_message(domain, &header.hash());
    let header_hash = header.hash();
    let da_root = header.da_root;
    let inputs = &mut witness.blocks[0].public_inputs;
    *inputs.context = input.context;
    inputs.block_hash = header_hash;
    inputs.state_root_after = output.post_state_root;
    inputs.transactions_root = output.transactions_root;
    inputs.receipt_root = output.receipts_root;
    inputs.da_root = da_root;
    inputs.gas_used = output.gas_used;
    inputs.runtime_extra = output.consensus_candidates_root;
    inputs.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
    let backend = NativeConsensusBackend { reject: false };
    let mut producer = Engine::genesis(witness.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    let mut follower = Engine::genesis(witness.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    for engine in [&mut producer, &mut follower] {
        engine.set_programs(support::guests([1; 8], [4; 32]));
        engine
            .replace_state_with_reconstructed(live.trie())
            .unwrap();
        engine.flush_trie_to_store().unwrap();
        let block = &witness.blocks[0];
        let hash = block.header.hash();
        engine
            .import_block(
                &neutrin0_consensus_types::Block {
                    header: block.header.clone(),
                    body: body.clone(),
                },
                &NativeReplayExecutor,
            )
            .unwrap();
        engine
            .store_mut()
            .put_block_state(&hash, BlockState::Proven)
            .unwrap();
        engine
            .store_mut()
            .put_block_proof(
                &hash,
                &BlockProof {
                    prover_address: block.public_inputs.proposer_address,
                    statement_key: neutrin0_consensus_types::evidence::commitment(
                        &block.statement(),
                    ),
                    height: 1,
                    block_hash: hash,
                    public_inputs: block.public_inputs.clone(),
                    proof_bytes: borsh::to_vec(&block.statement()).unwrap(),
                },
            )
            .unwrap();
    }
    follower.set_local_voter(newcomer.clone());
    assert!(
        follower
            .try_produce_block(
                2,
                neutrin0_consensus_engine::ProductionConfig {
                    proposer: &newcomer,
                },
                Body::default(),
                &NativeReplayExecutor,
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        neutrin0_storage::Database::iter_column(
            follower.store().db(),
            neutrin0_storage::Column::SigningJournal,
        )
        .unwrap()
        .len(),
        0
    );
    // Both the producer's stale index and the newcomer are resolved by key.
    let original = ProposerKey::from_ikm(&[42; 32], 77).unwrap();
    let finalized = producer.finalize_chunk(0, &backend, &original).unwrap();
    follower
        .import_chunk_proof(&finalized.chunk_proof, &backend)
        .unwrap();
    assert_eq!(follower.active_validator_set().len(), 2);
    assert_eq!(follower.active_validator_set()[1].activation_epoch, 2);
    assert_eq!(follower.active_validator_set()[1].effective_stake, 0);
    assert!(
        follower
            .try_produce_block(
                2,
                neutrin0_consensus_engine::ProductionConfig {
                    proposer: &newcomer,
                },
                Body::default(),
                &NativeReplayExecutor,
            )
            .unwrap()
            .is_none()
    );
    let next_block = producer
        .try_produce_block(
            2,
            neutrin0_consensus_engine::ProductionConfig {
                proposer: &original,
            },
            Body::default(),
            &NativeReplayExecutor,
        )
        .unwrap()
        .unwrap();
    let receipt = producer
        .prove_block(&next_block.block_hash, &backend)
        .unwrap();
    // The first block of a later chunk records the previous chunk's
    // participation, so a follower must execute it to hold the post-state
    // the chunk witness is built from.
    follower
        .import_block(&next_block.block, &NativeReplayExecutor)
        .unwrap();
    follower
        .import_block_proof(&receipt.block_proof, &backend)
        .unwrap();
    let finalized = producer.finalize_chunk(1, &backend, &original).unwrap();
    follower
        .import_chunk_proof(&finalized.chunk_proof, &backend)
        .unwrap();
    assert_eq!(follower.local_voter().unwrap().validator_index(), 1);
    assert_eq!(follower.active_validator_set()[1].effective_stake, 100);
    // Eligibility is a stake-weighted VRF draw; probe slots until the seated
    // newcomer wins one rather than depending on a single slot's randomness.
    let outcome = (3..64)
        .find_map(|slot| {
            follower
                .try_produce_block(
                    slot,
                    neutrin0_consensus_engine::ProductionConfig {
                        proposer: &newcomer,
                    },
                    Body::default(),
                    &NativeReplayExecutor,
                )
                .unwrap()
        })
        .expect("an active seat wins a slot within the probe window");
    assert_eq!(outcome.block.header.proposer_index, 1);
    assert_eq!(
        follower
            .observe_header_for_slashing(&outcome.block.header)
            .unwrap(),
        None
    );
    let bytes = follower
        .store()
        .get_witness(&outcome.block_hash)
        .unwrap()
        .unwrap();
    let (executed, _): (RuntimeBlockInput, neutrin0_runtime_abi::StateWitness) =
        borsh::from_slice(&bytes).unwrap();
    assert_eq!(executed.proposer_address, address);
    let mut restarted = Engine::open(witness.chain_spec, follower.store().db().clone()).unwrap();
    restarted.set_local_voter(newcomer.with_validator_index(0));
    assert_eq!(restarted.local_voter().unwrap().validator_index(), 1);
    assert_eq!(restarted.head_hash(), outcome.block_hash);
    assert_eq!(restarted.latest_finalized_chunk_id(), Some(1));
}

#[test]
fn the_proposer_keeps_and_publishes_its_receipt_after_a_faster_one() {
    use neutrin0_storage::Database;
    let (mut engine, witness) = engine();
    let hash = witness.blocks[0].header.hash();
    // The block has no receipt yet.
    let db = engine.store_mut().db_mut();
    db.delete(neutrin0_storage::Column::BlockProofs, &hash)
        .unwrap();
    for (key, _) in db
        .iter_column(neutrin0_storage::Column::BlockReceipts)
        .unwrap()
    {
        if key.starts_with(&hash) {
            db.delete(neutrin0_storage::Column::BlockReceipts, &key)
                .unwrap();
        }
    }
    engine
        .store_mut()
        .put_block_state(&hash, BlockState::BlockProduced)
        .unwrap();
    let (_, input, execution_witness) = support::fixture([1; 8], [4; 32]);
    engine
        .store_mut()
        .put_witness(&hash, &borsh::to_vec(&(input, execution_witness)).unwrap())
        .unwrap();
    let backend = NativeConsensusBackend { reject: false };
    // A third party proves the block first.
    engine.set_prover_address(neutrin0_primitives::runtime_account([0x77; 20]));
    let foreign = engine
        .prepare_block_proof(&hash)
        .unwrap()
        .prove(&backend)
        .unwrap();
    let foreign = engine.commit_block_proof(foreign).unwrap();
    assert_eq!(foreign.state, BlockState::Proven);
    let proposer = foreign.block_proof.public_inputs.proposer_address;
    assert_ne!(foreign.block_proof.prover_address, proposer);
    // The proposer's own proof is not cancelled: it is kept, becomes the
    // preferred receipt and is what this node publishes (rule P).
    engine.set_prover_address(proposer);
    let own = engine
        .prepare_block_proof(&hash)
        .unwrap()
        .prove(&backend)
        .unwrap();
    let own = engine.commit_block_proof(own).unwrap();
    assert_eq!(own.block_proof.prover_address, proposer);
    assert_eq!(
        engine.store().get_block_proof(&hash).unwrap().unwrap(),
        own.block_proof
    );
    assert!(!engine.lacks_proposer_receipt(&hash).unwrap());
    // Once it is held, nothing proves the block again.
    assert!(matches!(
        engine.prepare_block_proof(&hash),
        Err(neutrin0_consensus_engine::ProveError::AlreadyAdvanced { .. })
    ));
}

#[test]
fn proof_completion_preserves_concurrent_finalization_and_rejects_changed_snapshot() {
    let (mut engine, witness) = engine();
    let hash = witness.blocks[0].header.hash();
    // This fixture models a block whose first proof has not yet arrived.
    neutrin0_storage::Database::delete(
        engine.store_mut().db_mut(),
        neutrin0_storage::Column::BlockProofs,
        &hash,
    )
    .unwrap();
    engine
        .store_mut()
        .put_block_state(&hash, BlockState::BlockProduced)
        .unwrap();
    let (_, input, execution_witness) = support::fixture([1; 8], [4; 32]);
    let witness_bytes = borsh::to_vec(&(input, execution_witness)).unwrap();
    engine
        .store_mut()
        .put_witness(&hash, &witness_bytes)
        .unwrap();
    let first = engine.prepare_block_proof(&hash).unwrap();
    let second = engine.prepare_block_proof(&hash).unwrap();
    let backend = NativeConsensusBackend { reject: false };
    let first = first.prove(&backend).unwrap();
    let second = second.prove(&backend).unwrap();
    let original = engine.commit_block_proof(first).unwrap().block_proof;
    assert_eq!(
        engine.fork_choice().block(&hash).unwrap().proof_status,
        neutrin0_consensus_fork_choice::ProofStatus::Proven
    );
    engine
        .fork_choice_mut_for_test()
        .on_block_proof(hash, neutrin0_consensus_fork_choice::ProofStatus::Finalized)
        .unwrap();
    engine
        .store_mut()
        .put_block_state(&hash, BlockState::Finalized)
        .unwrap();
    let duplicate = engine.commit_block_proof(second).unwrap();
    assert_eq!(duplicate.state, BlockState::Finalized);
    assert_eq!(duplicate.block_proof, original);
    assert_eq!(
        engine.fork_choice().block(&hash).unwrap().proof_status,
        neutrin0_consensus_fork_choice::ProofStatus::Finalized
    );
    engine
        .store_mut()
        .put_block_state(&hash, BlockState::BlockProduced)
        .unwrap();
    let stale = engine
        .prepare_block_proof(&hash)
        .unwrap()
        .prove(&backend)
        .unwrap();
    engine.store_mut().put_witness(&hash, &[4, 5, 6]).unwrap();
    assert!(engine.commit_block_proof(stale).is_err());
    assert_eq!(
        engine.store().get_block_state(&hash).unwrap(),
        Some(BlockState::PendingProof)
    );
}

/// Isolated public-statement backend for admission fencing, never recursive finality.
struct StatementBackend {
    statement: RuntimeBlockOutput,
}

impl ProofSystem for StatementBackend {
    type BlockProof = BlockReceiptStatement;
    type ChunkProof = Vec<u8>;

    fn prove_block(
        &self,
        _: &[u8],
        inputs: &BlockProofPublicInputs,
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::BlockProof, ProofError> {
        let statement = BlockReceiptStatement {
            output: self.statement.clone(),
            prover_address,
        };
        self.verify_block(&statement, inputs)?;
        Ok(statement)
    }

    fn verify_block(
        &self,
        statement: &Self::BlockProof,
        inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        if neutrin0_prover_chunk::execution::output_binds(&statement.output, inputs) {
            Ok(())
        } else {
            Err(ProofError::PublicInputMismatch)
        }
    }

    fn block_statement(
        &self,
        statement: &Self::BlockProof,
    ) -> Result<BlockReceiptStatement, ProofError> {
        Ok(statement.clone())
    }
}

/// Receipts carrying a byte their statement ignores, as SP1 receipt bytes
/// can through noncanonical field elements and the TEE attestation. Counts
/// every verification it is asked for.
#[derive(Default)]
struct MalleableBackend {
    verified: std::sync::atomic::AtomicUsize,
}

impl ProofSystem for MalleableBackend {
    type BlockProof = (BlockReceiptStatement, u8);
    type ChunkProof = Vec<u8>;

    fn prove_block(
        &self,
        _: &[u8],
        _: &BlockProofPublicInputs,
        _: neutrin0_primitives::Hash,
    ) -> Result<Self::BlockProof, ProofError> {
        Err(ProofError::BackendRejected)
    }

    fn verify_block(
        &self,
        _: &Self::BlockProof,
        _: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        self.verified
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn block_statement(
        &self,
        proof: &Self::BlockProof,
    ) -> Result<BlockReceiptStatement, ProofError> {
        Ok(proof.0.clone())
    }
}

#[test]
fn a_held_statement_in_other_bytes_is_never_verified_again() {
    let (mut engine, witness) = engine();
    let block = &witness.blocks[0];
    let hash = block.header.hash();
    let held = engine.store().get_block_proof(&hash).unwrap().unwrap();
    let statement = BlockReceiptStatement {
        output: block.output.clone(),
        prover_address: held.prover_address,
    };
    assert_eq!(
        held.statement_key,
        neutrin0_consensus_engine::statement_key(&statement)
    );
    let backend = MalleableBackend::default();
    // Each variant is new bytes for the held statement; verifying one would
    // cost a full STARK verification under the engine lock.
    for variant in 0..3_u8 {
        let receipt = neutrin0_consensus_types::state_diff::BlockReceipt {
            block_hash: hash,
            proof_bytes: borsh::to_vec(&(statement.clone(), variant)).unwrap(),
        };
        assert!(matches!(
            engine.import_block_receipt(&receipt, &backend, None),
            Ok(neutrin0_consensus_engine::ReceiptOutcome::StatementHeld { .. })
        ));
    }
    assert_eq!(
        backend.verified.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "One receipt-fencing regression checks each header-bound input, unchanged availability, missing body and honest recovery."
)]
fn imported_receipt_for_different_participation_inputs_keeps_block_pending() {
    use neutrin0_consensus_engine::ImportError;
    use neutrin0_storage::{Column, Database};
    let (mut engine, witness) = engine();
    let block = &witness.blocks[0];
    let hash = block.header.hash();
    let correct = engine.store().get_block_proof(&hash).unwrap().unwrap();
    engine
        .store_mut()
        .db_mut()
        .delete(Column::BlockProofs, &hash)
        .unwrap();
    engine
        .store_mut()
        .put_block_state(&hash, BlockState::PendingProof)
        .unwrap();
    let head = engine.head_hash();
    let status = engine.fork_choice().block(&hash).unwrap().proof_status;
    let verifier = StatementBackend {
        statement: block.output.clone(),
    };
    for field in 0..3 {
        let mut statement = block.output.clone();
        match field {
            0 => statement.participation[0] ^= 1,
            1 => statement.participation_acks[0] ^= 1,
            _ => {
                statement
                    .accountability
                    .anchor
                    .max_block_proving_input_bytes ^= 1;
            }
        }
        // The header's inputs root binds these fields (design 08),
        // so a receipt that executed other inputs does not verify against the
        // header's public inputs at all.
        let statement = BlockReceiptStatement {
            output: statement,
            prover_address: correct.public_inputs.proposer_address,
        };
        assert_eq!(
            verifier.verify_block(&statement, &correct.public_inputs),
            Err(ProofError::PublicInputMismatch)
        );
        let alternate = BlockProof {
            proof_bytes: borsh::to_vec(&statement).unwrap(),
            ..correct.clone()
        };
        assert!(matches!(
            engine.import_block_proof(&alternate, &verifier),
            Err(ImportError::InvalidBlockProof(
                ProofError::PublicInputMismatch
            ))
        ));
        assert_eq!(
            engine.store().get_block_state(&hash).unwrap(),
            Some(BlockState::PendingProof)
        );
        assert_eq!(engine.store().get_block_proof(&hash).unwrap(), None);
        assert_eq!(
            engine.fork_choice().block(&hash).unwrap().proof_status,
            status
        );
        assert_eq!(engine.head_hash(), head);
        // The rejected bytes are kept for signed proof-attestation evidence;
        // they are never a verdict against the header.
        assert_eq!(engine.rejected_proof_cache_len(), 1);
    }
    let body = engine.store().get_body(&hash).unwrap().unwrap();
    engine
        .store_mut()
        .db_mut()
        .delete(Column::Blocks, &hash)
        .unwrap();
    assert!(
        engine
            .import_block_proof(&correct, &verifier)
            .unwrap_err()
            .awaits_local_finality()
    );
    assert_eq!(
        engine.store().get_block_state(&hash).unwrap(),
        Some(BlockState::PendingProof)
    );
    assert_eq!(engine.rejected_proof_cache_len(), 1);
    engine.store_mut().put_body(&hash, &body).unwrap();
    engine.import_block_proof(&correct, &verifier).unwrap();
    assert_eq!(
        engine.store().get_block_state(&hash).unwrap(),
        Some(BlockState::Proven)
    );
    assert_eq!(engine.head_hash(), head);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "Local completion checks capture, extraction, pruning, body tampering and later valid completion in one lifecycle."
)]
fn local_proof_job_checks_body_context_before_completion_and_rechecks_retention() {
    use neutrin0_consensus_engine::prove::ProveError;
    use neutrin0_storage::{Column, Database};
    let (mut engine, witness) = engine();
    let block = &witness.blocks[0];
    let hash = block.header.hash();
    engine
        .store_mut()
        .db_mut()
        .delete(Column::BlockProofs, &hash)
        .unwrap();
    engine
        .store_mut()
        .put_block_state(&hash, BlockState::BlockProduced)
        .unwrap();
    let (_, input, execution_witness) = support::fixture([1; 8], [4; 32]);
    engine
        .store_mut()
        .put_witness(&hash, &borsh::to_vec(&(input, execution_witness)).unwrap())
        .unwrap();
    for field in 0..3 {
        let mut statement = block.output.clone();
        match field {
            0 => statement.participation[0] ^= 1,
            1 => statement.participation_acks[0] ^= 1,
            _ => {
                statement
                    .accountability
                    .anchor
                    .max_block_proving_input_bytes ^= 1;
            }
        }
        let backend = StatementBackend { statement };
        assert!(matches!(
            engine.prepare_block_proof(&hash).unwrap().prove(&backend),
            Err(ProofError::PublicInputMismatch)
        ));
        assert_eq!(
            engine.store().get_block_state(&hash).unwrap(),
            Some(BlockState::PendingProof)
        );
        assert_eq!(engine.store().get_block_proof(&hash).unwrap(), None);
    }
    let backend = NativeConsensusBackend { reject: false };
    let completed = engine
        .prepare_block_proof(&hash)
        .unwrap()
        .prove(&backend)
        .unwrap();
    let body = engine.store().get_body(&hash).unwrap().unwrap();
    engine
        .store_mut()
        .db_mut()
        .delete(Column::Blocks, &hash)
        .unwrap();
    assert!(
        matches!(engine.commit_block_proof(completed), Err(ProveError::MissingBody(missing)) if missing == hash)
    );
    assert_eq!(
        engine.store().get_block_state(&hash).unwrap(),
        Some(BlockState::PendingProof)
    );
    assert!(
        matches!(engine.prepare_block_proof(&hash), Err(ProveError::MissingBody(missing)) if missing == hash)
    );
    engine.store_mut().put_body(&hash, &body).unwrap();
    let completed = engine
        .prepare_block_proof(&hash)
        .unwrap()
        .prove(&backend)
        .unwrap();
    let mut tampered = body.clone();
    tampered
        .transactions
        .push(borsh::to_vec(&neutrin0_runtime_abi::RuntimeTransaction::User(vec![1])).unwrap());
    engine.store_mut().put_body(&hash, &tampered).unwrap();
    assert!(matches!(
        engine.commit_block_proof(completed),
        Err(ProveError::Backend(ProofError::InvalidWitness))
    ));
    assert_eq!(
        engine.store().get_block_state(&hash).unwrap(),
        Some(BlockState::PendingProof)
    );
    engine.store_mut().put_body(&hash, &body).unwrap();
    engine.prove_block(&hash, &backend).unwrap();
    assert_eq!(
        engine.store().get_block_state(&hash).unwrap(),
        Some(BlockState::Proven)
    );
}

#[test]
fn finalization_makes_the_chunk_receipt_the_history_proof() {
    use neutrin0_consensus_types::history_proof::{ChainBinding, ProofDomain};
    let (mut engine, input) = engine();
    let domain = ProofDomain {
        chain: ChainBinding::new(&input.chain_spec),
        chunk: input.chain_spec.genesis_chunk,
        programs: support::programs([1; 8], [4; 32]),
    };
    engine.set_history_domain(domain).unwrap();
    assert!(engine.latest_history_proof().unwrap().is_none());
    let backend = NativeConsensusBackend { reject: false };
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine.finalize_chunk(0, &backend, &voter).unwrap();
    assert_eq!(engine.finalized_next_chunk_id(), 1);
    let end = engine.canonical_boundary(1).unwrap();
    let history = engine.latest_history_proof().unwrap().unwrap();
    assert_eq!(*history.end(), end);
    assert_eq!(
        history.statement.statement.start,
        engine.canonical_boundary(0).unwrap()
    );
    let stored = engine.store().get_chunk_proof(0).unwrap().unwrap();
    assert_eq!(history.receipt.as_slice(), stored.proof_bytes);
    assert_eq!(
        history.statement.chunk_prover_address,
        stored.prover_address
    );
    // Genesis and the endpoint itself need no opening; nothing lies beyond finality.
    assert_eq!(engine.anchor_opening(0, 1).unwrap(), None);
    assert_eq!(engine.anchor_opening(1, 1).unwrap(), None);
    assert!(engine.anchor_opening(1, 2).is_err());
    assert!(engine.history_proof(2).is_err());
    let restarted = Engine::open(input.chain_spec, engine.store().db().clone()).unwrap();
    assert_eq!(restarted.canonical_boundary(1).unwrap(), end);
    assert_eq!(restarted.latest_history_proof().unwrap(), Some(history));
    assert_eq!(
        restarted
            .store()
            .historical_opening(0, 1)
            .unwrap()
            .record
            .chunk
            .chunk_id,
        0
    );
}

#[derive(Clone, Debug, Default)]
struct RetargetDatabase {
    inner: MemoryDatabase,
    fail_durable_after: Option<usize>,
}

impl neutrin0_storage::Database for RetargetDatabase {
    type Error = std::io::Error;
    fn read_handle(&self) -> std::sync::Arc<dyn neutrin0_storage::ReadHandle> {
        self.inner.read_handle()
    }

    fn get(
        &self,
        column: neutrin0_storage::Column,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.inner.get(column, key).unwrap())
    }
    fn put(
        &mut self,
        column: neutrin0_storage::Column,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        self.inner.put(column, key, bytes).unwrap();
        Ok(())
    }
    fn delete(&mut self, column: neutrin0_storage::Column, key: &[u8]) -> Result<(), Self::Error> {
        self.inner.delete(column, key).unwrap();
        Ok(())
    }
    fn write_batch(&mut self, batch: neutrin0_storage::Batch) -> Result<(), Self::Error> {
        self.inner.write_batch(batch).unwrap();
        Ok(())
    }
    fn write_batch_durable(&mut self, batch: neutrin0_storage::Batch) -> Result<(), Self::Error> {
        if let Some(remaining) = &mut self.fail_durable_after {
            if *remaining == 0 {
                return Err(std::io::Error::other("interrupted BFT durable write"));
            }
            *remaining -= 1;
        }
        self.write_batch(batch)
    }
    fn iter_column(
        &self,
        column: neutrin0_storage::Column,
    ) -> Result<neutrin0_storage::ColumnSnapshot, Self::Error> {
        Ok(self.inner.iter_column(column).unwrap())
    }
}

/// Four equal seats: any three hold strictly more than two thirds, any two
/// do not.
fn retarget_keys() -> Vec<ProposerKey> {
    (0..4)
        .map(|index| {
            ProposerKey::from_ikm(&[42 + u8::try_from(index).unwrap(); 32], index).unwrap()
        })
        .collect()
}

/// Fixed slot of retarget proposals, past every fixture block's exclusive
/// window and never ahead of the local clock.
const RETARGET_PROPOSAL_SLOT: u64 = 1_000;

/// The payment selection every retarget proposal for `chunk` signs: the
/// receipts selected at the fixed slot (design 08).
fn retarget_selection(
    engine: &Engine<RetargetDatabase>,
    chunk: &neutrin0_consensus_types::Chunk,
) -> neutrin0_consensus_types::PaymentSelection {
    neutrin0_consensus_types::PaymentSelection {
        proposal_slot: RETARGET_PROPOSAL_SLOT,
        receipts: engine
            .selected_receipts(chunk, RETARGET_PROPOSAL_SLOT)
            .unwrap()
            .unwrap_or_default(),
        ratified_chunk_proofs: Vec::new(),
    }
}

fn retarget_vote(
    chunk: &neutrin0_consensus_types::Chunk,
    selection: neutrin0_primitives::Hash,
    round: u32,
    phase: neutrin0_consensus_types::FinalityVotePhase,
    index: usize,
    proof_hashes: Vec<neutrin0_primitives::Hash>,
) -> neutrin0_consensus_types::FinalityVote {
    let key = &retarget_keys()[index];
    let data = neutrin0_consensus_types::FinalityVoteData {
        chunk_id: chunk.chunk_id,
        chunk_hash: chunk.hash(),
        selection,
        round,
        phase,
    };
    let mut bits = neutrin0_primitives::BitVec::default();
    for position in 0..4 {
        bits.push(position == index);
    }
    let proof_manifests = if phase == neutrin0_consensus_types::FinalityVotePhase::Precommit {
        vec![neutrin0_consensus_types::ProofManifest {
            proof_hashes: proof_hashes.clone(),
        }]
    } else {
        Vec::new()
    };
    neutrin0_consensus_types::FinalityVote {
        proof_manifests,
        signature: key.sign_finality_vote(retarget_spec().consensus_domain(), &data),
        attestations: vec![key.attest_vote(
            retarget_spec().consensus_domain(),
            data.clone(),
            proof_hashes,
            None,
        )],
        data,
        aggregation_bits: bits,
    }
}

fn retarget_quorum(
    chunk: &neutrin0_consensus_types::Chunk,
    selection: neutrin0_primitives::Hash,
    round: u32,
) -> neutrin0_consensus_types::QuorumCertificate {
    let data = neutrin0_consensus_types::FinalityVoteData {
        chunk_id: chunk.chunk_id,
        chunk_hash: chunk.hash(),
        selection,
        round,
        phase: neutrin0_consensus_types::FinalityVotePhase::Prevote,
    };
    let signatures: Vec<_> = retarget_keys()[1..]
        .iter()
        .map(|key| {
            neutrin0_crypto::bls::Signature::from_bytes(
                &key.sign_finality_vote(retarget_spec().consensus_domain(), &data),
            )
            .unwrap()
        })
        .collect();
    neutrin0_consensus_types::QuorumCertificate {
        data,
        aggregate: neutrin0_consensus_types::AggregatedVote {
            aggregation_bits: neutrin0_primitives::BitVec::from_bytes(4, vec![0b1110]).unwrap(),
            signature: neutrin0_crypto::bls::aggregate_signatures(
                &signatures.iter().collect::<Vec<_>>(),
            )
            .unwrap()
            .to_bytes(),
        },
    }
}

fn retarget_spec() -> neutrin0_primitives::ChainSpec {
    let (fixture, _, _) = support::fixture([1; 8], [4; 32]);
    let mut spec = fixture.chain_spec;
    // Four seats at distinct accountable accounts; the first keeps the
    // fixture's account so the fixture input's proposer address stays valid.
    spec.initial_validators = retarget_keys()
        .iter()
        .enumerate()
        .map(|(index, key)| neutrin0_primitives::Validator {
            pubkey: *key.public_key_bytes(),
            withdrawal_credentials: support::credentials(8 + u8::try_from(index).unwrap()),
            ..spec.initial_validators[0].clone()
        })
        .collect();
    spec.genesis_validator_set_root =
        neutrin0_consensus_types::evidence::commitment(&spec.initial_validators);
    spec.consensus.expected_proposers_per_slot = neutrin0_primitives::fixed_u128_from_integer(4);
    // Seat 0 is the local voter; this seed draws other seats as the round 0 and
    // round 2 leaders, so the tests observe proposals instead of making them.
    spec.genesis_seed = [1; 32];
    // The committee changed, so the runtime genesis is re-derived for it.
    spec.genesis_state_root =
        support::genesis_live_for_spec(&spec, support::programs([1; 8], [4; 32]))
            .trie()
            .root();
    spec
}

#[allow(
    clippy::too_many_lines,
    reason = "Construct actual STF outputs and BLS-authenticated competing branches under one validator context."
)]
fn retarget_fixture() -> (
    Engine<RetargetDatabase>,
    neutrin0_consensus_types::Chunk,
    neutrin0_consensus_types::Chunk,
) {
    retarget_fixture_proven_by(None)
}

/// [`retarget_fixture`] with every block proven by `prover`, the proposer
/// when `None`.
fn retarget_fixture_proven_by(
    prover: Option<neutrin0_primitives::Hash>,
) -> (
    Engine<RetargetDatabase>,
    neutrin0_consensus_types::Chunk,
    neutrin0_consensus_types::Chunk,
) {
    let (fixture, mut input, _) = support::fixture([1; 8], [4; 32]);
    let spec = retarget_spec();
    input.evidence_anchor.chain_spec_hash = spec.hash();
    let live = support::genesis_live_for_spec(&spec, support::programs([1; 8], [4; 32]));
    let mut engine = Engine::genesis(spec.clone(), RetargetDatabase::default()).unwrap();
    engine.set_programs(support::guests([1; 8], [4; 32]));
    engine.install_genesis_state(live.trie().clone()).unwrap();
    let key = &retarget_keys()[0];
    let mut branch_hashes = Vec::new();
    for slot in 1..=2 {
        let vrf_proof = key
            .sign_raw(&neutrin0_vrf::vrf_message(
                spec.consensus_domain(),
                &spec.genesis_seed,
                slot,
            ))
            .to_bytes();
        let (mut header, public_inputs, output, branch_body) = sibling_execution(
            &engine,
            &input,
            &fixture.blocks[0].header,
            &fixture.blocks[0].public_inputs,
            slot,
            vrf_proof,
            &live,
        );
        header.signature = key.sign_proposer_message(spec.consensus_domain(), &header.hash());
        let hash = header.hash();
        branch_hashes.push(hash);
        engine
            .import_block(
                &neutrin0_consensus_types::Block {
                    header,
                    body: branch_body,
                },
                &NativeReplayExecutor,
            )
            .unwrap();
        let statement = BlockReceiptStatement {
            output,
            prover_address: prover.unwrap_or(public_inputs.proposer_address),
        };
        engine
            .store_mut()
            .put_block_proof(
                &hash,
                &BlockProof {
                    prover_address: statement.prover_address,
                    statement_key: neutrin0_consensus_types::evidence::commitment(&statement),
                    height: 1,
                    block_hash: hash,
                    public_inputs,
                    proof_bytes: borsh::to_vec(&statement).unwrap(),
                },
            )
            .unwrap();
        engine
            .store_mut()
            .put_block_state(&hash, BlockState::Proven)
            .unwrap();
    }
    let backend = NativeConsensusBackend { reject: false };
    let first_hash = branch_hashes[0];
    let second_hash = branch_hashes[1];
    let first = engine
        .prepare_consensus_chunk_on_branch(0, first_hash, None, &backend)
        .unwrap();
    let second = engine
        .prepare_consensus_chunk_on_branch(0, second_hash, None, &backend)
        .unwrap();
    let first = neutrin0_prover_chunk::consensus::as_chunk(
        &neutrin0_prover_chunk::consensus::validate_candidate(&first.witness)
            .unwrap()
            .execution
            .chunk,
    );
    let second = neutrin0_prover_chunk::consensus::as_chunk(
        &neutrin0_prover_chunk::consensus::validate_candidate(&second.witness)
            .unwrap()
            .execution
            .chunk,
    );
    engine
        .store_mut()
        .commit_tip(
            second_hash,
            spec.genesis_block_hash,
            neutrin0_storage::Batch::new(),
        )
        .unwrap();
    (engine, first, second)
}

fn retarget_proposal(
    engine: &Engine<RetargetDatabase>,
    chunk: &neutrin0_consensus_types::Chunk,
    round: u32,
    valid_quorum: Option<neutrin0_consensus_types::QuorumCertificate>,
) -> neutrin0_consensus_types::BftProposal {
    let leader = neutrin0_consensus_types::bft_leader(
        7,
        chunk.chunk_id,
        round,
        &engine.finalized_seed(),
        engine.active_validator_set(),
    )
    .unwrap();
    let selection = retarget_selection(engine, chunk);
    let mut proposal = neutrin0_consensus_types::BftProposal {
        chunk: chunk.clone(),
        round,
        proposer_index: leader,
        round_change_certificate: (round > 0)
            .then(|| retarget_round_certificate(round, valid_quorum.as_ref())),
        valid_quorum,
        proposal_slot: selection.proposal_slot,
        receipts: selection.receipts,
        ratified_chunk_proofs: selection.ratified_chunk_proofs,
        signature: [0; 96],
    };
    proposal.signature = retarget_keys()[leader as usize]
        .sign_raw(&proposal.signing_message(retarget_spec().consensus_domain()))
        .to_bytes();
    proposal
}

fn open_retarget_session(
    engine: &mut Engine<RetargetDatabase>,
    chunk: &neutrin0_consensus_types::Chunk,
) {
    engine.set_local_voter(retarget_keys()[0].clone());
    engine.open_bft_session_at(chunk.clone(), 100).unwrap();
    let proposal = retarget_proposal(engine, chunk, 0, None);
    engine
        .observe_bft_proposal(proposal, 100, &NativeConsensusBackend { reject: false })
        .unwrap();
}

fn retarget_round_certificate(
    round: u32,
    highest_quorum: Option<&neutrin0_consensus_types::QuorumCertificate>,
) -> neutrin0_consensus_types::RoundChangeCertificate {
    let reports = retarget_keys()[1..]
        .iter()
        .map(|key| {
            let mut report = neutrin0_consensus_types::RoundChange {
                chunk_id: 0,
                round,
                validator_index: key.validator_index(),
                highest_quorum: highest_quorum.cloned(),
                signature: [0; 96],
            };
            report.signature = key
                .sign_raw(&report.signing_message(retarget_spec().consensus_domain()))
                .to_bytes();
            report
        })
        .collect();
    neutrin0_consensus_types::RoundChangeCertificate {
        chunk_id: 0,
        round,
        reports,
    }
}

fn lock_retarget_first(
    engine: &mut Engine<RetargetDatabase>,
    first: &neutrin0_consensus_types::Chunk,
) -> neutrin0_consensus_types::QuorumCertificate {
    use neutrin0_consensus_types::FinalityVotePhase;
    open_retarget_session(engine, first);
    let selection = retarget_selection(engine, first).commitment();
    for peer in [1, 2] {
        engine
            .observe_finality_vote_at(
                retarget_vote(
                    first,
                    selection,
                    0,
                    FinalityVotePhase::Prevote,
                    peer,
                    vec![],
                ),
                100,
            )
            .unwrap();
    }
    assert!(engine.bft_session(0).unwrap().local_precommitted());
    engine
        .bft_session(0)
        .unwrap()
        .highest_lock_quorum()
        .unwrap()
        .clone()
}

#[test]
fn bft_signing_validates_each_exact_value_once_per_boundary() {
    use neutrin0_consensus_types::FinalityVotePhase;
    let (mut engine, first, _) = retarget_fixture();
    let backend = NativeConsensusBackend { reject: false };
    engine.set_local_voter(retarget_keys()[0].clone());
    engine.open_bft_session_at(first.clone(), 100).unwrap();
    // Gathering needs the engine; validation does not.
    let early = engine
        .pending_bft_signing(0, &backend)
        .unwrap()
        .expect("the opened value has no verdict")
        .validate()
        .unwrap();
    engine.record_bft_signing(early.clone());
    assert!(engine.pending_bft_signing(0, &backend).unwrap().is_none());
    for _ in 0..3 {
        engine.validate_bft_signing(0, &backend).unwrap();
    }
    assert_eq!(engine.bft_signing_validations(), 1);

    // The leader's proposal names the receipts: new inputs, validated once.
    let proposal = retarget_proposal(&engine, &first, 0, None);
    engine
        .observe_bft_proposal(proposal, 100, &backend)
        .unwrap();
    assert!(engine.pending_bft_signing(0, &backend).unwrap().is_some());
    for _ in 0..3 {
        engine.validate_bft_signing(0, &backend).unwrap();
    }
    assert_eq!(engine.bft_signing_validations(), 2);

    // Finality installs the next boundary; no earlier verdict applies to it.
    let selection = retarget_selection(&engine, &first).commitment();
    let receipt = engine
        .store()
        .get_block_proof(&first.end_block_hash)
        .unwrap()
        .unwrap();
    for (phase, proofs) in [
        (FinalityVotePhase::Prevote, vec![]),
        (
            FinalityVotePhase::Precommit,
            vec![neutrin0_consensus_types::evidence::commitment(&receipt)],
        ),
    ] {
        for peer in [1, 2] {
            engine
                .observe_finality_vote_at(
                    retarget_vote(&first, selection, 0, phase, peer, proofs.clone()),
                    100,
                )
                .unwrap();
        }
    }
    finalize_native_retarget_session(&mut engine, &backend);
    engine.record_bft_signing(early);
    assert_eq!(engine.bft_signing_validations(), 2);
}

#[test]
fn current_target_quorum_hints_preserve_pending_precommits_until_finality() {
    use neutrin0_consensus_types::FinalityVotePhase;
    let (mut engine, first, _) = retarget_fixture();
    let backend = NativeConsensusBackend { reject: false };
    let old_lock = lock_retarget_first(&mut engine, &first);
    let advertised = engine.bft_candidate(0).unwrap();
    assert_eq!(advertised.round, 1);
    assert_eq!(advertised.justification, Some(old_lock));
    let accumulated = engine.bft_session(0).unwrap().chunk_bft().clone();
    for _ in 0..3 {
        let actions = engine
            .offer_bft_candidate(&advertised, 101, &backend)
            .unwrap();
        assert!(actions.is_empty());
        let session = engine.bft_session(0).unwrap();
        assert_eq!(session.round(), 0);
        assert_eq!(session.chunk_bft(), &accumulated);
        assert!(session.local_precommitted());
        assert!(!session.precommit_quorum_observed());
    }
    let receipt = engine
        .store()
        .get_block_proof(&first.end_block_hash)
        .unwrap()
        .unwrap();
    let selection = retarget_selection(&engine, &first).commitment();
    for peer in [1, 2] {
        engine
            .observe_finality_vote(retarget_vote(
                &first,
                selection,
                0,
                FinalityVotePhase::Precommit,
                peer,
                vec![neutrin0_consensus_types::evidence::commitment(&receipt)],
            ))
            .unwrap();
    }
    let finalized = finalize_native_retarget_session(&mut engine, &backend);
    assert_eq!(finalized.chunk_hash, first.hash());
    assert_eq!(finalized.finality_cert.round, 0);
    assert_eq!(engine.latest_finalized_chunk_id(), Some(0));
}

#[test]
fn a_third_party_receipt_waits_for_the_exclusive_window_on_the_voters_clock() {
    let (engine, first, _) = retarget_fixture_proven_by(Some([0x77; 32]));
    let header = engine
        .store()
        .get_header(&first.end_block_hash)
        .unwrap()
        .unwrap();
    let opens = header.slot + engine.chain_spec().consensus.proof_exclusive_slots;
    let mut proposal = retarget_proposal(&engine, &first, 0, None);
    assert_eq!(proposal.receipts[0].prover_address, [0x77; 32]);
    // The signed slot is where the window has closed. A voter whose own clock
    // has not reached it refuses: the drift allowance on the signed slot
    // cannot shorten the proposer's window.
    proposal.proposal_slot = opens;
    proposal.signature = retarget_keys()[proposal.proposer_index as usize]
        .sign_raw(&proposal.signing_message(retarget_spec().consensus_domain()))
        .to_bytes();
    assert!(
        engine
            .check_receipt_selection(&proposal, opens - 1)
            .is_err()
    );
    engine.check_receipt_selection(&proposal, opens).unwrap();
    // The signed slot alone is checked as well.
    proposal.proposal_slot = opens - 1;
    assert!(engine.check_receipt_selection(&proposal, opens).is_err());
}

#[test]
fn higher_quorum_availability_hints_cannot_advance_without_signed_round_certificate() {
    use neutrin0_consensus_types::BftCandidate;
    let (mut engine, first, second) = retarget_fixture();
    let backend = NativeConsensusBackend { reject: false };
    let lock = lock_retarget_first(&mut engine, &first);
    let candidate = BftCandidate {
        chunk: second,
        round: 1_000,
        justification: None,
        selection: None,
    };
    engine
        .offer_bft_candidate(&candidate, 10_000, &backend)
        .unwrap();
    assert_eq!(engine.bft_session(0).unwrap().round(), 0);
    assert_eq!(engine.bft_session(0).unwrap().chunk_hash(), first.hash());
    let mut candidate = candidate;
    candidate.justification = Some(retarget_quorum(
        &candidate.chunk,
        retarget_selection(&engine, &candidate.chunk).commitment(),
        1,
    ));
    // A justification certifies the chunk with one payment selection; a hint
    // without it, or with another, is refused (design 08).
    for selection in [
        None,
        Some(neutrin0_consensus_types::PaymentSelection::default()),
    ] {
        let unbound = BftCandidate {
            selection,
            ..candidate.clone()
        };
        assert!(
            engine
                .offer_bft_candidate(&unbound, 10_000, &backend)
                .is_err()
        );
    }
    candidate.selection = Some(retarget_selection(&engine, &candidate.chunk));
    engine
        .offer_bft_candidate(&candidate, 10_000, &backend)
        .unwrap();
    assert_eq!(engine.bft_session(0).unwrap().round(), 0);
    assert_eq!(
        engine.bft_session(0).unwrap().highest_lock_quorum(),
        Some(&lock)
    );
    let mut minority = retarget_round_certificate(2, candidate.justification.as_ref());
    minority.reports.pop();
    assert!(
        engine
            .observe_round_change_certificate(minority, 101)
            .is_err()
    );
    assert_eq!(engine.bft_session(0).unwrap().round(), 0);
}

fn finalize_native_retarget_session(
    engine: &mut Engine<RetargetDatabase>,
    backend: &NativeConsensusBackend,
) -> neutrin0_consensus_engine::FinalizeOutcome {
    let mut prepared = engine.prepare_bft_consensus_chunk(0, backend).unwrap();
    engine
        .certify_consensus_chunk(&mut prepared, &retarget_keys()[0])
        .unwrap();
    let proof = backend
        .prove_consensus_chunk(
            &prepared.proofs,
            &prepared.ratified,
            &prepared.witness,
            [0; 32],
        )
        .unwrap();
    engine
        .commit_bft_consensus_chunk(
            &prepared.witness,
            &proof,
            backend,
            Some(&NativeReplayExecutor),
        )
        .unwrap()
}

#[test]
fn a_locked_validator_switches_only_with_a_signed_leader_and_earlier_higher_quorum_then_recovers() {
    use neutrin0_consensus_types::{BftCandidate, FinalityVotePhase};
    let (mut engine, first, second) = retarget_fixture();
    let backend = NativeConsensusBackend { reject: false };
    let old_lock = lock_retarget_first(&mut engine, &first);
    let selection = retarget_selection(&engine, &second);
    let candidate = BftCandidate {
        chunk: second.clone(),
        round: 2,
        justification: Some(retarget_quorum(&second, selection.commitment(), 1)),
        selection: Some(selection.clone()),
    };
    engine
        .offer_bft_candidate(&candidate, 101, &backend)
        .unwrap();
    let proposal = retarget_proposal(&engine, &second, 2, candidate.justification.clone());
    let mut unauthenticated = proposal.clone();
    unauthenticated.round_change_certificate = None;
    unauthenticated.signature = retarget_keys()[unauthenticated.proposer_index as usize]
        .sign_raw(&unauthenticated.signing_message(retarget_spec().consensus_domain()))
        .to_bytes();
    assert!(
        engine
            .observe_bft_proposal(unauthenticated, 101, &backend)
            .is_err()
    );
    assert_eq!(engine.bft_session(0).unwrap().round(), 0);
    let mut actions = engine
        .observe_round_change_certificate(
            retarget_round_certificate(2, candidate.justification.as_ref()),
            101,
        )
        .unwrap();
    actions.extend(
        engine
            .observe_bft_proposal(proposal, 101, &backend)
            .unwrap(),
    );
    assert!(actions.iter().any(|action| matches!(action, BftAction::BroadcastPrevote(vote) if vote.data.round == 2 && vote.attestations[0].unlock_quorum == candidate.justification)));
    assert_eq!(
        engine.bft_session(0).unwrap().highest_lock_quorum(),
        Some(&old_lock)
    );
    let mut engine =
        Engine::open(engine.chain_spec().clone(), engine.store().db().clone()).unwrap();
    engine.set_programs(support::guests([1; 8], [4; 32]));
    engine.set_local_voter(retarget_keys()[0].clone());
    engine.resume_bft_actions().unwrap();
    assert_eq!(engine.bft_session(0).unwrap().chunk_hash(), second.hash());
    assert_eq!(
        engine.bft_session(0).unwrap().highest_lock_quorum(),
        Some(&old_lock)
    );
    for peer in [1, 2] {
        engine
            .observe_finality_vote(retarget_vote(
                &second,
                selection.commitment(),
                2,
                FinalityVotePhase::Prevote,
                peer,
                vec![],
            ))
            .unwrap();
    }
    let receipt = engine
        .store()
        .get_block_proof(&second.end_block_hash)
        .unwrap()
        .unwrap();
    for peer in [1, 2] {
        engine
            .observe_finality_vote(retarget_vote(
                &second,
                selection.commitment(),
                2,
                FinalityVotePhase::Precommit,
                peer,
                vec![neutrin0_consensus_types::evidence::commitment(&receipt)],
            ))
            .unwrap();
    }
    let outcome = finalize_native_retarget_session(&mut engine, &backend);
    assert_eq!(outcome.chunk_hash, second.hash());
    assert_eq!(outcome.finality_cert.round, 2);
    assert_eq!(engine.latest_finalized_chunk_id(), Some(0));
}

#[test]
fn signed_candidate_transition_crashes_keep_the_retained_lock_and_exact_new_target() {
    use neutrin0_consensus_types::BftCandidate;
    for fail_after in 0..=4 {
        let (mut engine, first, second) = retarget_fixture();
        let backend = NativeConsensusBackend { reject: false };
        let old_lock = lock_retarget_first(&mut engine, &first);
        let selection = retarget_selection(&engine, &second);
        let quorum = retarget_quorum(&second, selection.commitment(), 1);
        engine
            .offer_bft_candidate(
                &BftCandidate {
                    chunk: second.clone(),
                    round: 2,
                    justification: Some(quorum.clone()),
                    selection: Some(selection),
                },
                101,
                &backend,
            )
            .unwrap();
        let proposal = retarget_proposal(&engine, &second, 2, Some(quorum.clone()));
        engine.store_mut().db_mut().fail_durable_after = Some(fail_after);
        let result = engine
            .observe_round_change_certificate(retarget_round_certificate(2, Some(&quorum)), 101);
        if fail_after < 2 {
            assert!(result.is_err());
        }
        let mut database = engine.store().db().clone();
        database.fail_durable_after = None;
        let mut restored = Engine::open(engine.chain_spec().clone(), database).unwrap();
        restored.set_programs(support::guests([1; 8], [4; 32]));
        restored.set_local_voter(retarget_keys()[0].clone());
        restored.resume_bft_actions().unwrap();
        assert_eq!(
            restored.bft_session(0).unwrap().highest_lock_quorum(),
            Some(&old_lock)
        );
        if restored.bft_session(0).unwrap().round() == 2 {
            restored
                .observe_bft_proposal(proposal, 102, &backend)
                .unwrap();
            assert_eq!(restored.bft_session(0).unwrap().chunk_hash(), second.hash());
        } else {
            assert_eq!(restored.bft_session(0).unwrap().round(), 0);
            assert_eq!(restored.bft_session(0).unwrap().chunk_hash(), first.hash());
        }
    }
}

#[test]
fn a_missing_leader_emits_nil_and_requires_quorum_before_round_replacement() {
    use neutrin0_consensus_types::FinalityVotePhase;
    let (mut engine, first, _) = retarget_fixture();
    let leader = neutrin0_consensus_types::bft_leader(
        7,
        0,
        0,
        &engine.finalized_seed(),
        engine.active_validator_set(),
    )
    .unwrap();
    let follower = (leader + 1) % 4;
    engine.set_local_voter(retarget_keys()[follower as usize].clone());
    assert!(engine.open_bft_session_at(first, 100).unwrap().is_empty());
    let base = engine.chain_spec().consensus.bft_round_timeout_base_secs;
    let actions = engine.tick_bft_round_timeouts(100 + base).unwrap();
    assert!(actions.iter().any(|action| matches!(action, BftAction::BroadcastNilVote(vote) if vote.data.phase == FinalityVotePhase::Prevote)));
    let actions = engine.tick_bft_round_timeouts(100 + base * 2).unwrap();
    assert!(actions.iter().any(|action| matches!(action, BftAction::BroadcastNilVote(vote) if vote.data.phase == FinalityVotePhase::Precommit)));
    let actions = engine.tick_bft_round_timeouts(100 + base * 3).unwrap();
    assert!(actions.iter().any(
        |action| matches!(action, BftAction::BroadcastRoundChange(report) if report.round == 1)
    ));
    assert_eq!(engine.bft_session(0).unwrap().round(), 0);
    engine
        .observe_round_change_certificate(retarget_round_certificate(1, None), 100 + base * 3)
        .unwrap();
    assert_eq!(engine.bft_session(0).unwrap().round(), 1);
    assert_eq!(engine.bft_session(0).unwrap().highest_lock_quorum(), None);
}

#[test]
fn initial_proposal_signing_crashes_keep_original_branch_after_fork_choice_changes() {
    for fail_after in 1..=2 {
        let (mut engine, first, second) = retarget_fixture();
        let backend = NativeConsensusBackend { reject: false };
        let leader = neutrin0_consensus_types::bft_leader(
            7,
            0,
            0,
            &engine.finalized_seed(),
            engine.active_validator_set(),
        )
        .unwrap();
        let voter = retarget_keys()[leader as usize].clone();
        engine.set_local_voter(voter.clone());
        engine.store_mut().db_mut().fail_durable_after = Some(fail_after);
        assert!(engine.open_bft_session_at(first.clone(), 100).is_err());
        let mut database = engine.store().db().clone();
        database.fail_durable_after = None;
        let mut restored = Engine::open(engine.chain_spec().clone(), database).unwrap();
        restored.set_programs(support::guests([1; 8], [4; 32]));
        restored.set_local_voter(voter);
        assert_eq!(restored.head_hash(), second.end_block_hash);
        let prepared = restored.prepare_bft_consensus_chunk(0, &backend).unwrap();
        assert_eq!(
            prepared.witness.blocks[0].header.hash(),
            first.end_block_hash
        );
        let actions = restored.resume_bft_actions().unwrap();
        assert!(actions.iter().any(|action| matches!(action, BftAction::BroadcastProposal(proposal) if proposal.chunk.hash() == first.hash())));
        assert!(!actions.iter().any(|action| matches!(action, BftAction::BroadcastPrevote(vote) if vote.data.chunk_hash == second.hash())));
    }
}

#[test]
fn a_fresh_higher_round_hint_opens_round_zero_then_certified_catchup_avoids_throwaway_votes() {
    use neutrin0_consensus_types::BftCandidate;
    let (mut engine, _, second) = retarget_fixture();
    let backend = NativeConsensusBackend { reject: false };
    let initial_leader = neutrin0_consensus_types::bft_leader(
        7,
        0,
        0,
        &engine.finalized_seed(),
        engine.active_validator_set(),
    )
    .unwrap();
    let follower = (initial_leader + 1) % 4;
    engine.set_local_voter(retarget_keys()[follower as usize].clone());
    let selection = retarget_selection(&engine, &second);
    let quorum = retarget_quorum(&second, selection.commitment(), 1);
    let candidate = BftCandidate {
        chunk: second.clone(),
        round: 2,
        justification: Some(quorum.clone()),
        selection: Some(selection),
    };
    let actions = engine
        .offer_bft_candidate(&candidate, 100, &backend)
        .unwrap();
    assert!(actions.is_empty());
    assert_eq!(engine.bft_session(0).unwrap().round(), 0);
    let mut actions = engine
        .observe_round_change_certificate(retarget_round_certificate(2, Some(&quorum)), 101)
        .unwrap();
    let proposal = retarget_proposal(&engine, &second, 2, Some(quorum));
    actions.extend(
        engine
            .observe_bft_proposal(proposal, 101, &backend)
            .unwrap(),
    );
    assert_eq!(engine.bft_session(0).unwrap().round(), 2);
    assert!(
        actions.iter().any(
            |action| matches!(action, BftAction::BroadcastPrevote(vote) if vote.data.round == 2)
        )
    );
    assert!(
        !actions.iter().any(
            |action| matches!(action, BftAction::BroadcastPrevote(vote) if vote.data.round == 0)
        )
    );
}
