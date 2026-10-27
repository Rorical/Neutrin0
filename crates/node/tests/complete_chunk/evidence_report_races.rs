//! Evidence verification races with a natively executed finalized append.

use super::{NativeConsensusBackend, engine, ready_prover};
use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_consensus_types::{
    Block, BlockProof, BlockProofPublicInputs, Body, FinalityVoteData, FinalityVotePhase,
    IndexedVote, SlashingEvidence,
    evidence::{EvidenceBatch, EvidenceReport},
    history_proof::{GuestPrograms, VkDigest},
};
use neutrin0_node::ChainBackend;
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_prover_chunk::consensus::ConsensusWitness;
use neutrin0_runtime_abi::BlockReceiptStatement;
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_core::host::{LiveTrie, TracingState};
use neutrin0_storage::{Batch, Column, Database, MemoryDatabase};
use neutrin0_sync::{EvidenceProofAcceptance, SyncBackend};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

struct PausedEvidenceVerifier {
    native: NativeConsensusBackend,
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    resume: Mutex<mpsc::Receiver<()>>,
}

impl ProofSystem for PausedEvidenceVerifier {
    type BlockProof = BlockReceiptStatement;
    type ChunkProof = neutrin0_consensus_types::history_proof::ChunkReceiptStatement;

    fn prove_block(
        &self,
        witness: &[u8],
        inputs: &BlockProofPublicInputs,
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::BlockProof, ProofError> {
        self.native.prove_block(witness, inputs, prover_address)
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        self.native.verify_block(proof, inputs)
    }

    fn programs(&self) -> Option<GuestPrograms> {
        self.native.programs()
    }

    fn verify_evidence(
        &self,
        bytes: &[u8],
        batch: &EvidenceBatch,
        program: &VkDigest,
    ) -> Result<(), ProofError> {
        self.entered
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .send(())
            .unwrap();
        self.resume
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| ProofError::BackendRejected)?;
        self.native.verify_evidence(bytes, batch, program)
    }
}

fn report(
    engine: &Engine<MemoryDatabase>,
    prover: &NativeConsensusBackend,
    round: u32,
) -> EvidenceReport {
    let key = neutrin0_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let vote = |chunk_hash| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round,
            chunk_hash,
            selection: [0; 32],
            phase: FinalityVotePhase::Precommit,
        };
        IndexedVote {
            signature: key
                .sign(&data.signing_message(engine.chain_spec().consensus_domain()))
                .to_bytes(),
            data,
        }
    };
    let evidence = SlashingEvidence::DoublePrecommit {
        validator_index: 0,
        vote_a: vote([1; 32]),
        vote_b: vote([2; 32]),
    };
    let artifact = prover
        .prove_evidence_batch(
            &[engine.evidence_witness(&evidence).unwrap()],
            &prover.programs().unwrap().execution,
        )
        .unwrap()
        .remove(0);
    EvidenceReport {
        history: engine
            .evidence_submission(artifact.statement.clone())
            .unwrap()
            .history,
        artifact,
    }
}

#[expect(
    clippy::redundant_pub_crate,
    reason = "shared by sibling integration-test modules"
)]
#[allow(
    clippy::too_many_lines,
    reason = "One native finalized append binds the first-block participation lane, execution context and public receipt."
)]
pub(super) fn finalize_next_empty(
    engine: &mut Engine<MemoryDatabase>,
    template: &ConsensusWitness,
) {
    let height = engine.head_height() + 1;
    let proposer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let (validators, seed) = engine.validator_context_for_height(height).unwrap();
    let chunk = (height - 1) / engine.chain_spec().consensus.chunk_size;
    let mut body = Body::default();
    if height == chunk * engine.chain_spec().consensus.chunk_size + 1 && chunk > 0 {
        body.participation = Some(
            engine
                .store()
                .historical_chunk(chunk - 1)
                .unwrap()
                .unwrap()
                .finality
                .carried_certificate(),
        );
    }
    let mut header = template.blocks[0].header.clone();
    header.height = height;
    header.slot = height;
    header.parent_hash = engine.head_hash();
    header.timestamp = engine.chain_spec().genesis_time
        + height * engine.chain_spec().consensus.slot_duration_secs;
    header.vrf_proof =
        proposer.vrf_eval(engine.chain_spec().consensus_domain(), &seed, header.slot);
    // A carrier block consumes both reports derived from its certificate.
    let reports = engine.reports_for_block(&header, &body).unwrap();
    let input = RuntimeBlockInput {
        program_pieces: Vec::new(),
        proposer_address: validators[header.proposer_index as usize].withdrawal_credentials,
        active_validators: validators,
        participation_acks: engine
            .participation_acknowledgements(height, &body)
            .unwrap(),
        context: neutrin0_prover_chunk::execution::runtime_context(
            &header,
            engine.canonical_boundary(chunk).unwrap(),
        ),
        evidence_anchor: engine.evidence_anchor(height).unwrap(),
        chain_id: engine.chain_spec().chain_id,
        block_height: height,
        block_gas_limit: engine.chain_spec().genesis_gas_limit,
        participation: reports
            .as_ref()
            .map(|(participation, _)| participation.clone()),
        proving: reports.map(|(_, proving)| proving),
        transactions: Vec::new(),
    };
    let live = LiveTrie::from_trie(engine.state().clone());
    let mut state = TracingState::new(&live);
    let result = neutrin0_evm_runtime_core::execute_block(&input, &mut state);
    body.artifacts = result.artifacts;
    let output = result.output;
    let (_, _, writes) = state.into_committed_witness_and_writes().unwrap();
    // The body's artifact and vote lanes are committed once execution fixed
    // the artifacts.
    let roots = neutrin0_consensus_engine::compute_body_roots(&body);
    header.votes_root = roots.votes_root;
    header.da_root = roots.da_root;
    header.state_root = output.post_state_root;
    header.transactions_root = output.transactions_root;
    header.runtime_extra = output.consensus_candidates_root;
    header.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
    header.receipts_root = output.receipts_root;
    header.gas_used = output.gas_used;
    header.signature =
        proposer.sign_proposer_message(engine.chain_spec().consensus_domain(), &header.hash());
    let hash = header.hash();
    let inputs = BlockProofPublicInputs {
        context: Box::new(input.context),
        chain_id: input.chain_id,
        height,
        parent_block_hash: header.parent_hash,
        block_hash: hash,
        state_root_before: output.pre_state_root,
        state_root_after: output.post_state_root,
        transactions_root: output.transactions_root,
        receipt_root: output.receipts_root,
        da_root: header.da_root,
        vm_code_hash: engine.runtime_code_hash_for(height).unwrap(),
        block_program: input.evidence_anchor.block_guest_vk_digest,
        gas_used: output.gas_used,
        gas_limit: input.block_gas_limit,
        proposer_address: input.proposer_address,
        runtime_extra: output.consensus_candidates_root,
        inputs_root: neutrin0_prover_chunk::execution::output_inputs_root(&output),
    };
    engine
        .import_block(
            &Block { header, body },
            &super::native_executor::NativeExecutor,
        )
        .unwrap();
    engine.flush_trie_to_store().unwrap();
    let statement = neutrin0_runtime_abi::BlockReceiptStatement {
        output: output.clone(),
        prover_address: inputs.proposer_address,
    };
    engine
        .store_mut()
        .put_proven_block(
            &hash,
            &BlockProof {
                prover_address: statement.prover_address,
                statement_key: neutrin0_consensus_types::evidence::commitment(&statement),
                height,
                block_hash: hash,
                public_inputs: inputs,
                proof_bytes: borsh::to_vec(&statement).unwrap(),
            },
        )
        .unwrap();
    engine
        .store_mut()
        .put_state_diff(
            &hash,
            &neutrin0_consensus_types::BlockStateDiff {
                height,
                block_hash: hash,
                state_root_before: output.pre_state_root,
                state_root_after: output.post_state_root,
                writes: writes
                    .into_iter()
                    .map(|(key, value)| neutrin0_consensus_types::StateWrite { key, value })
                    .collect(),
            },
        )
        .unwrap();
    engine
        .finalize_chunk(height - 1, &ready_prover(), &proposer)
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn incoming_report_refreshes_its_path_after_finality_during_verification() {
    let (mut engine, witness) = engine();
    let prover = ready_prover();
    let signer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine.finalize_chunk(0, &prover, &signer).unwrap();
    let original = report(&engine, &prover, 2);
    assert_eq!(original.history.count, 1);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let backend = Arc::new(ChainBackend::new(
        engine,
        PausedEvidenceVerifier {
            native: ready_prover(),
            entered: Mutex::new(Some(entered_tx)),
            resume: Mutex::new(resume_rx),
        },
    ));
    backend.set_block_executor(neutrin0_runtime_host::WasmExecutor::embedded().unwrap());
    let receiver = Arc::clone(&backend);
    let incoming = original.clone();
    let intake = tokio::spawn(async move { receiver.ingest_evidence_proof(incoming).await });
    tokio::time::timeout(Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    // The verifier must release the engine lock, permitting finalization.
    backend.with_engine_mut_for_test(|engine| finalize_next_empty(engine, &witness));
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        Some(1)
    );
    resume_tx.send(()).unwrap();
    assert_eq!(intake.await.unwrap(), EvidenceProofAcceptance::Accepted);
    backend.with_engine_mut_for_test(|engine| {
        let reports = engine.store().evidence_reports().unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].artifact, original.artifact);
        assert_eq!(reports[0].history.count, 2);
        assert_eq!(
            reports[0].history,
            engine
                .evidence_submission(original.artifact.statement.clone())
                .unwrap()
                .history
        );
    });
}

#[tokio::test(flavor = "current_thread")]
async fn forged_report_paths_are_rejected_and_unknown_future_anchors_are_deferred() {
    let (mut engine, _) = engine();
    let prover = ready_prover();
    let signer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine.finalize_chunk(0, &prover, &signer).unwrap();
    let mut forged = report(&engine, &prover, 2);
    let mut ahead = forged.clone();
    forged.history.siblings[0][0] ^= 1;
    ahead.history.count += 1;
    let backend = ChainBackend::new(engine, ready_prover());
    backend.set_block_executor(neutrin0_runtime_host::WasmExecutor::embedded().unwrap());
    assert_eq!(
        backend.ingest_evidence_proof(forged).await,
        EvidenceProofAcceptance::Rejected
    );
    assert_eq!(
        backend.ingest_evidence_proof(ahead).await,
        EvidenceProofAcceptance::Deferred
    );
    backend.with_engine_mut_for_test(|engine| {
        assert_eq!(
            engine.store().evidence_reports().unwrap(),
            [] as [EvidenceReport; 0]
        );
    });
}

fn dormant_pool_fixture() -> (Engine<MemoryDatabase>, EvidenceReport) {
    let (mut engine, witness) = engine();
    let prover = ready_prover();
    let signer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine.finalize_chunk(0, &prover, &signer).unwrap();
    let dormant = report(&engine, &prover, 2);
    engine.store_mut().put_evidence_report(&dormant).unwrap();
    let stored = engine
        .store()
        .db()
        .get(Column::EvidenceProofs, &dormant.artifact.statement_id())
        .unwrap()
        .unwrap();
    finalize_next_empty(&mut engine, &witness);
    // Model a verified pool entry preserved across a snapshot jump, whose
    // path predates the newly installed finalized root.
    let mut batch = Batch::new();
    batch.put(
        Column::EvidenceProofs,
        dormant.artifact.statement_id(),
        stored,
    );
    engine.store_mut().db_mut().write_batch(batch).unwrap();
    (engine, dormant)
}

#[tokio::test(flavor = "current_thread")]
async fn reporter_refresh_wakes_a_dormant_receipt_without_replacing_its_proof() {
    let (engine, dormant) = dormant_pool_fixture();
    let refreshed = report(&engine, &ready_prover(), 2);
    let backend = ChainBackend::new(engine, ready_prover());
    backend.set_block_executor(neutrin0_runtime_host::WasmExecutor::embedded().unwrap());
    assert_eq!(
        backend.ingest_evidence_proof(refreshed.clone()).await,
        EvidenceProofAcceptance::Accepted
    );
    backend.with_engine_mut_for_test(|engine| {
        let pooled = engine.store().evidence_reports().unwrap();
        assert_eq!(pooled.len(), 1);
        assert_eq!(pooled[0].artifact, dormant.artifact);
        assert_eq!(pooled[0].history, refreshed.history);
    });
}

#[tokio::test(flavor = "current_thread")]
async fn dormant_safety_receipt_does_not_suppress_a_usable_report_for_the_identity() {
    let (engine, dormant) = dormant_pool_fixture();
    let usable = report(&engine, &ready_prover(), 3);
    assert_eq!(
        usable.artifact.statement.offender,
        dormant.artifact.statement.offender
    );
    let backend = ChainBackend::new(engine, ready_prover());
    backend.set_block_executor(neutrin0_runtime_host::WasmExecutor::embedded().unwrap());
    assert_eq!(
        backend.ingest_evidence_proof(usable.clone()).await,
        EvidenceProofAcceptance::Accepted
    );
    backend.with_engine_mut_for_test(|engine| {
        let reports = engine.store().evidence_reports().unwrap();
        assert_eq!(reports.len(), 2);
        assert!(reports.contains(&dormant));
        assert!(reports.contains(&usable));
    });
}

/// Execute transparent test receipts only after the matching native verifier.
/// These fixtures cannot enter the production SP1 portable verifier.
struct NativeEvidenceExecutor(neutrin0_runtime_host::WasmExecutor);

impl neutrin0_proof_system::ErasedBlockExecutor for NativeEvidenceExecutor {
    fn execute_block(
        &self,
        context: &neutrin0_proof_system::BlockExecutionContext,
        body: &Body,
        state: &mut neutrin0_trie::Trie,
    ) -> Result<neutrin0_proof_system::ExecutionOutcome, String> {
        use neutrin0_runtime_abi::RuntimeTransaction;
        let input = RuntimeBlockInput {
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
        };
        neutrin0_runtime_core::execution::check_runtime_input(&input)
            .map_err(|error| error.message().to_owned())?;
        let submissions = input
            .transactions
            .iter()
            .filter_map(|transaction| {
                if let RuntimeTransaction::SubmitEvidence(submission) = transaction {
                    Some(submission)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(submissions.len(), body.evidence_proofs.len());
        for (submission, artifact) in submissions.iter().zip(&body.evidence_proofs) {
            assert!(artifact.binds(
                &submission.statement,
                &input.evidence_anchor.evidence_guest_vk_digest,
                &input.evidence_anchor.fact_guest_vk_digest,
            ));
            ready_prover()
                .verify_evidence(
                    &artifact.proof_bytes,
                    &artifact.membership.batch,
                    &input.evidence_anchor.evidence_guest_vk_digest,
                )
                .map_err(|error| error.to_string())?;
        }
        let live = LiveTrie::from_trie(state.clone());
        let mut tracing = TracingState::new(&live);
        let result = neutrin0_evm_runtime_core::execute_block(&input, &mut tracing);
        let (committed, witness, writes) = tracing.into_committed_witness_and_writes().unwrap();
        let witness_bytes =
            neutrin0_runtime_host::encode_witness_bundle(&input, &witness, &body.evidence_proofs)
                .map_err(|error| error.to_string())?;
        *state = committed;
        Ok(neutrin0_proof_system::ExecutionOutcome {
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

    fn query(
        &self,
        request: &neutrin0_runtime_abi::QueryRequest,
        runtime: neutrin0_primitives::Hash,
        state: &neutrin0_trie::Trie,
    ) -> Result<neutrin0_runtime_abi::QueryResponse, String> {
        neutrin0_proof_system::ErasedBlockExecutor::query(&self.0, request, runtime, state)
    }

    fn validate_tx(
        &self,
        transaction: &[u8],
        chain: u64,
        gas_limit: u64,
        runtime: neutrin0_primitives::Hash,
        state: &neutrin0_trie::Trie,
    ) -> Result<neutrin0_runtime_abi::TxValidity, String> {
        neutrin0_proof_system::ErasedBlockExecutor::validate_tx(
            &self.0,
            transaction,
            chain,
            gas_limit,
            runtime,
            state,
        )
    }

    fn install_runtime(&self, wasm: &[u8]) -> Result<neutrin0_primitives::Hash, String> {
        neutrin0_proof_system::ErasedBlockExecutor::install_runtime(&self.0, wasm)
    }

    fn installed_runtimes(&self) -> Vec<neutrin0_primitives::Hash> {
        neutrin0_proof_system::ErasedBlockExecutor::installed_runtimes(&self.0)
    }
}

#[tokio::test(flavor = "current_thread")]
#[allow(
    clippy::too_many_lines,
    reason = "Authenticate a finalized report, certify its successor boundary and execute its admission without advancing pool finality."
)]
async fn certified_successor_admits_finalized_evidence_without_reanchoring_the_pool() {
    use super::certified_execution::NativePipelineProofs;
    use neutrin0_consensus_engine::ProductionConfig;
    use neutrin0_consensus_types::evidence::commitment;
    use neutrin0_runtime_abi::RuntimeTransaction;
    use neutrin0_runtime_host::WasmExecutor;

    let (mut engine, _) = engine();
    let signer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine.finalize_chunk(0, &ready_prover(), &signer).unwrap();
    let original = report(&engine, &ready_prover(), 2);
    assert_eq!(original.history.count, 1);
    let executor = WasmExecutor::embedded().unwrap();
    let predecessor = engine
        .try_produce_block(
            2,
            ProductionConfig { proposer: &signer },
            Body::default(),
            &executor,
        )
        .unwrap()
        .unwrap()
        .block;
    engine
        .prove_block(&predecessor.hash(), &NativePipelineProofs)
        .unwrap();
    let mut prepared = engine
        .prepare_consensus_chunk(1, &NativePipelineProofs)
        .unwrap();
    engine
        .certify_consensus_chunk(&mut prepared, &signer)
        .unwrap();
    engine
        .certify_execution_chunk(&prepared, &NativePipelineProofs, None)
        .unwrap();
    let anchor = engine.evidence_anchor(3).unwrap();
    let transient = engine
        .evidence_submission_for_execution(3, &original.artifact.statement, &original.history)
        .unwrap();
    assert_eq!(transient.history.count, 2);
    assert!(transient.binds(engine.chain_spec().chain_id, 3, &anchor));
    assert_eq!(engine.finalized_next_chunk_id(), 1);
    assert!(engine.canonical_boundary(2).is_err());
    let mut forged = original.history.clone();
    forged.siblings[0][0] ^= 1;
    assert!(
        engine
            .evidence_submission_for_execution(3, &original.artifact.statement, &forged,)
            .is_err()
    );
    assert!(
        engine
            .evidence_submission_with_path(&original.artifact.statement, &transient.history,)
            .is_err()
    );

    let backend = ChainBackend::new(engine, ready_prover());
    backend.set_block_executor(NativeEvidenceExecutor(executor));
    assert_eq!(
        backend.ingest_evidence_proof(original.clone()).await,
        EvidenceProofAcceptance::Accepted
    );
    backend.with_engine_mut_for_test(|engine| {
        assert_eq!(
            engine.store().evidence_reports().unwrap(),
            vec![original.clone()]
        );
        let reopened =
            Engine::open(engine.chain_spec().clone(), engine.store().db().clone()).unwrap();
        assert_eq!(
            reopened
                .evidence_submission_for_execution(
                    3,
                    &original.artifact.statement,
                    &original.history
                )
                .unwrap(),
            transient
        );
    });
    let successor = backend
        .try_produce_block(3, &signer)
        .unwrap()
        .unwrap()
        .block;
    assert_eq!(
        successor.body.evidence_proofs,
        vec![original.artifact.clone()]
    );
    let RuntimeTransaction::SubmitEvidence(submission) =
        borsh::from_slice(&successor.body.transactions[0]).unwrap()
    else {
        panic!("the ready report must be selected for admission")
    };
    assert_eq!(submission.history, transient.history);
    assert!(submission.history.verify(
        commitment(&submission.statement.context),
        anchor.history_root
    ));
    backend.with_engine_mut_for_test(|engine| {
        assert_eq!(engine.finalized_next_chunk_id(), 1);
        assert_eq!(engine.head_height(), 3);
        assert_eq!(engine.store().evidence_reports().unwrap(), vec![original]);
    });
}
