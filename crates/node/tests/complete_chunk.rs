//! Native consensus backend tests for asynchronous proof scheduling, not SP1 soundness.
#[path = "complete_chunk/bft_proof_notifications.rs"]
mod bft_proof_notifications;
#[path = "complete_chunk/certified_execution.rs"]
mod certified_execution;
#[path = "complete_chunk/consensus_rpc.rs"]
mod consensus_rpc;
#[path = "complete_chunk/evidence_report_races.rs"]
mod evidence_report_races;
#[path = "complete_chunk/finalized_metrics.rs"]
mod finalized_metrics;
#[path = "support/native_executor.rs"]
pub mod native_executor;
#[path = "complete_chunk/proving_duties.rs"]
mod proving_duties;
#[path = "complete_chunk/reporter_mode.rs"]
mod reporter_mode;
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use alloy_primitives::U256;
use neutrin0_consensus_engine::{BlockState, Engine, ProposerKey};
use neutrin0_consensus_types::{BlockProof, BlockProofPublicInputs};
use neutrin0_node::ChainBackend;
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_prover_chunk::consensus::{ConsensusWitness, validate_consensus};
use neutrin0_runtime_abi::{BlockReceiptStatement, RuntimeBlockOutput};
use neutrin0_storage::MemoryDatabase;
use neutrin0_sync::SyncBackend;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};

struct NativeConsensusBackend {
    decisions: Mutex<mpsc::Receiver<bool>>,
    attempts: Arc<AtomicUsize>,
}

impl ProofSystem for NativeConsensusBackend {
    type BlockProof = BlockReceiptStatement;
    type ChunkProof = neutrin0_consensus_types::history_proof::ChunkReceiptStatement;

    fn prove_block(
        &self,
        _: &[u8],
        _: &BlockProofPublicInputs,
        _: neutrin0_primitives::Hash,
    ) -> Result<Self::BlockProof, ProofError> {
        Err(ProofError::Unsupported)
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
        Some(support::guests(
            [1; 8],
            neutrin0_runtime_host::embedded_runtime_code_hash(),
        ))
    }

    // Transparent native witness receipts are test-only. Production uses the
    // SP1 portable verifier; these bytes deliberately cannot pass that verifier.
    fn prove_evidence_batch(
        &self,
        witnesses: &[neutrin0_prover_chunk::evidence::EvidenceWitness],
        execution: &neutrin0_consensus_types::history_proof::ExecutionPrograms,
    ) -> Result<Vec<neutrin0_consensus_types::evidence::EvidenceArtifact>, ProofError> {
        if execution.fact != [3; 8] || execution.evidence != [2; 8] {
            return Err(ProofError::Unsupported);
        }
        let statements = witnesses
            .iter()
            .map(neutrin0_prover_chunk::evidence::validate_evidence)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProofError::InvalidWitness)?;
        let bytes = borsh::to_vec(witnesses).map_err(|_| ProofError::InvalidWitness)?;
        let mut artifacts = Vec::new();
        for (index, statement) in statements.iter().enumerate() {
            artifacts.push(neutrin0_consensus_types::evidence::EvidenceArtifact {
                membership: neutrin0_consensus_types::evidence::EvidenceMembership::build(
                    &statements,
                    index,
                    [3; 8],
                )
                .ok_or(ProofError::InvalidWitness)?,
                statement: statement.clone(),
                evidence_guest_vk_digest: [2; 8],
                proof_bytes: bytes.clone(),
            });
        }
        Ok(artifacts)
    }

    fn verify_evidence(
        &self,
        bytes: &[u8],
        expected: &neutrin0_consensus_types::evidence::EvidenceBatch,
        evidence_program: &neutrin0_consensus_types::history_proof::VkDigest,
    ) -> Result<(), ProofError> {
        if *evidence_program != [2; 8] {
            return Err(ProofError::PublicInputMismatch);
        }
        let witnesses: Vec<neutrin0_prover_chunk::evidence::EvidenceWitness> =
            borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
        let statements = witnesses
            .iter()
            .map(neutrin0_prover_chunk::evidence::validate_evidence)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ProofError::InvalidWitness)?;
        let batch = neutrin0_consensus_types::evidence::EvidenceBatch::new(&statements, [3; 8])
            .ok_or(ProofError::InvalidWitness)?;
        if &batch != expected {
            return Err(ProofError::PublicInputMismatch);
        }
        Ok(())
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
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if !self
            .decisions
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap_or(false)
        {
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
        if proof != expected {
            return Err(ProofError::BackendRejected);
        }
        Ok(())
    }
}

/// The fixture's runtime genesis: the EVM runtime seats the fixture
/// validator with a stake record at its withdrawal credentials, as the
/// node's genesis builder does, so a safety claim binds to slashable balance.
fn seeded_genesis_state() -> neutrin0_runtime_core::host::LiveTrie {
    support::fixture_genesis_live(
        [1; 8],
        neutrin0_runtime_host::embedded_runtime_code_hash(),
        30_000_000,
    )
}

/// A fresh engine at the fixture genesis with the seeded state installed.
fn genesis_engine(spec: neutrin0_primitives::ChainSpec) -> Engine<MemoryDatabase> {
    let live = seeded_genesis_state();
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).unwrap();
    engine.install_genesis_state(live.trie().clone()).unwrap();
    engine.flush_trie_to_store().unwrap();
    engine
}

/// Import the executed fixture `block` with its executed `body` as a proven
/// publication: the native executor reproduces its header over the engine's
/// state and records the block's diff; the fixture output stands in for its
/// receipt.
fn import_fixture_block(
    engine: &mut Engine<MemoryDatabase>,
    block: &neutrin0_prover_chunk::execution::ProvenBlock,
    body: neutrin0_consensus_types::Body,
) {
    let hash = block.header.hash();
    engine
        .import_block(
            &neutrin0_consensus_types::Block {
                header: block.header.clone(),
                body,
            },
            &native_executor::NativeExecutor,
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
}

fn engine() -> (Engine<MemoryDatabase>, ConsensusWitness) {
    let (engine, witness, _) = engine_with_input();
    (engine, witness)
}

/// [`engine`] that also returns the fixture block's runtime input, for tests
/// that derive sibling executions from it.
fn engine_with_input() -> (
    Engine<MemoryDatabase>,
    ConsensusWitness,
    neutrin0_runtime_abi::RuntimeBlockInput,
) {
    engine_with_live_and_input(&seeded_genesis_state())
}

fn engine_with_live(
    live: &neutrin0_runtime_core::host::LiveTrie,
) -> (Engine<MemoryDatabase>, ConsensusWitness) {
    let (engine, witness, _) = engine_with_live_and_input(live);
    (engine, witness)
}

fn engine_with_live_and_input(
    live: &neutrin0_runtime_core::host::LiveTrie,
) -> (
    Engine<MemoryDatabase>,
    ConsensusWitness,
    neutrin0_runtime_abi::RuntimeBlockInput,
) {
    let (mut witness, input, _) = support::fixture_with_live(
        [1; 8],
        neutrin0_runtime_host::embedded_runtime_code_hash(),
        vec![],
        30_000_000,
        live,
    );
    let mut engine = Engine::genesis(witness.chain_spec.clone(), MemoryDatabase::new()).unwrap();
    engine.install_genesis_state(live.trie().clone()).unwrap();
    engine.flush_trie_to_store().unwrap();
    engine.set_programs(support::guests(
        [1; 8],
        neutrin0_runtime_host::embedded_runtime_code_hash(),
    ));
    let block = &witness.blocks[0];
    let hash = block.header.hash();
    import_fixture_block(&mut engine, block, support::executed_body(live, &input));
    let receipt = engine.store().get_block_proof(&hash).unwrap().unwrap();
    let manifest = neutrin0_consensus_types::ProofManifest {
        proof_hashes: vec![neutrin0_consensus_types::evidence::commitment(&receipt)],
    };
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    witness.finality_cert.precommit_attestations = vec![voter.attest_vote(
        witness.chain_spec.consensus_domain(),
        witness.finality_cert.precommit_vote().data,
        manifest.proof_hashes.clone(),
        None,
    )];
    witness.finality_cert.proof_manifests = vec![manifest];
    (engine, witness, input)
}

/// Execute the fixture's first block again as a sibling at `slot` over the
/// genesis state `live`: the same empty body under its own slot, timestamp
/// and VRF output, so its state root, receipts root and artifacts are its
/// own. The header is signed by the fixture's proposer key.
fn sibling_at_slot(
    witness: &ConsensusWitness,
    input: &neutrin0_runtime_abi::RuntimeBlockInput,
    live: &neutrin0_runtime_core::host::LiveTrie,
    slot: u64,
) -> (neutrin0_consensus_types::Block, RuntimeBlockOutput) {
    let spec = &witness.chain_spec;
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let mut block = neutrin0_consensus_types::Block {
        header: witness.blocks[0].header.clone(),
        body: neutrin0_consensus_types::Body::default(),
    };
    block.header.slot = slot;
    block.header.timestamp = spec.genesis_time + slot * spec.consensus.slot_duration_secs;
    block.header.vrf_proof = voter.vrf_eval(spec.consensus_domain(), &witness.seed, slot);
    let mut sibling_input = input.clone();
    sibling_input.context = neutrin0_prover_chunk::execution::runtime_context(
        &block.header,
        neutrin0_consensus_types::history_proof::ConsensusBoundary::genesis(spec),
    );
    let mut traced = neutrin0_runtime_core::host::TracingState::new(live);
    let result = neutrin0_evm_runtime_core::execute_block(&sibling_input, &mut traced);
    block.body.artifacts = result.artifacts;
    let output = result.output;
    block.header.state_root = output.post_state_root;
    block.header.transactions_root = output.transactions_root;
    block.header.receipts_root = output.receipts_root;
    block.header.runtime_extra = output.consensus_candidates_root;
    block.header.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
    block.header.gas_used = output.gas_used;
    block.header.da_root = neutrin0_prover_chunk::consensus::body_da_root(&block.body);
    block.header.signature = voter.sign_proposer_message(spec.consensus_domain(), &block.hash());
    (block, output)
}

/// `base` rebound to the sibling `block` and its execution `output`.
fn sibling_public_inputs(
    base: &BlockProofPublicInputs,
    block: &neutrin0_consensus_types::Block,
    output: &RuntimeBlockOutput,
) -> BlockProofPublicInputs {
    let mut inputs = base.clone();
    inputs.context = Box::new(output.context);
    inputs.block_hash = block.hash();
    inputs.state_root_after = output.post_state_root;
    inputs.transactions_root = output.transactions_root;
    inputs.receipt_root = output.receipts_root;
    inputs.da_root = block.header.da_root;
    inputs.gas_used = output.gas_used;
    inputs.runtime_extra = output.consensus_candidates_root;
    inputs.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(output);
    inputs
}

#[tokio::test(flavor = "current_thread")]
async fn proof_job_keeps_network_responsive_and_retries_without_advancing_on_failure() {
    use neutrin0_prover_chunk::consensus::as_chunk;
    use std::time::Duration;
    let (engine, witness) = engine();
    let (decisions, receiver) = mpsc::channel();
    let attempts = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(ChainBackend::new(
        engine,
        NativeConsensusBackend {
            decisions: Mutex::new(receiver),
            attempts: Arc::clone(&attempts),
        },
    ));
    let actor = tokio::spawn(Arc::clone(&backend).run_consensus_proof_notifications());
    backend.set_local_voter(ProposerKey::from_ikm(&[42; 32], 0).unwrap());
    backend.with_engine_mut_for_test(|engine| {
        engine
            .open_bft_session(as_chunk(&validate_consensus(&witness).unwrap().chunk))
            .unwrap()
    });
    // The worker deliberately waits for a test-controlled result. Neither the
    // network-facing tick nor status may wait for that result.
    tokio::time::timeout(Duration::from_secs(5), backend.tick_bft_round_timeouts(0))
        .await
        .unwrap();
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        None
    );
    decisions.send(false).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while attempts.load(Ordering::SeqCst) < 2 {
            backend.tick_bft_round_timeouts(0).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        None
    );
    decisions.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while backend
            .local_status()
            .await
            .unwrap()
            .finalized_chunk_id
            .is_none()
        {
            backend.tick_bft_round_timeouts(0).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        Some(0)
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    actor.abort();
    assert!(actor.await.unwrap_err().is_cancelled());
}

#[tokio::test(flavor = "current_thread")]
async fn evidence_worker_persists_gossips_and_rehydrates_verified_receipts() {
    for foreign_prover in [false, true] {
        Box::pin(evidence_worker_case(foreign_prover)).await;
    }
}

fn double_precommit(
    domain: neutrin0_primitives::ConsensusDomain,
) -> neutrin0_consensus_types::SlashingEvidence {
    use neutrin0_consensus_types::{
        FinalityVoteData, FinalityVotePhase, IndexedVote, SlashingEvidence,
    };
    let key = neutrin0_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let sign = |hash| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 2,
            chunk_hash: [hash; 32],
            selection: [0; 32],
            phase: FinalityVotePhase::Precommit,
        };
        IndexedVote {
            signature: key.sign(&data.signing_message(domain)).to_bytes(),
            data,
        }
    };
    SlashingEvidence::DoublePrecommit {
        validator_index: 0,
        vote_a: sign(1),
        vote_b: sign(2),
    }
}

async fn evidence_worker_case(foreign_prover: bool) {
    use neutrin0_consensus_types::evidence::EvidenceReport;
    use neutrin0_network::{Topic, service::NetworkCommand};
    use neutrin0_sync::SyncBackend;
    let (mut engine, witness) = engine();
    engine.set_programs(support::guests(
        [1; 8],
        neutrin0_runtime_host::embedded_runtime_code_hash(),
    ));
    let (decisions, receiver) = mpsc::channel();
    decisions.send(true).unwrap();
    let prover = NativeConsensusBackend {
        decisions: Mutex::new(receiver),
        attempts: Arc::new(AtomicUsize::new(0)),
    };
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine.finalize_chunk(0, &prover, &voter).unwrap();
    let offence = double_precommit(engine.chain_spec().consensus_domain());
    let backend = ChainBackend::new(engine, prover);
    backend.set_prove_foreign_blocks(foreign_prover);
    // Evidence intake queries runtime policy through the installed executor.
    backend.set_block_executor(neutrin0_runtime_host::WasmExecutor::embedded().unwrap());
    let (publisher, mut messages) = tokio::sync::mpsc::channel(8);
    backend.set_network_publisher(publisher);
    let _ = backend.ingest_slashing_evidence(offence).await;
    if !foreign_prover {
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), messages.recv())
                .await
                .is_err()
        );
        backend.with_engine_mut_for_test(|engine| {
            assert_eq!(
                engine.store().evidence_reports().unwrap(),
                Vec::<EvidenceReport>::new()
            );
        });
        return;
    }
    let report = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if let NetworkCommand::Publish {
                topic: Topic::EvidenceProofs,
                data,
            } = messages.recv().await.unwrap()
            {
                break borsh::from_slice::<EvidenceReport>(&data).unwrap();
            }
        }
    })
    .await
    .expect("background evidence completion notification");
    let database = backend.with_engine_mut_for_test(|engine| {
        assert_eq!(
            engine.store().evidence_reports().unwrap(),
            vec![report.clone()]
        );
        engine.store().db().clone()
    });
    let reopened = Engine::open(witness.chain_spec, database).unwrap();
    let (_sender, receiver) = mpsc::channel();
    let restarted = ChainBackend::new(
        reopened,
        NativeConsensusBackend {
            decisions: Mutex::new(receiver),
            attempts: Arc::new(AtomicUsize::new(0)),
        },
    );
    restarted.set_block_executor(neutrin0_runtime_host::WasmExecutor::embedded().unwrap());
    assert_eq!(
        restarted.ingest_evidence_proof(report.clone()).await,
        neutrin0_sync::EvidenceProofAcceptance::Accepted
    );
    let mut forged = report.clone();
    forged.artifact.statement.offender.withdrawal_credentials[0] ^= 1;
    assert_eq!(
        restarted.ingest_evidence_proof(forged).await,
        neutrin0_sync::EvidenceProofAcceptance::Rejected
    );
    let mut corrupt = report.clone();
    corrupt.artifact.proof_bytes.push(0);
    assert_eq!(
        restarted.ingest_evidence_proof(corrupt).await,
        neutrin0_sync::EvidenceProofAcceptance::Rejected
    );
    let mut wrong_program = report.clone();
    wrong_program.artifact.evidence_guest_vk_digest[0] ^= 1;
    assert_eq!(
        restarted.ingest_evidence_proof(wrong_program).await,
        neutrin0_sync::EvidenceProofAcceptance::Rejected
    );
    restarted.with_engine_mut_for_test(|engine| {
        assert_eq!(engine.store().evidence_reports().unwrap(), vec![report]);
    });
}

#[tokio::test(flavor = "current_thread")]
async fn one_safety_receipt_per_identity_is_pooled_and_redundant_reports_are_skipped() {
    use neutrin0_consensus_types::{
        FinalityVoteData, FinalityVotePhase, IndexedVote, SlashingEvidence,
        evidence::EvidenceReport,
    };
    use neutrin0_network::{Topic, service::NetworkCommand};
    use neutrin0_sync::{EvidenceProofAcceptance, SyncBackend};
    let (mut engine, _) = engine();
    engine.set_programs(support::guests(
        [1; 8],
        neutrin0_runtime_host::embedded_runtime_code_hash(),
    ));
    let (decisions, receiver) = mpsc::channel();
    decisions.send(true).unwrap();
    let prover = NativeConsensusBackend {
        decisions: Mutex::new(receiver),
        attempts: Arc::new(AtomicUsize::new(0)),
    };
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    engine.finalize_chunk(0, &prover, &voter).unwrap();
    let key = neutrin0_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let domain = engine.chain_spec().consensus_domain();
    let sign = |round: u32, hash: u8| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round,
            chunk_hash: [hash; 32],
            selection: [0; 32],
            phase: FinalityVotePhase::Precommit,
        };
        IndexedVote {
            signature: key.sign(&data.signing_message(domain)).to_bytes(),
            data,
        }
    };
    // Two distinct offences by one identity: different rounds, different
    // offence identities, one BLS key.
    let first = SlashingEvidence::DoublePrecommit {
        validator_index: 0,
        vote_a: sign(2, 1),
        vote_b: sign(2, 2),
    };
    let second = SlashingEvidence::DoublePrecommit {
        validator_index: 0,
        vote_a: sign(3, 3),
        vote_b: sign(3, 4),
    };
    let second_receipt = prove_local_report(&engine, &prover, &second);
    let backend = ChainBackend::new(engine, prover);
    backend.set_local_voter(voter);
    // Evidence intake queries runtime policy through the installed executor.
    backend.set_block_executor(neutrin0_runtime_host::WasmExecutor::embedded().unwrap());
    let (publisher, mut messages) = tokio::sync::mpsc::channel(8);
    backend.set_network_publisher(publisher);
    let _ = backend.ingest_slashing_evidence(first).await;
    let pooled = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if let NetworkCommand::Publish {
                topic: Topic::EvidenceProofs,
                data,
            } = messages.recv().await.unwrap()
            {
                break borsh::from_slice::<EvidenceReport>(&data).unwrap();
            }
        }
    })
    .await
    .expect("first receipt is proven and published");
    assert_ne!(
        pooled.artifact.statement.offence_id,
        second_receipt.artifact.statement.offence_id
    );
    assert_eq!(
        pooled.artifact.statement.offender.pubkey,
        second_receipt.artifact.statement.offender.pubkey
    );
    // A different safety receipt against the pooled identity is redundant: it
    // is neither verified nor stored, and relaying it is not penalised.
    assert_eq!(
        backend.ingest_evidence_proof(second_receipt).await,
        EvidenceProofAcceptance::Deferred
    );
    // The exact pooled statement still answers Accepted.
    assert_eq!(
        backend.ingest_evidence_proof(pooled.clone()).await,
        EvidenceProofAcceptance::Accepted
    );
    // A raw report against the covered identity enters the raw pool but never
    // starts a proving job while the receipt stands.
    let _ = backend.ingest_slashing_evidence(second).await;
    while backend.evidence_worker_running_for_test() {
        tokio::task::yield_now().await;
    }
    assert_eq!(backend.slashing_pool_len(), 2);
    while let Ok(message) = messages.try_recv() {
        assert!(
            !matches!(
                message,
                NetworkCommand::Publish {
                    topic: Topic::EvidenceProofs,
                    ..
                }
            ),
            "redundant safety report must not produce a receipt"
        );
    }
    backend.with_engine_mut_for_test(|engine| {
        assert_eq!(engine.store().evidence_reports().unwrap(), vec![pooled]);
    });
}

fn prove_local_report(
    engine: &Engine<MemoryDatabase>,
    prover: &NativeConsensusBackend,
    evidence: &neutrin0_consensus_types::SlashingEvidence,
) -> neutrin0_consensus_types::evidence::EvidenceReport {
    let artifact = prover
        .prove_evidence_batch(
            &[engine.evidence_witness(evidence).unwrap()],
            &support::guests([1; 8], neutrin0_runtime_host::embedded_runtime_code_hash()).execution,
        )
        .unwrap()
        .remove(0);
    neutrin0_consensus_types::evidence::EvidenceReport {
        history: engine
            .evidence_submission(artifact.statement.clone())
            .unwrap()
            .history,
        artifact,
    }
}

fn ready_prover() -> NativeConsensusBackend {
    let (sender, receiver) = mpsc::channel();
    sender.send(true).unwrap();
    NativeConsensusBackend {
        decisions: Mutex::new(receiver),
        attempts: Arc::new(AtomicUsize::new(0)),
    }
}

fn cached_candidate_fixture() -> (
    Engine<MemoryDatabase>,
    neutrin0_consensus_types::Chunk,
    neutrin0_consensus_types::Chunk,
) {
    let (mut engine, witness, input) = engine_with_input();
    engine.set_programs(support::guests(
        [1; 8],
        neutrin0_runtime_host::embedded_runtime_code_hash(),
    ));
    let first = witness.blocks[0].header.hash();
    // The sibling executes the same empty body over the same genesis state
    // under its own slot, so its receipt commits its own execution.
    let (sibling, sibling_output) = sibling_at_slot(&witness, &input, &seeded_genesis_state(), 2);
    let second = sibling.hash();
    engine
        .import_block(&sibling, &native_executor::NativeExecutor)
        .unwrap();
    let mut receipt = engine.store().get_block_proof(&first).unwrap().unwrap();
    receipt.block_hash = second;
    receipt.public_inputs =
        sibling_public_inputs(&receipt.public_inputs, &sibling, &sibling_output);
    let statement = BlockReceiptStatement {
        output: sibling_output,
        prover_address: receipt.public_inputs.proposer_address,
    };
    receipt.prover_address = statement.prover_address;
    receipt.statement_key = neutrin0_consensus_types::evidence::commitment(&statement);
    receipt.proof_bytes = borsh::to_vec(&statement).unwrap();
    engine
        .store_mut()
        .put_proven_block(&second, &receipt)
        .unwrap();
    let prover = ready_prover();
    let [first_chunk, second_chunk] = [first, second].map(|head| {
        let prepared = engine
            .prepare_consensus_chunk_on_branch(0, head, None, &prover)
            .unwrap();
        neutrin0_prover_chunk::consensus::as_chunk(
            &neutrin0_prover_chunk::consensus::validate_candidate(&prepared.witness)
                .unwrap()
                .execution
                .chunk,
        )
    });
    engine
        .store_mut()
        .commit_tip(
            second,
            witness.chain_spec.genesis_block_hash,
            neutrin0_storage::Batch::new(),
        )
        .unwrap();
    let mut reopened = Engine::open(witness.chain_spec, engine.store().db().clone()).unwrap();
    // A restarted node re-pins its Guests from the proof backend before use.
    reopened.set_programs(support::guests(
        [1; 8],
        neutrin0_runtime_host::embedded_runtime_code_hash(),
    ));
    (reopened, first_chunk, second_chunk)
}

/// Fixed slot of the candidate fixtures' proposals, past every fixture
/// block's exclusive window and never ahead of the local clock.
const CANDIDATE_PROPOSAL_SLOT: u64 = 1_000;

/// The payment selection a fixture proposal for `chunk` signs (design 08).
fn candidate_selection(
    engine: &Engine<MemoryDatabase>,
    chunk: &neutrin0_consensus_types::Chunk,
) -> neutrin0_consensus_types::PaymentSelection {
    neutrin0_consensus_types::PaymentSelection {
        proposal_slot: CANDIDATE_PROPOSAL_SLOT,
        receipts: engine
            .selected_receipts(chunk, CANDIDATE_PROPOSAL_SLOT)
            .unwrap()
            .unwrap_or_default(),
        ratified_chunk_proofs: Vec::new(),
    }
}

fn candidate_quorum(
    domain: neutrin0_primitives::ConsensusDomain,
    voter: &ProposerKey,
    chunk: &neutrin0_consensus_types::Chunk,
    selection: &neutrin0_consensus_types::PaymentSelection,
    round: u32,
) -> neutrin0_consensus_types::QuorumCertificate {
    let data = neutrin0_consensus_types::FinalityVoteData {
        chunk_id: chunk.chunk_id,
        chunk_hash: chunk.hash(),
        selection: selection.commitment(),
        round,
        phase: neutrin0_consensus_types::FinalityVotePhase::Prevote,
    };
    neutrin0_consensus_types::QuorumCertificate {
        aggregate: neutrin0_consensus_types::AggregatedVote {
            aggregation_bits: neutrin0_primitives::BitVec::from_bytes(1, vec![1]).unwrap(),
            signature: voter.sign_finality_vote(domain, &data),
        },
        data,
    }
}

fn retain_report_before_changed_highest_value(
    engine: &mut Engine<MemoryDatabase>,
    retained: &neutrin0_consensus_types::Chunk,
    current: &neutrin0_consensus_types::Chunk,
) {
    use neutrin0_consensus_types::{
        BftCandidate, BftProposal, RoundChange, RoundChangeCertificate,
    };
    let prover = ready_prover();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let domain = engine.chain_spec().consensus_domain();
    let retained_selection = candidate_selection(engine, retained);
    let current_selection = candidate_selection(engine, current);
    engine.open_bft_session_at(retained.clone(), 100).unwrap();
    engine
        .offer_bft_candidate(
            &BftCandidate {
                chunk: retained.clone(),
                round: 1,
                justification: Some(candidate_quorum(
                    domain,
                    &voter,
                    retained,
                    &retained_selection,
                    0,
                )),
                selection: Some(retained_selection.clone()),
            },
            100,
            &prover,
        )
        .unwrap();
    let mut report = RoundChange {
        chunk_id: 0,
        round: 2,
        validator_index: 0,
        highest_quorum: Some(candidate_quorum(
            domain,
            &voter,
            retained,
            &retained_selection,
            0,
        )),
        signature: [0; 96],
    };
    report.signature = voter.sign_raw(&report.signing_message(domain)).to_bytes();
    engine
        .observe_round_change_certificate(
            RoundChangeCertificate {
                chunk_id: 0,
                round: 2,
                reports: vec![report],
            },
            101,
        )
        .unwrap();
    engine
        .offer_bft_candidate(
            &BftCandidate {
                chunk: current.clone(),
                round: 2,
                justification: Some(candidate_quorum(
                    domain,
                    &voter,
                    current,
                    &current_selection,
                    1,
                )),
                selection: Some(current_selection.clone()),
            },
            102,
            &prover,
        )
        .unwrap();
    let mut proposal = BftProposal {
        chunk: current.clone(),
        round: 2,
        proposer_index: 0,
        valid_quorum: Some(candidate_quorum(
            domain,
            &voter,
            current,
            &current_selection,
            1,
        )),
        round_change_certificate: engine
            .bft_session(0)
            .unwrap()
            .round_change_certificate()
            .cloned(),
        proposal_slot: current_selection.proposal_slot,
        receipts: current_selection.receipts,
        ratified_chunk_proofs: current_selection.ratified_chunk_proofs,
        signature: [0; 96],
    };
    proposal.signature = voter.sign_raw(&proposal.signing_message(domain)).to_bytes();
    engine.observe_bft_proposal(proposal, 102, &prover).unwrap();
}

#[tokio::test]
async fn exact_candidate_rpc_serves_retained_report_target_after_highest_value_changes() {
    let (mut engine, retained, current) = cached_candidate_fixture();
    retain_report_before_changed_highest_value(&mut engine, &retained, &current);
    assert_eq!(engine.bft_candidate(0).unwrap().chunk, current);
    assert_eq!(engine.bft_session(0).unwrap().chunk_hash(), current.hash());
    assert_eq!(engine.head_hash(), current.end_block_hash);
    let spec = engine.chain_spec().clone();
    let backend = ChainBackend::new(engine, ready_prover());
    let entry = backend
        .bft_round_by_chunk(0)
        .await
        .unwrap()
        .round_change
        .unwrap();
    assert_eq!(
        entry.highest_quorum().unwrap().data.chunk_hash,
        retained.hash()
    );
    assert_eq!(
        backend
            .bft_candidate(0, Some(retained.hash()))
            .await
            .unwrap()
            .candidate
            .chunk,
        retained
    );
    let restarted = ChainBackend::new(
        Engine::open(spec, backend.snapshot_database()).unwrap(),
        ready_prover(),
    );
    assert_eq!(
        restarted
            .bft_candidate(0, Some(retained.hash()))
            .await
            .unwrap()
            .candidate
            .chunk,
        retained
    );
    restarted.with_engine_mut_for_test(|engine| {
        neutrin0_storage::Database::delete(
            engine.store_mut().db_mut(),
            neutrin0_storage::Column::BlockProofs,
            &retained.end_block_hash,
        )
        .unwrap();
    });
    assert!(
        restarted
            .bft_candidate(0, Some(retained.hash()))
            .await
            .is_err()
    );
}

/// Encoded EVM account record of `address` in `state`, as RPC storage reads
/// return it.
fn account_bytes(
    state: &neutrin0_trie::Trie,
    address: alloy_primitives::Address,
) -> Option<Vec<u8>> {
    state
        .get(&neutrin0_evm_runtime_core::state::account_key(address))
        .unwrap()
}

async fn assert_account_view(
    backend: &ChainBackend<MemoryDatabase, NativeConsensusBackend>,
    at: &neutrin0_rpc::BlockId,
    address: alloy_primitives::Address,
    expected: Option<&[u8]>,
) {
    use neutrin0_rpc::RpcBackend;
    let raw = backend
        .storage_at(&neutrin0_evm_runtime_core::state::account_key(address), at)
        .await
        .unwrap();
    assert_eq!(raw.as_deref(), expected);
    let response = backend
        .runtime_call("evm:account".to_owned(), address.as_slice().to_vec(), at)
        .await
        .unwrap();
    assert_eq!(
        response.code,
        neutrin0_runtime_abi::QueryStatus::Ok.as_u32()
    );
    // The query answers a missing account with the zero account.
    let actual: neutrin0_evm_runtime_core::state::EvmAccount =
        borsh::from_slice(&response.payload).unwrap();
    assert_eq!(
        U256::from_be_bytes(actual.balance),
        expected.map_or(U256::ZERO, |bytes| {
            let account: neutrin0_evm_runtime_core::state::EvmAccount =
                borsh::from_slice(bytes).unwrap();
            U256::from_be_bytes(account.balance)
        })
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // One finality boundary, subsequent execution, forks and restart.
async fn rpc_queries_follow_committed_roots_across_finality_forks_and_restart() {
    use neutrin0_consensus_types::{Block, Body};
    use neutrin0_evm_runtime_core::state::account_key;
    use neutrin0_primitives::{DOMAIN_PROPOSER_SIG, ZERO_HASH};
    use neutrin0_rpc::{BlockId, QueryError, RpcBackend, RuntimeCallError};
    use neutrin0_runtime_core::host::LiveTrie;
    use neutrin0_runtime_host::WasmExecutor;
    use neutrin0_storage::{Column, Database};
    use neutrin0_trie::{Hasher, Poseidon2Hasher};

    // The fixture genesis funds the development sender; the recipient starts
    // without an account.
    let sender = support::sender();
    // The fixture transfer pays one wei to this account.
    let recipient = alloy_primitives::Address::from([4; 20]);
    let live = seeded_genesis_state();
    let initial = account_bytes(live.trie(), sender).unwrap();
    let (witness, input, _) = support::fixture_with_live(
        [1; 8],
        neutrin0_runtime_host::embedded_runtime_code_hash(),
        vec![],
        30_000_000,
        &live,
    );
    let spec = witness.chain_spec.clone();
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    engine.set_programs(support::guests([1; 8], spec.runtime_code_hash));
    engine.install_genesis_state(live.trie().clone()).unwrap();
    engine.flush_trie_to_store().unwrap();
    let prover = ready_prover();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let first = &witness.blocks[0];
    let boundary = first.header.hash();
    import_fixture_block(&mut engine, first, support::executed_body(&live, &input));
    engine.finalize_chunk(0, &prover, &voter).unwrap();
    // The finalized chunk's receipt is itself the History proof.
    assert_eq!(
        engine
            .latest_history_proof()
            .unwrap()
            .expect("finalized receipt")
            .end()
            .block_hash,
        boundary
    );
    let backend = Arc::new(ChainBackend::new(engine, prover));
    let executor = tokio::task::spawn_blocking(WasmExecutor::embedded)
        .await
        .unwrap()
        .unwrap();
    backend.set_block_executor(executor);
    let finalized = backend.finalized().await.unwrap();
    assert_eq!(finalized.chunk_id, Some(0));
    assert_eq!(finalized.block_hash, boundary);
    assert_eq!(finalized.height, 1);
    assert_eq!(finalized.state_root, first.header.state_root);
    let boundary_state = backend.with_engine_mut_for_test(|engine| engine.state().clone());
    assert_eq!(boundary_state.root(), finalized.state_root);
    // The empty block charges nothing: the sender keeps its genesis record.
    assert_eq!(
        account_bytes(&boundary_state, sender).as_deref(),
        Some(initial.as_slice())
    );

    let status = backend.local_status().await.unwrap();
    assert_eq!(status.finalized_chunk_id, Some(0));
    assert_eq!(status.checkpoint_hash, neutrin0_primitives::ZERO_HASH);
    assert_ne!(status.finalized_chunk_hash, status.checkpoint_hash);
    assert_eq!(
        backend.local_progress().await.unwrap().finalized_chunk_hash,
        status.finalized_chunk_hash
    );

    let tx = borsh::to_vec(&support::transfer(0)).unwrap();
    backend.submit_transaction(tx).unwrap();
    let producer = Arc::clone(&backend);
    let second = tokio::task::spawn_blocking(move || {
        producer
            .try_produce_block(2, &voter)
            .unwrap()
            .unwrap()
            .block
    })
    .await
    .unwrap();
    assert_ne!(second.header.state_root, finalized.state_root);
    assert_eq!(backend.finalized().await.unwrap(), finalized);
    assert_eq!(backend.head().await.unwrap().hash, second.hash());
    let head_state = backend.with_engine_mut_for_test(|engine| engine.state().clone());
    assert_eq!(head_state.root(), second.header.state_root);
    let paid = account_bytes(&head_state, recipient).unwrap();
    assert_eq!(
        U256::from_be_bytes(
            borsh::from_slice::<neutrin0_evm_runtime_core::state::EvmAccount>(&paid)
                .unwrap()
                .balance
        ),
        U256::from(1)
    );
    // The local production is a candidate until proven: `latest` serves its
    // state, `safe` stays at the proven head (design 08).
    for at in [
        BlockId::Latest,
        BlockId::Hash(second.hash()),
        BlockId::Height(2),
    ] {
        assert_account_view(&backend, &at, recipient, Some(&paid)).await;
    }
    assert_account_view(&backend, &BlockId::Safe, recipient, None).await;
    for at in [
        BlockId::Finalized,
        BlockId::Hash(boundary),
        BlockId::Height(1),
        BlockId::Height(0),
        BlockId::Hash(spec.genesis_block_hash),
    ] {
        assert_account_view(&backend, &at, recipient, None).await;
        assert_account_view(&backend, &at, sender, Some(&initial)).await;
    }
    assert_eq!(
        backend.resolve_block_id(&BlockId::Finalized).await.unwrap(),
        Some(boundary)
    );

    // Archiving a sibling preserves the selected index for RPC and P2P reads.
    // The sibling opens the same chunk, so it selects the same certificate.
    let mut sibling = Block {
        header: second.header.clone(),
        body: Body {
            participation: second.body.participation.clone(),
            ..Body::default()
        },
    };
    neutrin0_consensus_engine::apply_body_roots(
        &mut sibling.header,
        &neutrin0_consensus_engine::compute_body_roots(&sibling.body),
    );
    // The sibling commits whatever executing it over the chunk boundary's
    // state produces: an empty body still records the selected participation.
    let (sibling_output, sibling_artifacts) = backend.with_engine_mut_for_test(|engine| {
        let (validators, _) = engine.validator_context_for_height(2).unwrap();
        let reports = engine
            .reports_for_block(&sibling.header, &sibling.body)
            .unwrap();
        let input = neutrin0_runtime_abi::RuntimeBlockInput {
            program_pieces: Vec::new(),
            proposer_address: validators[sibling.header.proposer_index as usize]
                .withdrawal_credentials,
            active_validators: validators,
            participation_acks: engine
                .participation_acknowledgements(2, &sibling.body)
                .unwrap(),
            context: neutrin0_prover_chunk::execution::runtime_context(
                &sibling.header,
                engine.canonical_boundary(1).unwrap(),
            ),
            evidence_anchor: engine.evidence_anchor(2).unwrap(),
            chain_id: spec.chain_id,
            block_height: 2,
            block_gas_limit: spec.genesis_gas_limit,
            participation: reports
                .as_ref()
                .map(|(participation, _)| participation.clone()),
            proving: reports.map(|(_, proving)| proving),
            transactions: Vec::new(),
        };
        let parent = engine.store().state_at(finalized.state_root);
        let live = LiveTrie::from_trie(parent);
        let mut traced = neutrin0_runtime_core::host::TracingState::new(&live);
        let result = neutrin0_evm_runtime_core::execute_block(&input, &mut traced);
        (result.output, result.artifacts)
    });
    sibling.body.artifacts = sibling_artifacts;
    sibling.header.state_root = sibling_output.post_state_root;
    sibling.header.gas_used = sibling_output.gas_used;
    sibling.header.receipts_root = sibling_output.receipts_root;
    sibling.header.runtime_extra = sibling_output.consensus_candidates_root;
    sibling.header.inputs_root =
        neutrin0_prover_chunk::execution::output_inputs_root(&sibling_output);
    neutrin0_consensus_engine::apply_body_roots(
        &mut sibling.header,
        &neutrin0_consensus_engine::compute_body_roots(&sibling.body),
    );
    let message = spec
        .consensus_domain()
        .signing_message(DOMAIN_PROPOSER_SIG, &sibling.hash());
    sibling.header.signature = neutrin0_crypto::bls::SecretKey::key_gen(&[42; 32], &[])
        .unwrap()
        .sign(&message)
        .to_bytes();
    backend.with_engine_mut_for_test(|engine| {
        // Keep the produced block selected: fork choice would otherwise be
        // free to replay the archived sibling as the head.
        support_block(engine.fork_choice_mut_for_test(), second.hash());
        engine
            .import_block(&sibling, &native_executor::NativeExecutor)
            .unwrap();
        assert_eq!(
            engine.store().get_block_hash_by_height(2).unwrap(),
            Some(second.hash())
        );
        assert_eq!(engine.head_hash(), second.hash());
    });
    assert_eq!(
        backend.header_by_height(2).await.unwrap(),
        Some(second.header.clone())
    );
    assert_eq!(
        backend.block_by_height(2).await.unwrap(),
        Some(second.clone())
    );
    assert_account_view(&backend, &BlockId::Height(2), recipient, Some(&paid)).await;
    assert_account_view(&backend, &BlockId::Hash(sibling.hash()), recipient, None).await;

    // Complete publications come first: the proven page under either branch
    // ends at the unproven second block, which follows as a candidate.
    let page = backend
        .blocks_by_range(1, 16, second.hash())
        .await
        .unwrap()
        .blocks;
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].block.hash(), boundary);
    // The unproven local production is served only as a candidate (design 08).
    let page = backend
        .blocks_by_range(2, 16, second.hash())
        .await
        .expect("a candidate page is served under the pending head");
    assert_eq!(page.blocks, Vec::new());
    assert_eq!(page.candidates.len(), 1);
    assert_eq!(page.candidates[0].block.hash(), second.hash());
    // The executed sibling has a write set and no receipt: a candidate too.
    let page = backend
        .blocks_by_range(2, 1, sibling.hash())
        .await
        .expect("a candidate page is served under the sibling branch");
    assert_eq!(page.blocks, Vec::new());
    assert_eq!(page.candidates.len(), 1);
    assert_eq!(page.candidates[0].block.hash(), sibling.hash());
    assert!(matches!(
        backend.blocks_by_range(1, 1, [99; 32]).await,
        Err(neutrin0_sync::SyncBackendError::NotAvailable(_))
    ));
    let snapshot_client = ChainBackend::new(
        Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap(),
        ready_prover(),
    );
    // The client's own head is genesis, so its `Latest` view needs the
    // genesis state; the finalized root is the first block's state.
    let genesis_values =
        transfer_snapshot(backend.as_ref(), &snapshot_client, spec.genesis_state_root).await;
    assert!(genesis_values.contains(&initial));
    let old_values =
        transfer_snapshot(backend.as_ref(), &snapshot_client, finalized.state_root).await;
    assert!(old_values.contains(&initial));
    assert!(!old_values.contains(&paid));
    assert_eq!(
        snapshot_client
            .storage_at(&account_key(sender), &BlockId::Safe)
            .await
            .unwrap(),
        Some(initial.clone())
    );
    let head_values =
        transfer_snapshot(backend.as_ref(), &snapshot_client, second.header.state_root).await;
    assert!(head_values.contains(&paid));
    assert!(!head_values.contains(&initial));
    assert!(snapshot_client.engine_state_invariant_holds());
    assert_eq!(
        snapshot_client
            .storage_at(&account_key(sender), &BlockId::Safe)
            .await
            .unwrap(),
        Some(initial.clone())
    );
    let bad_item = neutrin0_consensus_types::bootstrap::StateItem::node([99; 32]);
    assert!(matches!(
        backend.state_nodes([99; 32], &[bad_item]).await,
        Err(neutrin0_sync::SyncBackendError::NotAvailable(_))
    ));
    let too_many = vec![bad_item; 129];
    assert!(matches!(
        backend.state_nodes(finalized.state_root, &too_many).await,
        Err(neutrin0_sync::SyncBackendError::InvalidRequest(_))
    ));

    let database = backend.with_engine_mut_for_test(|engine| engine.store().db().clone());
    let reopened = ChainBackend::new(Engine::open(spec, database).unwrap(), ready_prover());
    let executor = tokio::task::spawn_blocking(WasmExecutor::embedded)
        .await
        .unwrap()
        .unwrap();
    reopened.set_block_executor(executor);
    assert_eq!(reopened.finalized().await.unwrap(), finalized);
    assert_account_view(&reopened, &BlockId::Finalized, recipient, None).await;
    assert_account_view(&reopened, &BlockId::Height(2), recipient, Some(&paid)).await;
    assert_eq!(
        reopened
            .storage_at(b"missing", &BlockId::Hash(ZERO_HASH))
            .await,
        Err(QueryError::BlockNotFound)
    );

    reopened.with_engine_mut_for_test(|engine| {
        engine
            .store_mut()
            .put_body(&second.hash(), &Body::default())
            .unwrap();
    });
    assert!(matches!(
        reopened.block_by_hash(second.hash()).await,
        Err(QueryError::Storage(_))
    ));

    reopened.with_engine_mut_for_test(|engine| {
        engine
            .store_mut()
            .db_mut()
            .delete(Column::Blocks, &second.hash())
            .unwrap();
        engine
            .store_mut()
            .db_mut()
            .delete(Column::TrieNodes, &second.header.state_root)
            .unwrap();
    });
    assert_eq!(
        reopened.block_by_hash(second.hash()).await,
        Err(QueryError::BodyUnavailable)
    );
    // The latest head's state was not retained across the restart; the
    // safe (proven) head, the finalized block, still answers (design 08).
    assert_eq!(
        reopened
            .storage_at(&account_key(recipient), &BlockId::Latest)
            .await,
        Err(QueryError::StateUnavailable)
    );
    assert_eq!(
        reopened
            .storage_at(&account_key(recipient), &BlockId::Safe)
            .await,
        Ok(None)
    );
    assert_eq!(
        reopened
            .runtime_call(
                "evm:account".to_owned(),
                recipient.as_slice().to_vec(),
                &BlockId::Latest
            )
            .await,
        Err(RuntimeCallError::Query(QueryError::StateUnavailable))
    );
    assert!(matches!(
        reopened.blocks_by_range(2, 1, second.hash()).await,
        Err(neutrin0_sync::SyncBackendError::NotAvailable(_))
    ));
    assert!(matches!(
        reopened
            .state_nodes(
                second.header.state_root,
                &[neutrin0_consensus_types::bootstrap::StateItem::value(
                    Poseidon2Hasher::hash_value(&paid)
                )]
            )
            .await,
        Err(neutrin0_sync::SyncBackendError::NotAvailable(_))
    ));

    // A corrupt or missing leaf value fails the read that reaches it
    // explicitly rather than answering from a different state.
    let value_hash = Poseidon2Hasher::hash_value(&initial);
    reopened.with_engine_mut_for_test(|engine| {
        engine
            .store_mut()
            .db_mut()
            .put(Column::StateValues, &value_hash, b"corrupt")
            .unwrap();
    });
    assert!(matches!(
        reopened
            .storage_at(&account_key(sender), &BlockId::Finalized)
            .await,
        Err(QueryError::Storage(_))
    ));
    reopened.with_engine_mut_for_test(|engine| {
        engine
            .store_mut()
            .db_mut()
            .delete(Column::StateValues, &value_hash)
            .unwrap();
    });
    assert_eq!(
        reopened
            .storage_at(&account_key(sender), &BlockId::Finalized)
            .await,
        Err(QueryError::StateUnavailable)
    );
    reopened.with_engine_mut_for_test(|engine| {
        for hash in [second.hash(), boundary] {
            engine
                .store_mut()
                .db_mut()
                .delete(Column::Headers, &hash)
                .unwrap();
        }
    });
    assert!(matches!(reopened.head().await, Err(QueryError::Storage(_))));
    assert!(matches!(
        reopened.finalized().await,
        Err(QueryError::Storage(_))
    ));
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Proof rejection, branch finalization and restart share one fixture.
async fn imported_finality_selects_a_proven_archived_fork_and_survives_restart() {
    use neutrin0_consensus_types::Block;
    use neutrin0_rpc::RpcBackend;
    use neutrin0_runtime_host::WasmExecutor;
    let (mut producer, witness, input) = engine_with_input();
    let prover = ready_prover();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    let finalized = producer.finalize_chunk(0, &prover, &voter).unwrap();
    let genesis = seeded_genesis_state();
    let remote = Block {
        header: witness.blocks[0].header.clone(),
        body: support::executed_body(&genesis, &input),
    };
    let (local, _) = sibling_at_slot(&witness, &input, &genesis, 2);
    let mut follower = genesis_engine(witness.chain_spec.clone());
    follower.set_programs(support::guests(
        [1; 8],
        neutrin0_runtime_host::embedded_runtime_code_hash(),
    ));
    follower
        .import_block(&local, &native_executor::NativeExecutor)
        .unwrap();
    // Explicit support keeps the local block selected until finality names
    // the remote one.
    support_block(follower.fork_choice_mut_for_test(), local.hash());
    follower
        .import_block(&remote, &native_executor::NativeExecutor)
        .unwrap();
    let proof = producer
        .store()
        .get_block_proof(&remote.hash())
        .unwrap()
        .unwrap();
    follower
        .store_mut()
        .put_block_proof(&remote.hash(), &proof)
        .unwrap();
    follower
        .store_mut()
        .put_block_state(&remote.hash(), BlockState::Proven)
        .unwrap();
    follower
        .store_mut()
        .put_state_diff(
            &remote.hash(),
            &neutrin0_consensus_types::BlockStateDiff {
                height: 1,
                block_hash: remote.hash(),
                state_root_before: witness.chain_spec.genesis_state_root,
                state_root_after: remote.header.state_root,
                writes: Vec::new(),
            },
        )
        .unwrap();
    let backend = ChainBackend::new(follower, ready_prover());
    let executor = tokio::task::spawn_blocking(WasmExecutor::embedded)
        .await
        .unwrap()
        .unwrap();
    backend.set_block_executor(executor);
    assert_eq!(
        backend.local_status().await.unwrap().head_block_hash,
        local.hash()
    );
    let mut invalid = finalized.chunk_proof.clone();
    invalid.proof_bytes.push(1);
    assert!(
        backend
            .verify_and_import_chunk_proof(invalid, neutrin0_network::PeerId::random())
            .await
            .is_err()
    );
    assert_eq!(
        backend.local_status().await.unwrap().head_block_hash,
        local.hash()
    );
    assert_eq!(
        backend.local_status().await.unwrap().finalized_chunk_id,
        None
    );
    backend
        .verify_and_import_chunk_proof(
            finalized.chunk_proof.clone(),
            neutrin0_network::PeerId::random(),
        )
        .await
        .unwrap();
    assert_eq!(
        backend.header_by_height(1).await.unwrap(),
        Some(remote.header.clone())
    );
    assert_eq!(
        backend.local_status().await.unwrap().head_block_hash,
        remote.hash()
    );
    assert_eq!(backend.finalized().await.unwrap().block_hash, remote.hash());
    // The replaced local block never had a receipt: under its branch it is
    // served only as a candidate (design 08), while the certified block is
    // served as a complete publication.
    let page = backend
        .blocks_by_range(1, 1, local.hash())
        .await
        .expect("a candidate page is served under the replaced branch");
    assert_eq!(page.blocks, Vec::new());
    assert_eq!(page.candidates.len(), 1);
    assert_eq!(page.candidates[0].block.hash(), local.hash());
    assert_eq!(
        backend
            .blocks_by_range(1, 1, remote.hash())
            .await
            .unwrap()
            .blocks[0]
            .block
            .hash(),
        remote.hash()
    );
    let restarted = ChainBackend::new(
        Engine::open(witness.chain_spec, backend.snapshot_database()).unwrap(),
        ready_prover(),
    );
    assert_eq!(
        restarted.local_status().await.unwrap().head_block_hash,
        remote.hash()
    );
    assert_eq!(
        restarted.local_status().await.unwrap().finalized_chunk_id,
        Some(0)
    );
    assert_eq!(
        restarted.finalized().await.unwrap().block_hash,
        remote.hash()
    );
}

async fn transfer_snapshot(
    source: &impl neutrin0_sync::SyncBackend,
    target: &impl neutrin0_sync::SyncBackend,
    root: neutrin0_primitives::Hash,
) -> Vec<Vec<u8>> {
    use neutrin0_consensus_types::bootstrap::{StateItem, StateItemKind};
    let mut items = if root == neutrin0_primitives::ZERO_HASH {
        Vec::new()
    } else {
        vec![StateItem::node(root)]
    };
    let mut values = Vec::new();
    loop {
        let response = source.state_nodes(root, &items).await.unwrap();
        for entry in response
            .entries
            .iter()
            .filter(|entry| entry.item.kind == StateItemKind::Value)
        {
            values.push(entry.bytes.as_slice().to_vec());
        }
        let progress = target
            .import_state_nodes(root, items, response.entries.to_vec())
            .await
            .unwrap();
        if progress.root_complete {
            return values;
        }
        items = progress.next_items;
    }
}

#[tokio::test]
async fn delayed_leader_proposal_after_finality_is_neutral() {
    let (mut engine, witness) = engine();
    engine.set_programs(support::guests(
        [1; 8],
        neutrin0_runtime_host::embedded_runtime_code_hash(),
    ));
    let proposal = witness.finality_cert.proposal.clone();
    let backend = ChainBackend::new(engine, ready_prover());
    backend.validate_bft_proposal_hint(&proposal).await.unwrap();
    let voter = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    backend.with_engine_mut_for_test(|engine| {
        engine.finalize_chunk(0, &ready_prover(), &voter).unwrap();
    });
    assert!(matches!(
        backend.validate_bft_proposal_hint(&proposal).await,
        Err(neutrin0_sync::SyncBackendError::NotAvailable(_))
    ));
    assert!(matches!(
        backend
            .ingest_bft_message(neutrin0_consensus_types::BftMessage::Proposal(Box::new(
                proposal
            )))
            .await,
        Err(neutrin0_sync::SyncBackendError::NotAvailable(_))
    ));
}

/// Weight `block` and its descendants through one chunk vote so the test chooses
/// the head; a later call replaces the earlier support.
fn support_block(
    fork_choice: &mut neutrin0_consensus_fork_choice::ForkChoice,
    block: neutrin0_primitives::BlockHash,
) {
    let zero = neutrin0_primitives::ZERO_HASH;
    let chunk = neutrin0_consensus_types::Chunk {
        chunk_id: 0,
        start_height: 0,
        end_height: 0,
        start_state_root: zero,
        end_state_root: zero,
        start_block_hash: block,
        end_block_hash: block,
        block_hash_root: zero,
        block_proof_root: zero,
        vrf_proof_root: zero,
        active_validator_set_root: zero,
        next_validator_set_root: zero,
        next_identity_sanctions_root: zero,
        da_root: zero,
    };
    let chunk_hash = fork_choice.add_chunk(&chunk);
    fork_choice.add_vote(
        0,
        neutrin0_consensus_fork_choice::ChunkVote {
            data: neutrin0_consensus_types::FinalityVoteData {
                chunk_id: 0,
                round: 0,
                chunk_hash,
                selection: [0; 32],
                phase: neutrin0_consensus_types::FinalityVotePhase::Precommit,
            },
            weight: 100,
        },
    );
}
