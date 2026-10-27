//! Deterministic bootstrap admission races; no proof receipt is accepted here.

use super::super::state_sync_tests;
use super::{BootstrapRuntime, ChainBackend};
use neutrin0_consensus_engine::{Engine, ProposerKey, RetentionPolicy};
use neutrin0_consensus_types::{
    BlockProof, BlockProofPublicInputs, Chunk, FinalityVotePhase, Header, NilVote,
    NilVoteAttestation, NilVoteData,
    history_proof::{ChainBinding, ConsensusBoundary, ExecutionPrograms},
    signed_artifacts::SignedArtifact,
};
use neutrin0_proof_system::{
    MockBlockProof, MockProofSystem, ProofError, ProofSystem, UnsupportedExecutor,
};
use neutrin0_storage::{Column, Database, MemoryDatabase};
use neutrin0_sync::{EvidenceProofAcceptance, SyncBackendError};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};

fn backend<P>(proof_system: P) -> ChainBackend<MemoryDatabase, P>
where
    P: ProofSystem + Send + Sync + 'static,
{
    let spec = state_sync_tests::spec();
    let chain = ChainBinding::new(&spec);
    let backend = ChainBackend::new(
        Engine::genesis(spec, MemoryDatabase::new()).unwrap(),
        proof_system,
    );
    *backend.bootstrap.lock().unwrap() = Some(BootstrapRuntime {
        chain,
        configured: None,
        max_future_drift_secs: 30,
        fetching: false,
        pending: None,
    });
    backend.set_local_voter(ProposerKey::from_ikm(&[6; 32], 0).unwrap());
    backend
}

/// Stop production after its optimistic pending check, before its engine lock.
struct PausingProofSystem {
    entered: mpsc::Sender<()>,
    resume: Mutex<mpsc::Receiver<()>>,
    paused: AtomicBool,
}

#[tokio::test]
async fn production_rechecks_operator_pause_after_optimistic_admission() {
    use neutrin0_rpc::management::ManagementRequest;
    for request in [
        ManagementRequest::PauseSigning,
        ManagementRequest::PauseProduction,
    ] {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let backend = Arc::new(backend(PausingProofSystem {
            entered: entered_tx,
            resume: Mutex::new(resume_rx),
            paused: AtomicBool::new(true),
        }));
        backend.proof_system.paused.store(false, Ordering::Release);
        backend.set_block_executor(UnsupportedExecutor);
        let producer = Arc::clone(&backend);
        let task = std::thread::spawn(move || {
            producer.try_produce_block(1, &ProposerKey::from_ikm(&[6; 32], 0).unwrap())
        });
        entered_rx.recv().unwrap();
        backend.apply_management(&request).unwrap();
        resume_tx.send(()).unwrap();
        assert!(task.join().unwrap().unwrap().is_none());
        assert_eq!(backend.head_height(), 0);
    }
}

#[tokio::test]
async fn operator_resume_does_not_clear_bootstrap_barrier() {
    use neutrin0_rpc::management::ManagementRequest;
    let backend = backend(MockProofSystem);
    backend.set_block_executor(UnsupportedExecutor);
    backend.bootstrap_fetch(true);
    backend
        .apply_management(&ManagementRequest::PauseSigning)
        .unwrap();
    let status = backend
        .apply_management(&ManagementRequest::ResumeSigning)
        .unwrap();
    assert!(!status.signing_paused);
    assert!(status.bootstrap_pending);
    assert!(!status.validator_active);
    assert!(
        backend
            .try_produce_block(1, &ProposerKey::from_ikm(&[6; 32], 0).unwrap())
            .unwrap()
            .is_none()
    );
}

impl ProofSystem for PausingProofSystem {
    type BlockProof = MockBlockProof;
    type ChunkProof = Vec<u8>;

    fn prove_block(
        &self,
        witness: &[u8],
        inputs: &BlockProofPublicInputs,
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<MockBlockProof, ProofError> {
        MockProofSystem.prove_block(witness, inputs, prover_address)
    }

    fn verify_block(
        &self,
        proof: &MockBlockProof,
        inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        MockProofSystem.verify_block(proof, inputs)
    }

    fn block_statement(
        &self,
        proof: &MockBlockProof,
    ) -> Result<neutrin0_runtime_abi::BlockReceiptStatement, ProofError> {
        MockProofSystem.block_statement(proof)
    }

    fn programs(&self) -> Option<neutrin0_consensus_types::history_proof::GuestPrograms> {
        if !self.paused.swap(true, Ordering::AcqRel) {
            self.entered.send(()).unwrap();
            self.resume.lock().unwrap().recv().unwrap();
        }
        None
    }
}

#[tokio::test]
async fn production_rechecks_barrier_after_passing_optimistic_admission() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let backend = Arc::new(backend(PausingProofSystem {
        entered: entered_tx,
        resume: Mutex::new(resume_rx),
        // Construction also asks for this key; arm the pause afterwards.
        paused: AtomicBool::new(true),
    }));
    backend.proof_system.paused.store(false, Ordering::Release);
    backend.set_block_executor(UnsupportedExecutor);
    let producer = Arc::clone(&backend);
    let task = std::thread::spawn(move || {
        producer.try_produce_block(1, &ProposerKey::from_ikm(&[6; 32], 0).unwrap())
    });
    entered_rx.recv().unwrap();
    backend.bootstrap_fetch(true);
    resume_tx.send(()).unwrap();
    // Without the locked recheck this reaches the installed executor and errors.
    assert!(task.join().unwrap().unwrap().is_none());
    assert_eq!(backend.head_height(), 0);
    assert_eq!(
        backend.with_engine(|engine| engine
            .store()
            .db()
            .iter_column(Column::SigningJournal)
            .unwrap()),
        Vec::<(Vec<u8>, Vec<u8>)>::new()
    );
}

fn candidate() -> Chunk {
    Chunk {
        next_identity_sanctions_root: [0; 32],

        chunk_id: 0,
        start_height: 1,
        end_height: 1,
        start_state_root: [1; 32],
        end_state_root: [2; 32],
        start_block_hash: [3; 32],
        end_block_hash: [4; 32],
        block_hash_root: [5; 32],
        block_proof_root: [6; 32],
        vrf_proof_root: [7; 32],
        active_validator_set_root: state_sync_tests::spec().genesis_validator_set_root,
        next_validator_set_root: state_sync_tests::spec().genesis_validator_set_root,
        da_root: [8; 32],
    }
}

#[tokio::test]
async fn stale_bft_admission_cannot_reserve_a_vote_or_open_a_session() {
    let backend = Arc::new(backend(MockProofSystem));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let voter = Arc::clone(&backend);
    let task = std::thread::spawn(move || {
        assert!(!voter.bootstrap_pending());
        entered_tx.send(()).unwrap();
        resume_rx.recv().unwrap();
        // This is the same guarded commit used after async chunk preparation.
        voter.with_live_engine_mut(|engine| {
            engine
                .open_bft_session_at(candidate(), 0)
                .map_err(|error| SyncBackendError::Rejected(error.to_string()))
        })
    });
    entered_rx.recv().unwrap();
    backend.bootstrap_fetch(true);
    resume_tx.send(()).unwrap();
    assert!(matches!(
        task.join().unwrap(),
        Err(SyncBackendError::NotAvailable(_))
    ));
    backend.with_engine(|engine| {
        assert!(engine.bft_session(0).is_none());
        for column in [Column::SigningJournal, Column::BftSessions] {
            assert_eq!(
                engine.store().db().iter_column(column).unwrap(),
                Vec::<(Vec<u8>, Vec<u8>)>::new()
            );
        }
    });
    backend.bootstrap_fetch(false);
    assert_eq!(backend.with_live_engine_mut(|_| Ok(7)).unwrap(), 7);
}

#[tokio::test]
async fn barrier_waits_for_an_admitted_engine_mutation_to_finish() {
    let backend = Arc::new(backend(MockProofSystem));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let mutation_backend = Arc::clone(&backend);
    let mutation = std::thread::spawn(move || {
        mutation_backend
            .with_live_engine_mut(|_| {
                entered_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                // Fetching cannot flip while this admitted mutation holds the engine.
                assert!(!mutation_backend.bootstrap_pending());
                Ok(())
            })
            .unwrap();
    });
    entered_rx.recv().unwrap();
    let barrier_backend = Arc::clone(&backend);
    let barrier = std::thread::spawn(move || barrier_backend.bootstrap_fetch(true));
    resume_tx.send(()).unwrap();
    mutation.join().unwrap();
    barrier.join().unwrap();
    assert!(backend.bootstrap_pending());
}

fn nil_source() -> SignedArtifact {
    let signer = ProposerKey::from_ikm(&[6; 32], 0).unwrap();
    let domain = state_sync_tests::spec().consensus_domain();
    let data = NilVoteData {
        chunk_id: 0,
        round: 0,
        phase: FinalityVotePhase::Prevote,
    };
    let signature = signer.sign_raw(&data.signing_message(domain)).to_bytes();
    let mut attestation = NilVoteAttestation {
        validator_index: 0,
        vote: data.clone(),
        vote_signature: signature,
        signature: [0; 96],
    };
    attestation.signature = signer
        .sign_raw(&attestation.signing_message(domain))
        .to_bytes();
    SignedArtifact::NilVote(NilVote {
        data,
        signature,
        aggregation_bits: neutrin0_primitives::BitVec::from_bytes(1, vec![1]).unwrap(),
        attestations: vec![attestation],
    })
}

#[tokio::test]
async fn reporter_history_created_by_an_admitted_source_write_does_not_block_bootstrap() {
    let backend = Arc::new(backend(MockProofSystem));
    backend.with_engine_mut(|engine| {
        engine
            .set_retention_policy(RetentionPolicy::Reporter)
            .unwrap();
    });
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let source = nil_source();
    let source_id = source.id();
    let writer = Arc::clone(&backend);
    let write = std::thread::spawn(move || {
        writer
            .with_live_engine_mut(|engine| {
                entered_tx.send(()).unwrap();
                resume_rx.recv().unwrap();
                engine
                    .retain_signed_artifact(&source, false)
                    .map_err(super::super::storage_error)
            })
            .unwrap()
    });
    entered_rx.recv().unwrap();
    let downloading = Arc::clone(&backend);
    let fetch = std::thread::spawn(move || downloading.bootstrap_fetch(true));
    resume_tx.send(()).unwrap();
    write.join().unwrap();
    fetch.join().unwrap();
    // A reporter keeps its evidence across a snapshot jump (design 18), so
    // retained history does not hold it to continuous following.
    assert!(backend.bootstrap_pending());
    backend.with_engine(|engine| {
        assert!(engine.reporter_has_history().unwrap());
        assert!(
            engine
                .store()
                .signed_artifact(&source_id)
                .unwrap()
                .is_some()
        );
    });
}

/// A source accepted before fetching began but observed afterwards must not
/// create reporter history that the checkpoint installation would discard.
#[tokio::test]
async fn signed_source_observation_rechecks_the_bootstrap_barrier() {
    let backend = backend(MockProofSystem);
    backend.with_engine_mut(|engine| {
        engine
            .set_retention_policy(RetentionPolicy::Reporter)
            .unwrap();
    });
    let source = nil_source();
    backend.bootstrap_fetch(true);
    assert!(backend.bootstrap_pending());
    backend
        .observe_signed_source_accountability(&source, source.id(), Some(0))
        .await;
    backend.with_engine(|engine| {
        assert!(!engine.reporter_has_history().unwrap());
        assert_eq!(
            engine
                .store()
                .db()
                .iter_column(Column::ReporterSources)
                .unwrap(),
            [] as [(Vec<u8>, Vec<u8>); 0]
        );
    });
    // Outside the barrier the same observation is retained.
    backend.bootstrap_fetch(false);
    backend
        .observe_signed_source_accountability(&source, source.id(), Some(0))
        .await;
    assert!(backend.with_engine(|engine| engine.reporter_has_history().unwrap()));
}

fn prevote(tag: u8) -> neutrin0_consensus_types::FinalityVote {
    let signer = ProposerKey::from_ikm(&[6; 32], 0).unwrap();
    let domain = state_sync_tests::spec().consensus_domain();
    let data = neutrin0_consensus_types::FinalityVoteData {
        chunk_id: 0,
        round: 0,
        phase: FinalityVotePhase::Prevote,
        chunk_hash: [tag; 32],
        selection: [0; 32],
    };
    neutrin0_consensus_types::FinalityVote {
        proof_manifests: Vec::new(),
        attestations: vec![signer.attest_vote(domain, data.clone(), Vec::new(), None)],
        aggregation_bits: neutrin0_primitives::BitVec::from_bytes(1, vec![1]).unwrap(),
        signature: signer.sign_finality_vote(domain, &data),
        data,
    }
}

/// A vote that passed the optimistic entry check but is observed after
/// fetching began records nothing in the slashing monitor.
#[tokio::test]
async fn vote_observation_rechecks_the_bootstrap_barrier() {
    let backend = backend(MockProofSystem);
    backend.bootstrap_fetch(true);
    assert_eq!(backend.observe_value_vote_offences(&prevote(1)), Vec::new());
    backend.bootstrap_fetch(false);
    // Nothing was recorded, so the conflicting vote establishes no offence.
    assert_eq!(backend.observe_value_vote_offences(&prevote(2)), Vec::new());
    // Observed outside the barrier, the first vote now conflicts.
    assert!(matches!(
        backend.observe_value_vote_offences(&prevote(1)).as_slice(),
        [neutrin0_consensus_types::SlashingEvidence::DoublePrevote {
            validator_index: 0,
            ..
        }]
    ));
}

struct PausedVerdictProofSystem {
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    resume: Mutex<mpsc::Receiver<()>>,
}

impl ProofSystem for PausedVerdictProofSystem {
    type BlockProof = MockBlockProof;
    type ChunkProof = Vec<u8>;

    fn prove_block(
        &self,
        witness: &[u8],
        inputs: &BlockProofPublicInputs,
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<MockBlockProof, ProofError> {
        MockProofSystem.prove_block(witness, inputs, prover_address)
    }

    fn verify_block(
        &self,
        proof: &MockBlockProof,
        inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        MockProofSystem.verify_block(proof, inputs)
    }

    fn block_statement(
        &self,
        proof: &MockBlockProof,
    ) -> Result<neutrin0_runtime_abi::BlockReceiptStatement, ProofError> {
        MockProofSystem.block_statement(proof)
    }

    fn classify_block_rejection(
        &self,
        proof: &BlockProof,
        expected: &neutrin0_consensus_types::history_proof::VkDigest,
    ) -> Result<Option<neutrin0_consensus_types::ProofRejectionReason>, ProofError> {
        self.entered
            .lock()
            .unwrap()
            .take()
            .unwrap()
            .send(())
            .unwrap();
        self.resume.lock().unwrap().recv().unwrap();
        MockProofSystem.classify_block_rejection(proof, expected)
    }
}

fn proof_source<P: ProofSystem + Send + Sync + 'static>(
    backend: &ChainBackend<MemoryDatabase, P>,
) -> SignedArtifact {
    backend.with_engine_mut(|engine| {
        engine.set_programs(neutrin0_consensus_types::history_proof::GuestPrograms {
            execution: ExecutionPrograms {
                fact: [1; 8],
                evidence: [2; 8],
                block: [3; 8],
            },
            chunk: [4; 8],
        });
        let spec = engine.chain_spec();
        let mut header = Header {
            height: 1,
            slot: 1,
            parent_hash: spec.genesis_block_hash,
            proposer_index: 0,
            vrf_proof: [0; 96],
            state_root: spec.genesis_state_root,
            transactions_root: [0; 32],
            votes_root: [0; 32],
            da_root: [0; 32],
            runtime_extra: [0; 32],
            inputs_root: [0; 32],
            receipts_root: neutrin0_consensus_types::Body::default()
                .artifacts
                .commitment(),
            gas_used: 0,
            gas_limit: spec.genesis_gas_limit,
            timestamp: 1,
            signature: [0; 96],
        };
        header.signature = ProposerKey::from_ikm(&[6; 32], 0)
            .unwrap()
            .sign_proposer_message(spec.consensus_domain(), &header.hash());
        // Authentication recomputes the context from the header and the
        // genesis boundary, so the proof must commit exactly that context.
        let context = neutrin0_consensus_types::runtime::ConsensusExecutionContext {
            slot: header.slot,
            timestamp: header.timestamp,
            parent_block_hash: header.parent_hash,
            proposer_vrf_output: neutrin0_vrf::proof_output(&header.vrf_proof),
            finalized: ConsensusBoundary::genesis(spec),
        };
        let public_inputs = BlockProofPublicInputs {
            context: Box::new(context),
            chain_id: spec.chain_id,
            height: header.height,
            parent_block_hash: header.parent_hash,
            block_hash: header.hash(),
            state_root_before: spec.genesis_state_root,
            state_root_after: header.state_root,
            transactions_root: header.transactions_root,
            receipt_root: header.receipts_root,
            da_root: header.da_root,
            vm_code_hash: spec.runtime_code_hash,
            block_program: [3; 8],
            gas_used: header.gas_used,
            gas_limit: header.gas_limit,
            proposer_address: spec.initial_validators[0].withdrawal_credentials,
            runtime_extra: header.runtime_extra,
            inputs_root: [0; 32],
        };
        let receipt = MockProofSystem
            .prove_block(&[], &public_inputs, public_inputs.proposer_address)
            .unwrap();
        let statement = MockProofSystem.block_statement(&receipt).unwrap();
        // The header was authenticated before enabling reporter retention; the
        // proof's asynchronous verdict is its first selective source write.
        engine.store_mut().put_header(&header).unwrap();
        SignedArtifact::BlockProof(BlockProof {
            height: header.height,
            block_hash: header.hash(),
            prover_address: statement.prover_address,
            statement_key: neutrin0_consensus_engine::statement_key(&statement),
            public_inputs,
            proof_bytes: borsh::to_vec(&receipt).unwrap(),
        })
    })
}

#[tokio::test]
async fn signed_source_rechecks_bootstrap_after_async_proof_classification() {
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let backend = Arc::new(backend(PausedVerdictProofSystem {
        entered: Mutex::new(Some(entered_tx)),
        resume: Mutex::new(resume_rx),
    }));
    let source = proof_source(&backend);
    backend.with_engine_mut(|engine| {
        engine
            .set_retention_policy(RetentionPolicy::Reporter)
            .unwrap();
    });
    let accepting = Arc::clone(&backend);
    let accept = tokio::spawn(async move { accepting.accept_signed_source(source).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), entered_rx)
        .await
        .unwrap()
        .unwrap();
    backend.bootstrap_fetch(true);
    assert!(backend.bootstrap_pending());
    resume_tx.send(()).unwrap();
    assert_eq!(accept.await.unwrap(), EvidenceProofAcceptance::Deferred);
    backend.with_engine(|engine| {
        assert!(!engine.reporter_has_history().unwrap());
        for column in [Column::SignedArtifacts, Column::ReporterSources] {
            assert_eq!(
                engine.store().db().iter_column(column).unwrap(),
                [] as [(Vec<u8>, Vec<u8>); 0]
            );
        }
    });
}
