//! A paused receipt verifier must leave real HTTP RPC batches available.

use super::*;
use jsonrpsee::{
    core::{client::ClientT, params::BatchRequestBuilder},
    rpc_params,
};
use neutrin0_rpc::build_module;
use neutrin0_runtime_host::WasmExecutor;
use std::time::Duration;

struct PausedVerification {
    pause_at: usize,
    calls: AtomicUsize,
    proofs: Arc<AtomicUsize>,
    started: Arc<tokio::sync::Notify>,
    resume: Mutex<mpsc::Receiver<()>>,
}

impl ProofSystem for PausedVerification {
    type BlockProof = BlockReceiptStatement;
    type ChunkProof = neutrin0_consensus_types::history_proof::ChunkReceiptStatement;

    fn programs(&self) -> Option<neutrin0_consensus_types::history_proof::GuestPrograms> {
        ready_prover().programs()
    }

    fn history_domain(
        &self,
        spec: &neutrin0_primitives::ChainSpec,
    ) -> Result<neutrin0_consensus_types::history_proof::ProofDomain, ProofError> {
        super::certified_execution::NativePipelineProofs.history_domain(spec)
    }

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
        inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.pause_at {
            self.started.notify_one();
            self.resume
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(30))
                .expect("test must release the verifier");
        }
        ready_prover().verify_block(proof, inputs)
    }

    fn prove_consensus_chunk(
        &self,
        _: &[Self::BlockProof],
        _: &[Self::ChunkProof],
        _: &ConsensusWitness,
        _: neutrin0_primitives::Hash,
    ) -> Result<Self::ChunkProof, ProofError> {
        self.proofs.fetch_add(1, Ordering::SeqCst);
        Err(ProofError::Unsupported)
    }

    fn block_statement(
        &self,
        proof: &Self::BlockProof,
    ) -> Result<BlockReceiptStatement, ProofError> {
        Ok(proof.clone())
    }
}

#[tokio::test]
async fn cold_receipt_and_native_certification_leave_four_rpc_batches_available() {
    // Call one is receipt preparation, call two is native certification's
    // independent receipt check; call three reconstructs the proof job.
    // None may hold the engine while paused.
    for pause_at in [1, 2, 3] {
        let (engine, witness) = engine();
        let started = Arc::new(tokio::sync::Notify::new());
        let (resume, receiver) = mpsc::channel();
        let backend = Arc::new(ChainBackend::new(
            engine,
            PausedVerification {
                pause_at,
                calls: AtomicUsize::new(0),
                proofs: Arc::default(),
                started: started.clone(),
                resume: Mutex::new(receiver),
            },
        ));
        backend.set_block_executor(WasmExecutor::embedded().unwrap());
        if pause_at == 3 {
            backend.set_prove_foreign_blocks(true);
            backend.set_prover_address(neutrin0_primitives::runtime_account([77; 20]));
            backend.set_proving_policy(neutrin0_node::config::ProvingPolicy {
                chunk_fallback_secs: 0,
                ..Default::default()
            });
        }

        let server = jsonrpsee::server::Server::builder()
            .build("127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr().unwrap();
        let handle = server.start(build_module(backend.clone()).unwrap());
        let certification = tokio::spawn({
            let backend = backend.clone();
            async move {
                backend
                    .verify_and_import_execution_certificate(witness.finality_cert)
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(5), started.notified())
            .await
            .unwrap();
        let mut readers = tokio::task::JoinSet::new();
        for _ in 0..4 {
            readers.spawn(async move {
                let client = jsonrpsee::http_client::HttpClientBuilder::default()
                    .build(format!("http://{address}"))
                    .unwrap();
                let mut batch = BatchRequestBuilder::new();
                batch
                    .insert("eth_getBlockByNumber", rpc_params!["finalized", false])
                    .unwrap();
                batch
                    .insert("eth_getBlockReceipts", rpc_params!["0x1"])
                    .unwrap();
                batch
                    .insert(
                        "eth_call",
                        rpc_params![
                            serde_json::json!({"to": format!("0x{}", "00".repeat(20))}),
                            "0x1"
                        ],
                    )
                    .unwrap();
                batch
                    .insert(
                        "eth_feeHistory",
                        rpc_params!["0x1", "latest", Vec::<f64>::new()],
                    )
                    .unwrap();
                let result = client
                    .batch_request::<serde_json::Value>(batch)
                    .await
                    .unwrap();
                result.into_iter().collect::<Vec<_>>()
            });
        }
        let reads = tokio::time::timeout(Duration::from_secs(2), async {
            let mut results = Vec::new();
            while let Some(result) = readers.join_next().await {
                results.push(result);
            }
            results
        })
        .await;
        // Release even when the deadline assertion fails, so no worker is left
        // waiting during runtime shutdown.
        resume.send(()).unwrap();
        for client in reads.expect("RPC must finish before the verifier is released") {
            for response in client.unwrap() {
                assert!(response.is_ok(), "{response:?}");
            }
        }
        certification.await.unwrap().unwrap();
        assert_eq!(
            backend.with_engine_mut_for_test(|engine| engine.finalized_next_chunk_id()),
            0
        );
        handle.stop().unwrap();
        handle.stopped().await;
    }
}

#[test]
fn validated_certificate_rechecks_sources_and_finality_before_commit() {
    use super::certified_execution::NativePipelineProofs;
    use neutrin0_consensus_engine::ValidatedExecutionChunk;
    for finalize in [false, true] {
        let (mut engine, witness) = engine();
        let mut prepared = engine
            .prepare_consensus_chunk(0, &NativePipelineProofs)
            .unwrap();
        prepared.witness.finality_cert = witness.finality_cert;
        let checked = ValidatedExecutionChunk::validate(&prepared, &NativePipelineProofs).unwrap();
        if finalize {
            engine
                .finalize_chunk(
                    0,
                    &NativePipelineProofs,
                    &ProposerKey::from_ikm(&[42; 32], 0).unwrap(),
                )
                .unwrap();
        } else {
            engine
                .store_mut()
                .put_block_state(
                    &prepared.witness.blocks[0].header.hash(),
                    BlockState::BlockProduced,
                )
                .unwrap();
        }
        assert!(engine.commit_execution_certificate(checked, None).is_err());
        assert!(engine.certified_execution_boundary().is_none());
    }
}

#[test]
fn certification_uses_commit_time_and_keeps_the_original_time_on_duplicates() {
    use super::certified_execution::NativePipelineProofs;
    use neutrin0_consensus_engine::ValidatedExecutionChunk;
    let (mut engine, witness) = engine();
    engine.set_wall_clock(|| 1);
    let mut prepared = engine
        .prepare_consensus_chunk(0, &NativePipelineProofs)
        .unwrap();
    prepared.witness.finality_cert = witness.finality_cert;
    let checked = ValidatedExecutionChunk::validate(&prepared, &NativePipelineProofs).unwrap();
    engine.set_wall_clock(|| 42);
    assert!(engine.commit_execution_certificate(checked, None).unwrap());
    assert_eq!(engine.execution_certified_at_secs(), Some(42));
    let duplicate = ValidatedExecutionChunk::validate(&prepared, &NativePipelineProofs).unwrap();
    engine.set_wall_clock(|| 99);
    assert!(
        !engine
            .commit_execution_certificate(duplicate, None)
            .unwrap()
    );
    assert_eq!(engine.execution_certified_at_secs(), Some(42));
}

#[tokio::test]
async fn bootstrap_started_during_chunk_preparation_prevents_prover_launch() {
    let (engine, witness) = engine();
    let started = Arc::new(tokio::sync::Notify::new());
    let proofs = Arc::new(AtomicUsize::new(0));
    let (resume, receiver) = mpsc::channel();
    let backend = Arc::new(ChainBackend::new(
        engine,
        PausedVerification {
            pause_at: 3,
            calls: AtomicUsize::new(0),
            proofs: proofs.clone(),
            started: started.clone(),
            resume: Mutex::new(receiver),
        },
    ));
    backend.set_block_executor(WasmExecutor::embedded().unwrap());
    backend
        .initialize_bootstrap(&neutrin0_node::config::BootstrapConfig::default())
        .unwrap();
    backend.set_prove_foreign_blocks(true);
    backend.set_prover_address(neutrin0_primitives::runtime_account([77; 20]));
    backend.set_proving_policy(neutrin0_node::config::ProvingPolicy {
        chunk_fallback_secs: 0,
        ..Default::default()
    });
    backend
        .verify_and_import_execution_certificate(witness.finality_cert)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .unwrap();
    backend.bootstrap_fetch(true).await;
    resume.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut metrics = String::new();
            backend.metrics().proof_pipeline.render(&mut metrics);
            if metrics
                .lines()
                .any(|line| line == "neutrin0_chunk_queue_pending 0")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("preparation must leave the queue after bootstrap starts");
    assert_eq!(proofs.load(Ordering::SeqCst), 0);
}
