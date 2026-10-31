//! Followers certify execution without starting their own Chunk prover.

use super::*;
use neutrin0_consensus_engine::RetentionPolicy;
use std::time::Duration;

#[tokio::test]
async fn followers_only_prove_certified_chunks_after_explicit_opt_in() {
    for retention in [
        RetentionPolicy::Pruned,
        RetentionPolicy::Archive,
        RetentionPolicy::Reporter,
    ] {
        let (engine, witness) = engine();
        let (decisions, receiver) = mpsc::channel();
        decisions.send(true).unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let backend = Arc::new(ChainBackend::new(
            engine,
            NativeConsensusBackend {
                decisions: Mutex::new(receiver),
                attempts: Arc::clone(&attempts),
            },
        ));
        backend.set_retention_policy(retention).unwrap();
        backend.set_prover_address(neutrin0_primitives::runtime_account([77; 20]));
        backend.set_block_executor(neutrin0_runtime_host::WasmExecutor::embedded().unwrap());
        if retention == RetentionPolicy::Reporter {
            backend
                .initialize_reporter(neutrin0_primitives::runtime_account([77; 20]))
                .unwrap();
        }
        // Zero delay makes an accidental fallback prover start immediately.
        backend.set_proving_policy(neutrin0_node::config::ProvingPolicy {
            chunk_fallback_secs: 0,
            ..Default::default()
        });
        backend
            .verify_and_import_execution_certificate(witness.finality_cert.clone())
            .await
            .unwrap();
        backend.with_engine_mut_for_test(|engine| {
            assert!(engine.can_extend_execution());
            assert_eq!(engine.certified_execution_boundary().unwrap().height, 1);
            assert_eq!(engine.finalized_next_chunk_id(), 0);
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 0);

        // The same certificate must still drive proving on an opted-in node.
        backend.set_prove_foreign_blocks(true);
        let actor = tokio::spawn(Arc::clone(&backend).run_consensus_proof_notifications());
        backend
            .verify_and_import_execution_certificate(witness.finality_cert)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while backend
                .local_status()
                .await
                .unwrap()
                .finalized_chunk_id
                .is_none()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        actor.abort();
        assert!(actor.await.unwrap_err().is_cancelled());
    }
}
