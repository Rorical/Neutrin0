//! Consensus query envelopes and replay through real transports, using the native test verifier.

use super::{engine, ready_prover};
use jsonrpsee::{rpc_params, server::Server, ws_client::WsClientBuilder};
use neutrin0_consensus_engine::ProposerKey;
use neutrin0_node::ChainBackend;
use neutrin0_primitives::blake3_256;
use neutrin0_rpc::{
    QueryError, RpcBackend,
    client::{ChainEventsApiClient, NodeApiClient, NodeClient},
    types::{ArtifactIdJson, ChainCursorJson, ChainNotificationJson, HashHex},
};
use std::{sync::Arc, time::Duration};

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One finalized fixture covers exact encodings, downloads and missing/corrupt artifacts."
)]
async fn finalized_artifacts_match_stored_borsh_and_download_over_http() {
    let (engine, _) = engine();
    let backend = Arc::new(ChainBackend::new(engine, ready_prover()));
    backend.initialize_chain_events().unwrap();
    assert!(backend.chunk(None).await.unwrap().is_none());
    assert!(backend.certificate(0).await.unwrap().is_none());
    backend
        .finalize_chunk(0, &ProposerKey::from_ikm(&[42; 32], 0).unwrap())
        .unwrap();
    let chunk = backend.chunk(None).await.unwrap().unwrap();
    assert_eq!(chunk.chunk_id, 0);
    assert!(chunk.proof_available && chunk.certificate_available);
    assert!(backend.chunk(Some(1)).await.unwrap().is_none());
    let certificate = backend.certificate(0).await.unwrap().unwrap();
    assert_eq!(certificate.chunk_hash, chunk.hash);
    assert_eq!(certificate.prevote_signers, vec![0]);
    assert_eq!(certificate.precommit_signers, vec![0]);
    let block = backend.with_engine_mut_for_test(|engine| {
        engine
            .store()
            .get_header_by_height(1)
            .unwrap()
            .unwrap()
            .hash()
    });
    let artifacts = [
        ArtifactIdJson::Certificate { chunk: 0 },
        ArtifactIdJson::ChunkProof { chunk: 0 },
        ArtifactIdJson::BlockProof {
            block: HashHex(block),
        },
    ];
    let module = neutrin0_rpc::server::build_module(backend.clone()).unwrap();
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let client = NodeClient::connect(
        &format!("http://{}", server.local_addr().unwrap()),
        Duration::from_secs(5),
    )
    .unwrap();
    let handle = server.start(module);
    let execution = client
        .rpc()
        .block_artifacts(HashHex(block))
        .await
        .unwrap()
        .unwrap();
    let expected_execution = backend.with_engine_mut_for_test(|engine| {
        let body = engine.store().get_body(&block).unwrap().unwrap();
        (
            borsh::to_vec(&body.artifacts).unwrap(),
            engine.runtime_code_hash_for(1).unwrap(),
        )
    });
    assert_eq!(execution.artifacts.0, expected_execution.0);
    assert_eq!(execution.runtime_code_hash.0, expected_execution.1);
    let decoded: neutrin0_runtime_abi::ExecutionArtifacts =
        borsh::from_slice(&execution.artifacts.0).unwrap();
    let header = client
        .rpc()
        .header(neutrin0_rpc::BlockIdJson(neutrin0_rpc::BlockId::Hash(
            block,
        )))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(decoded.commitment(), header.receipts_root.0);
    assert!(
        client
            .rpc()
            .block_artifacts(HashHex([255; 32]))
            .await
            .unwrap()
            .is_none()
    );
    for id in artifacts {
        let expected = backend.with_engine_mut_for_test(|engine| match id {
            ArtifactIdJson::Certificate { chunk } => {
                borsh::to_vec(&engine.store().get_finality_cert(chunk).unwrap().unwrap()).unwrap()
            }
            ArtifactIdJson::ChunkProof { chunk } => {
                borsh::to_vec(&engine.store().get_chunk_proof(chunk).unwrap().unwrap()).unwrap()
            }
            ArtifactIdJson::BlockProof { block } => {
                borsh::to_vec(&engine.store().get_block_proof(&block.0).unwrap().unwrap()).unwrap()
            }
        });
        let (info, bytes) = client.download_artifact(id.clone()).await.unwrap();
        let error = client
            .rpc()
            .artifact_bytes(id.clone(), HashHex([0; 32]), 0, 1)
            .await
            .unwrap_err();
        let jsonrpsee::core::client::Error::Call(error) = error else {
            panic!("expected JSON-RPC error");
        };
        assert_eq!(error.code(), -32027);
        assert_eq!(bytes, expected);
        assert_eq!(info.artifact_hash.0, blake3_256(&expected));
        assert_eq!(info.encoded_bytes, expected.len() as u64);
        assert_eq!(
            backend.artifact_bytes(id.clone(), [0; 32], 0, 10).await,
            Err(QueryError::ArtifactChanged)
        );
        assert!(matches!(
            backend
                .artifact_bytes(id.clone(), info.artifact_hash.0, 0, 0)
                .await,
            Err(QueryError::InvalidRequest(_))
        ));
        assert!(matches!(
            backend
                .artifact_bytes(id.clone(), info.artifact_hash.0, info.encoded_bytes + 1, 1)
                .await,
            Err(QueryError::InvalidRequest(_))
        ));
        let eof = backend
            .artifact_bytes(id, info.artifact_hash.0, info.encoded_bytes, 1)
            .await
            .unwrap();
        assert_eq!(eof.bytes.0, Vec::<u8>::new());
    }
    assert!(
        backend
            .artifact(ArtifactIdJson::ChunkProof { chunk: 1 })
            .await
            .unwrap()
            .is_none()
    );
    backend.with_engine_mut_for_test(|engine| {
        use neutrin0_storage::{Column, Database};
        engine
            .store_mut()
            .db_mut()
            .delete(Column::ChunkProofs, &0_u64.to_be_bytes())
            .unwrap();
    });
    assert!(
        !backend
            .chunk(Some(0))
            .await
            .unwrap()
            .unwrap()
            .proof_available
    );
    assert_eq!(
        backend
            .artifact(ArtifactIdJson::ChunkProof { chunk: 0 })
            .await,
        Err(QueryError::ArtifactUnavailable)
    );
    backend.with_engine_mut_for_test(|engine| {
        // The certificate lives once, in the chunk's historical record.
        let mut record = engine.store().historical_chunk(0).unwrap().unwrap();
        record.finality.round += 1;
        let mut batch = neutrin0_storage::Batch::new();
        batch.put(
            neutrin0_storage::Column::HistoricalChunks,
            0u64.to_be_bytes(),
            borsh::to_vec(&record).unwrap(),
        );
        engine
            .store_mut()
            .write_observed_batch(batch, false)
            .unwrap();
    });
    assert!(matches!(
        backend.certificate(0).await,
        Err(QueryError::Storage(_))
    ));
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn websocket_reconnect_replays_finality_and_rejects_invalid_cursors() {
    let (engine, _) = engine();
    let backend = Arc::new(ChainBackend::new(engine, ready_prover()));
    backend.initialize_chain_events().unwrap();
    let initial = backend.chain_events(None, 1).await.unwrap();
    assert_eq!(initial.events, Vec::new());
    let cursor = initial.next;
    for (sequence, reason) in [("00", "malformed"), ("2", "future")] {
        let bad = ChainCursorJson {
            sequence: sequence.into(),
            ..cursor.clone()
        };
        assert!(
            matches!(backend.chain_events(Some(bad), 1).await, Err(QueryError::EventCursor { reason: actual, .. }) if actual == reason)
        );
    }
    let foreign = ChainCursorJson {
        stream_id: HashHex([0; 32]),
        ..cursor.clone()
    };
    assert!(
        matches!(backend.chain_events(Some(foreign), 1).await, Err(QueryError::EventCursor { reason, .. }) if reason == "wrong_stream")
    );
    let module = neutrin0_rpc::server::build_module(backend.clone()).unwrap();
    let error = module
        .call::<_, serde_json::Value>(
            "chain_getChunk",
            rpc_params![serde_json::Value::Null, serde_json::Value::Null],
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("params"));
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", server.local_addr().unwrap());
    let handle = server.start(module);
    let client = WsClientBuilder::default().build(&endpoint).await.unwrap();
    let bad = ChainCursorJson {
        sequence: "02".into(),
        ..cursor.clone()
    };
    let error = client.subscribe_events(Some(bad)).await.unwrap_err();
    let jsonrpsee::core::client::Error::Call(error) = error else {
        panic!("expected JSON-RPC error");
    };
    assert_eq!(error.code(), -32028);
    let recovery: serde_json::Value = serde_json::from_str(error.data().unwrap().get()).unwrap();
    assert_eq!(recovery["reason"], "malformed");
    assert_eq!(recovery["status"]["latest"]["sequence"], cursor.sequence);
    let mut subscription = client.subscribe_events(Some(cursor.clone())).await.unwrap();
    assert!(
        matches!(subscription.next().await.unwrap().unwrap(), ChainNotificationJson::Snapshot { after, .. } if after == cursor)
    );
    backend
        .finalize_chunk(0, &ProposerKey::from_ikm(&[42; 32], 0).unwrap())
        .unwrap();
    let delivered = tokio::time::timeout(Duration::from_secs(5), subscription.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let ChainNotificationJson::Event { event } = delivered else {
        panic!("expected event");
    };
    assert_eq!(event.kind, "finalized");
    assert_eq!(event.finalized_chunks, 1);
    assert_eq!(event.previous_finalized_chunks, 0);
    subscription.unsubscribe().await.unwrap();
    let mut resumed = client.subscribe_events(Some(cursor.clone())).await.unwrap();
    assert!(
        matches!(resumed.next().await.unwrap().unwrap(), ChainNotificationJson::Snapshot { after, .. } if after == cursor)
    );
    assert_eq!(
        resumed.next().await.unwrap().unwrap(),
        ChainNotificationJson::Event {
            event: event.clone()
        }
    );
    resumed.unsubscribe().await.unwrap();
    let caught_up = backend.chain_events(Some(event.cursor), 1).await.unwrap();
    assert!(caught_up.events.is_empty() && !caught_up.has_more);
    handle.stop().unwrap();
    handle.stopped().await;
}

#[tokio::test]
async fn reopened_engine_preserves_the_cursor_and_finalized_replay() {
    let (engine, _) = engine();
    let backend = ChainBackend::new(engine, ready_prover());
    backend.initialize_chain_events().unwrap();
    let initial = backend.chain_events(None, 128).await.unwrap();
    backend
        .finalize_chunk(0, &ProposerKey::from_ikm(&[42; 32], 0).unwrap())
        .unwrap();
    let expected = backend
        .chain_events(Some(initial.next.clone()), 128)
        .await
        .unwrap();
    let (spec, database) = backend.with_engine_mut_for_test(|engine| {
        (engine.chain_spec().clone(), engine.store().db().clone())
    });
    let resumed = ChainBackend::new(
        neutrin0_consensus_engine::Engine::open(spec, database).unwrap(),
        ready_prover(),
    );
    resumed.initialize_chain_events().unwrap();
    assert_eq!(
        resumed.chain_events(Some(initial.next), 128).await.unwrap(),
        expected
    );
}
