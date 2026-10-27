//! PostgreSQL integration tests. Use only a disposable database supplied explicitly by the test runner.
#![deny(unsafe_code)]
#![allow(
    clippy::too_many_lines,
    reason = "Acceptance scenarios keep restart/reorg assertions beside their shared fixture"
)]
mod common;
use common::{Fixture, config, input, store};
use neutrin0_indexer::{
    Error, api,
    db::query::{Filter, Kind},
    extract,
    ingest::Indexer,
    model::hex,
};
use std::sync::Arc;

#[tokio::test]
#[ignore = "requires NEUTRIN0_INDEXER_TEST_DATABASE_URL pointing to a disposable PostgreSQL database"]
async fn backfill_restart_reorg_snapshots_and_finality() {
    let config = config();
    let store = store().await;
    let source = Arc::new(Fixture::new(5, 1));
    let mut worker = Indexer::new(config.clone(), store.clone(), source.clone())
        .await
        .unwrap();
    assert!(matches!(store.writer().await, Err(Error::WriterBusy)));
    let reader = neutrin0_indexer::db::Store::open_read_only(
        &std::env::var("NEUTRIN0_INDEXER_TEST_DATABASE_URL").unwrap(),
        store.schema(),
    )
    .await
    .unwrap();
    assert_eq!(reader.state().await.unwrap().unwrap().head.height, 0);
    reader.close().await;
    assert!(!worker.step().await.unwrap());
    let partial = store.state().await.unwrap().unwrap();
    assert_eq!(partial.head.height, 2);
    assert_eq!(partial.finalized.height, 2);
    assert!(partial.cursor.is_none());
    drop(worker);
    let mut worker = Indexer::new(config.clone(), store.clone(), source.clone())
        .await
        .unwrap();
    assert!(!worker.step().await.unwrap());
    assert!(worker.step().await.unwrap());
    let state = store.state().await.unwrap().unwrap();
    assert_eq!(state.transactions, 5);
    assert_eq!(state.logs, 5);
    assert_eq!(state.gas, "105000");
    assert_eq!(state.cursor.unwrap().sequence, "1");
    assert!(store.ready().await.unwrap());
    let snapshot = store.read_view().await.unwrap();
    let first = snapshot
        .page(Kind::Blocks, Filter::default(), 2, None)
        .await
        .unwrap();
    assert_eq!(
        first
            .records
            .iter()
            .map(|row| row.height)
            .collect::<Vec<_>>(),
        vec![5, 4]
    );
    assert!(first.has_more);
    let cursor = first.records[1].cursor.clone();
    let second = snapshot
        .page(Kind::Blocks, Filter::default(), 2, Some(&cursor))
        .await
        .unwrap();
    assert_eq!(second.records[0].height, 3);
    assert!(matches!(
        snapshot
            .page(Kind::Transactions, Filter::default(), 2, Some(&cursor))
            .await,
        Err(Error::Cursor("INVALID_CURSOR_SCOPE"))
    ));
    source.fork(2, 4);
    assert!(worker.step().await.unwrap());
    // An already opened GraphQL request keeps its entire old view, including its progress cards.
    assert_eq!(snapshot.state.head.height, 5);
    assert_eq!(
        snapshot
            .page(Kind::Blocks, Filter::default(), 1, None)
            .await
            .unwrap()
            .records[0]
            .height,
        5
    );
    drop(snapshot);
    let fresh = store.read_view().await.unwrap();
    assert!(matches!(
        fresh
            .page(Kind::Blocks, Filter::default(), 2, Some(&cursor))
            .await,
        Err(Error::Cursor("STALE_CURSOR"))
    ));
    assert_eq!(fresh.state.transactions, 4);
    assert_eq!(fresh.state.logs, 4);
    assert_eq!(fresh.state.gas, "84000");
    assert_eq!(fresh.state.generation, 1);
    assert_eq!(
        fresh
            .page(
                Kind::Transactions,
                Filter {
                    finalized_only: true,
                    ..Filter::default()
                },
                100,
                None
            )
            .await
            .unwrap()
            .records
            .len(),
        2
    );
    assert_eq!(
        fresh
            .page(Kind::Logs, Filter::default(), 100, None)
            .await
            .unwrap()
            .records
            .len(),
        4
    );
    assert_eq!(
        fresh
            .page(Kind::Transfers, Filter::default(), 100, None)
            .await
            .unwrap()
            .records
            .len(),
        4
    );
    assert_eq!(
        fresh
            .page(Kind::Chunks, Filter::default(), 100, None)
            .await
            .unwrap()
            .records
            .len(),
        1
    );
    assert_eq!(
        fresh
            .page(Kind::Proofs, Filter::default(), 100, None)
            .await
            .unwrap()
            .records
            .len(),
        6
    );
    assert_eq!(
        fresh.address(&hex(&[2; 20])).await.unwrap()["transactionCount"],
        "4"
    );
    assert_eq!(
        fresh.activity(24, 3600).await.unwrap()[0]["gasUsed"],
        "84000"
    );
    let head_hash = hex(&fresh.state.head.hash.0);
    assert_eq!(
        fresh.log_data(&head_hash, 0, 0, 2).await.unwrap(),
        (32, "0xffff".into())
    );
    assert!(matches!(
        fresh.log_data(&head_hash, 0, u32::MAX, 2).await,
        Err(Error::Data(_))
    ));
    assert_eq!(
        fresh.validators().await.unwrap()[0]["effectiveStake"],
        u128::MAX.to_string()
    );
    drop(fresh);
    source.state.lock().unwrap().expire = true;
    source.state.lock().unwrap().stream = neutrin0_rpc::HashHex([12; 32]);
    assert!(worker.step().await.unwrap());
    assert_eq!(
        store
            .state()
            .await
            .unwrap()
            .unwrap()
            .cursor
            .unwrap()
            .stream_id,
        neutrin0_rpc::HashHex([12; 32])
    );
    source.state.lock().unwrap().finalized_chunks = 0;
    assert!(matches!(worker.step().await, Err(Error::SourceBehind)));
    source.state.lock().unwrap().finalized_chunks = 1;
    source.fork(0, 4);
    let error = worker.step().await.unwrap_err();
    assert!(matches!(error, Error::FinalityConflict));
    worker.record_error(&error).await.unwrap();
    assert!(!store.ready().await.unwrap());
    assert_eq!(store.state().await.unwrap().unwrap().finalized.height, 2);
    drop(worker);
    store.close().await;
}

#[tokio::test]
#[ignore = "requires NEUTRIN0_INDEXER_TEST_DATABASE_URL pointing to a disposable PostgreSQL database"]
async fn incomplete_data_never_advances_checkpoint_and_atomic_failure_leaves_no_rows() {
    let config = config();
    let store = store().await;
    let source = Arc::new(Fixture::new(3, 0));
    source.state.lock().unwrap().missing = Some(2);
    let mut worker = Indexer::new(config.clone(), store.clone(), source.clone())
        .await
        .unwrap();
    let error = worker.step().await.unwrap_err();
    worker.record_error(&error).await.unwrap();
    let state = store.state().await.unwrap().unwrap();
    assert_eq!(state.head.height, 1);
    assert!(state.cursor.is_none());
    source.state.lock().unwrap().missing = None;
    source.state.lock().unwrap().corrupt = Some(2);
    assert!(matches!(worker.step().await, Err(Error::Data(_))));
    assert_eq!(store.state().await.unwrap().unwrap().head.height, 1);
    drop(worker);
    let mut writer = store.writer().await.unwrap();
    let next = input(2, store.state().await.unwrap().unwrap().head.hash, 1);
    source.state.lock().unwrap().corrupt = None;
    let mut indexed = extract::block(source.as_ref(), &config, next.block.clone())
        .await
        .unwrap();
    indexed.logs[0].transaction_position = 9;
    assert!(matches!(
        writer.append(&indexed).await,
        Err(Error::Database(_))
    ));
    let view = store.read_view().await.unwrap();
    assert!(
        view.block(&hex(&next.block.header.block_hash.0))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(view.state.head.height, 1);
    drop(view);
    drop(writer);
    let mut worker = Indexer::new(config.clone(), store.clone(), source.clone())
        .await
        .unwrap();
    assert!(worker.step().await.unwrap());
    assert_eq!(store.state().await.unwrap().unwrap().head.height, 3);
    source.state.lock().unwrap().wrong_spec = true;
    assert!(matches!(worker.step().await, Err(Error::Binding(_))));
    assert_eq!(
        store
            .state()
            .await
            .unwrap()
            .unwrap()
            .cursor
            .unwrap()
            .sequence,
        "1"
    );
    drop(worker);
    store.close().await;
}

#[tokio::test]
#[ignore = "requires NEUTRIN0_INDEXER_TEST_DATABASE_URL pointing to a disposable PostgreSQL database"]
async fn graphql_http_lossless_queries_limits_and_delayed_proofs() {
    let mut config = config();
    config.cors_origins = vec!["https://explorer.example".into()];
    let store = store().await;
    let source = Arc::new(Fixture::new(2, 1));
    source
        .state
        .lock()
        .unwrap()
        .inputs
        .get_mut(&2)
        .unwrap()
        .receipt
        .details["logs"][0]["data"] = serde_json::json!(format!("0x{}", "ab".repeat(400)));
    source.state.lock().unwrap().delayed_proofs = true;
    let mut worker = Indexer::new(config.clone(), store.clone(), source.clone())
        .await
        .unwrap();
    assert!(worker.step().await.unwrap());
    let view = store.read_view().await.unwrap();
    assert_eq!(
        view.page(Kind::Proofs, Filter::default(), 100, None)
            .await
            .unwrap()
            .records[0]
            .data["availability"],
        "unavailable"
    );
    drop(view);
    source.state.lock().unwrap().delayed_proofs = false;
    for _ in 0..4 {
        assert!(worker.step().await.unwrap());
    }
    let view = store.read_view().await.unwrap();
    assert!(
        view.page(Kind::Proofs, Filter::default(), 100, None)
            .await
            .unwrap()
            .records
            .iter()
            .all(|row| row.data["availability"] == "available")
    );
    drop(view);
    let router = api::server::router(store.clone(), &config).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let client = reqwest::Client::new();
    let query = format!(
        "{{ status {{ indexedHeight transactionCount logCount gasUsed phase }} transactions(first:2) {{ edges {{ node {{ value nonce status rawEnvelope(offset:0,length:2) {{ totalBytes bytes }} }} }} }} tokenTransfers(first:2) {{ edges {{ node {{ amount standard from }} }} }} chunks(first:1) {{ edges {{ node {{ id certificate }} }} }} proof(locator: {{kind: \"chunk_proof\", chunk: 0}}) {{ height kind availability }} proofs(first:4) {{ edges {{ node {{ height kind availability }} }} }} logs(first:2) {{ edges {{ node {{ dataBytes dataPrefix }} }} }} address(address:\"{}\") }}",
        hex(&[2; 20])
    );
    let response = client
        .post(format!("{url}/graphql"))
        .header("Origin", "https://explorer.example")
        .json(&serde_json::json!({"query":query}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        "https://explorer.example"
    );
    let result: serde_json::Value = response.json().await.unwrap();
    assert!(result.get("errors").is_none(), "{result}");
    let data = &result["data"];
    assert_eq!(data["status"]["indexedHeight"], "2");
    assert_eq!(data["status"]["transactionCount"], "2");
    assert_eq!(
        data["transactions"]["edges"][0]["node"]["value"],
        alloy_primitives::U256::MAX.to_string()
    );
    assert_eq!(
        data["tokenTransfers"]["edges"][0]["node"]["amount"],
        alloy_primitives::U256::MAX.to_string()
    );
    assert_eq!(
        data["tokenTransfers"]["edges"][0]["node"]["from"],
        hex(&[0; 20])
    );
    assert_eq!(data["chunks"]["edges"][0]["node"]["id"], "0");
    assert_eq!(data["proof"]["kind"], "chunk_proof");
    assert_eq!(data["proof"]["height"], "2");
    assert_eq!(data["logs"]["edges"][0]["node"]["dataBytes"], "400");
    assert_eq!(
        data["logs"]["edges"][0]["node"]["dataPrefix"]
            .as_str()
            .unwrap()
            .len(),
        514
    );
    for query in [
        "{ blocks(first:101) { edges { node { height } } } }",
        "{ blocks(first:0) { edges { node { height } } } }",
        "mutation { reset }",
    ] {
        let result: serde_json::Value = client
            .post(format!("{url}/graphql"))
            .json(&serde_json::json!({"query":query}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(result.get("errors").is_some());
    }
    let body =
        serde_json::json!({"query":"{status{phase}}","variables":{"oversized":"a".repeat(65536)}});
    assert_eq!(
        client
            .post(format!("{url}/graphql"))
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE
    );
    assert!(
        client
            .get(format!("{url}/health/ready"))
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    assert!(
        client
            .get(format!("{url}/graphql/schema"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
            .contains("tokenTransfers")
    );
    stop.send(()).unwrap();
    server.await.unwrap();
    drop(worker);
    store.close().await;
}

#[tokio::test]
async fn ethereum_projection_must_match_committed_envelope_identity_and_log_order() {
    let source = Fixture::new(1, 0);
    let config = config();
    let original = source.state.lock().unwrap().inputs[&1].block.clone();
    let decoded = extract::block(&source, &config, original.clone())
        .await
        .unwrap();
    assert_eq!(
        decoded.transactions[0].value.as_deref(),
        Some(alloy_primitives::U256::MAX.to_string().as_str())
    );
    assert_eq!(
        decoded.transfers[0].amount,
        alloy_primitives::U256::MAX.to_string()
    );
    assert!(
        decoded.transactions[0]
            .receipt
            .as_ref()
            .unwrap()
            .get("logs")
            .is_none()
    );
    source
        .state
        .lock()
        .unwrap()
        .inputs
        .get_mut(&1)
        .unwrap()
        .receipt
        .details["logs"][0]["logIndex"] = serde_json::json!("0x1");
    assert!(matches!(
        extract::block(&source, &config, original.clone()).await,
        Err(Error::Data(_))
    ));
    source
        .state
        .lock()
        .unwrap()
        .inputs
        .get_mut(&1)
        .unwrap()
        .receipt
        .transaction_hash = neutrin0_rpc::HashHex([0; 32]);
    assert!(matches!(
        extract::block(&source, &config, original).await,
        Err(Error::BranchChanged)
    ));
}
