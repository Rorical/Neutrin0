//! Durable journal retention and disk recovery, without synthetic proof acceptance.
use super::{ChainBackend, state_sync_tests::spec};
use jsonrpsee::{server::Server, ws_client::WsClientBuilder};
use neutrin0_consensus_engine::{
    Engine,
    store::{CHAIN_EVENT_WINDOW, ChainStore},
};
use neutrin0_consensus_types::Header;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::MockProofSystem;
use neutrin0_rpc::{
    QueryError, RpcBackend, client::ChainEventsApiClient, types::ChainNotificationJson,
};
use neutrin0_storage::{Batch, MemoryDatabase, RocksDbDatabase};
use std::{sync::Arc, time::Duration};

fn header(height: u64, parent_hash: Hash) -> Header {
    Header {
        height,
        slot: height,
        parent_hash,
        state_root: [0; 32],
        proposer_index: 0,
        vrf_proof: [0; 96],
        transactions_root: [0; 32],
        votes_root: [0; 32],
        da_root: [0; 32],
        runtime_extra: [0; 32],
        inputs_root: [0; 32],
        receipts_root: [0; 32],
        gas_used: 0,
        gas_limit: 1_000_000,
        timestamp: height * 4,
        signature: [0; 96],
    }
}

#[tokio::test]
async fn slow_subscription_requests_reset_after_retention_and_http_can_page_retained_events() {
    let backend = Arc::new(ChainBackend::new(
        Engine::genesis(spec(), MemoryDatabase::new()).unwrap(),
        MockProofSystem,
    ));
    backend.initialize_chain_events().unwrap();
    let initial = backend.chain_events(None, 1).await.unwrap();
    let module = neutrin0_rpc::server::build_module(backend.clone()).unwrap();
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", server.local_addr().unwrap());
    let handle = server.start(module);
    let client = WsClientBuilder::default().build(&endpoint).await.unwrap();
    let mut subscription = client
        .subscribe_events(Some(initial.next.clone()))
        .await
        .unwrap();
    assert!(matches!(
        subscription.next().await.unwrap().unwrap(),
        ChainNotificationJson::Snapshot { .. }
    ));
    // Storage publication drives this journal; no test receipt is finalized.
    backend.with_engine_mut_for_test(|engine| {
        let genesis = engine.chain_spec().genesis_block_hash;
        let mut parent = genesis;
        for height in 1..=CHAIN_EVENT_WINDOW + 1 {
            let header = header(height, parent);
            engine.store_mut().put_header(&header).unwrap();
            parent = header.hash();
            engine
                .store_mut()
                .commit_tip(parent, genesis, Batch::new())
                .unwrap();
        }
    });
    let reset = tokio::time::timeout(Duration::from_secs(5), subscription.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let ChainNotificationJson::ResetRequired {
        reason,
        status: Some(status),
    } = reset
    else {
        panic!("expected explicit reset");
    };
    assert_eq!(reason, "expired");
    assert!(
        matches!(backend.chain_events(Some(initial.next), 1).await, Err(QueryError::EventCursor { reason, .. }) if reason == "expired")
    );
    let page = backend
        .chain_events(Some(status.replay_from), 2)
        .await
        .unwrap();
    assert_eq!(page.events.len(), 2);
    assert!(page.has_more);
    let next = backend
        .chain_events(Some(page.next.clone()), 2)
        .await
        .unwrap();
    assert_eq!(next.events[0].previous_head, Some(page.events[1].head));
    assert_ne!(next.events[0].cursor, page.events[1].cursor);
    assert!(matches!(
        backend.chain_events(None, 257).await,
        Err(QueryError::InvalidRequest(_))
    ));
    handle.stop().unwrap();
    handle.stopped().await;
}

#[test]
fn rocksdb_restart_preserves_identity_sequence_and_snapshot() {
    let path = std::env::temp_dir().join(format!(
        "neutrin0-chain-events-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
    ));
    let genesis = [1; 32];
    let state;
    {
        let mut store = ChainStore::new(RocksDbDatabase::open(&path).unwrap());
        store.commit_tip(genesis, genesis, Batch::new()).unwrap();
        store.put_finalized_head(genesis).unwrap();
        store
            .initialize_chain_events([2; 32], [3; 32], genesis)
            .unwrap();
        let header = header(1, genesis);
        store.put_header(&header).unwrap();
        store
            .commit_tip(header.hash(), genesis, Batch::new())
            .unwrap();
        state = store.chain_event_state().unwrap().unwrap();
    }
    {
        let mut reopened = ChainStore::new(RocksDbDatabase::open(&path).unwrap());
        reopened
            .initialize_chain_events([9; 32], [3; 32], genesis)
            .unwrap();
        assert_eq!(reopened.chain_event_state().unwrap().unwrap(), state);
        assert_eq!(
            reopened.chain_event(state.next - 1).unwrap().unwrap().head,
            state.head
        );
    }
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn subscription_capacity_is_shared_across_connections_and_released_on_unsubscribe() {
    let backend = Arc::new(ChainBackend::new(
        Engine::genesis(spec(), MemoryDatabase::new()).unwrap(),
        MockProofSystem,
    ));
    backend.initialize_chain_events().unwrap();
    let server = Server::builder().build("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", server.local_addr().unwrap());
    let handle = server.start(neutrin0_rpc::server::build_module(backend).unwrap());
    let client = WsClientBuilder::default().build(&endpoint).await.unwrap();
    let other = WsClientBuilder::default().build(&endpoint).await.unwrap();
    let mut subscriptions = Vec::new();
    for _ in 0..64 {
        let mut subscription = client.subscribe_events(None).await.unwrap();
        assert!(matches!(
            subscription.next().await.unwrap().unwrap(),
            ChainNotificationJson::Snapshot { .. }
        ));
        subscriptions.push(subscription);
    }
    let error = other.subscribe_events(None).await.unwrap_err();
    let jsonrpsee::core::client::Error::Call(error) = error else {
        panic!("expected capacity error");
    };
    assert_eq!(error.code(), -32005);
    subscriptions.pop().unwrap().unsubscribe().await.unwrap();
    let subscription = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(subscription) = other.subscribe_events(None).await {
                break subscription;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    subscription.unsubscribe().await.unwrap();
    for subscription in subscriptions {
        subscription.unsubscribe().await.unwrap();
    }
    handle.stop().unwrap();
    handle.stopped().await;
}
