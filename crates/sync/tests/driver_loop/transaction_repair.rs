use super::*;
use neutrin0_network::rpc::{RpcError, TransactionInventoryResponse, TransactionsByHashResponse};

type Reply = tokio::sync::oneshot::Sender<Result<RpcResponse, RpcError>>;

struct Harness {
    backend: MockBackend,
    events: mpsc::Sender<NetworkEvent>,
    commands: mpsc::Receiver<NetworkCommand>,
    runner: tokio::task::JoinHandle<()>,
}

impl Harness {
    fn new() -> Self {
        let backend = MockBackend::default();
        backend.inner.lock().unwrap().transaction_sync = true;
        let (commands_tx, commands) = mpsc::channel(64);
        let (events, events_rx) = mpsc::channel(64);
        let driver = SyncDriver::new(
            SyncDriverConfig::default(),
            Arc::new(backend.clone()),
            LocalProgress::default(),
            commands_tx,
            events_rx,
        );
        Self {
            backend,
            events,
            commands,
            runner: tokio::spawn(driver.run()),
        }
    }

    async fn request(&mut self) -> (RpcRequest, Reply) {
        loop {
            if let NetworkCommand::SendRpcRequest {
                request,
                response_tx,
                ..
            } = timeout(Duration::from_secs(40), self.commands.recv())
                .await
                .unwrap()
                .unwrap()
            {
                return (request, response_tx);
            }
        }
    }

    async fn connect(&mut self, peer: PeerId, status: Status) {
        self.events
            .send(NetworkEvent::PeerConnected(peer))
            .await
            .unwrap();
        let (request, reply) = self.request().await;
        assert!(matches!(request, RpcRequest::Status(_)));
        reply.send(Ok(RpcResponse::Status(status))).unwrap();
    }

    async fn stop(self) {
        drop(self.events);
        self.runner.await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn repair_retries_transport_failure_and_checks_exact_requested_hashes() {
    let mut h = Harness::new();
    h.connect(random_peer(), Status::default()).await;
    let (request, reply) = h.request().await;
    assert!(matches!(request, RpcRequest::TransactionInventory(_)));
    reply
        .send(Err(RpcError::Outbound("dropped response".into())))
        .unwrap();
    let (request, reply) = h.request().await;
    assert!(matches!(request, RpcRequest::TransactionInventory(_)));
    let bytes = vec![1, 2, 3];
    let hash = neutrin0_primitives::blake3_256(&bytes);
    reply
        .send(Ok(RpcResponse::TransactionInventory(
            TransactionInventoryResponse { hashes: vec![hash] },
        )))
        .unwrap();
    let (request, reply) = h.request().await;
    assert!(matches!(request, RpcRequest::TransactionsByHash(ref r) if r.hashes == vec![hash]));
    reply
        .send(Ok(RpcResponse::TransactionsByHash(
            TransactionsByHashResponse {
                transactions: vec![vec![9]],
            },
        )))
        .unwrap();
    // An unsolicited body cannot enter the ordinary admission path.
    let (_, reply) = h.request().await;
    assert_eq!(
        h.backend.inner.lock().unwrap().admitted_transactions,
        Vec::<Vec<u8>>::new()
    );
    reply
        .send(Ok(RpcResponse::TransactionInventory(
            TransactionInventoryResponse { hashes: vec![hash] },
        )))
        .unwrap();
    let (_, reply) = h.request().await;
    reply
        .send(Ok(RpcResponse::TransactionsByHash(
            TransactionsByHashResponse {
                transactions: vec![bytes.clone()],
            },
        )))
        .unwrap();
    let _next_poll = h.request().await;
    assert_eq!(
        h.backend.inner.lock().unwrap().admitted_transactions,
        vec![bytes]
    );
    h.stop().await;
}

#[tokio::test(start_paused = true)]
async fn disconnected_response_cannot_complete_reconnected_inventory() {
    let mut h = Harness::new();
    let peer = random_peer();
    h.connect(peer, Status::default()).await;
    let (_, old_reply) = h.request().await;
    h.events
        .send(NetworkEvent::PeerDisconnected(peer))
        .await
        .unwrap();
    h.connect(peer, Status::default()).await;
    let (_, new_reply) = h.request().await;
    old_reply
        .send(Ok(RpcResponse::TransactionInventory(
            TransactionInventoryResponse {
                hashes: vec![[9; 32]],
            },
        )))
        .unwrap();
    new_reply
        .send(Ok(RpcResponse::TransactionInventory(
            TransactionInventoryResponse::default(),
        )))
        .unwrap();
    let (request, _) = h.request().await;
    assert!(
        matches!(request, RpcRequest::TransactionInventory(_)),
        "stale response must not start a body request"
    );
    h.stop().await;
}

#[tokio::test(start_paused = true)]
async fn mismatching_chain_does_not_start_pool_queries() {
    let mut h = Harness::new();
    h.connect(
        random_peer(),
        Status {
            chain_spec_hash: [1; 32],
            ..Status::default()
        },
    )
    .await;
    assert!(
        timeout(Duration::from_secs(16), h.commands.recv())
            .await
            .is_err()
    );
    assert_eq!(
        h.backend.inner.lock().unwrap().admitted_transactions,
        Vec::<Vec<u8>>::new()
    );
    h.stop().await;
}

#[tokio::test(start_paused = true)]
async fn inventory_paginates_in_bounded_body_batches_and_rejects_regressing_cursor() {
    let mut h = Harness::new();
    h.connect(random_peer(), Status::default()).await;
    let (_, reply) = h.request().await;
    let hashes: Vec<_> = (0..128u8).map(|byte| [byte; 32]).collect();
    reply
        .send(Ok(RpcResponse::TransactionInventory(
            TransactionInventoryResponse {
                hashes: hashes.clone(),
            },
        )))
        .unwrap();
    for batch in hashes.chunks(16) {
        let (request, reply) = h.request().await;
        assert!(matches!(request, RpcRequest::TransactionsByHash(ref r) if r.hashes == batch));
        reply
            .send(Ok(RpcResponse::TransactionsByHash(
                TransactionsByHashResponse::default(),
            )))
            .unwrap();
    }
    let (request, reply) = h.request().await;
    assert!(
        matches!(request, RpcRequest::TransactionInventory(ref r) if r.after == Some([127; 32]))
    );
    reply
        .send(Ok(RpcResponse::TransactionInventory(
            TransactionInventoryResponse {
                hashes: vec![[127; 32]],
            },
        )))
        .unwrap();
    let (request, _) = h.request().await;
    assert!(
        matches!(request, RpcRequest::TransactionInventory(ref r) if r.after == Some([127; 32]))
    );
    assert_eq!(
        h.backend.inner.lock().unwrap().admitted_transactions,
        Vec::<Vec<u8>>::new()
    );
    h.stop().await;
}

#[tokio::test(start_paused = true)]
async fn unordered_or_duplicate_inventory_never_fetches_bodies() {
    for hashes in [vec![[2; 32], [1; 32]], vec![[1; 32], [1; 32]]] {
        let mut h = Harness::new();
        h.connect(random_peer(), Status::default()).await;
        let (_, reply) = h.request().await;
        reply
            .send(Ok(RpcResponse::TransactionInventory(
                TransactionInventoryResponse { hashes },
            )))
            .unwrap();
        let (request, _) = h.request().await;
        assert!(matches!(request, RpcRequest::TransactionInventory(_)));
        h.stop().await;
    }
}

#[tokio::test(start_paused = true)]
async fn a_peer_whose_bodies_are_all_refused_backs_off_across_reconnects() {
    let mut h = Harness::new();
    let peer = random_peer();
    h.connect(peer, Status::default()).await;
    let bytes = vec![1, 2, 3];
    let hash = neutrin0_primitives::blake3_256(&bytes);
    let (_, reply) = h.request().await;
    reply
        .send(Ok(RpcResponse::TransactionInventory(
            TransactionInventoryResponse { hashes: vec![hash] },
        )))
        .unwrap();
    let (request, reply) = h.request().await;
    assert!(matches!(request, RpcRequest::TransactionsByHash(_)));
    h.backend.inner.lock().unwrap().admission_error =
        Some(SyncBackendError::Rejected("malformed".into()));
    reply
        .send(Ok(RpcResponse::TransactionsByHash(
            TransactionsByHashResponse {
                transactions: vec![bytes],
            },
        )))
        .unwrap();
    // Let the driver judge the bodies before the peer leaves.
    tokio::time::sleep(Duration::from_secs(1)).await;
    // Neither the poll nor a reconnect asks it again within its backoff.
    h.events
        .send(NetworkEvent::PeerDisconnected(peer))
        .await
        .unwrap();
    h.connect(peer, Status::default()).await;
    let asked = timeout(Duration::from_secs(20), async {
        loop {
            if let Some(NetworkCommand::SendRpcRequest { request, .. }) = h.commands.recv().await
                && !matches!(request, RpcRequest::Status(_))
            {
                return request;
            }
        }
    })
    .await;
    assert!(asked.is_err(), "asked again: {asked:?}");
    h.stop().await;
}
