//! The public listener's per-client admission over real TCP: one address's
//! connection bound, the request budget it shares across its connections and
//! the WebSocket session slots.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use neutrin0_consensus_types::{Block, Header};
use neutrin0_primitives::{BlockHash, ChainId, Hash, Height, Validator};
use neutrin0_rpc::{
    BlockId, FinalizedInfo, HeadInfo, QueryError, RpcBackend, RpcConfig, RuntimeCallError,
    RuntimeCallResponse, SubmitError,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A backend that answers `system_chainId` and holds nothing else.
struct ChainOnly;

#[async_trait]
impl RpcBackend for ChainOnly {
    fn chain_id(&self) -> ChainId {
        7
    }
    fn runtime_code_hash(&self) -> Option<Hash> {
        None
    }
    fn runtime_available(&self) -> bool {
        false
    }
    fn mempool_len(&self) -> usize {
        0
    }
    async fn head(&self) -> Result<HeadInfo, QueryError> {
        Err(QueryError::ArtifactUnavailable)
    }
    async fn finalized(&self) -> Result<FinalizedInfo, QueryError> {
        Err(QueryError::ArtifactUnavailable)
    }
    async fn active_validator_set(&self) -> Vec<Validator> {
        Vec::new()
    }
    async fn resolve_block_id(&self, _id: &BlockId) -> Result<Option<BlockHash>, QueryError> {
        Ok(None)
    }
    async fn header_by_hash(&self, _hash: BlockHash) -> Result<Option<Header>, QueryError> {
        Ok(None)
    }
    async fn header_by_height(&self, _height: Height) -> Result<Option<Header>, QueryError> {
        Ok(None)
    }
    async fn block_by_hash(&self, _hash: BlockHash) -> Result<Option<Block>, QueryError> {
        Ok(None)
    }
    async fn block_by_height(&self, _height: Height) -> Result<Option<Block>, QueryError> {
        Ok(None)
    }
    async fn storage_at(&self, _key: &[u8], _at: &BlockId) -> Result<Option<Vec<u8>>, QueryError> {
        Ok(None)
    }
    async fn submit_transaction(&self, _bytes: Vec<u8>) -> Result<Hash, SubmitError> {
        Err(SubmitError::Full)
    }
    async fn runtime_call(
        &self,
        _method: String,
        _args: Vec<u8>,
        _at: &BlockId,
    ) -> Result<RuntimeCallResponse, RuntimeCallError> {
        Err(RuntimeCallError::RuntimeNotConfigured)
    }
}

const CHAIN_ID: &str = r#"{"jsonrpc":"2.0","id":1,"method":"system_chainId","params":[]}"#;
const UPGRADE: &str = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n\
    Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";

fn post(body: &str) -> String {
    format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

async fn start(config: RpcConfig) -> (SocketAddr, jsonrpsee::server::ServerHandle) {
    // The server binds its own listener; take a port that was just free.
    let listen = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let handle = neutrin0_rpc::serve(Arc::new(ChainOnly), RpcConfig { listen, ..config })
        .await
        .unwrap();
    (listen, handle)
}

/// Send `request` on `stream` and read one response's status line and
/// body, or `None` once the server closed the connection.
async fn exchange(stream: &mut TcpStream, request: &str) -> Option<(String, String)> {
    tokio::time::timeout(Duration::from_secs(5), async {
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut received = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            if let Some(end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&received[..end]).into_owned();
                let length = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                let body = end + 4..end + 4 + length;
                if received.len() >= body.end {
                    let status = head.lines().next().unwrap().to_owned();
                    return Some((
                        status,
                        String::from_utf8_lossy(&received[body]).into_owned(),
                    ));
                }
            }
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                return None;
            }
            received.extend_from_slice(&chunk[..read]);
        }
    })
    .await
    .expect("the server answers or closes")
}

#[tokio::test]
async fn one_address_holds_bounded_connections_that_share_one_budget() {
    let (listen, handle) = start(RpcConfig {
        max_connections_per_client: 2,
        requests_per_second_per_client: 1,
        ..RpcConfig::default()
    })
    .await;
    let mut first = TcpStream::connect(listen).await.unwrap();
    let mut second = TcpStream::connect(listen).await.unwrap();
    for stream in [&mut first, &mut second] {
        let (status, body) = exchange(stream, &post(CHAIN_ID)).await.unwrap();
        assert!(status.contains("200"), "{status}");
        assert!(body.contains(r#""result":7"#), "{body}");
    }
    // A third connection from the same address is closed unanswered.
    let mut third = TcpStream::connect(listen).await.unwrap();
    assert_eq!(exchange(&mut third, &post(CHAIN_ID)).await, None);
    // The two requests spent the address's burst, whichever connection
    // asks next.
    let (_, body) = exchange(&mut first, &post(CHAIN_ID)).await.unwrap();
    assert!(body.contains("-32006"), "{body}");
    handle.stop().unwrap();
}

#[tokio::test]
async fn a_websocket_session_holds_its_slot_until_it_closes() {
    let (listen, handle) = start(RpcConfig {
        max_ws_connections: 1,
        ..RpcConfig::default()
    })
    .await;
    let mut session = TcpStream::connect(listen).await.unwrap();
    let (status, _) = exchange(&mut session, UPGRADE).await.unwrap();
    assert!(status.contains("101"), "{status}");
    let mut refused = TcpStream::connect(listen).await.unwrap();
    let (status, _) = exchange(&mut refused, UPGRADE).await.unwrap();
    assert!(status.contains("429"), "{status}");
    // Plain requests do not need a session slot.
    let mut plain = TcpStream::connect(listen).await.unwrap();
    let (status, _) = exchange(&mut plain, &post(CHAIN_ID)).await.unwrap();
    assert!(status.contains("200"), "{status}");
    drop(session);
    // The slot frees once the server sees the session close.
    let reopened = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut stream = TcpStream::connect(listen).await.unwrap();
            if exchange(&mut stream, UPGRADE)
                .await
                .is_some_and(|(status, _)| status.contains("101"))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(reopened.is_ok());
    handle.stop().unwrap();
}
