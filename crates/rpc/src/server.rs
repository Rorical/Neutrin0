//! JSON-RPC server wiring.
//!
//! [`build_module`] returns an [`RpcModule`] populated with all
//! Neutrin0 methods, parameterised by an [`Arc<dyn RpcBackend>`].
//! [`serve`] additionally binds a TCP listener and spawns the
//! jsonrpsee server task; the returned [`ServerHandle`] terminates the
//! server when dropped.
//!
//! All methods share these characteristics:
//!
//! - Inputs are validated up front; invalid params return JSON-RPC
//!   error code `-32602`.
//! - Backend errors use distinct server error codes for block lookup,
//!   unavailable data, storage, runtime invocation, and transaction admission.
//!   A `runtime_call` deadline expiry (`-32012`) is distinct from a runtime
//!   execution failure (`-32014`).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use jsonrpsee::core::BoxError;
use jsonrpsee::server::http::response::too_many_requests;
use jsonrpsee::server::middleware::rpc::RpcServiceBuilder;
use jsonrpsee::server::ws::is_upgrade_request;
use jsonrpsee::server::{
    BatchRequestConfig, HttpResponse, Methods, RpcModule, Server, ServerConfig, ServerHandle,
    StopHandle, TowerService, serve_with_graceful_shutdown,
};
use tower::Service as _;

use crate::backend::RpcBackend;

mod clients;
mod consensus;
pub(crate) mod errors;
mod ethereum;
mod governor;
mod methods;

use clients::Clients;
use governor::{RequestGovernor, RequestLimits};

/// Responses a WebSocket session buffers while its client is slow to read.
/// With [`RpcConfig::max_ws_connections`] sessions of at most
/// [`RpcConfig::max_response_body_size`] each, this bounds the memory slow
/// readers can hold (32 x 4 x 15 MiB, about 1.9 GiB, by default).
const MESSAGE_BUFFER: u32 = 4;

/// Live subscriptions of each kind across all connections. Every one polls
/// the backend outside the request governor, so the total stays fixed.
const SUBSCRIPTIONS: usize = 64;
/// Live subscriptions of each kind one client may hold.
const SUBSCRIPTIONS_PER_CLIENT: usize = 8;
/// Live subscriptions one connection may hold.
const SUBSCRIPTIONS_PER_CONNECTION: u32 = 16;

/// Bind address + tuning knobs for the JSON-RPC server.
#[derive(Clone, Debug)]
pub struct RpcConfig {
    /// `host:port` to bind on. Use `127.0.0.1:9933` for local-only
    /// access; `0.0.0.0:9933` to listen on every interface.
    pub listen: SocketAddr,
    /// Maximum concurrent connections. Reasonable default: 200.
    pub max_connections: u32,
    /// WebSocket sessions at once (default 32). Each buffers up to four
    /// responses while its client is slow to read.
    pub max_ws_connections: u32,
    /// Connections one client may hold (default 16): an IPv4 address or an
    /// IPv6 /64. Trusted proxies count only toward `max_connections`.
    pub max_connections_per_client: u32,
    /// Proxies whose connections name their client as the last hop of
    /// `X-Forwarded-For`; every other peer is the client itself.
    pub trusted_proxies: Vec<IpAddr>,
    /// Maximum size of a single request body in bytes (default 10 MiB).
    pub max_request_body_size: u32,
    /// Maximum size of a single response body in bytes (default 15 MiB).
    pub max_response_body_size: u32,
    /// Requests allowed to execute at once across every connection
    /// (default 64). Excess requests fail immediately with `-32005`.
    pub max_concurrent_requests: u32,
    /// Sustained request rate per client (default 50/s, burst twice that),
    /// across all its connections. Requests over the budget fail with
    /// `-32006`.
    pub requests_per_second_per_client: u32,
    /// Maximum entries in one JSON-RPC batch (default 16).
    pub max_batch_requests: u32,
    /// Wall-clock budget for one `runtime_call` (default 2 s). The WASM
    /// fuel cap bounds CPU; this bounds the caller's wait.
    pub runtime_call_timeout: Duration,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9933".parse().expect("default listen parses"),
            max_connections: 200,
            max_ws_connections: 32,
            max_connections_per_client: 16,
            trusted_proxies: Vec::new(),
            max_request_body_size: 10 * 1024 * 1024,
            max_response_body_size: 15 * 1024 * 1024,
            max_concurrent_requests: 64,
            requests_per_second_per_client: 50,
            max_batch_requests: 16,
            runtime_call_timeout: Duration::from_secs(2),
        }
    }
}

/// Errors raised while building or starting the RPC server.
#[derive(Debug, thiserror::Error)]
pub enum RpcStartError {
    /// jsonrpsee's transport-layer setup failed.
    #[error("rpc transport error: {0}")]
    Transport(String),
    /// Failed to register one of the canonical methods.
    #[error("rpc method registration failed: {0}")]
    Registration(String),
}

/// Build a fully-populated [`RpcModule`] without binding a listener.
/// Useful for in-process tests that exercise method dispatch via
/// `RpcModule::call` without spinning up a TCP socket.
pub fn build_module(backend: Arc<dyn RpcBackend>) -> Result<RpcModule<RpcContext>, RpcStartError> {
    build_module_with(backend, RpcConfig::default().runtime_call_timeout)
}

/// [`build_module`] with an explicit `runtime_call` wall-clock budget.
///
/// # Errors
/// Returns [`RpcStartError::Registration`] when a method name collides.
pub fn build_module_with(
    backend: Arc<dyn RpcBackend>,
    runtime_call_timeout: Duration,
) -> Result<RpcModule<RpcContext>, RpcStartError> {
    let mut module = RpcModule::new(RpcContext {
        backend,
        runtime_call_timeout,
        ethereum_filters: Arc::new(ethereum::Filters::default()),
        chain_subscriptions: Arc::new(clients::ClientSlots::new(
            SUBSCRIPTIONS,
            SUBSCRIPTIONS_PER_CLIENT,
        )),
        ethereum_subscriptions: Arc::new(clients::ClientSlots::new(
            SUBSCRIPTIONS,
            SUBSCRIPTIONS_PER_CLIENT,
        )),
    });
    methods::register_methods(&mut module)?;
    Ok(module)
}

/// Build the RPC module and start the jsonrpsee server. The returned
/// handle keeps the server alive until it is dropped or `stop()` is
/// called.
pub async fn serve(
    backend: Arc<dyn RpcBackend>,
    config: RpcConfig,
) -> Result<ServerHandle, RpcStartError> {
    serve_with_metrics(
        backend,
        config,
        Arc::new(crate::metrics::RpcMetrics::default()),
    )
    .await
}

/// Start the RPC server with externally accessible fixed-cardinality metrics.
///
/// The listener's own accept loop admits each TCP connection against the
/// listener's and its client's bounds and hands it to jsonrpsee with the
/// client attached,
/// so rate limits follow the client across connections and a WebSocket
/// session takes one of the separate session slots for its connection's life.
pub async fn serve_with_metrics(
    backend: Arc<dyn RpcBackend>,
    config: RpcConfig,
    metrics: Arc<crate::metrics::RpcMetrics>,
) -> Result<ServerHandle, RpcStartError> {
    let module = build_module_with(backend, config.runtime_call_timeout)?;
    let server_config = ServerConfig::builder()
        .max_request_body_size(config.max_request_body_size)
        .max_response_body_size(config.max_response_body_size)
        .set_message_buffer_capacity(MESSAGE_BUFFER)
        .max_subscriptions_per_connection(SUBSCRIPTIONS_PER_CONNECTION)
        .set_batch_request_config(BatchRequestConfig::Limit(config.max_batch_requests.max(1)))
        .build();
    let limits = RequestLimits::new(
        config.max_concurrent_requests,
        config.requests_per_second_per_client,
        config.max_connections,
    );
    let rpc_middleware = RpcServiceBuilder::new().layer_fn(move |service| {
        RequestGovernor::new(service, Arc::clone(&metrics), limits.clone())
    });
    let builder = Server::builder()
        .set_config(server_config)
        .set_rpc_middleware(rpc_middleware)
        .to_service_builder()
        .max_connections(config.max_connections);
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|err| RpcStartError::Transport(err.to_string()))?;
    let clients = Clients::new(
        &config.trusted_proxies,
        config.max_connections,
        config.max_connections_per_client,
        config.max_ws_connections,
    );
    let (stop_handle, server_handle) = jsonrpsee::server::stop_channel();
    let methods: Methods = module.into();
    let connections = stop_handle.clone();
    tokio::spawn(accept(listener, stop_handle, clients, move || {
        builder.clone().build(methods.clone(), connections.clone())
    }));
    Ok(server_handle)
}

/// The response future of one HTTP request on an admitted connection.
type ResponseFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<HttpResponse, ServeError>> + Send>>;

/// A failure serving one request, which closes its connection. A concrete
/// type, as `BoxError` itself fails the spawned connection's `Send` check
/// for every lifetime (jsonrpsee's own examples convert it likewise).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct ServeError(BoxError);

/// Accept connections until the server stops, serving each admitted one
/// with a jsonrpsee service from `service`.
async fn accept<R, H>(
    listener: tokio::net::TcpListener,
    stop_handle: StopHandle,
    clients: Arc<Clients>,
    service: impl Fn() -> TowerService<R, H> + Send + 'static,
) where
    TowerService<R, H>: tower::Service<
            http::Request<hyper::body::Incoming>,
            Response = HttpResponse,
            Error = BoxError,
        > + Clone
        + Send
        + 'static,
    <TowerService<R, H> as tower::Service<http::Request<hyper::body::Incoming>>>::Future: Send,
{
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = stop_handle.clone().shutdown() => return,
        };
        // A failed accept or a connection past the listener's or its
        // client's bound is dropped, which closes its socket.
        let Ok((socket, peer)) = accepted else {
            continue;
        };
        let Some(admission) = clients.admit(peer.ip()) else {
            continue;
        };
        let admission = Arc::new(admission);
        let connection_service = service();
        let clients = Arc::clone(&clients);
        let connection =
            tower::service_fn(move |mut request: http::Request<hyper::body::Incoming>| {
                let client = clients.client(peer.ip(), request.headers());
                request.extensions_mut().insert(client);
                let mut rpc = connection_service.clone();
                if is_upgrade_request(&request) {
                    let Some(slot) = clients.websocket() else {
                        let refused: ResponseFuture =
                            Box::pin(std::future::ready(Ok(too_many_requests())));
                        return refused;
                    };
                    // A session outlives the request that opens it: its slot and
                    // the client's connection count last until it closes, or
                    // until the upgrade fails and drops it.
                    let closed = rpc.on_session_closed();
                    let admission = Arc::clone(&admission);
                    tokio::spawn(async move {
                        closed.await;
                        drop((slot, admission));
                    });
                }
                let served: ResponseFuture =
                    Box::pin(async move { rpc.call(request).await.map_err(ServeError) });
                served
            });
        let stopped = stop_handle.clone().shutdown();
        tokio::spawn(async move {
            let _ = serve_with_graceful_shutdown(socket, connection, stopped).await;
        });
    }
}

/// Shared context handed to every RPC handler.
#[derive(Clone)]
pub struct RpcContext {
    backend: Arc<dyn RpcBackend>,
    runtime_call_timeout: Duration,
    ethereum_filters: Arc<ethereum::Filters>,
    chain_subscriptions: Arc<clients::ClientSlots>,
    ethereum_subscriptions: Arc<clients::ClientSlots>,
}

impl RpcContext {
    /// Borrow the underlying backend.
    pub fn backend(&self) -> &Arc<dyn RpcBackend> {
        &self.backend
    }
}
