//! `[rpc]` section: the TOML mirror of the JSON-RPC server configuration.

use std::net::SocketAddr;
use std::time::Duration;

use serde::Deserialize;

/// TOML-deserialisable mirror of [`neutrin0_rpc::RpcConfig`].
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcConfigToml {
    /// `host:port` to bind on. Examples: `"127.0.0.1:9933"` for
    /// local-only, `"0.0.0.0:9933"` to listen on every interface.
    pub listen: String,
    /// Maximum concurrent connections. Defaults to `200`.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// WebSocket sessions at once; each buffers up to four responses while
    /// its client is slow to read. Defaults to `32`.
    #[serde(default = "default_max_ws_connections")]
    pub max_ws_connections: u32,
    /// Connections one client (an IPv4 address or an IPv6 /64) may hold;
    /// trusted proxies count only toward `max_connections`. Defaults to `16`.
    #[serde(default = "default_max_connections_per_client")]
    pub max_connections_per_client: u32,
    /// Proxies whose connections name their client as the last hop of
    /// `X-Forwarded-For`, e.g. `["127.0.0.1"]` behind a local reverse proxy.
    #[serde(default)]
    pub trusted_proxies: Vec<std::net::IpAddr>,
    /// Maximum size of a single request body in bytes. Defaults to
    /// 10 MiB.
    #[serde(default = "default_max_request_body_size")]
    pub max_request_body_size: u32,
    /// Maximum size of a single response body in bytes. Defaults to
    /// 15 MiB.
    #[serde(default = "default_max_response_body_size")]
    pub max_response_body_size: u32,
    /// Requests executing at once across all connections. Defaults to 64.
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: u32,
    /// Sustained request rate per client across its connections; burst is
    /// twice this. Defaults to 50.
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second_per_client: u32,
    /// Maximum entries per JSON-RPC batch. Defaults to 16.
    #[serde(default = "default_max_batch_requests")]
    pub max_batch_requests: u32,
    /// Wall-clock budget for one `runtime_call`, in milliseconds.
    /// Defaults to 2000.
    #[serde(default = "default_runtime_call_timeout_ms")]
    pub runtime_call_timeout_ms: u64,
}

// Defaults come from the RPC crate so the TOML mirror cannot drift from it.
fn default_max_connections() -> u32 {
    neutrin0_rpc::RpcConfig::default().max_connections
}
fn default_max_ws_connections() -> u32 {
    neutrin0_rpc::RpcConfig::default().max_ws_connections
}
fn default_max_connections_per_client() -> u32 {
    neutrin0_rpc::RpcConfig::default().max_connections_per_client
}
fn default_max_request_body_size() -> u32 {
    neutrin0_rpc::RpcConfig::default().max_request_body_size
}
fn default_max_response_body_size() -> u32 {
    neutrin0_rpc::RpcConfig::default().max_response_body_size
}
fn default_max_concurrent_requests() -> u32 {
    neutrin0_rpc::RpcConfig::default().max_concurrent_requests
}
fn default_requests_per_second() -> u32 {
    neutrin0_rpc::RpcConfig::default().requests_per_second_per_client
}
fn default_max_batch_requests() -> u32 {
    neutrin0_rpc::RpcConfig::default().max_batch_requests
}
fn default_runtime_call_timeout_ms() -> u64 {
    u64::try_from(
        neutrin0_rpc::RpcConfig::default()
            .runtime_call_timeout
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

impl RpcConfigToml {
    /// Parse the configured `listen` address into a [`SocketAddr`] and
    /// build the runtime [`neutrin0_rpc::RpcConfig`].
    pub fn to_runtime_config(&self) -> Result<neutrin0_rpc::RpcConfig, std::net::AddrParseError> {
        let listen: SocketAddr = self.listen.parse()?;
        Ok(neutrin0_rpc::RpcConfig {
            listen,
            max_connections: self.max_connections,
            max_ws_connections: self.max_ws_connections,
            max_connections_per_client: self.max_connections_per_client,
            trusted_proxies: self.trusted_proxies.clone(),
            max_request_body_size: self.max_request_body_size,
            max_response_body_size: self.max_response_body_size,
            max_concurrent_requests: self.max_concurrent_requests,
            requests_per_second_per_client: self.requests_per_second_per_client,
            max_batch_requests: self.max_batch_requests,
            runtime_call_timeout: Duration::from_millis(self.runtime_call_timeout_ms),
        })
    }
}
