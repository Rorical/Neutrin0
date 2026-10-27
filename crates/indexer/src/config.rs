//! Deployment settings for one independently bound index database.
use crate::{Error, Result};
use serde::Deserialize;
use std::{net::SocketAddr, path::Path, time::Duration};

/// Standalone service configuration. Database credentials are read only from the named environment variable.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Full/archive node HTTP RPC endpoint.
    pub rpc_url: String,
    /// Independently pinned complete chain specification hash.
    pub chain_spec_hash: String,
    /// PostgreSQL connection-string environment variable.
    #[serde(default = "database_env")]
    pub database_url_env: String,
    /// Dedicated PostgreSQL schema, isolated from other application tables.
    #[serde(default = "schema")]
    pub database_schema: String,
    /// GraphQL and health listener.
    #[serde(default = "listen")]
    pub listen: SocketAddr,
    /// evm or opaque. Changing the decoding profile requires a fresh schema.
    #[serde(default = "runtime")]
    pub runtime: String,
    /// Maximum blocks ingested before yielding to the next source observation.
    #[serde(default = "batch")]
    pub batch_blocks: u32,
    /// Maximum unfinalized rollback search; deeper forks stop with an explicit error.
    #[serde(default = "reorg")]
    pub max_reorg_blocks: u32,
    /// Artifact observation budget per pass, shared by fair retries and recent blocks.
    #[serde(default = "refresh")]
    pub proof_refresh_blocks: u32,
    /// Retained orphan height distance. Canonical history is never deleted.
    #[serde(default = "orphans")]
    pub orphan_retention_blocks: u32,
    /// Idle source observation interval.
    #[serde(default = "poll")]
    pub poll_seconds: u64,
    /// Bound on each upstream RPC call.
    #[serde(default = "timeout")]
    pub timeout_seconds: u64,
    /// Exact allowed browser origins, empty by default.
    #[serde(default)]
    pub cors_origins: Vec<String>,
}
fn database_env() -> String {
    "NEUTRIN0_INDEXER_DATABASE_URL".into()
}
fn schema() -> String {
    "neutrin0_indexer".into()
}
fn runtime() -> String {
    "evm".into()
}
fn listen() -> SocketAddr {
    "127.0.0.1:8080".parse().expect("constant socket")
}
const fn batch() -> u32 {
    128
}
const fn reorg() -> u32 {
    8192
}
const fn refresh() -> u32 {
    32
}
const fn orphans() -> u32 {
    256
}
const fn poll() -> u64 {
    1
}
const fn timeout() -> u64 {
    10
}
impl Config {
    /// Load and validate a TOML configuration.
    pub fn load(path: &Path) -> Result<Self> {
        let config: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        config.validate()?;
        Ok(config)
    }
    /// Refuse ambiguous runtime profiles, unbounded resource settings and unsafe schema names.
    pub fn validate(&self) -> Result<()> {
        crate::model::hash(&self.chain_spec_hash)?;
        validate_schema(&self.database_schema)?;
        if !matches!(self.runtime.as_str(), "evm" | "opaque")
            || !(1..=1024).contains(&self.batch_blocks)
            || !(1..=65_536).contains(&self.max_reorg_blocks)
            || self.proof_refresh_blocks > 256
            || self.orphan_retention_blocks > 65_536
            || !(1..=60).contains(&self.poll_seconds)
            || !(1..=120).contains(&self.timeout_seconds)
            || self.database_url_env.is_empty()
        {
            return Err(Error::Config(
                "invalid runtime profile or resource limits".into(),
            ));
        }
        Ok(())
    }
    /// Upstream deadline.
    pub const fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_seconds)
    }
    /// Stable decoding profile commitment. Operational tuning does not alter stored semantics.
    pub fn decoder_hash(&self) -> Result<String> {
        Ok(crate::model::hex(&neutrin0_primitives::blake3_256(
            self.runtime.as_bytes(),
        )))
    }
}
pub(crate) fn validate_schema(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 63
        || name.starts_with("pg_")
        || name == "public"
        || !name
            .bytes()
            .enumerate()
            .all(|(i, c)| c == b'_' || c.is_ascii_lowercase() || (i > 0 && c.is_ascii_digit()))
    {
        return Err(Error::Config(
            "database_schema must be a dedicated lowercase SQL identifier".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
