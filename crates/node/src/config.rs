//! TOML configuration for [`crate::run`].

use serde::Deserialize;
use std::path::PathBuf;

mod execution;
mod proving;
mod rpc;
mod trust;
mod validator_key;

pub use execution::{ExecutionLimitsConfig, ExecutionMode};
pub use proving::{HexAddress, ProvingBackend, ProvingConfig, ProvingPolicy};
pub use rpc::RpcConfigToml;
pub(crate) use trust::read_trusted_checkpoint;
pub use trust::{BootstrapConfig, LightClientConfig};
pub use validator_key::{
    DoppelgangerConfig, ProposerIkmError, ProposerIkmSource, RemoteSignerConfig,
};

/// Environment variable that supplies the validator's BLS IKM as hex.
/// Exclusive with `proposer_ikm_path` and `proposer_ikm_hex`.
pub const PROPOSER_IKM_ENV: &str = "NEUTRIN0_PROPOSER_IKM_HEX";

/// Environment variable that supplies the validator keystore's password.
/// Takes precedence over `proposer_keystore_password_path`.
pub const KEYSTORE_PASSWORD_ENV: &str = "NEUTRIN0_KEYSTORE_PASSWORD";

/// Self-declared role for the node.
///
/// Selects full execution or proof-only synchronization and storage.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum NodeRole {
    /// Full validator node.
    #[default]
    Validator,
    /// Full non-validator node.
    Full,
    /// Light client.
    LightClient,
    /// Archive node.
    Archive,
    /// Non-validator that retains slashable identities' signed evidence inputs.
    Reporter,
}

impl NodeRole {
    /// Select complete, bounded or economically scoped source retention.
    #[must_use]
    pub const fn retention_policy(self) -> neutrin0_consensus_engine::RetentionPolicy {
        match self {
            Self::Archive => neutrin0_consensus_engine::RetentionPolicy::Archive,
            Self::Reporter => neutrin0_consensus_engine::RetentionPolicy::Reporter,
            Self::Validator | Self::Full | Self::LightClient => {
                neutrin0_consensus_engine::RetentionPolicy::Pruned
            }
        }
    }

    /// Map the role to the FSM sync mode.
    #[must_use]
    pub const fn sync_mode(self) -> neutrin0_sync::SyncMode {
        match self {
            Self::LightClient => neutrin0_sync::SyncMode::LightClient,
            Self::Archive => neutrin0_sync::SyncMode::Archive,
            Self::Validator | Self::Full | Self::Reporter => neutrin0_sync::SyncMode::Snap,
        }
    }
}

/// Node configuration loaded from TOML.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Self-declared role (validator / full / archive / light / reporter).
    #[serde(default)]
    pub role: NodeRole,
    /// Proof-bound reward recipient, required when `role = "reporter"`.
    #[serde(default)]
    pub reporter: Option<ReporterConfig>,
    /// Chain id this node participates in.
    pub chain_id: u64,
    /// Proving backend, global concurrency and bounded block queue capacity.
    #[serde(default)]
    pub proving: ProvingConfig,
    /// Explicit local trust anchor and time policy for proof-only operation.
    #[serde(default)]
    pub light_client: LightClientConfig,
    /// Full/validator checkpoint bootstrap and local weak-subjectivity policy.
    #[serde(default)]
    pub bootstrap: BootstrapConfig,
    /// Bind addresses (multiaddr) the libp2p listener attaches to.
    ///
    /// Defaults to `/ip4/0.0.0.0/tcp/0` if empty.
    #[serde(default)]
    pub listen: Vec<String>,
    /// Bootnode multiaddrs to dial on startup.
    #[serde(default)]
    pub bootnodes: Vec<String>,
    /// Path to a `chain-spec.toml` file. The runner rejects configs that
    /// leave this unset.
    #[serde(default)]
    pub chain_spec_path: Option<String>,
    /// Data directory for the chain database. Optional — when unset the
    /// node runs against an in-memory backend (useful for ephemeral
    /// test containers).
    #[serde(default)]
    pub data_dir: Option<std::path::PathBuf>,
    /// File containing the persistent libp2p private identity, in protobuf form.
    ///
    /// Overrides `data_dir/p2p-key`. When both paths are absent the node uses a
    /// temporary identity, so its PeerID changes on restart. Unix key files
    /// must have mode `0600`; existing invalid files are never replaced.
    #[serde(default)]
    pub network_key_path: Option<PathBuf>,
    /// Peer connectivity and finalized-progress requirements for readiness.
    #[serde(default)]
    pub health: HealthConfig,
    /// Free-space quota of the data directory's filesystem.
    #[serde(default)]
    pub storage: StorageConfig,
    /// Inline hex-encoded BLS IKM (32 bytes). Convenient for tests only:
    /// the runner warns when a validator key is read from the config
    /// file itself. Prefer [`PROPOSER_IKM_ENV`] or `proposer_ikm_path`.
    #[serde(default)]
    pub proposer_ikm_hex: Option<String>,
    /// File holding the hex-encoded BLS IKM. On Unix the file must not be
    /// readable by group or others; the runner refuses looser modes.
    #[serde(default)]
    pub proposer_ikm_path: Option<PathBuf>,
    /// EIP-2335 keystore holding the validator's BLS key, instead of an IKM.
    /// Its password comes from [`KEYSTORE_PASSWORD_ENV`] or
    /// `proposer_keystore_password_path`.
    #[serde(default)]
    pub proposer_keystore_path: Option<PathBuf>,
    /// File holding the keystore's password, readable by its owner only.
    #[serde(default)]
    pub proposer_keystore_password_path: Option<PathBuf>,
    /// Keystore of the validator's next key, under the same password: a key
    /// rotation seats it in place of `proposer_keystore_path`'s key, and the
    /// node signs with whichever key its seat holds (design 19).
    #[serde(default)]
    pub proposer_next_keystore_path: Option<PathBuf>,
    /// A `neutrin0-signer` holding the validator's key instead of this node.
    #[serde(default)]
    pub remote_signer: Option<RemoteSignerConfig>,
    /// Doppelganger protection of the validator key.
    #[serde(default)]
    pub doppelganger: DoppelgangerConfig,
    /// Fuel and memory budgets for WASM queries and admission checks.
    #[serde(default)]
    pub execution: ExecutionLimitsConfig,
    /// Initial position hint; signing resolves the public key in the authenticated active set.
    #[serde(default)]
    pub proposer_index: Option<u32>,
    /// Gossip topics to subscribe to on startup. Defaults to all canonical
    /// topics from `docs/design/21-networking.md`.
    #[serde(default)]
    pub subscribe_topics: Option<Vec<String>>,
    /// JSON-RPC server configuration. When omitted, no RPC listener
    /// is started; the node still functions for consensus and gossip
    /// but external observers have no read API.
    #[serde(default)]
    pub rpc: Option<RpcConfigToml>,
    /// Prometheus metrics listener. When omitted no metrics endpoint is started.
    #[serde(default)]
    pub metrics: Option<MetricsConfigToml>,
    /// Optional private Unix socket, separate from public RPC.
    #[serde(default)]
    pub management: Option<ManagementConfig>,
}

/// Selective evidence retention and reward destination for reporter nodes.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReporterConfig {
    /// Nonzero 32-byte runtime account address encoded as hexadecimal.
    pub reward_address_hex: String,
}

impl NodeConfig {
    /// Validate the reporter role and decode its proof-bound payout address.
    ///
    /// # Errors
    /// Rejects a missing, malformed or zero reward address, or a reporter section
    /// on a different node role.
    pub fn reporter_reward_address(&self) -> Result<Option<[u8; 32]>, String> {
        match (self.role, &self.reporter) {
            (NodeRole::Reporter, Some(config)) => {
                let address = crate::chain_spec::decode_hex_exact::<32>(
                    &config.reward_address_hex,
                    "reporter.reward_address_hex",
                )
                .map_err(|error| error.to_string())?;
                if address == [0; 32] || !neutrin0_primitives::is_runtime_account(&address) {
                    return Err(
                        "reporter.reward_address_hex must be a nonzero runtime account (twelve zero bytes, then the 20-byte address)"
                            .into(),
                    );
                }
                Ok(Some(address))
            }
            (NodeRole::Reporter, None) => {
                Err("role = reporter requires [reporter].reward_address_hex".into())
            }
            (_, Some(_)) => Err("[reporter] requires role = reporter".into()),
            (_, None) => Ok(None),
        }
    }
}

/// `[metrics]` section: a plain-text Prometheus endpoint at `GET /metrics`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfigToml {
    /// `host:port` to bind on, e.g. `"127.0.0.1:9615"`.
    pub listen: String,
}

/// `[health]` section: operational readiness requirements.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct HealthConfig {
    /// Minimum connected peers required for readiness; zero permits isolation.
    pub min_peers: usize,
    /// Maximum seconds without new finality before readiness fails.
    ///
    /// When absent the runner derives a threshold from the chain specification.
    pub finality_stall_timeout_secs: Option<u64>,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            min_peers: 1,
            finality_stall_timeout_secs: None,
        }
    }
}

impl HealthConfig {
    /// Reject an explicitly configured zero finality-stall timeout.
    ///
    /// # Errors
    /// Returns an error when `finality_stall_timeout_secs = 0`.
    pub fn validate(&self) -> Result<(), String> {
        if self.finality_stall_timeout_secs == Some(0) {
            return Err("health.finality_stall_timeout_secs must be nonzero".into());
        }
        Ok(())
    }
}

/// `[storage]` section: the unconditional free-space quota of `data_dir`.
///
/// Finality drives pruning, so a stalled chunk proof leaves unfinalized
/// candidates and their witnesses accumulating. Below `min_free_bytes` the
/// node stops adding unfinalized data; below `halt_free_bytes` it stops.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    /// Free bytes below which production and new candidate imports pause.
    pub min_free_bytes: u64,
    /// Free bytes below which the node shuts down before the database fills
    /// the filesystem.
    pub halt_free_bytes: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            min_free_bytes: 10 << 30,
            halt_free_bytes: 2 << 30,
        }
    }
}

impl StorageConfig {
    /// The halt floor must be positive and below the pressure threshold.
    ///
    /// # Errors
    /// Returns an error for a zero halt floor or one at or above `min_free_bytes`.
    pub fn validate(&self) -> Result<(), String> {
        if self.halt_free_bytes == 0 || self.halt_free_bytes >= self.min_free_bytes {
            return Err(
                "storage.halt_free_bytes must be positive and below storage.min_free_bytes".into(),
            );
        }
        Ok(())
    }
}

impl NodeConfig {
    /// Default listen multiaddr used when `listen` is empty.
    pub const DEFAULT_LISTEN: &'static str = "/ip4/0.0.0.0/tcp/0";

    /// Effective listen addresses.
    #[must_use]
    pub fn effective_listen(&self) -> Vec<String> {
        if self.listen.is_empty() {
            vec![Self::DEFAULT_LISTEN.to_owned()]
        } else {
            self.listen.clone()
        }
    }
}

/// Owner-authenticated, local-only operator endpoint.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementConfig {
    /// Absolute socket path in a canonical directory owned by this user (0700).
    /// The leaf directory is created if absent; existing socket paths are refused.
    pub socket: PathBuf,
}

#[cfg(test)]
mod tests;
