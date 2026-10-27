//! Serde-friendly chain-spec file loader.
//!
//! The canonical [`neutrin0_primitives::ChainSpec`] is borsh-encoded
//! consensus data, not a serde type. For operators we expose a thin
//! TOML/JSON-compatible [`ChainSpecFile`] wrapper that captures the
//! configurable subset and derives every other field deterministically.
//!
//! All nodes participating in a deployment **must** load an identical
//! `chain-spec.toml`; the resulting `ChainSpec::hash()` is what peers
//! compare during handshake.

use std::fs;
use std::path::Path;

use neutrin0_primitives::{Hash, RuntimeParams, ZERO_HASH};
use serde::Deserialize;
use thiserror::Error;

mod allocation;
mod materialize;
mod programs;
/// Native-token amounts in the chain-spec file, in wei (18 decimals).
///
/// TOML integers stop at `i64::MAX`, below 10 tokens, so an amount is either
/// an integer or a string of decimal digits such as `"32000000000000000000"`.
pub mod wei;

pub use materialize::pin_genesis_root;
pub use programs::{GenesisPrograms, ProgramPins, vk_hex};

/// Errors returned by [`ChainSpecFile::load_from_path`] and
/// [`ChainSpecFile::to_chain_spec`].
#[derive(Debug, Error)]
pub enum ChainSpecError {
    /// Reading the file from disk failed.
    #[error("failed to read chain spec `{path}`: {source}")]
    Io {
        /// Path the loader attempted.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Parsing the TOML payload failed.
    #[error("failed to parse chain spec TOML: {0}")]
    Toml(#[from] toml::de::Error),
    /// One of the hex-encoded byte fields was malformed.
    #[error("invalid hex in field `{field}`: {reason}")]
    Hex {
        /// Field name in the chain spec file.
        field: String,
        /// Operator-readable reason.
        reason: String,
    },
    /// The chain name was longer than [`neutrin0_primitives::MAX_CHAIN_NAME_BYTES`].
    #[error("chain name is too long: {len} bytes")]
    NameTooLong {
        /// Observed length in bytes.
        len: usize,
    },
    /// Optional metadata exceeded [`neutrin0_primitives::MAX_METADATA_BYTES`].
    #[error("metadata is too long: {len} bytes")]
    MetadataTooLong {
        /// Observed length in bytes.
        len: usize,
    },
    /// Provided fields produced an invalid canonical [`ChainSpec`](neutrin0_primitives::ChainSpec).
    #[error("chain spec validation failed: {0}")]
    Validation(String),
}

/// One validator entry in the chain-spec file.
///
/// `pubkey_hex` must be exactly 96 hex characters (48 bytes).
/// `withdrawal_credentials_hex` is optional and defaults to all-zero.
/// `pop_hex` is the key's registration proof of possession for those
/// credentials, as `neutrin0-cli keygen` prints it.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorEntry {
    /// Hex-encoded BLS public key (48 bytes, 96 hex chars).
    pub pubkey_hex: String,
    /// Optional hex-encoded withdrawal credentials (32 bytes), or a 20-byte
    /// Ethereum address padded canonically. Defaults to all-zero.
    #[serde(default)]
    pub withdrawal_credentials_hex: Option<String>,
    /// Hex-encoded BLS signature (96 bytes) over
    /// [`neutrin0_primitives::registration_pop_message`] of the key and its
    /// padded withdrawal credentials.
    pub pop_hex: String,
    /// Effective stake at genesis, in wei (`"32000000000000000000"` is 32
    /// tokens); see [`wei`].
    #[serde(deserialize_with = "wei::deserialize")]
    pub effective_stake: u128,
}

/// One funded account in the genesis allocation.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountEntry {
    /// Hex-encoded Ethereum address: 20 bytes, or 32 bytes canonically padded.
    pub address_hex: String,
    /// Spendable balance at genesis, in wei; see [`wei`].
    #[serde(default, deserialize_with = "wei::deserialize")]
    pub balance: u128,
    /// Optional full U256 balance for Ethereum allocations, encoded as 32-byte hex.
    #[serde(default)]
    pub balance_hex: Option<String>,
}

/// A hard fork's anchor (`[fork]`, design 20), as the predecessor's node
/// writes it from its History proof once it finalized up to the fork count.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkFile {
    /// Hash of the specification this one replaces.
    pub predecessor_hex: String,
    /// Borsh hex of the predecessor's authenticated boundary at the fork
    /// count, which its History proof ends at. The fork's start is this
    /// boundary with this specification's programs.
    pub endpoint_hex: String,
    /// Runtime account that proved the endpoint receipt.
    pub endpoint_prover_hex: String,
    /// Signing domains of every predecessor, oldest first; the last is the
    /// predecessor's and ends at the fork count.
    pub prior_domains: Vec<PriorDomainFile>,
}

/// One predecessor signing domain of a [`ForkFile`].
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorDomainFile {
    /// That specification's hash.
    pub chain_spec_hash_hex: String,
    /// First chunk it did not sign.
    pub end_chunk: u64,
    /// Last height it signed.
    pub end_height: u64,
}

/// TOML-deserializable chain spec file.
///
/// Fields not exposed here fall back to canonical
/// [`ConsensusParams`](neutrin0_primitives::ConsensusParams),
/// [`ProofParams`](neutrin0_primitives::ProofParams) and
/// [`LightClientParams`](neutrin0_primitives::LightClientParams) defaults.
/// Unknown fields are rejected, including inside validator and account entries.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainSpecFile {
    /// Positive initial EIP-1559 fee for a chain on the embedded EVM runtime.
    #[serde(default)]
    pub initial_base_fee: Option<u64>,
    /// Human-readable chain name (must be ≤ 64 bytes).
    pub name: String,
    /// Chain identifier; must be non-zero.
    pub chain_id: u64,
    /// Genesis timestamp in seconds since UNIX epoch.
    pub genesis_time: u64,
    /// Block gas limit applied to every block at genesis.
    pub genesis_gas_limit: u64,
    /// Optional hex-encoded genesis seed (32 bytes). Defaults to all-zero.
    #[serde(default)]
    pub genesis_seed_hex: Option<String>,
    /// Optional hex-encoded genesis state root (32 bytes). The root is
    /// always derived from `accounts` and the validators' runtime records
    /// (see [`crate::genesis::build_genesis_state`]); when this field is
    /// present it must equal the derived value, which lets operators pin
    /// the allocation they reviewed. `neutrin0-cli genesis` prints it.
    #[serde(default)]
    pub genesis_state_root_hex: Option<String>,
    /// Optional hex-encoded genesis block hash (32 bytes). Defaults to
    /// all-zero.
    #[serde(default)]
    pub genesis_block_hash_hex: Option<String>,
    /// Pinned genesis program identities. Required to derive the chain
    /// specification: `neutrin0-cli genesis --write` pins the programs this
    /// binary embeds into a file that has none yet
    /// ([`Self::pin_embedded_programs`]).
    #[serde(default)]
    pub programs: Option<ProgramPins>,
    /// Optional override for [`ConsensusParams::slot_duration_secs`](neutrin0_primitives::ConsensusParams::slot_duration_secs).
    ///
    /// Used by integration tests that need shorter slots to exercise
    /// chunk-close and checkpointing within their wall-clock budget.
    #[serde(default)]
    pub slot_duration_secs: Option<u64>,
    /// Optional override for [`ConsensusParams::chunk_size`](neutrin0_primitives::ConsensusParams::chunk_size).
    #[serde(default)]
    pub chunk_size: Option<u64>,
    /// Maximum serialized block proving envelope; defaults to 32 MiB, at most 128 MiB.
    #[serde(default)]
    pub max_block_proving_input_bytes: Option<u64>,
    /// Optional override for [`RuntimeParams::min_validator_stake`], in wei.
    /// Must be positive; defaults to
    /// [`neutrin0_primitives::DEFAULT_MIN_VALIDATOR_STAKE`] (32 tokens).
    #[serde(default, deserialize_with = "wei::optional")]
    pub min_validator_stake: Option<u128>,
    /// Optional override for [`RuntimeParams::unbonding_delay_blocks`].
    /// Defaults to the canonical evidence-safe delay in `RuntimeParams`.
    #[serde(default)]
    pub unbonding_delay_blocks: Option<u64>,
    /// Liveness evidence admission window after the source chunk ends.
    /// Safety evidence has no window: it binds while the offender still holds
    /// slashable balance.
    #[serde(default)]
    pub evidence_max_age_blocks: Option<u64>,
    /// Maximum pending mandatory sanctions.
    #[serde(default)]
    pub evidence_max_pending: Option<u32>,
    /// Maximum evidence admissions per block.
    #[serde(default)]
    pub evidence_admissions_per_block: Option<u32>,
    /// Mandatory FIFO execution cap per block.
    #[serde(default)]
    pub evidence_executions_per_block: Option<u32>,
    /// Optional override for [`RuntimeParams::inactivity_leak_amount`], in
    /// wei. Defaults to zero (disabled).
    #[serde(default, deserialize_with = "wei::optional")]
    pub inactivity_leak_amount: Option<u128>,
    /// Optional override for [`RuntimeParams::abandonment_penalty_amount`],
    /// in wei. Defaults to one token; zero disables the offence.
    #[serde(default, deserialize_with = "wei::optional")]
    pub abandonment_penalty_amount: Option<u128>,
    /// Optional override for [`RuntimeParams::chunk_prover_fee_bps`]
    /// (design 08).
    #[serde(default)]
    pub chunk_prover_fee_bps: Option<u16>,
    /// Optional override for [`RuntimeParams::annual_issuance_bps`]
    /// (design 08).
    #[serde(default)]
    pub annual_issuance_bps: Option<u16>,
    /// Optional free-form metadata (≤ 256 bytes).
    #[serde(default)]
    pub metadata: Option<String>,
    /// Hard-fork anchor, for a specification that replaces another (design
    /// 20). Its genesis fields are the predecessor's: `genesis_state_root_hex`
    /// is required and pinned, not derived from this file's programs.
    #[serde(default)]
    pub fork: Option<ForkFile>,
    /// Initial validator set (must be non-empty).
    pub validators: Vec<ValidatorEntry>,
    /// Genesis account balances. Defaults to none.
    #[serde(default)]
    pub accounts: Vec<AccountEntry>,
}

impl ChainSpecFile {
    /// Load and parse the chain spec at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainSpecError::Io`] or [`ChainSpecError::Toml`] on
    /// read / parse failures.
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, ChainSpecError> {
        let path_ref = path.as_ref();
        let raw = fs::read_to_string(path_ref).map_err(|source| ChainSpecError::Io {
            path: path_ref.display().to_string(),
            source,
        })?;
        Self::from_toml_str(&raw)
    }

    /// Parse a chain spec from an in-memory TOML string.
    ///
    /// # Errors
    ///
    /// Returns [`ChainSpecError::Toml`] when the input is invalid TOML.
    pub fn from_toml_str(raw: &str) -> Result<Self, ChainSpecError> {
        toml::from_str(raw).map_err(ChainSpecError::Toml)
    }

    /// Runtime parameters declared by this file over the canonical defaults.
    ///
    /// Genesis state construction seeds the governable policy from these
    /// values directly, because the full [`ChainSpec`](neutrin0_primitives::ChainSpec) cannot be built before
    /// the genesis state root it embeds.
    #[must_use]
    pub fn runtime_params(&self) -> RuntimeParams {
        let mut runtime = RuntimeParams::default();
        if let Some(min_stake) = self.min_validator_stake {
            runtime.min_validator_stake = min_stake;
        }
        if let Some(unbonding) = self.unbonding_delay_blocks {
            runtime.unbonding_delay_blocks = unbonding;
        }
        if let Some(value) = self.evidence_max_age_blocks {
            runtime.evidence_max_age_blocks = value;
        }
        if let Some(value) = self.evidence_max_pending {
            runtime.evidence_max_pending = value;
        }
        if let Some(value) = self.evidence_admissions_per_block {
            runtime.evidence_admissions_per_block = value;
        }
        if let Some(value) = self.evidence_executions_per_block {
            runtime.evidence_executions_per_block = value;
        }
        if let Some(leak) = self.inactivity_leak_amount {
            runtime.inactivity_leak_amount = leak;
        }
        if let Some(penalty) = self.abandonment_penalty_amount {
            runtime.abandonment_penalty_amount = penalty;
        }
        if let Some(value) = self.chunk_prover_fee_bps {
            runtime.chunk_prover_fee_bps = value;
        }
        if let Some(value) = self.annual_issuance_bps {
            runtime.annual_issuance_bps = value;
        }
        runtime
    }
}

// --- helpers --------------------------------------------------------------

pub(super) fn decode_hash_or_zero(hex: Option<&str>, field: &str) -> Result<Hash, ChainSpecError> {
    let Some(hex) = hex else {
        return Ok(ZERO_HASH);
    };
    let bytes = decode_hex_exact::<32>(hex, field)?;
    Ok(bytes)
}

pub(crate) fn decode_hex_exact<const N: usize>(
    hex: &str,
    field: &str,
) -> Result<[u8; N], ChainSpecError> {
    let trimmed = hex.strip_prefix("0x").unwrap_or(hex);
    if trimmed.len() != N * 2 {
        return Err(ChainSpecError::Hex {
            field: field.to_owned(),
            reason: format!(
                "expected {expected} hex chars, got {actual}",
                expected = N * 2,
                actual = trimmed.len()
            ),
        });
    }
    let mut out = [0_u8; N];
    hex::decode_to_slice(trimmed, &mut out).map_err(|error| ChainSpecError::Hex {
        field: field.to_owned(),
        reason: error.to_string(),
    })?;
    Ok(out)
}

#[cfg(test)]
pub(crate) use allocation::test_validator_fields;

#[cfg(test)]
mod tests;
