//! Deterministic genesis runtime state derived from a [`ChainSpecFile`].
//!
//! Every node materialises the same trie from the same spec file, so the
//! allocation never has to be distributed separately. The resulting root is
//! bound into the chain spec hash through `genesis_state_root`, which peers
//! compare at handshake.

use neutrin0_primitives::{Hash, ZERO_HASH};
use neutrin0_trie::Trie;

use crate::chain_spec::{ChainSpecError, ChainSpecFile, decode_hex_exact};

/// Genesis runtime state built from the spec's accounts and validators.
pub struct GenesisState {
    /// State trie holding every genesis record.
    pub trie: Trie,
    /// Root committed in the chain spec. Never all-zero: the governable
    /// runtime policy is seeded into state even when the allocation is empty.
    pub root: Hash,
    /// Metadata read from the selected runtime after initialization.
    pub runtime_info: neutrin0_primitives::RuntimeInfo,
    /// Exact execution identities supplied to this genesis initialization.
    pub programs: neutrin0_primitives::ProgramSet,
    /// Number of funded accounts.
    pub accounts: usize,
    /// Number of validators with a runtime stake record.
    pub staked_validators: usize,
}

/// Build genesis using the selected runtime, with opaque application configuration.
/// # Errors
/// Reports malformed configuration, traps, inconsistent roots or invalid candidates.
pub fn build_genesis_state(file: &ChainSpecFile) -> Result<GenesisState, ChainSpecError> {
    build_genesis_state_with(file, &file.runtime_package()?)
}

/// [`build_genesis_state`] under an already resolved runtime package.
/// # Errors
/// As [`build_genesis_state`].
pub fn build_genesis_state_with(
    file: &ChainSpecFile,
    package: &neutrin0_runtime_host::package::RuntimePackage,
) -> Result<GenesisState, ChainSpecError> {
    let validators = file.genesis_validators()?;
    let input = neutrin0_runtime_abi::RuntimeGenesisInput {
        max_block_proving_input_bytes: file
            .max_block_proving_input_bytes
            .unwrap_or(neutrin0_primitives::DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES),
        chain_id: file.chain_id,
        timestamp: file.genesis_time,
        seed: file
            .genesis_seed_hex
            .as_ref()
            .map(|seed| decode_hex_exact::<32>(seed, "genesis seed"))
            .transpose()?
            .unwrap_or(ZERO_HASH),
        genesis_block_hash: file
            .genesis_block_hash_hex
            .as_ref()
            .map(|hash| decode_hex_exact::<32>(hash, "genesis block hash"))
            .transpose()?
            .unwrap_or(ZERO_HASH),
        chunk_size: file
            .chunk_size
            .unwrap_or(neutrin0_primitives::DEFAULT_CHUNK_SIZE),
        programs: package.programs,
        block_gas_limit: file.genesis_gas_limit,
        runtime_params: file.runtime_params(),
        validators: validators.clone(),
        configuration: package.genesis.clone(),
    };
    let runtime = neutrin0_runtime_host::wasm::WasmRuntime::new(&package.wasm)
        .map_err(|error| ChainSpecError::Validation(error.to_string()))?;
    let (output, trie) = runtime
        .init_genesis(&input)
        .map_err(|error| ChainSpecError::Validation(format!("runtime genesis: {error}")))?;
    let candidates = trie
        .get(neutrin0_consensus_types::runtime::CONSENSUS_CANDIDATES_KEY)
        .map_err(|error| ChainSpecError::Validation(format!("genesis state: {error}")))?
        .map(|bytes| {
            borsh::from_slice::<neutrin0_consensus_types::runtime::ConsensusCandidates>(&bytes)
        })
        .transpose()
        .map_err(|error| ChainSpecError::Validation(error.to_string()))?
        .unwrap_or_default();
    validate_genesis_candidates(&candidates, &validators)?;
    let response = runtime
        .query(
            &neutrin0_runtime_abi::QueryRequest {
                method: "runtime_info".into(),
                args: Vec::new(),
            },
            &trie,
        )
        .map_err(|error| ChainSpecError::Validation(error.to_string()))?;
    if !response.is_ok() {
        return Err(ChainSpecError::Validation(
            "runtime genesis metadata unavailable".into(),
        ));
    }
    let runtime_info = borsh::from_slice(&response.payload)
        .map_err(|error| ChainSpecError::Validation(error.to_string()))?;
    Ok(GenesisState {
        runtime_info,
        programs: package.programs,
        root: output.state_root,
        accounts: file.accounts.len(),
        staked_validators: candidates.entries.len(),
        trie,
    })
}

fn validate_genesis_candidates(
    candidates: &neutrin0_consensus_types::runtime::ConsensusCandidates,
    validators: &[neutrin0_primitives::Validator],
) -> Result<(), ChainSpecError> {
    // Validate identities of standby candidates too. They may be supplied by
    // opaque application configuration before being seated by later rotation.
    for candidate in &candidates.entries {
        if candidate.address == ZERO_HASH {
            return Err(ChainSpecError::Validation(
                "runtime genesis candidate has zero withdrawal credentials".into(),
            ));
        }
        if let Some(identity) = candidate.identity {
            let public = neutrin0_crypto::bls::PublicKey::from_bytes(&identity.pubkey)
                .map_err(|error| ChainSpecError::Validation(error.to_string()))?;
            let pop = neutrin0_crypto::bls::Signature::from_bytes(&identity.pop_signature)
                .map_err(|error| ChainSpecError::Validation(error.to_string()))?;
            public
                .verify_registration(&candidate.address, &pop)
                .map_err(|error| ChainSpecError::Validation(error.to_string()))?;
        }
    }
    for validator in validators {
        if validator.withdrawal_credentials == ZERO_HASH {
            continue;
        }
        let candidate = candidates
            .get(&validator.withdrawal_credentials)
            .ok_or_else(|| {
                ChainSpecError::Validation("runtime omitted a genesis consensus candidate".into())
            })?;
        if candidate.stake != validator.effective_stake
            || candidate
                .identity
                .is_some_and(|identity| identity.pubkey != validator.pubkey)
        {
            return Err(ChainSpecError::Validation(
                "runtime genesis candidate differs from initial consensus identity or stake".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
