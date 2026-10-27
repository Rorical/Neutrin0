//! The execution export's call envelope: genesis and block operations.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{Hash, StateRoot};

use crate::execution::{RuntimeBlockInput, RuntimeBlockResult};

/// Operation encoded for the execution export. Genesis and blocks use the same
/// memory-transfer ABI; the host chooses the operation.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum RuntimeCallInput {
    /// Initialize an empty chain state using runtime-owned configuration.
    Genesis(alloc::boxed::Box<RuntimeGenesisInput>),
    /// Execute one authenticated block.
    Block(alloc::boxed::Box<RuntimeBlockInput>),
}

/// Result returned by the execution export for the corresponding operation.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum RuntimeCallOutput {
    /// Initialized state and consensus candidate commitments.
    Genesis(alloc::boxed::Box<RuntimeGenesisOutput>),
    /// Executed block and its authenticated artifacts.
    Block(alloc::boxed::Box<RuntimeBlockResult>),
}

/// Common genesis facts; configuration is opaque to the host and consensus.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct RuntimeGenesisInput {
    /// Chain-spec-bound block proving envelope allocation limit.
    pub max_block_proving_input_bytes: u64,
    /// Chain identity for runtime initialization.
    pub chain_id: u64,
    /// Chain-specification genesis timestamp.
    pub timestamp: u64,
    /// Chain-specification initial randomness.
    pub seed: Hash,
    /// Specification-defined synthetic genesis block identifier.
    pub genesis_block_hash: Hash,
    /// Genesis-fixed blocks per chunk.
    pub chunk_size: u64,
    /// Locally authenticated initial execution program identities.
    pub programs: neutrin0_primitives::ProgramSet,
    /// Genesis-fixed block resource ceiling.
    pub block_gas_limit: u64,
    /// Genesis-fixed and initial governed runtime parameters.
    pub runtime_params: neutrin0_primitives::RuntimeParams,
    /// Initial consensus validators, including withdrawal credentials.
    pub validators: Vec<neutrin0_primitives::Validator>,
    /// Runtime-specific allocation and initialization configuration.
    pub configuration: Vec<u8>,
}

/// Initialization commitments independently checked against the resulting host trie.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct RuntimeGenesisOutput {
    /// Complete initialized state commitment.
    pub state_root: StateRoot,
    /// Consensus-facing candidates emitted by initialization.
    pub consensus_candidates_root: StateRoot,
}
