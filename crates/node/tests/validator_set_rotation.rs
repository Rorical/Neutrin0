//! Complete chunk proofs derive the next consensus stake from authenticated
//! runtime accounts. WASM execution and SP1 block bindings feed native consensus
//! validation; finalization installs the verified rotation atomically.

use std::sync::Arc;

use alloy_primitives::Address;
use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo,
    RuntimeParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrin0_rpc::RpcBackend;
#[path = "support/native_chunk.rs"]
pub mod native_chunk;
use native_chunk::NativeChunkTestSystem;
use neutrin0_runtime_host::WasmExecutor;
use neutrin0_storage::MemoryDatabase;
#[path = "support/evm.rs"]
pub mod evm;

const CHAIN_ID: u64 = 9_191_919;
const GENESIS_STAKE: u128 = 1_000_000_000;
const RUNTIME_STAKE: u128 = 250_000;
/// Development account whose key signs the staking call.
const VALIDATOR_SEED: u8 = 0xC0;

type RotationBackend = ChainBackend<MemoryDatabase, NativeChunkTestSystem>;

/// The validator's Ethereum account.
fn validator_account() -> Address {
    evm::address_of(VALIDATOR_SEED)
}

fn proposer_key() -> ProposerKey {
    ProposerKey::from_ikm(&[0x77; 32], 0).expect("derive proposer")
}

fn chain_spec_validators(runtime_addr: [u8; 32]) -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer_key().public_key_bytes(),
        withdrawal_credentials: runtime_addr,
        effective_stake: GENESIS_STAKE,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }]
}

/// Runtime parameters whose stake floor admits the test's small stake.
fn runtime_params() -> RuntimeParams {
    RuntimeParams {
        min_validator_stake: RUNTIME_STAKE,
        ..RuntimeParams::default()
    }
}

fn build_chain_spec(runtime_addr: [u8; 32]) -> ChainSpec {
    let validators = chain_spec_validators(runtime_addr);
    let proof = ProofParams::default();
    let consensus = ConsensusParams {
        chunk_size: 1,
        // Inflated proposer-expectation keeps the single validator
        // VRF-eligible for slot 1 regardless of finalized-seed entropy.
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    let vs_root = neutrin0_consensus_engine::validator_set_root(&validators);
    let genesis_block_hash = [0xCC; 32];
    ChainSpec {
        genesis_execution: NativeChunkTestSystem::execution_programs(),
        name: BoundedBytes::new(b"rotation-test".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: neutrin0_runtime_host::embedded_runtime_code_hash(),
        genesis_chunk: [7; 8],
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: [0xAB; 32],
        genesis_state_root: ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        consensus,
        proof,
        light_client: LightClientParams::default(),
        runtime: runtime_params(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    }
}

fn build_backend() -> Arc<RotationBackend> {
    // The genesis validator's accountable account is the development
    // account that signs the staking call; genesis funds it.
    let mut spec = build_chain_spec(evm::system_address(validator_account()));
    let trie = evm::seal_genesis(&mut spec, evm::funded(&[validator_account()]));
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    engine.install_genesis_state(trie).expect("genesis state");
    let proof_system = NativeChunkTestSystem::mock().expect("mock SP1 setup");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    backend.set_block_executor(WasmExecutor::embedded().expect("wasm runtime"));
    backend.set_local_voter(proposer_key());
    backend
}

/// Minimal tokio runtime for the one async helper this test needs
/// (`RpcBackend::active_validator_set`). Mirrors the pattern in
/// `full_lifecycle.rs`.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt")
}

fn active_set(backend: &RotationBackend) -> Vec<Validator> {
    rt().block_on(backend.active_validator_set())
}

/// Encoded `stake(uint256)` call from the validator's account.
fn stake_call(amount: u128, nonce: u64) -> Vec<u8> {
    evm::system_call(
        VALIDATOR_SEED,
        nonce,
        neutrin0_evm_runtime_core::addresses::STAKING,
        evm::calldata(b"stake(uint256)", &[evm::word(amount)]),
        CHAIN_ID,
    )
}

#[test]
fn finalize_chunk_rotates_consensus_active_set_to_runtime_stake() {
    let _ = tracing_subscriber::fmt::try_init();

    let backend = build_backend();
    let proposer = proposer_key();

    // -- 1. Sanity: genesis active set carries the chain-spec stake.
    let pre_rotation = active_set(&backend);
    assert_eq!(
        pre_rotation[0].effective_stake, GENESIS_STAKE,
        "genesis active set must carry the chain-spec effective_stake",
    );

    // -- 2. Block 1: a staking call adds `RUNTIME_STAKE` to the genesis
    //       validator's runtime record, so a successful rotation visibly
    //       *changes* the consensus effective_stake — the easiest signal to
    //       distinguish from "rotation never ran".
    backend
        .submit_transaction(stake_call(RUNTIME_STAKE, 0))
        .expect("admission accepts stake");

    let outcome = backend
        .try_produce_block(1, &proposer)
        .expect("produce")
        .expect("validator eligible for slot 1");
    let _proven = backend
        .prove_block(&outcome.block_hash)
        .expect("prove block 1");
    // The block touches the validator-set storage so its
    // runtime-emitted root differs from the parent's — the import-side
    // `runtime_extra` check exempts non-empty bodies for exactly this
    // reason.
    assert_ne!(
        outcome.block.header.runtime_extra, ZERO_HASH,
        "stake tx mutates the runtime validator_set root",
    );

    // -- 3. Close chunk 0 and run the complete chunk validator transition.
    let _finalize = backend
        .finalize_chunk(0, &proposer)
        .expect("finalize chunk 0");

    // -- 4. Acceptance: the consensus active set now reflects the
    //       runtime's stake. A node querying VRF eligibility or the
    //       BFT quorum threshold for chunk 1 will observe the new
    //       stake distribution.
    let post_rotation = active_set(&backend);
    assert_eq!(
        post_rotation[0].effective_stake,
        GENESIS_STAKE + RUNTIME_STAKE,
        "rotation must copy the runtime's stake into the consensus active set",
    );
    assert_eq!(
        post_rotation[0].pubkey,
        *proposer_key().public_key_bytes(),
        "rotation must preserve the consensus BLS pubkey",
    );
}

#[test]
fn rotation_preserves_genesis_stake_without_staking_activity() {
    // A chain that has not yet seen any staking activity should leave the
    // consensus active set at its genesis collateral. The bridge joins on
    // `withdrawal_credentials`; the runtime record genesis seeded carries
    // exactly the chain-spec stake.
    let _ = tracing_subscriber::fmt::try_init();

    let backend = build_backend();
    let proposer = proposer_key();

    // Produce an empty block. With chunk_size = 1 it closes chunk 0
    // immediately. No staking call has been included.
    let outcome = backend
        .try_produce_block(1, &proposer)
        .expect("produce")
        .expect("validator eligible for slot 1");
    let _proven = backend
        .prove_block(&outcome.block_hash)
        .expect("prove empty block");
    let _finalize = backend
        .finalize_chunk(0, &proposer)
        .expect("finalize chunk 0");

    let set = active_set(&backend);
    assert_eq!(
        set[0].effective_stake, GENESIS_STAKE,
        "without staking activity the chain-spec stake stays in force",
    );
}
