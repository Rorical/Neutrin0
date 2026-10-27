//! End-to-end coverage of the JSON-RPC `runtime_call` path:
//! `ChainBackend::runtime_call` → `WasmExecutor::query` →
//! master cdylib `_neutrin0_query` → `runtime-core::query` →
//! `QueryResponse` → `RuntimeCallResponse`.
//!
//! Exercises:
//!
//! - the four canonical methods (`account_get`, `validator_get`,
//!   `validator_set`, `runtime_info`),
//! - the `RuntimeNotConfigured` error when no executor is installed,
//! - explicit errors for unknown blocks and reads from retained historical roots,
//! - `runtime_available()` / `runtime_code_hash()` flipping on/off
//!   alongside `set_block_executor`,
//! - that block production does not disturb the read-only query path
//!   (`runtime_info` still resolves after a block is sealed and proven).

#[path = "support/evm.rs"]
pub mod evm;
use std::sync::Arc;

use neutrin0_consensus_engine::{ProposerKey, validator_set_root};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo,
    RuntimeParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrin0_rpc::{BlockId, QueryError, RpcBackend, RuntimeCallError};
use neutrin0_runtime_abi::QueryStatus;
use neutrin0_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrin0_runtime_system::{
    QUERY_METHOD_RUNTIME_INFO, QUERY_METHOD_VALIDATOR_GET, QUERY_METHOD_VALIDATOR_SET, ValidatorSet,
};
use neutrin0_storage::MemoryDatabase;

const CHAIN_ID: u64 = 99;
const GENESIS_SEED: [u8; 32] = [0xAB; 32];

fn proposer() -> ProposerKey {
    ProposerKey::from_ikm(&[0xA1; 32], 0).expect("derive proposer")
}

fn single_validator_set() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer().public_key_bytes(),
        withdrawal_credentials: evm::padded(0xA1),
        effective_stake: 32_000_000_000_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }]
}

fn chain_spec() -> ChainSpec {
    let validators = single_validator_set();
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash = [0xCC; 32];
    let consensus = ConsensusParams {
        chunk_size: 1,
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    evm::sealed(ChainSpec {
        genesis_execution: neutrin0_runtime_host::package::RuntimePackage::embedded(Vec::new())
            .expect("authenticated fixture programs")
            .programs
            .execution,
        name: BoundedBytes::new(b"runtime-call-rpc".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: neutrin0_runtime_host::embedded_runtime_code_hash(),
        genesis_chunk: neutrin0_runtime_host::package::embedded_chunk_program()
            .expect("embedded chunk Guest"),
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: GENESIS_SEED,
        genesis_state_root: ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        consensus,
        proof,
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    })
}

type Backend = ChainBackend<MemoryDatabase, Sp1ProofSystem<sp1_sdk::blocking::MockProver>>;

fn build_backend_without_executor() -> Arc<Backend> {
    let engine = evm::genesis_engine(chain_spec(), MemoryDatabase::new(), Vec::new());
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 setup");
    Arc::new(ChainBackend::new(engine, proof_system))
}

fn build_backend_with_executor() -> Arc<Backend> {
    let backend = build_backend_without_executor();
    let executor = WasmExecutor::embedded().expect("wasm runtime");
    backend.set_block_executor(executor);
    backend
}

/// `Sp1ProofSystem::mock()` and `WasmExecutor::embedded()`
/// spin up their own tokio runtime internally for SP1 SDK setup
/// and module compilation; that clashes with the test's
/// `#[tokio::test]` worker thread. `spawn_blocking` hands them a
/// dedicated blocking thread so the runtimes nest cleanly. Same
/// pattern as `three_node_sp1_gossip::build_node`.
async fn fresh_backend_with_executor() -> Arc<Backend> {
    tokio::task::spawn_blocking(build_backend_with_executor)
        .await
        .expect("spawn_blocking backend build")
}

async fn fresh_backend_without_executor() -> Arc<Backend> {
    tokio::task::spawn_blocking(build_backend_without_executor)
        .await
        .expect("spawn_blocking backend build")
}

#[tokio::test(flavor = "multi_thread")]
async fn control_status_resolves_signer_identity_instead_of_configured_index() {
    let backend = fresh_backend_without_executor().await;
    backend.set_local_voter(proposer().with_validator_index(99));
    let status = backend.management_status();
    assert_eq!(status.membership, "member");
    assert_eq!(status.validator_index, Some(0));
    assert_eq!(
        status.validator_public_key.expect("public key").0,
        proposer().public_key_bytes()
    );
    assert!(status.local_votes.is_empty());
    let diagnostics = backend.diagnostics().await.expect("diagnostics");
    assert_eq!(diagnostics.chain_spec_hash.0, chain_spec().hash());
    assert!(diagnostics.sync.is_none());
    assert_eq!(diagnostics.bft_sessions.expect("sessions"), []);
    backend.set_local_voter(ProposerKey::from_ikm(&[0xB1; 32], 0).expect("foreign local identity"));
    let status = backend.management_status();
    assert_eq!(status.membership, "not_in_committee");
    assert_eq!(status.validator_index, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_info_round_trips_through_rpc_layer() {
    let backend = fresh_backend_with_executor().await;

    assert!(backend.runtime_available());
    assert_eq!(
        backend.runtime_code_hash(),
        Some(neutrin0_runtime_host::embedded_runtime_code_hash()),
    );

    let response = backend
        .runtime_call(
            QUERY_METHOD_RUNTIME_INFO.to_owned(),
            Vec::new(),
            &BlockId::Latest,
        )
        .await
        .expect("runtime_info should succeed");

    assert_eq!(response.code, QueryStatus::Ok.as_u32());
    let decoded: RuntimeInfo = borsh::from_slice(&response.payload).expect("decode");
    assert_eq!(decoded.spec_name, *b"NEUTRIN0_EVM\0\0\0\0");
}

#[tokio::test(flavor = "multi_thread")]
async fn unfunded_account_reads_as_empty() {
    let backend = fresh_backend_with_executor().await;
    let addr: [u8; 20] = [0xAA; 20];

    let response = backend
        .runtime_call("evm:account".to_owned(), addr.to_vec(), &BlockId::Latest)
        .await
        .expect("evm:account should succeed");

    assert_eq!(response.code, QueryStatus::Ok.as_u32());
    let decoded: neutrin0_runtime_abi::ethereum::EvmAccount =
        borsh::from_slice(&response.payload).expect("decode");
    assert_eq!(decoded.nonce, 0);
    assert_eq!(decoded.balance, [0; 32]);
}

#[tokio::test(flavor = "multi_thread")]
async fn validator_get_against_empty_state_returns_none() {
    let backend = fresh_backend_with_executor().await;
    let addr: [u8; 32] = [0xBB; 32];

    let response = backend
        .runtime_call(
            QUERY_METHOD_VALIDATOR_GET.to_owned(),
            addr.to_vec(),
            &BlockId::Latest,
        )
        .await
        .expect("validator_get should succeed");

    assert_eq!(response.code, QueryStatus::Ok.as_u32());
    let decoded: Option<neutrin0_runtime_system::Validator> =
        borsh::from_slice(&response.payload).expect("decode");
    assert_eq!(decoded, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn validator_set_holds_the_genesis_validator() {
    let backend = fresh_backend_with_executor().await;

    let response = backend
        .runtime_call(
            QUERY_METHOD_VALIDATOR_SET.to_owned(),
            Vec::new(),
            &BlockId::Latest,
        )
        .await
        .expect("validator_set should succeed");

    assert_eq!(response.code, QueryStatus::Ok.as_u32());
    let decoded: ValidatorSet = borsh::from_slice(&response.payload).expect("decode");
    let mut expected = ValidatorSet::default();
    for validator in single_validator_set() {
        expected.upsert(validator.withdrawal_credentials, validator.effective_stake);
    }
    assert_eq!(decoded, expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_method_surfaces_unknown_method_status() {
    let backend = fresh_backend_with_executor().await;

    let response = backend
        .runtime_call(
            "definitely_not_a_method".to_owned(),
            Vec::new(),
            &BlockId::Latest,
        )
        .await
        .expect("dispatch should reach the runtime and decode a response");

    assert_eq!(response.code, QueryStatus::UnknownMethod.as_u32());
    assert_eq!(response.payload, b"definitely_not_a_method");
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_args_surface_invalid_arguments_status() {
    let backend = fresh_backend_with_executor().await;

    // `validator_get` expects exactly 32 bytes; supplying 5 triggers
    // `QueryStatus::InvalidArguments` from the runtime's dispatcher.
    let response = backend
        .runtime_call(
            QUERY_METHOD_VALIDATOR_GET.to_owned(),
            vec![0xFE; 5],
            &BlockId::Latest,
        )
        .await
        .expect("dispatch should succeed even with bad args");

    assert_eq!(response.code, QueryStatus::InvalidArguments.as_u32());
}

#[tokio::test(flavor = "multi_thread")]
async fn no_executor_returns_runtime_not_configured() {
    let backend = fresh_backend_without_executor().await;

    assert!(!backend.runtime_available());
    assert_eq!(backend.runtime_code_hash(), None);

    let err = backend
        .runtime_call(
            QUERY_METHOD_RUNTIME_INFO.to_owned(),
            Vec::new(),
            &BlockId::Latest,
        )
        .await
        .expect_err("no executor → RuntimeNotConfigured");

    assert!(matches!(err, RuntimeCallError::RuntimeNotConfigured));
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_hash_block_id_is_rejected() {
    let backend = fresh_backend_with_executor().await;

    let err = backend
        .runtime_call(
            QUERY_METHOD_RUNTIME_INFO.to_owned(),
            Vec::new(),
            &BlockId::Hash([0xFF; 32]),
        )
        .await
        .expect_err("unknown block hash");

    assert_eq!(err, RuntimeCallError::Query(QueryError::BlockNotFound));
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_height_block_id_is_rejected() {
    let backend = fresh_backend_with_executor().await;

    let err = backend
        .runtime_call(
            QUERY_METHOD_RUNTIME_INFO.to_owned(),
            Vec::new(),
            &BlockId::Height(42),
        )
        .await
        .expect_err("unknown block height");

    assert_eq!(err, RuntimeCallError::Query(QueryError::BlockNotFound));
}

#[tokio::test(flavor = "multi_thread")]
async fn finalized_block_id_selects_trusted_genesis() {
    let backend = fresh_backend_with_executor().await;

    let spec = chain_spec();
    let finalized = backend.finalized().await.unwrap();
    assert_eq!(finalized.chunk_id, None);
    assert_eq!(finalized.block_hash, spec.genesis_block_hash);
    assert_eq!(finalized.height, 0);
    assert_eq!(finalized.state_root, spec.genesis_state_root);
    assert_eq!(
        backend.resolve_block_id(&BlockId::Height(0)).await.unwrap(),
        Some(spec.genesis_block_hash)
    );

    let response = backend
        .runtime_call(
            QUERY_METHOD_RUNTIME_INFO.to_owned(),
            Vec::new(),
            &BlockId::Finalized,
        )
        .await
        .expect("Finalized id should be accepted");

    assert_eq!(response.code, QueryStatus::Ok.as_u32());
}

#[tokio::test(flavor = "multi_thread")]
async fn query_path_survives_block_production() {
    // Produce + prove one block to confirm the executor is not
    // consumed or invalidated by the block-production path. Then
    // re-issue `runtime_info` against the new head and assert
    // the same metadata still resolves.
    let backend = fresh_backend_with_executor().await;
    let proposer = proposer();

    // Both `try_produce_block` and `prove_block` route through SP1
    // SDK + wasmtime internals that briefly take a tokio runtime
    // handle. Run them off the tokio worker pool to avoid the
    // "Cannot start a runtime from within a runtime" panic — same
    // pattern as the multi-validator SP1 integration test.
    let backend_for_produce = Arc::clone(&backend);
    let outcome = tokio::task::spawn_blocking(move || {
        backend_for_produce
            .try_produce_block(1, &proposer)
            .expect("produce slot 1")
            .expect("single validator is eligible")
    })
    .await
    .expect("spawn_blocking try_produce_block");

    let backend_for_prove = Arc::clone(&backend);
    let block_hash = outcome.block_hash;
    tokio::task::spawn_blocking(move || {
        backend_for_prove
            .prove_block(&block_hash)
            .expect("prove block 1");
    })
    .await
    .expect("spawn_blocking prove_block");

    assert_eq!(backend.head_height(), 1);

    let response = backend
        .runtime_call(
            QUERY_METHOD_RUNTIME_INFO.to_owned(),
            Vec::new(),
            &BlockId::Latest,
        )
        .await
        .expect("runtime_info still works after production");

    assert_eq!(response.code, QueryStatus::Ok.as_u32());
    let decoded: RuntimeInfo = borsh::from_slice(&response.payload).expect("decode");
    assert_eq!(decoded.spec_name, *b"NEUTRIN0_EVM\0\0\0\0");
}
