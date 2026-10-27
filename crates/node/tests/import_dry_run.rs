//! Executing followers re-execute every imported block against the parent
//! state and reject any that disagrees with the header's `state_root` /
//! `runtime_extra` / `receipts_root` / `gas_used` commitments.
//!
//! A publication carries the block together with its receipt and write
//! set, and the executing follower judges it as a unit: the receipt is
//! verified against the public inputs derived from the header, and the
//! body is re-executed. A malicious proposer who publishes a header with
//! forged commitments therefore never advances the follower's head
//! pointer. The dry-run hook is the second line: every published block is
//! re-executed against the parent state and rejected at import time if the
//! local executor produces a different post-state.
//!
//! Four scenarios cover the surface:
//!
//! 1. `legitimate_block_passes_dry_run` — happy path. A real
//!    block produced by node A via the WASM executor imports
//!    cleanly on a fresh node B that also has the WASM executor
//!    installed. The dry-run accepts; the head advances.
//!
//! 2. `tampered_state_root_blocks_import` — the same legitimate
//!    block, mutated with a forged `state_root` and re-signed.
//!    The dry-run on node B re-executes against the parent state,
//!    produces the correct `state_root`, observes the mismatch, and
//!    rejects the block. The head does NOT advance.
//!
//! 3. `tampered_gas_used_blocks_import` — same setup, but the
//!    tampered field is `gas_used`. The dry-run surfaces the
//!    mismatch via `ImportError::GasUsedMismatch`.
//!
//! 4. `sibling_block_dry_run_rejects_tampered_state_root`: a tampered
//!    block whose parent is not the follower's head is re-executed against
//!    its own reconstructed parent state and rejected.

#[path = "support/evm.rs"]
pub mod evm;
use std::sync::Arc;

use neutrin0_consensus_engine::ProposerKey;
use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_types::{Block, ProvenBlock};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrin0_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrin0_storage::MemoryDatabase;
use neutrin0_sync::{SyncBackend, SyncBackendError};
use sp1_sdk::blocking::MockProver;

#[path = "support/proven.rs"]
pub mod proven;
use proven::import_blocking;

const TEST_CHAIN_ID: u64 = 33333;
const TEST_GENESIS_SEED: [u8; 32] = [0xC1; 32];

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn validators(count: u8) -> Vec<Validator> {
    (0..count)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: evm::padded(0x40 + i),
            effective_stake: 32_000_000_000_000_000_000,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect()
}

fn chain_spec(count: u8) -> ChainSpec {
    let validators = validators(count);
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash: BlockHash = [0xC2; 32];
    let consensus = ConsensusParams {
        chunk_size: 1,
        // High expectation so v0 reliably wins slot 1.
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 4),
        ..ConsensusParams::default()
    };
    evm::sealed(ChainSpec {
        genesis_execution: neutrin0_runtime_host::package::RuntimePackage::embedded(Vec::new())
            .expect("authenticated fixture programs")
            .programs
            .execution,
        name: BoundedBytes::new(b"import-dry-run".to_vec()).expect("name fits"),
        chain_id: TEST_CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: neutrin0_runtime_host::embedded_runtime_code_hash(),
        genesis_chunk: neutrin0_runtime_host::package::embedded_chunk_program()
            .expect("embedded chunk Guest"),
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: TEST_GENESIS_SEED,
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

type Backend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

/// Build a fresh [`ChainBackend`] with the real WASM executor installed.
///
/// Wrapped in `spawn_blocking` because `Sp1ProofSystem::mock()` and
/// `WasmExecutor::embedded()` are sync-blocking (SP1
/// initialisation reads the VK cache, WASM initialisation builds
/// the engine), and the tokio multi-thread runtime refuses to
/// `block_on` from inside a worker thread.
async fn build_backend(local_voter: ProposerKey) -> Arc<Backend> {
    tokio::task::spawn_blocking(move || {
        let engine = evm::genesis_engine(chain_spec(2), MemoryDatabase::new(), Vec::new());
        let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
        let backend = Arc::new(ChainBackend::new(engine, proof_system));
        let executor = WasmExecutor::embedded().expect("default wasm runtime");
        backend.set_block_executor(executor);
        backend.set_local_voter(local_voter);
        backend
    })
    .await
    .expect("spawn_blocking build_backend")
}

/// Produce and prove slot 1 on `producer_backend` using the v0 proposer key
/// and return its publication. Asserts the production succeeded.
async fn produce_legitimate_publication(
    producer_backend: Arc<Backend>,
    voter: ProposerKey,
) -> ProvenBlock {
    tokio::task::spawn_blocking(move || proven::produce_publication(&producer_backend, 1, &voter))
        .await
        .expect("spawn_blocking try_produce_block")
}

/// The same publication with its block replaced by a tampered one. The
/// receipt and writes still describe the honest execution.
fn with_block(publication: &ProvenBlock, block: Block) -> ProvenBlock {
    ProvenBlock {
        block,
        ..publication.clone()
    }
}

/// Tamper `block.header.state_root` and re-sign the header so the
/// resulting block passes signature verification (allowing the
/// import path to reach the dry-run hook).
fn tamper_state_root(mut block: Block, signer: &ProposerKey) -> Block {
    block.header.state_root = [0xFF; 32];
    block.header.signature = [0; 96];
    let header_hash = block.header.hash();
    block.header.signature =
        signer.sign_proposer_message(chain_spec(2).consensus_domain(), &header_hash);
    block
}

/// Tamper `block.header.gas_used` and re-sign.
fn tamper_gas_used(mut block: Block, signer: &ProposerKey) -> Block {
    // Genuine empty-body blocks burn 0 gas; bump to a non-zero
    // value that the dry-run will not reproduce.
    block.header.gas_used = block.header.gas_used.wrapping_add(0xDEAD_BEEF);
    block.header.signature = [0; 96];
    let header_hash = block.header.hash();
    block.header.signature =
        signer.sign_proposer_message(chain_spec(2).consensus_domain(), &header_hash);
    block
}

/// Happy path: a legitimate block produced by node A imports
/// cleanly on a fresh node B with the same chain spec + executor.
/// The dry-run executes, agrees with the header, and the import
/// succeeds. Head advances to height 1 on B.
#[tokio::test]
async fn legitimate_block_passes_dry_run() {
    let v0 = proposer(0);
    let backend_a = build_backend(v0.clone()).await;
    let backend_b = build_backend(v0.clone()).await;

    let publication = produce_legitimate_publication(Arc::clone(&backend_a), v0.clone()).await;

    let outcome = import_blocking(&backend_b, vec![publication.clone()])
        .await
        .expect("dry-run accepts a legitimate block");
    assert_eq!(
        outcome.new_head_height, 1,
        "head must advance to height 1 on the follower"
    );
    assert_eq!(
        outcome.new_head_hash,
        publication.block.hash(),
        "follower's head must be the imported block"
    );
}

/// The same legitimate block, mutated to claim a forged `state_root`. B
/// derives the receipt's public inputs from the tampered header, so the
/// published receipt no longer verifies, and its own re-execution would not
/// reproduce the header either; the publication is rejected as a unit and
/// B's head stays at genesis.
#[tokio::test]
async fn tampered_state_root_blocks_import() {
    let v0 = proposer(0);
    let backend_a = build_backend(v0.clone()).await;
    let backend_b = build_backend(v0.clone()).await;
    let genesis_head = backend_b.local_status().await.unwrap().head_block_hash;

    let publication = produce_legitimate_publication(Arc::clone(&backend_a), v0.clone()).await;
    let tampered = with_block(
        &publication,
        tamper_state_root(publication.block.clone(), &v0),
    );

    let err = import_blocking(&backend_b, vec![tampered])
        .await
        .expect_err("dry-run must reject the tampered header");
    assert!(
        matches!(err, SyncBackendError::Rejected(_)),
        "expected SyncBackendError::Rejected on dry-run mismatch (got {err:?})",
    );

    let head_after = backend_b.local_status().await.unwrap().head_block_hash;
    assert_eq!(
        head_after, genesis_head,
        "head must not advance on a rejected block",
    );
}

/// Sibling dry-run.
///
/// Two validators v0 and v1 both produce a block at slot 1 (high
/// `expected_proposers_per_slot` makes both VRF-eligible). On a
/// target follower, we import v0's block first (head advances to
/// `block_v0`). v1's block then arrives: its parent is genesis,
/// which is not the follower's materialised head (`block_v0`), so
/// it is a DAG sibling. `dry_run_block_against_parent` rebuilds the
/// parent's trie from persisted nodes/values and re-executes the body
/// against it, which catches a tampered `state_root` on the sibling.
#[tokio::test]
async fn sibling_block_dry_run_rejects_tampered_state_root() {
    let v0 = proposer(0);
    let v1 = proposer(1);
    let backend_v0 = build_backend(v0.clone()).await;
    let backend_v1 = build_backend(v1.clone()).await;
    let target = build_backend(v0.clone()).await;
    let genesis_head = target.local_status().await.unwrap().head_block_hash;

    let publication_a = produce_legitimate_publication(Arc::clone(&backend_v0), v0.clone()).await;
    let publication_b = produce_legitimate_publication(Arc::clone(&backend_v1), v1.clone()).await;
    let block_a = publication_a.block.clone();
    let block_b = publication_b.block.clone();
    assert_ne!(
        block_a.hash(),
        block_b.hash(),
        "different proposers must produce distinct blocks at the same slot"
    );
    assert_eq!(
        block_a.header.parent_hash, block_b.header.parent_hash,
        "both sibling blocks must extend the same parent (genesis)"
    );

    // Import block_a first → target's head = block_a.
    import_blocking(&target, vec![publication_a.clone()])
        .await
        .expect("block_a imports cleanly as the extending block");
    let head_after_a = target.local_status().await.unwrap().head_block_hash;
    assert_eq!(head_after_a, block_a.hash());

    // block_b arrives → its parent (genesis) ≠ target's head
    // (block_a). The executor reconstructs the genesis state trie and
    // re-runs the body, so a tampered state_root is caught.
    let tampered_b = with_block(&publication_b, tamper_state_root(block_b, &v1));
    let err = import_blocking(&target, vec![tampered_b])
        .await
        .expect_err("sibling dry-run must reject the tampered state_root");
    assert!(
        matches!(err, SyncBackendError::Rejected(_)),
        "expected SyncBackendError::Rejected on sibling dry-run mismatch (got {err:?})",
    );

    // Head must not have moved — block_a is still the materialised
    // tip; the sibling DAG entry is not added because import
    // failed before fork-choice registration.
    let head_after_b = target.local_status().await.unwrap().head_block_hash;
    assert_eq!(
        head_after_b,
        block_a.hash(),
        "head must stay on block_a; the tampered sibling must not enter the DAG. \
         (genesis was {genesis_head:?})",
    );
}

/// Companion to `tampered_state_root_blocks_import`: tampering
/// with `gas_used` is caught by the same dry-run hook.
#[tokio::test]
async fn tampered_gas_used_blocks_import() {
    let v0 = proposer(0);
    let backend_a = build_backend(v0.clone()).await;
    let backend_b = build_backend(v0.clone()).await;
    let genesis_head = backend_b.local_status().await.unwrap().head_block_hash;

    let publication = produce_legitimate_publication(Arc::clone(&backend_a), v0.clone()).await;
    let tampered = with_block(
        &publication,
        tamper_gas_used(publication.block.clone(), &v0),
    );

    let err = import_blocking(&backend_b, vec![tampered])
        .await
        .expect_err("dry-run must reject the gas_used-tampered header");
    assert!(
        matches!(err, SyncBackendError::Rejected(_)),
        "expected SyncBackendError::Rejected on gas_used mismatch (got {err:?})",
    );

    let head_after = backend_b.local_status().await.unwrap().head_block_hash;
    assert_eq!(
        head_after, genesis_head,
        "head must not advance on a rejected block",
    );
}
