//! Invalid publications do not poison local fork choice.
//!
//! A producer makes a real block and its receipt. Followers with the same
//! chain spec, one executing and one following receipts, receive tampered
//! publications of that block and must reject each as a unit: the head stays
//! at genesis and nothing is proven. The exact publication then imports
//! cleanly and the block is proven on arrival.
//!
//! Coverage matrix:
//!
//! | Class | Tamper                        | Follower verdict                      |
//! | ----- | ----------------------------- | ------------------------------------- |
//! | A     | receipt bytes                 | receipt verification fails            |
//! | B     | write set                     | writes do not reproduce the state root |
//! | C     | body                          | body does not match the signed header |
//!
//! Borsh-decode failure (driver layer) is exercised by
//! `crates/sync/tests/driver_loop.rs` and is out of scope here.

#[path = "support/evm.rs"]
pub mod evm;
use std::sync::Arc;

use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_engine::{BlockState, ProposerKey};
use neutrin0_consensus_types::{ProvenBlock, StateWrite};
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

const CHAIN_ID: u64 = 314_159;
const GENESIS_SEED: [u8; 32] = [0xCD; 32];

type Backend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

fn proposer() -> ProposerKey {
    ProposerKey::from_ikm(&[0xB2; 32], 0).expect("derive proposer")
}

fn validators() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer().public_key_bytes(),
        withdrawal_credentials: evm::padded(0xB2),
        effective_stake: 32_000_000_000_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }]
}

fn chain_spec() -> ChainSpec {
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators());
    let genesis_block_hash: BlockHash = [0xEE; 32];
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
        name: BoundedBytes::new(b"proven-block-rejection".to_vec()).expect("name fits"),
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
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    })
}

/// A node with the real SP1 adapter (mock prover) and the WASM executor,
/// mirroring the production node binary; `follow` selects receipt following.
async fn build_backend(follow: bool) -> Arc<Backend> {
    tokio::task::spawn_blocking(move || {
        let engine = evm::genesis_engine(chain_spec(), MemoryDatabase::new(), Vec::new());
        let proof_system = Sp1ProofSystem::mock().expect("mock SP1 adapter");
        let backend = Arc::new(ChainBackend::new(engine, proof_system));
        let executor = WasmExecutor::embedded().expect("wasm runtime");
        backend.set_block_executor(executor);
        if follow {
            backend.enable_proof_follow().expect("proof following");
        }
        backend
    })
    .await
    .expect("spawn_blocking build backend")
}

async fn assert_rejected(follower: &Arc<Backend>, publication: ProvenBlock, class: &str) {
    let genesis = follower.local_status().await.unwrap().head_block_hash;
    let hash = publication.block.hash();
    let err = import_blocking(follower, vec![publication])
        .await
        .expect_err("tampered publication must be rejected");
    assert!(
        matches!(err, SyncBackendError::Rejected(_)),
        "class {class}: expected Rejected, got {err:?}",
    );
    assert_eq!(
        follower.block_state(&hash),
        None,
        "class {class}: nothing of the publication may be archived",
    );
    assert_eq!(
        follower.local_status().await.unwrap().head_block_hash,
        genesis,
        "class {class}: head must stay at genesis",
    );
    assert_eq!(follower.local_progress().await.unwrap().proven_height, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampered_publications_are_rejected_as_a_unit_and_the_exact_one_imports() {
    let _ = tracing_subscriber::fmt::try_init();

    let producer = build_backend(false).await;
    let publication = tokio::task::spawn_blocking({
        let producer = Arc::clone(&producer);
        move || proven::produce_publication(&producer, 1, &proposer())
    })
    .await
    .expect("spawn_blocking produce");
    let hash = publication.block.hash();
    assert_eq!(producer.block_state(&hash), Some(BlockState::Proven));

    for follow in [false, true] {
        let follower = build_backend(follow).await;

        // ---- Class A: receipt bytes --------------------------------
        let mut bad_receipt = publication.clone();
        bad_receipt.proof_bytes[0] ^= 0xFF;
        assert_rejected(&follower, bad_receipt, "A").await;

        // ---- Class B: write set ------------------------------------
        let mut bad_writes = publication.clone();
        bad_writes.writes = vec![StateWrite {
            key: vec![0xFF; 32],
            value: Some(vec![1]),
        }];
        assert_rejected(&follower, bad_writes, "B").await;

        // ---- Class C: body -----------------------------------------
        let mut bad_body = publication.clone();
        bad_body.block.body.transactions.push(vec![1]);
        assert_rejected(&follower, bad_body, "C").await;

        // ---- Recovery: the exact publication imports cleanly. ------
        let imported = import_blocking(&follower, vec![publication.clone()])
            .await
            .expect("the exact publication must be accepted after rejections");
        assert_eq!(imported.new_head_hash, hash);
        assert_eq!(
            follower.block_state(&hash),
            Some(BlockState::Proven),
            "follow = {follow}: the block is proven on arrival",
        );
        assert_eq!(follower.local_progress().await.unwrap().proven_height, 1);
        assert!(follower.engine_state_invariant_holds());
    }
}
