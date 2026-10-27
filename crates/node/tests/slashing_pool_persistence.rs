//! Locally detected slashing evidence survives a node restart: the pool
//! is persisted in `Column::SlashingPool`, so an equivocation observed just
//! before a crash or routine restart is still reported.
//!
//! Two scenarios are covered:
//!
//! 1. `double_proposal_evidence_survives_restart` —
//!    the canonical equivocation case from `slashing_detection.rs`,
//!    extended with a snapshot+restart cycle. The fresh backend
//!    that re-opens the same database must observe the prior
//!    evidence and surface it in the next produced block.
//!
//! 2. `drain_persists_across_restart` — once the producer drains
//!    the pool for a block body, the on-disk
//!    `Column::SlashingPool` row is also removed. A subsequent
//!    restart therefore observes an empty pool (idempotent drain).

use std::sync::Arc;

use neutrin0_consensus_engine::body::compute_body_roots;
use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_consensus_types::{Block, Body, Header, SlashingEvidence};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, Height, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrin0_proof_system::MockProofSystem;
#[path = "support/proven.rs"]
pub mod proven;
use neutrin0_storage::MemoryDatabase;
use neutrin0_sync::SyncBackend;
use proven::mock_bundle;

const TEST_CHAIN_ID: u64 = 22222;
const TEST_GENESIS_SEED: [u8; 32] = [0xB2; 32];

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn validators(count: u8) -> Vec<Validator> {
    (0..count)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: neutrin0_primitives::runtime_account([0x55; 20]),
            effective_stake: 32_000_000_000_000_000_000,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect()
}

fn spec(count: u8) -> ChainSpec {
    let validators = validators(count);
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators);
    let genesis_block_hash: BlockHash = [0xAB; 32];
    let consensus = ConsensusParams {
        chunk_size: 1,
        // Pick a high expectation so v0's VRF output reliably clears
        // the threshold; this test never gates on VRF.
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 4),
        ..ConsensusParams::default()
    };
    ChainSpec {
        genesis_execution: neutrin0_primitives::ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
        name: BoundedBytes::new(b"slashing-pool-persistence".to_vec()).expect("name fits"),
        chain_id: TEST_CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: ZERO_HASH,
        genesis_chunk: [7; 8],
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
    }
}

/// An empty block over the empty genesis state; `extra_byte` distinguishes
/// otherwise identical (equivocating) blocks through `runtime_extra`.
fn signed_block(
    slot: u64,
    parent: BlockHash,
    height: Height,
    extra_byte: u8,
    signer: &ProposerKey,
) -> Block {
    let body = Body::default();
    let roots = compute_body_roots(&body);
    let vrf_proof = signer.vrf_eval(spec(2).consensus_domain(), &TEST_GENESIS_SEED, slot);

    let mut header = Header {
        height,
        slot,
        parent_hash: parent,
        proposer_index: signer.validator_index(),
        vrf_proof,
        state_root: ZERO_HASH,
        transactions_root: roots.transactions_root,
        votes_root: roots.votes_root,
        da_root: roots.da_root,
        runtime_extra: [extra_byte; 32],
        inputs_root: [0; 32],
        receipts_root: Body::default().artifacts.commitment(),
        gas_used: 0,
        gas_limit: 30_000_000,
        timestamp: 1_700_000_000 + slot * 4,
        signature: [0; 96],
    };
    header.inputs_root = fixture_inputs_root(&spec(2), &header, &body);
    let header_hash = header.hash();
    header.signature = signer.sign_proposer_message(spec(2).consensus_domain(), &header_hash);
    Block { header, body }
}

fn following(engine: Engine<MemoryDatabase>) -> Arc<ChainBackend<MemoryDatabase, MockProofSystem>> {
    let backend = ChainBackend::new(engine, MockProofSystem::new());
    backend
        .enable_proof_follow()
        .expect("executor-less fixture follows receipts");
    Arc::new(backend)
}

fn fresh_backend_on(db: MemoryDatabase) -> Arc<ChainBackend<MemoryDatabase, MockProofSystem>> {
    following(Engine::genesis(spec(2), db).expect("genesis"))
}

fn reopen_backend_on(db: MemoryDatabase) -> Arc<ChainBackend<MemoryDatabase, MockProofSystem>> {
    following(Engine::open(spec(2), db).expect("re-open engine on existing db"))
}

/// Pool an equivocating header pair, snapshot the DB, drop the
/// original backend, re-open a fresh backend on the snapshot, and
/// confirm the prior `DoubleProposal` evidence is observable on the
/// fresh backend.
#[tokio::test]
async fn double_proposal_evidence_survives_restart() {
    let backend_a = fresh_backend_on(MemoryDatabase::new());
    let v0 = proposer(0);
    let genesis_hash = backend_a.local_status().await.unwrap().head_block_hash;

    let block_a = signed_block(1, genesis_hash, 1, 0x11, &v0);
    let block_b = signed_block(1, genesis_hash, 1, 0x22, &v0);
    assert_ne!(
        block_a.hash(),
        block_b.hash(),
        "equivocating blocks must differ"
    );

    let publication_a = mock_bundle(&backend_a, block_a);
    let publication_b = mock_bundle(&backend_a, block_b);
    backend_a
        .verify_and_import_proven_blocks(vec![publication_a])
        .await
        .expect("import first block");
    let _ = backend_a
        .verify_and_import_proven_blocks(vec![publication_b])
        .await;
    assert_eq!(
        backend_a.slashing_pool_len(),
        1,
        "double-proposal pooled before restart"
    );

    // Simulate a crash + restart: snapshot the on-disk state and
    // drop the live backend.
    let snapshot = backend_a.snapshot_database();
    drop(backend_a);

    let backend_b = reopen_backend_on(snapshot);
    assert_eq!(
        backend_b.slashing_pool_len(),
        1,
        "fresh ChainBackend on the same DB must rehydrate the pool",
    );

    let drained = backend_b.drain_slashing_pool(10);
    assert!(
        matches!(
            drained.as_slice(),
            [SlashingEvidence::DoubleProposal {
                proposer_index: 0,
                ..
            }],
        ),
        "rehydrated evidence preserves the original variant + offender (got {drained:?})",
    );
}

/// Draining the pool also clears the on-disk rows. A subsequent
/// restart therefore observes an empty pool — drain is the only
/// path through which an item should disappear from disk.
#[tokio::test]
async fn drain_persists_across_restart() {
    let backend_a = fresh_backend_on(MemoryDatabase::new());
    let v0 = proposer(0);
    let genesis_hash = backend_a.local_status().await.unwrap().head_block_hash;

    let first = mock_bundle(&backend_a, signed_block(1, genesis_hash, 1, 0x33, &v0));
    let second = mock_bundle(&backend_a, signed_block(1, genesis_hash, 1, 0x44, &v0));
    backend_a
        .verify_and_import_proven_blocks(vec![first])
        .await
        .expect("import first block");
    let _ = backend_a
        .verify_and_import_proven_blocks(vec![second])
        .await;
    assert_eq!(backend_a.slashing_pool_len(), 1, "evidence pooled");

    // Drain on backend_a — this is what the producer does when
    // assembling a block body. The on-disk row must disappear too.
    let drained = backend_a.drain_slashing_pool(10);
    assert_eq!(drained.len(), 1, "drain returns the single pooled item");
    assert_eq!(
        backend_a.slashing_pool_len(),
        0,
        "in-memory pool empty after drain"
    );

    // Restart: the prior on-disk row was deleted, so the new
    // backend observes an empty pool.
    let snapshot = backend_a.snapshot_database();
    drop(backend_a);

    let backend_b = reopen_backend_on(snapshot);
    assert_eq!(
        backend_b.slashing_pool_len(),
        0,
        "drained evidence must not resurrect across restart",
    );
}

/// The inputs root the importing engine derives for a chunk-zero fixture
/// block (design 08): the mock backend installs no programs, so a genesis
/// engine of the same specification derives exactly the same commitment.
fn fixture_inputs_root(
    spec: &neutrin0_primitives::ChainSpec,
    header: &neutrin0_consensus_types::Header,
    body: &neutrin0_consensus_types::Body,
) -> neutrin0_primitives::Hash {
    neutrin0_consensus_engine::Engine::genesis(
        spec.clone(),
        neutrin0_storage::MemoryDatabase::new(),
    )
    .unwrap()
    .expected_inputs_root(header, body)
    .unwrap()
}
