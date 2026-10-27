//! End-to-end checks for [`ChainBackend`].
//!
//! The test builds an `Engine` against an in-memory database, wraps it
//! with [`ChainBackend`] + [`MockProofSystem`], and exercises the
//! read/write paths the sync driver uses:
//! - status / progress queries return engine-consistent values,
//! - published blocks extend the local head exactly once,
//! - the corresponding RPC read methods see what we just imported.

use neutrin0_consensus_engine::Engine;
use neutrin0_consensus_engine::ProposerKey;
use neutrin0_consensus_engine::body::compute_body_roots;
use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_types::{Block, Body, Header};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BlockHash, BoundedBytes, ChainSpec, ConsensusParams, Height, LightClientParams, ProofParams,
    RuntimeInfo, RuntimeParams, Validator, ZERO_HASH,
};
use neutrin0_proof_system::MockProofSystem;
use neutrin0_storage::MemoryDatabase;
use neutrin0_sync::SyncBackend;

#[path = "support/proven.rs"]
pub mod proven;
use proven::mock_bundle;

/// An executor-less backend imports publications by following receipts.
fn following(
    backend: ChainBackend<MemoryDatabase, MockProofSystem>,
) -> ChainBackend<MemoryDatabase, MockProofSystem> {
    backend
        .enable_proof_follow()
        .expect("mock backends follow receipts");
    backend
}

const TEST_CHAIN_ID: u64 = 9;
const TEST_GENESIS_SEED: [u8; 32] = [0xDD; 32];
const TEST_IKM: [u8; 32] = [0xAA; 32];

fn proposer() -> ProposerKey {
    ProposerKey::from_ikm(&TEST_IKM, 0).expect("derive proposer key")
}

fn validators() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer().public_key_bytes(),
        withdrawal_credentials: neutrin0_primitives::runtime_account([2; 20]),
        effective_stake: 32_000_000_000_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }]
}
fn spec() -> ChainSpec {
    let proof = ProofParams::default();
    let vs_root = validator_set_root(&validators());
    let genesis_block_hash: BlockHash = [0xAA; 32];
    ChainSpec {
        genesis_execution: neutrin0_primitives::ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
        name: BoundedBytes::new(b"chain-backend-test".to_vec()).unwrap(),
        chain_id: TEST_CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: [0xCC; 32],
        genesis_chunk: [7; 8],
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: TEST_GENESIS_SEED,
        genesis_state_root: ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        consensus: ConsensusParams::default(),
        proof,
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).unwrap(),
    }
}

/// Build a fully signed, VRF-eligible block over the canonical test
/// proposer key. The active set declared in [`validators`] holds the
/// matching public key so the resulting block passes both header
/// signature and VRF eligibility checks during `import_block`.
fn block(height: Height, slot: u64, parent: BlockHash, state_root: [u8; 32]) -> Block {
    block_with_spec(&spec(), height, slot, parent, state_root)
}

fn block_with_spec(
    chain: &ChainSpec,
    height: Height,
    slot: u64,
    parent: BlockHash,
    state_root: [u8; 32],
) -> Block {
    let p = proposer();
    let body = Body::default();
    let roots = compute_body_roots(&body);
    let vrf_proof = p.vrf_eval(chain.consensus_domain(), &chain.genesis_seed, slot);

    let mut header = Header {
        height,
        slot,
        parent_hash: parent,
        proposer_index: p.validator_index(),
        vrf_proof,
        state_root,
        transactions_root: roots.transactions_root,
        votes_root: roots.votes_root,
        da_root: roots.da_root,
        runtime_extra: ZERO_HASH,
        inputs_root: [0; 32],
        receipts_root: Body::default().artifacts.commitment(),
        gas_used: 0,
        gas_limit: 30_000_000,
        timestamp: chain.genesis_time + slot * chain.consensus.slot_duration_secs,
        signature: [0; 96],
    };
    header.inputs_root = fixture_inputs_root(chain, &header, &body);
    let header_hash = header.hash();
    header.signature = p.sign_proposer_message(chain.consensus_domain(), &header_hash);
    Block { header, body }
}

#[tokio::test(flavor = "current_thread")]
async fn status_reflects_engine_head_at_genesis() {
    let engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let backend = ChainBackend::new(engine, MockProofSystem::new());

    let status = backend.local_status().await.unwrap();
    assert_eq!(status.chain_id, 9);
    assert_eq!(status.head_height, 0);
    assert_eq!(status.head_block_hash, [0xAA; 32]);
    assert_eq!(backend.chain_id(), 9);
}

#[tokio::test(flavor = "current_thread")]
async fn archive_capability_requires_actual_complete_history() {
    use neutrin0_consensus_engine::RetentionPolicy;
    use neutrin0_network::rpc::role_flags;
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    engine
        .set_retention_policy(RetentionPolicy::Archive)
        .unwrap();
    let backend = ChainBackend::new(engine, MockProofSystem::new());
    let metadata = backend.local_metadata().await;
    assert_eq!(
        metadata.role_flags,
        role_flags::FULL_NODE | role_flags::ARCHIVE
    );
    assert_eq!(metadata.retained_from_chunk, Some(0));
    assert_eq!(metadata.retained_from_height, Some(1));
    let retention = neutrin0_rpc::RpcBackend::history_retention(&backend)
        .await
        .unwrap();
    assert!(retention.archive);
    assert_eq!(retention.finalized_chunks, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn queries_distinguish_persisted_pruning_from_unknown_hashes() {
    use neutrin0_consensus_engine::{RetentionInfo, RetentionPolicy};
    use neutrin0_network::rpc::role_flags;
    use neutrin0_rpc::{QueryError, RpcBackend};
    use neutrin0_storage::{Column, Database};
    use neutrin0_sync::SyncBackendError;
    let mut chain = spec();
    chain.consensus.chunk_size = 2;
    let engine = Engine::genesis(chain.clone(), MemoryDatabase::new()).unwrap();
    let backend = following(ChainBackend::new(engine, MockProofSystem::new()));
    let first = block_with_spec(&chain, 1, 1, [0xAA; 32], ZERO_HASH);
    let anchor = block_with_spec(&chain, 2, 2, first.hash(), ZERO_HASH);
    backend
        .verify_and_import_proven_blocks(vec![mock_bundle(&backend, first.clone())])
        .await
        .unwrap();
    backend
        .verify_and_import_proven_blocks(vec![mock_bundle(&backend, anchor.clone())])
        .await
        .unwrap();
    // Query-layer fixture for an already atomically committed pruning watermark;
    // the engine's retention suite separately proves deletion authorization.
    backend.with_engine_mut_for_test(|engine| {
        let db = engine.store_mut().db_mut();
        db.put(
            Column::Meta,
            b"history_retention",
            &borsh::to_vec(&RetentionInfo {
                policy: RetentionPolicy::Pruned,
                pruned_before_chunk: 1,
                first_retained_height: 3,
            })
            .unwrap(),
        )
        .unwrap();
        db.delete(Column::HeaderByHeight, &1_u64.to_be_bytes())
            .unwrap();
        db.delete(Column::Headers, &first.hash()).unwrap();
        db.delete(Column::Blocks, &first.hash()).unwrap();
        db.delete(Column::Blocks, &anchor.hash()).unwrap();
    });
    let error = QueryError::Pruned {
        retained_from_chunk: 1,
        retained_from_height: 3,
    };
    assert_eq!(backend.block_by_height(1).await, Err(error.clone()));
    assert_eq!(backend.block_by_hash(anchor.hash()).await, Err(error));
    assert_eq!(
        backend.header_by_height(2).await.unwrap(),
        Some(anchor.header.clone())
    );
    assert_eq!(backend.block_by_hash(first.hash()).await.unwrap(), None);
    assert!(matches!(
        backend.blocks_by_range(1, 1, anchor.hash()).await,
        Err(SyncBackendError::Pruned {
            retained_from_chunk: 1,
            retained_from_height: 3
        })
    ));
    assert!(matches!(
        backend.chunk_proofs_by_id(&[0]).await,
        Err(SyncBackendError::Pruned { .. })
    ));
    let metadata = backend.local_metadata().await;
    assert_eq!(metadata.role_flags, role_flags::FULL_NODE);
    assert_eq!(metadata.retained_from_chunk, Some(1));
    assert_eq!(metadata.retained_from_height, Some(3));
    assert!(
        !RpcBackend::history_retention(&backend)
            .await
            .unwrap()
            .archive
    );
    // A pruned receipt is reported as pruned; an endpoint that is not
    // finalized here is unavailable, never substituted.
    assert!(matches!(
        SyncBackend::history_proof(&backend, 0, 1, [9; 32]).await,
        Err(SyncBackendError::Pruned {
            retained_from_chunk: 1,
            retained_from_height: 3
        })
    ));
    assert!(matches!(
        SyncBackend::history_proof(&backend, 0, 2, [9; 32]).await,
        Err(SyncBackendError::NotAvailable(_))
    ));
    assert_eq!(
        RpcBackend::history_latest(&backend).await,
        Err(QueryError::HistoryUnavailable)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn published_block_extends_head_and_is_served_back_proven() {
    let engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let backend = following(ChainBackend::new(engine, MockProofSystem::new()));

    let genesis_hash = backend.local_status().await.unwrap().head_block_hash;
    let b1 = block(1, 1, genesis_hash, ZERO_HASH);
    let publication = mock_bundle(&backend, b1.clone());
    let imported = backend
        .verify_and_import_proven_blocks(vec![publication.clone()])
        .await
        .expect("import succeeds");
    assert_eq!(imported.new_head_height, 1);
    assert_eq!(imported.new_head_hash, b1.hash());

    let status = backend.local_status().await.unwrap();
    assert_eq!(status.head_height, 1);
    assert_eq!(status.head_block_hash, b1.hash());

    // The block is proven on arrival and the exact publication is served back.
    assert_eq!(backend.local_progress().await.unwrap().proven_height, 1);
    let resp = backend
        .blocks_by_range(1, 8, status.head_block_hash)
        .await
        .unwrap();
    assert_eq!(resp.blocks, vec![publication]);
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_publication_is_idempotent_and_preserves_proof_state() {
    let engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let backend = following(ChainBackend::new(engine, MockProofSystem::new()));

    let genesis_hash = backend.local_status().await.unwrap().head_block_hash;
    let b1 = block(1, 1, genesis_hash, ZERO_HASH);
    let publication = mock_bundle(&backend, b1.clone());
    backend
        .verify_and_import_proven_blocks(vec![publication.clone()])
        .await
        .expect("first import");
    let before = backend.local_progress().await.unwrap();
    let outcome = backend
        .verify_and_import_proven_blocks(vec![publication.clone()])
        .await
        .expect("identical publication is idempotent");
    assert_eq!(outcome.new_head_height, 1);
    assert_eq!(outcome.new_head_hash, b1.hash());
    assert_eq!(
        backend.local_progress().await.unwrap().proven_height,
        before.proven_height
    );
    assert_eq!(
        backend
            .blocks_by_range(1, 1, backend.local_status().await.unwrap().head_block_hash)
            .await
            .unwrap()
            .blocks,
        vec![publication]
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
