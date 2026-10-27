//! Publication bundles for integration tests (design 07): the single unit a
//! node gossips, serves and imports.
#![allow(dead_code)] // Each integration test binary uses a subset.

use std::sync::Arc;

use neutrin0_consensus_types::{Block, BlockReceipt, CandidateBlock, ProvenBlock};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::BlockHash;
use neutrin0_proof_system::{MockProofSystem, ProofSystem};
use neutrin0_storage::Database;
use neutrin0_sync::{HeadersImported, ReceiptsImported, SyncBackend, SyncBackendError};

/// Receipt bytes the mock proof system accepts for `block` on `backend`,
/// committing to the canonical public inputs the engine derives.
pub fn mock_receipt<DB>(backend: &ChainBackend<DB, MockProofSystem>, block: &Block) -> Vec<u8>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
{
    let public_inputs = backend.with_engine_mut_for_test(|engine| {
        let state_root_before = engine
            .state_root_before(&block.header)
            .expect("store")
            .expect("the parent block is known");
        engine
            .canonical_block_proof(&block.header, state_root_before, Vec::new())
            .expect("canonical receipt envelope")
            .public_inputs
    });
    let proof = MockProofSystem::new()
        .prove_block(&[], &public_inputs, public_inputs.proposer_address)
        .expect("mock proof");
    borsh::to_vec(&proof).expect("encode mock proof")
}

/// The publication a mock backend accepts for `block`: a mock receipt and no
/// writes. Fixture headers commit whatever state root they declare; an
/// executor-less backend trusts it.
pub fn mock_bundle<DB>(backend: &ChainBackend<DB, MockProofSystem>, block: Block) -> ProvenBlock
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
{
    let proof_bytes = mock_receipt(backend, &block);
    ProvenBlock {
        block,
        proof_bytes,
        writes: Vec::new(),
    }
}

/// The publication `backend` retains for its canonical block `hash`.
pub fn published<DB, P>(backend: &ChainBackend<DB, P>, hash: &BlockHash) -> ProvenBlock
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    backend
        .proven_block_for_publication(hash)
        .expect("block, receipt and write set are retained")
}

/// Produce `slot` on `backend`, prove it and return its publication.
pub fn produce_publication<DB, P>(
    backend: &ChainBackend<DB, P>,
    slot: u64,
    voter: &neutrin0_consensus_engine::ProposerKey,
) -> ProvenBlock
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    let outcome = backend
        .try_produce_block(slot, voter)
        .expect("try_produce_block")
        .expect("eligible for the slot");
    backend
        .prove_block(&outcome.block_hash)
        .expect("prove_block");
    published(backend, &outcome.block_hash)
}

/// Import publications on a blocking thread: receipt verification may enter
/// the SP1 SDK's own runtime, which must not nest inside the test runtime.
pub async fn import_blocking<DB, P>(
    backend: &Arc<ChainBackend<DB, P>>,
    blocks: Vec<ProvenBlock>,
) -> Result<HeadersImported, SyncBackendError>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    let backend = Arc::clone(backend);
    tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("inner runtime");
        runtime.block_on(backend.verify_and_import_proven_blocks(blocks))
    })
    .await
    .expect("spawn_blocking import")
}

/// The candidate and the receipt of `backend`'s canonical block `hash`, as
/// the producer publishes them (design 08).
pub fn candidate_and_receipt<DB, P>(
    backend: &ChainBackend<DB, P>,
    hash: &BlockHash,
) -> (CandidateBlock, BlockReceipt)
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    published(backend, hash).split()
}

/// Import candidates on a blocking thread; see [`import_blocking`].
pub async fn import_candidates_blocking<DB, P>(
    backend: &Arc<ChainBackend<DB, P>>,
    candidates: Vec<CandidateBlock>,
) -> Result<HeadersImported, SyncBackendError>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    let backend = Arc::clone(backend);
    tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("inner runtime");
        runtime.block_on(backend.verify_and_import_candidates(candidates))
    })
    .await
    .expect("spawn_blocking import")
}

/// Import receipts on a blocking thread; see [`import_blocking`].
pub async fn import_receipts_blocking<DB, P>(
    backend: &Arc<ChainBackend<DB, P>>,
    receipts: Vec<BlockReceipt>,
) -> Result<ReceiptsImported, SyncBackendError>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    let backend = Arc::clone(backend);
    tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("inner runtime");
        runtime.block_on(backend.verify_and_import_receipts(receipts, gossip_source()))
    })
    .await
    .expect("spawn_blocking import")
}

/// The peer a test receipt is attributed to.
pub fn gossip_source() -> neutrin0_network::PeerId {
    neutrin0_network::libp2p::identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id()
}
