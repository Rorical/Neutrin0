//! Finalized statistics follow durable commits, never duplicate receipt imports.

use super::{NativeConsensusBackend, engine, ready_prover};
use neutrin0_consensus_engine::ProposerKey;
use neutrin0_consensus_types::BlockProofPublicInputs;
use neutrin0_node::ChainBackend;
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_prover_chunk::consensus::ConsensusWitness;
use neutrin0_runtime_abi::BlockReceiptStatement;
use neutrin0_sync::SyncBackend;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// The native fixture can stop exposing a local prover while retaining its
/// verifier, exercising the engine's successful duplicate-receipt response.
struct OptionalLocalProver {
    native: NativeConsensusBackend,
    enabled: Arc<AtomicBool>,
}

impl ProofSystem for OptionalLocalProver {
    type BlockProof = BlockReceiptStatement;
    type ChunkProof = neutrin0_consensus_types::history_proof::ChunkReceiptStatement;

    fn prove_block(
        &self,
        witness: &[u8],
        inputs: &BlockProofPublicInputs,
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::BlockProof, ProofError> {
        self.native.prove_block(witness, inputs, prover_address)
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        self.native.verify_block(proof, inputs)
    }

    fn block_statement(
        &self,
        proof: &Self::BlockProof,
    ) -> Result<BlockReceiptStatement, ProofError> {
        self.native.block_statement(proof)
    }

    fn programs(&self) -> Option<neutrin0_consensus_types::history_proof::GuestPrograms> {
        self.enabled
            .load(Ordering::Relaxed)
            .then(|| self.native.programs().unwrap())
    }

    fn prove_consensus_chunk(
        &self,
        proofs: &[Self::BlockProof],
        ratified: &[Self::ChunkProof],
        witness: &ConsensusWitness,
        chunk_prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::ChunkProof, ProofError> {
        self.native
            .prove_consensus_chunk(proofs, ratified, witness, chunk_prover_address)
    }

    fn chunk_prover_address(
        &self,
        proof: &Self::ChunkProof,
    ) -> Result<neutrin0_primitives::Hash, ProofError> {
        Ok(proof.chunk_prover_address)
    }

    fn verify_consensus_chunk(
        &self,
        proof: &Self::ChunkProof,
        expected: &neutrin0_consensus_types::history_proof::ChunkReceiptStatement,
    ) -> Result<(), ProofError> {
        self.native.verify_consensus_chunk(proof, expected)
    }
}

#[tokio::test]
async fn each_new_finalized_chunk_is_counted_once_and_duplicate_success_counts_nothing() {
    let (mut source, template) = engine();
    let proposer = ProposerKey::from_ikm(&[42; 32], 0).unwrap();
    source
        .finalize_chunk(0, &ready_prover(), &proposer)
        .unwrap();
    super::evidence_report_races::finalize_next_empty(&mut source, &template);
    let receipt = source.store().get_chunk_proof(1).unwrap().unwrap();
    let header = source.store().get_header_by_height(2).unwrap().unwrap();
    let proof = source
        .store()
        .get_block_proof(&header.hash())
        .unwrap()
        .unwrap();
    let expected_gas = template.blocks[0].header.gas_used + header.gas_used;
    let (follower, _) = engine();
    let enabled = Arc::new(AtomicBool::new(true));
    let backend = ChainBackend::new(
        follower,
        OptionalLocalProver {
            native: ready_prover(),
            enabled: Arc::clone(&enabled),
        },
    );
    let metrics = &backend.metrics().execution;
    metrics.opened(0, None);
    backend.finalize_chunk(0, &proposer).unwrap();
    assert_eq!(metrics.finalized_chunks.load(Ordering::Relaxed), 1);
    let executor = tokio::task::spawn_blocking(neutrin0_runtime_host::WasmExecutor::embedded)
        .await
        .unwrap()
        .unwrap();
    backend.set_block_executor(executor);
    // Ordinary execution materializes the second block's post-state nodes,
    // which consensus rotation reads while admitting its chunk receipt.
    // The second block opens chunk one and carries its predecessor's
    // certificate, so the follower imports the exact publication the source
    // retained: body, receipt bytes and write set.
    let publication = source.proven_block(&header.hash()).unwrap().unwrap();
    assert_eq!(publication.proof_bytes, proof.proof_bytes);
    backend
        .verify_and_import_proven_blocks(vec![publication])
        .await
        .unwrap();
    metrics.opened(1, None);
    backend
        .verify_and_import_chunk_proof(receipt.clone(), neutrin0_network::PeerId::random())
        .await
        .unwrap();
    assert_eq!(metrics.finalized_chunks.load(Ordering::Relaxed), 2);
    assert_eq!(metrics.finalized_gas.load(Ordering::Relaxed), expected_gas);
    assert_eq!(
        metrics
            .finalized_observation_failures
            .load(Ordering::Relaxed),
        0
    );
    // No local program profile disables only the node's already-finalized
    // shortcut. The engine recognizes exact previously accepted proof bytes.
    enabled.store(false, Ordering::Relaxed);
    backend
        .verify_and_import_chunk_proof(receipt, neutrin0_network::PeerId::random())
        .await
        .unwrap();
    assert_eq!(metrics.finalized_chunks.load(Ordering::Relaxed), 2);
    let mut rendered = String::new();
    metrics
        .finalization
        .render(&mut rendered, "finality", "Finality");
    assert!(rendered.contains("finality_seconds_count 2"));
}
