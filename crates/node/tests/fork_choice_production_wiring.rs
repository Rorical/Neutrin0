//! Production finalization advances the fork-choice anchor and records the
//! local validator's real BFT votes. Even a single-validator chain runs the
//! durable signing/session path and requires a proof-bound precommit attestation.

#[path = "support/evm.rs"]
pub mod evm;
use std::sync::Arc;

use neutrin0_consensus_engine::{BlockState, ProposerKey, validator_set_root};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo,
    RuntimeParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
#[path = "support/native_chunk.rs"]
pub mod native_chunk;
use native_chunk::NativeChunkTestSystem;
use neutrin0_runtime_host::WasmExecutor;
use neutrin0_storage::MemoryDatabase;

const CHAIN_ID: u64 = 66666;
const GENESIS_SEED: [u8; 32] = [0xF1; 32];

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
    let genesis_block_hash = [0xF2; 32];
    let consensus = ConsensusParams {
        chunk_size: 1,
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    evm::sealed(ChainSpec {
        genesis_execution: NativeChunkTestSystem::execution_programs(),
        name: BoundedBytes::new(b"fork-choice-prod-wire".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: neutrin0_runtime_host::embedded_runtime_code_hash(),
        genesis_chunk: [7; 8],
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

type Backend = ChainBackend<MemoryDatabase, NativeChunkTestSystem>;

fn fresh_backend() -> Arc<Backend> {
    let engine = evm::genesis_engine(chain_spec(), MemoryDatabase::new(), Vec::new());
    let proof_system = NativeChunkTestSystem::mock().expect("mock SP1 setup");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    let executor = WasmExecutor::embedded().expect("wasm runtime");
    backend.set_block_executor(executor);
    backend
}

/// Acceptance test for `Engine::finalize_chunk` →
/// `fork_choice.add_finalized_chunk`.
///
/// A fresh backend starts with `fork_choice_finalized() ==
/// chain_spec.genesis_block_hash`. After producing + proving +
/// finalising chunk 0 (which covers block 1 since
/// `chunk_size = 1`), the anchor must advance to
/// `block_1.hash() == chunk_0.end_block_hash`.
#[test]
fn chunk_finalisation_advances_fork_choice_finalized_anchor() {
    let backend = fresh_backend();
    let proposer = proposer();
    let genesis_block_hash = chain_spec().genesis_block_hash;

    // Anchor starts at genesis.
    assert_eq!(
        backend.fork_choice_finalized(),
        genesis_block_hash,
        "fresh backend's fork-choice anchor must be the chain-spec genesis hash",
    );

    // Produce block 1 (which fills chunk 0).
    let outcome = backend
        .try_produce_block(1, &proposer)
        .expect("try_produce_block")
        .expect("single validator wins slot 1");
    assert_eq!(outcome.block.header.height, 1);

    // Prove block 1 so the chunk is finalisable.
    let proven = backend
        .prove_block(&outcome.block_hash)
        .expect("prove_block");
    assert_eq!(proven.state, BlockState::Proven);

    // Finalize chunk 0 through a real BFT session whose local signer meets quorum.
    let finalize_outcome = backend
        .finalize_chunk(0, &proposer)
        .expect("finalize chunk 0");
    assert_eq!(finalize_outcome.chunk.chunk_id, 0);
    assert_eq!(
        finalize_outcome.chunk.end_block_hash, outcome.block_hash,
        "chunk 0 ends on block 1 (chunk_size = 1)",
    );

    // The fork-choice anchor must have advanced in lockstep.
    assert_eq!(
        backend.fork_choice_finalized(),
        outcome.block_hash,
        "after finalising chunk 0, the fork-choice anchor must be block 1's hash",
    );
    assert_ne!(
        backend.fork_choice_finalized(),
        genesis_block_hash,
        "anchor must have moved off genesis",
    );

    // A second finalisation (chunk 1, after block 2) must
    // advance the anchor again — confirms `add_finalized_chunk`
    // is invoked on every successful finalisation, not just the
    // first.
    let outcome2 = backend
        .try_produce_block(2, &proposer)
        .expect("try_produce_block 2")
        .expect("single validator wins slot 2");
    backend
        .prove_block(&outcome2.block_hash)
        .expect("prove_block 2");
    backend
        .finalize_chunk(1, &proposer)
        .expect("finalize chunk 1");
    assert_eq!(
        backend.fork_choice_finalized(),
        outcome2.block_hash,
        "after finalising chunk 1, the anchor must be block 2's hash",
    );
}

/// A single validator meets quorum with its own journaled votes, which feed
/// fork choice and bind the exact block proof in the mandatory attestation.
#[test]
fn single_validator_finalisation_records_real_bft_votes_and_attestation() {
    let backend = fresh_backend();
    let proposer = proposer();

    assert_eq!(
        backend.fork_choice_vote_count(),
        0,
        "fresh backend's vote count must be zero",
    );

    let outcome = backend
        .try_produce_block(1, &proposer)
        .expect("produce")
        .expect("eligible");
    backend.prove_block(&outcome.block_hash).expect("prove");
    let block_proof = backend.with_engine_mut_for_test(|engine| {
        engine
            .store()
            .get_block_proof(&outcome.block_hash)
            .expect("read proven block")
            .expect("proof present")
    });
    let finalized = backend.finalize_chunk(0, &proposer).expect("finalize");

    assert_eq!(
        backend.fork_choice_vote_count(),
        1,
        "the local validator's real prevote and precommit feed fork choice",
    );
    let cert = &finalized.finality_cert;
    assert_eq!(cert.chunk_hash, finalized.chunk_hash);
    assert_eq!(cert.precommit_attestations.len(), 1);
    let attestation = &cert.precommit_attestations[0];
    assert_eq!(attestation.validator_index, 0);
    assert_eq!(attestation.vote, cert.precommit_vote().data);
    assert_eq!(
        attestation.proof_acceptance,
        Some(
            neutrin0_consensus_types::ProofManifest {
                proof_hashes: vec![neutrin0_consensus_types::evidence::commitment(&block_proof)]
            }
            .commitment()
        )
    );
    assert!(neutrin0_consensus_types::proof_manifests_valid(
        &cert.precommit_attestations,
        &cert.proof_manifests
    ));
    assert!(attestation.unlock_quorum.is_some());
    let spec = chain_spec();
    neutrin0_prover_chunk::finality::verify_finality(
        spec.consensus_domain(),
        &spec.consensus,
        &spec.initial_validators,
        &spec.genesis_seed,
        &finalized.chunk,
        cert,
    )
    .expect("real signed BFT certificate and mandatory attestation verify");
}
