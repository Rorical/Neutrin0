//! Detect, verify, and apply the `InvalidProofSigning` slashing
//! variant end-to-end against [`MockProofSystem`].
//!
//! The variant accuses a validator of signing a chunk-precommit covering a
//! block whose proof the local engine independently rejected. Coverage:
//!
//! 1. Bad receipt published → `verify_and_import_proven_blocks` rejects
//!    → engine caches the rejected proof.
//! 2. The malicious validator publishes a precommit for the chunk
//!    covering the bad block.
//! 3. `ingest_finality_vote` runs the detector → produces an
//!    `InvalidProofSigning` evidence carrying the bad proof.
//! 4. The evidence lands in the slashing pool.
//! 5. Peer-supplied evidence with a proof that *actually* verifies
//!    is rejected at `ingest_slashing_evidence` time.

use std::sync::Arc;

use neutrin0_consensus_engine::body::compute_body_roots;
use neutrin0_consensus_engine::validator_set::validator_set_root;
use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_consensus_types::{
    Block, BlockProof, BlockProofPublicInputs, Body, FinalityVote, FinalityVoteData,
    FinalityVotePhase, Header, ProofRejectionReason, ProvenBlock, SlashingEvidence,
};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BitVec, BlockHash, BoundedBytes, ChainSpec, ConsensusParams, Height, LightClientParams,
    ProofParams, RuntimeInfo, RuntimeParams, Validator, ZERO_HASH, fixed_u128_from_integer,
};
use neutrin0_proof_system::{MockBlockProof, MockProofSystem};
use neutrin0_storage::MemoryDatabase;
use neutrin0_sync::SyncBackend;

const TEST_CHAIN_ID: u64 = 222_222;
const TEST_GENESIS_SEED: [u8; 32] = [0xC2; 32];

fn proposer(seed: u8) -> ProposerKey {
    ProposerKey::from_ikm(&[seed; 32], u32::from(seed)).expect("derive proposer")
}

fn validators(count: u8) -> Vec<Validator> {
    (0..count)
        .map(|i| Validator {
            pubkey: *proposer(i).public_key_bytes(),
            withdrawal_credentials: neutrin0_primitives::runtime_account([0x44; 20]),
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
    let genesis_block_hash: BlockHash = [0xAA; 32];
    let consensus = ConsensusParams {
        chunk_size: 1,
        expected_proposers_per_slot: fixed_u128_from_integer(u64::from(count) + 4),
        ..ConsensusParams::default()
    };
    ChainSpec {
        genesis_execution: neutrin0_primitives::ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
        name: BoundedBytes::new(b"m7-invalid-proof-signing".to_vec()).expect("name fits"),
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
        consensus,
        proof,
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators,
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    }
}

fn fresh_backend() -> Arc<ChainBackend<MemoryDatabase, MockProofSystem>> {
    let engine = Engine::genesis(spec(2), MemoryDatabase::new()).expect("genesis");
    let backend = ChainBackend::new(engine, MockProofSystem::new());
    backend
        .enable_proof_follow()
        .expect("executor-less fixture follows receipts");
    Arc::new(backend)
}

fn signed_block(slot: u64, parent: BlockHash, height: Height, signer: &ProposerKey) -> Block {
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
        runtime_extra: ZERO_HASH,
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

/// Construct a wire `BlockProof` whose inner `MockBlockProof` carries
/// a deliberately-wrong commitment so `MockProofSystem::verify_block`
/// rejects with `PublicInputMismatch`.
///
/// `proposer_address` must match `chain_spec.initial_validators[0].withdrawal_credentials`
/// (`runtime_account([0x44; 20])` per the test's `validators()` helper) so the
/// engine's `block_proof_public_inputs` cross-check at
/// `Engine::import_block_proof` accepts the envelope and only the
/// inner backend proof bytes get rejected.
fn bad_mock_proof(block: &Block) -> BlockProof {
    let public_inputs = BlockProofPublicInputs {
        context: Box::new(neutrin0_prover_chunk::execution::runtime_context(
            &block.header,
            neutrin0_consensus_types::history_proof::ConsensusBoundary::genesis(&spec(2)),
        )),
        chain_id: TEST_CHAIN_ID,
        height: block.header.height,
        parent_block_hash: block.header.parent_hash,
        block_hash: block.hash(),
        state_root_before: ZERO_HASH,
        state_root_after: block.header.state_root,
        transactions_root: block.header.transactions_root,
        receipt_root: block.header.receipts_root,
        da_root: block.header.da_root,
        vm_code_hash: [0xCC; 32],
        block_program: [3; 8],
        gas_used: block.header.gas_used,
        gas_limit: block.header.gas_limit,
        proposer_address: neutrin0_primitives::runtime_account([0x44; 20]),
        runtime_extra: block.header.runtime_extra,
        inputs_root: block.header.inputs_root,
    };
    // Commitment doesn't match what MockProofSystem would compute,
    // so verify_block fails with PublicInputMismatch.
    let bogus = MockBlockProof {
        commitment: [0xEE; 32],
        prover_address: neutrin0_primitives::runtime_account([0x44; 20]),
    };
    let proof_bytes = borsh::to_vec(&bogus).expect("encode mock proof");
    // Receivers read attribution from verified public values; the envelope
    // of a rejected receipt carries none.
    BlockProof {
        prover_address: ZERO_HASH,
        statement_key: ZERO_HASH,
        height: block.header.height,
        block_hash: block.hash(),
        public_inputs,
        proof_bytes,
    }
}

/// Construct a wire `BlockProof` whose inner `MockBlockProof` carries
/// the commitment `MockProofSystem` will accept — i.e. a *valid*
/// proof. Used to demonstrate that peer evidence carrying a
/// well-formed proof is correctly rejected by the ingest path.
fn good_mock_proof(block: &Block) -> BlockProof {
    let public_inputs = BlockProofPublicInputs {
        context: Box::new(neutrin0_prover_chunk::execution::runtime_context(
            &block.header,
            neutrin0_consensus_types::history_proof::ConsensusBoundary::genesis(&spec(2)),
        )),
        chain_id: TEST_CHAIN_ID,
        height: block.header.height,
        parent_block_hash: block.header.parent_hash,
        block_hash: block.hash(),
        state_root_before: ZERO_HASH,
        state_root_after: block.header.state_root,
        transactions_root: block.header.transactions_root,
        receipt_root: block.header.receipts_root,
        da_root: block.header.da_root,
        vm_code_hash: [0xCC; 32],
        block_program: [3; 8],
        gas_used: block.header.gas_used,
        gas_limit: block.header.gas_limit,
        proposer_address: neutrin0_primitives::runtime_account([0x44; 20]),
        runtime_extra: block.header.runtime_extra,
        inputs_root: block.header.inputs_root,
    };
    let mock_proof = MockProofSystem::new()
        .prove_block_for_test(&public_inputs)
        .expect("prove mock proof");
    let proof_bytes = borsh::to_vec(&mock_proof).expect("encode mock proof");
    // The stored envelope carries the attribution of the verified statement.
    let statement =
        neutrin0_proof_system::ProofSystem::block_statement(&MockProofSystem::new(), &mock_proof)
            .expect("mock statement");
    BlockProof {
        prover_address: statement.prover_address,
        statement_key: neutrin0_consensus_engine::statement_key(&statement),
        height: block.header.height,
        block_hash: block.hash(),
        public_inputs,
        proof_bytes,
    }
}

/// The publication of `block` carrying `proof`'s receipt bytes. Fixture
/// blocks declare their state root; the executor-less backend trusts it.
fn bundle_with(block: &Block, proof: &BlockProof) -> ProvenBlock {
    ProvenBlock {
        block: block.clone(),
        proof_bytes: proof.proof_bytes.clone(),
        writes: Vec::new(),
    }
}

/// The receipt the node archived for `hash`.
fn stored_receipt(
    backend: &ChainBackend<MemoryDatabase, MockProofSystem>,
    hash: BlockHash,
) -> BlockProof {
    backend.with_engine_mut_for_test(|engine| {
        engine
            .store()
            .get_block_proof(&hash)
            .expect("store")
            .expect("receipt archived")
    })
}

/// Convenience wrapper since `MockProofSystem::prove_block` is hidden
/// behind a trait. The trait method's signature is identical to what
/// we want here.
trait MockProofForTest {
    fn prove_block_for_test(
        &self,
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<MockBlockProof, neutrin0_proof_system::ProofError>;
}

impl MockProofForTest for MockProofSystem {
    fn prove_block_for_test(
        &self,
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<MockBlockProof, neutrin0_proof_system::ProofError> {
        use neutrin0_proof_system::ProofSystem;
        ProofSystem::prove_block(self, &[], public_inputs, public_inputs.proposer_address)
    }
}

fn partial_vote(
    chunk_id: u64,
    phase: FinalityVotePhase,
    signer: &ProposerKey,
    active_set_len: usize,
) -> FinalityVote {
    let data = FinalityVoteData {
        chunk_id,
        round: 0,
        chunk_hash: [0x77; 32],
        selection: [0; 32],
        phase,
    };
    let signature = signer.sign_finality_vote(spec(2).consensus_domain(), &data);
    let voter_position = usize::try_from(signer.validator_index()).expect("u32 fits usize");
    let mut bits = BitVec::default();
    for position in 0..active_set_len {
        bits.push(position == voter_position);
    }
    FinalityVote {
        proof_manifests: Vec::new(),
        attestations: Vec::new(),
        aggregation_bits: bits,
        data,
        signature,
    }
}

#[tokio::test]
async fn invalid_proof_signing_detector_emits_evidence_on_precommit() {
    let backend = fresh_backend();
    let v0 = proposer(0);
    let v1 = proposer(1);

    // Step 1: import block 1 via the gossip path (peer-signed).
    let genesis_hash = backend.local_status().await.unwrap().head_block_hash;
    let block_1 = signed_block(1, genesis_hash, 1, &v0);
    backend
        .verify_and_import_proven_blocks(vec![bundle_with(&block_1, &good_mock_proof(&block_1))])
        .await
        .expect("import block 1");

    // Step 2: publish a tampered receipt for block 1. The engine
    // rejects and caches it under `rejected_proofs`.
    let bad_proof = bad_mock_proof(&block_1);
    let err = backend
        .verify_and_import_proven_blocks(vec![bundle_with(&block_1, &bad_proof)])
        .await
        .expect_err("tampered proof must be rejected");
    assert!(
        matches!(err, neutrin0_sync::SyncBackendError::Rejected(_)),
        "expected Rejected, got {err:?}",
    );

    assert_eq!(backend.slashing_pool_len(), 0, "no evidence pooled yet");

    // Step 3: v1 (malicious from the local node's perspective)
    // publishes a precommit for chunk 0 covering the bad block.
    // The detector fires and pools an InvalidProofSigning entry.
    let active_set_len = 2;
    let mut bad_vote = partial_vote(0, FinalityVotePhase::Precommit, &v1, active_set_len);
    let mut hashes = vec![[0; 32]; usize::try_from(spec(2).consensus.chunk_size).unwrap()];
    hashes[0] = neutrin0_consensus_types::evidence::commitment(&bad_proof);
    bad_vote.proof_manifests = vec![neutrin0_consensus_types::ProofManifest {
        proof_hashes: hashes.clone(),
    }];
    bad_vote.attestations.push(v1.attest_vote(
        spec(2).consensus_domain(),
        bad_vote.data.clone(),
        hashes,
        None,
    ));
    let _ = backend.ingest_finality_vote(bad_vote.clone()).await;

    assert_eq!(
        backend.slashing_pool_len(),
        1,
        "InvalidProofSigning evidence must land in the pool",
    );

    // Drain and inspect.
    let drained = backend.drain_slashing_pool(8);
    assert_eq!(drained.len(), 1);
    match &drained[0] {
        SlashingEvidence::InvalidProofSigning {
            validator_index,
            vote,
            rejected_proof,
            reason,
            ..
        } => {
            assert_eq!(
                *validator_index,
                v1.validator_index(),
                "evidence attributes to v1 (the precommit signer)",
            );
            assert_eq!(vote.data.chunk_id, 0);
            assert!(matches!(vote.data.phase, FinalityVotePhase::Precommit));
            assert_eq!(rejected_proof.block_hash, block_1.hash());
            assert_eq!(
                *reason,
                ProofRejectionReason::PublicInputsMismatch,
                "MockProofSystem fails the tampered commitment with PublicInputMismatch",
            );
        }
        other => panic!("expected InvalidProofSigning, got {other:?}"),
    }
}

#[tokio::test]
async fn prevote_does_not_trigger_invalid_proof_signing_detector() {
    // The detector only fires on precommits — prevoting for a chunk
    // expresses readiness to lock, not declaration of proof
    // acceptance, so the prevote phase is not slashable through this
    // path.
    let backend = fresh_backend();
    let v0 = proposer(0);
    let v1 = proposer(1);

    let genesis_hash = backend.local_status().await.unwrap().head_block_hash;
    let block_1 = signed_block(1, genesis_hash, 1, &v0);
    backend
        .verify_and_import_proven_blocks(vec![bundle_with(&block_1, &good_mock_proof(&block_1))])
        .await
        .expect("import block 1");

    let bad_proof = bad_mock_proof(&block_1);
    let _ = backend
        .verify_and_import_proven_blocks(vec![bundle_with(&block_1, &bad_proof)])
        .await;

    let prevote = partial_vote(0, FinalityVotePhase::Prevote, &v1, 2);
    let _ = backend.ingest_finality_vote(prevote).await;

    assert_eq!(
        backend.slashing_pool_len(),
        0,
        "prevotes do not trigger InvalidProofSigning",
    );
}

#[tokio::test]
async fn ingest_rejects_invalid_proof_signing_evidence_whose_proof_verifies() {
    // Peer-supplied evidence that claims a proof was rejected but
    // carries a proof that actually verifies must be dropped. This
    // is the dishonest-emitter guard.
    let backend = fresh_backend();
    let v0 = proposer(0);
    let v1 = proposer(1);

    let genesis_hash = backend.local_status().await.unwrap().head_block_hash;
    let block_1 = signed_block(1, genesis_hash, 1, &v0);
    backend
        .verify_and_import_proven_blocks(vec![bundle_with(&block_1, &good_mock_proof(&block_1))])
        .await
        .expect("import block 1");

    // Construct evidence whose carried proof *would verify* against
    // MockProofSystem. The signature side check passes (v1 actually
    // signed a precommit). But the proof side check fails — the
    // ingest path rejects.
    let valid_proof = good_mock_proof(&block_1);
    let valid_vote = partial_vote(0, FinalityVotePhase::Precommit, &v1, 2);
    let indexed = neutrin0_consensus_types::IndexedVote {
        data: valid_vote.data,
        signature: valid_vote.signature,
    };
    let manifest = neutrin0_consensus_types::ProofManifest {
        proof_hashes: vec![
            neutrin0_consensus_types::evidence::commitment(&valid_proof);
            usize::try_from(spec(2).consensus.chunk_size).unwrap()
        ],
    };
    let dishonest_evidence = SlashingEvidence::InvalidProofSigning {
        proof_opening: manifest.opening(0).unwrap(),
        validator_index: v1.validator_index(),
        attestation: v1.attest_vote(
            spec(2).consensus_domain(),
            indexed.data.clone(),
            manifest.proof_hashes,
            None,
        ),
        vote: indexed,
        rejected_proof: valid_proof,
        reason: ProofRejectionReason::VerifierRejected,
    };

    let _ = backend.ingest_slashing_evidence(dishonest_evidence).await;
    assert_eq!(
        backend.slashing_pool_len(),
        0,
        "evidence carrying a proof that verifies must be dropped",
    );
}

#[tokio::test]
async fn ordinary_precommit_does_not_accept_a_peers_substituted_proof() {
    let backend = fresh_backend();
    let genesis_hash = backend.local_status().await.unwrap().head_block_hash;
    let block = signed_block(1, genesis_hash, 1, &proposer(0));
    backend
        .verify_and_import_proven_blocks(vec![bundle_with(&block, &good_mock_proof(&block))])
        .await
        .unwrap();
    let proof = bad_mock_proof(&block);
    assert!(
        backend
            .verify_and_import_proven_blocks(vec![bundle_with(&block, &proof)])
            .await
            .is_err()
    );
    let vote = partial_vote(0, FinalityVotePhase::Precommit, &proposer(1), 2);
    let _ = backend.ingest_finality_vote(vote).await;
    assert_eq!(
        backend.slashing_pool_len(),
        0,
        "a peer cannot frame an ordinary precommit signer by injecting a rejected proof"
    );
}

#[tokio::test]
async fn aggregate_only_proof_acceptance_attributes_every_signer() {
    let backend = fresh_backend();
    let genesis = backend.local_status().await.unwrap().head_block_hash;
    let block = signed_block(1, genesis, 1, &proposer(0));
    backend
        .verify_and_import_proven_blocks(vec![bundle_with(&block, &good_mock_proof(&block))])
        .await
        .unwrap();
    let rejected = bad_mock_proof(&block);
    assert!(
        backend
            .verify_and_import_proven_blocks(vec![bundle_with(&block, &rejected)])
            .await
            .is_err()
    );
    let mut aggregate = partial_vote(0, FinalityVotePhase::Precommit, &proposer(0), 2);
    aggregate.proof_manifests = vec![neutrin0_consensus_types::ProofManifest {
        proof_hashes: vec![neutrin0_consensus_types::evidence::commitment(&rejected)],
    }];
    aggregate.aggregation_bits = BitVec::from_bytes(2, vec![3]).unwrap();
    let signatures: Vec<_> = (0..2)
        .map(|index| {
            let voter = proposer(index);
            aggregate.attestations.push(voter.attest_vote(
                spec(2).consensus_domain(),
                aggregate.data.clone(),
                vec![neutrin0_consensus_types::evidence::commitment(&rejected)],
                None,
            ));
            neutrin0_crypto::bls::Signature::from_bytes(
                &voter.sign_finality_vote(spec(2).consensus_domain(), &aggregate.data),
            )
            .unwrap()
        })
        .collect();
    aggregate.signature =
        neutrin0_crypto::bls::aggregate_signatures(&signatures.iter().collect::<Vec<_>>())
            .unwrap()
            .to_bytes();
    let _ = backend.ingest_aggregate_finality_vote(0, aggregate).await;
    let evidence = backend.drain_slashing_pool(8);
    assert_eq!(evidence.len(), 2);
    let mut signers: Vec<_> = evidence
        .iter()
        .map(|evidence| {
            let SlashingEvidence::InvalidProofSigning {
                validator_index, ..
            } = evidence
            else {
                panic!("wrong sanction")
            };
            *validator_index
        })
        .collect();
    signers.sort_unstable();
    assert_eq!(signers, vec![0, 1]);
}

fn proof_acceptance_vote(proof: &BlockProof, signer: &ProposerKey) -> FinalityVote {
    let mut vote = partial_vote(0, FinalityVotePhase::Precommit, signer, 2);
    vote.proof_manifests = vec![neutrin0_consensus_types::ProofManifest {
        proof_hashes: vec![neutrin0_consensus_types::evidence::commitment(proof)],
    }];
    vote.attestations.push(signer.attest_vote(
        spec(2).consensus_domain(),
        vote.data.clone(),
        vec![neutrin0_consensus_types::evidence::commitment(proof)],
        None,
    ));
    vote
}

fn assert_objective_invalid_acceptance(
    offences: &[SlashingEvidence],
    invalid: &BlockProof,
    signer_index: u32,
    expected_reason: ProofRejectionReason,
) {
    use neutrin0_proof_system::ProofSystem;
    let [
        SlashingEvidence::InvalidProofSigning {
            validator_index,
            vote,
            attestation,
            rejected_proof,
            proof_opening,
            reason,
        },
    ] = offences
    else {
        panic!("expected one objectively attributable invalid-proof offence, got {offences:?}")
    };
    assert_eq!(*validator_index, signer_index);
    assert_eq!(
        rejected_proof, invalid,
        "later valid bytes do not change the old exact-byte verdict"
    );
    assert_eq!(*reason, expected_reason);
    assert!(attestation.proof_acceptance.unwrap().verify(
        &neutrin0_consensus_types::evidence::commitment(rejected_proof),
        proof_opening
    ));
    neutrin0_consensus_engine::slashing::verify_proof_signing_attribution(
        *validator_index,
        vote,
        attestation,
        rejected_proof,
        proof_opening,
        &validators(2),
        spec(2).consensus_domain(),
        1,
    )
    .unwrap();
    let rejected =
        borsh::from_slice::<MockBlockProof>(&rejected_proof.proof_bytes).map_or(true, |decoded| {
            MockProofSystem::new()
                .verify_block(&decoded, &rejected_proof.public_inputs)
                .is_err()
        });
    assert!(
        rejected,
        "the carried exact bytes are independently rejected"
    );
}

#[tokio::test]
async fn valid_replacement_preserves_accountability_for_later_signed_invalid_bytes() {
    for malformed in [false, true] {
        let backend = fresh_backend();
        let signer = proposer(1);
        let genesis = backend.local_status().await.unwrap().head_block_hash;
        let block = signed_block(1, genesis, 1, &proposer(0));
        let hash = block.hash();
        let mut invalid = bad_mock_proof(&block);
        let expected_reason = if malformed {
            invalid.proof_bytes = vec![0x99];
            ProofRejectionReason::MalformedProof
        } else {
            ProofRejectionReason::PublicInputsMismatch
        };
        // The invalid publication imports nothing; the valid one proves the block.
        assert!(
            backend
                .verify_and_import_proven_blocks(vec![bundle_with(&block, &invalid)])
                .await
                .is_err()
        );
        assert_eq!(backend.block_state(&hash), None);
        let valid = good_mock_proof(&block);
        backend
            .verify_and_import_proven_blocks(vec![bundle_with(&block, &valid)])
            .await
            .unwrap();
        assert_eq!(
            backend.block_state(&hash),
            Some(neutrin0_consensus_engine::BlockState::Proven)
        );
        assert_eq!(stored_receipt(&backend, hash), valid);

        let valid_vote = proof_acceptance_vote(&valid, &signer);
        let _ = backend.ingest_finality_vote(valid_vote.clone()).await;
        assert_eq!(
            backend.slashing_pool_len(),
            0,
            "accepting valid bytes cannot inherit an older rejection"
        );
        let _ = backend
            .ingest_finality_vote(proof_acceptance_vote(&invalid, &signer))
            .await;
        let offences = backend.drain_slashing_pool(8);
        assert_objective_invalid_acceptance(
            &offences,
            &invalid,
            signer.validator_index(),
            expected_reason,
        );

        // The objective evidence affects neither proof storage nor the block FSM.
        assert_eq!(
            backend.block_state(&hash),
            Some(neutrin0_consensus_engine::BlockState::Proven)
        );
        assert_eq!(stored_receipt(&backend, hash), valid);
        let _ = backend.ingest_finality_vote(valid_vote).await;
        assert_eq!(backend.slashing_pool_len(), 0);
    }
}

#[tokio::test]
async fn exact_fetched_rejected_proof_arriving_after_attestation_detects_offence() {
    use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
    let backend = fresh_backend();
    let block = signed_block(1, spec(2).genesis_block_hash, 1, &proposer(0));
    backend
        .verify_and_import_proven_blocks(vec![bundle_with(&block, &good_mock_proof(&block))])
        .await
        .unwrap();
    let proof = bad_mock_proof(&block);
    let source = SignedArtifact::BlockProof(proof.clone());
    let mut vote = partial_vote(0, FinalityVotePhase::Precommit, &proposer(1), 2);
    vote.proof_manifests = vec![neutrin0_consensus_types::ProofManifest {
        proof_hashes: vec![source.id()],
    }];
    vote.attestations.push(proposer(1).attest_vote(
        spec(2).consensus_domain(),
        vote.data.clone(),
        vec![source.id()],
        None,
    ));
    let _ = backend.ingest_finality_vote(vote.clone()).await;
    assert_eq!(backend.slashing_pool_len(), 0);
    assert_eq!(backend.missing_vote_artifacts(&vote).await.len(), 1);
    assert_eq!(
        backend.ingest_signed_artifact(source.clone()).await,
        neutrin0_sync::EvidenceProofAcceptance::Accepted
    );
    assert_eq!(backend.slashing_pool_len(), 1);
    assert_eq!(
        backend
            .signed_artifact_by_id(source.id())
            .await
            .unwrap()
            .artifact,
        source
    );
    assert_eq!(
        backend.missing_vote_artifacts(&vote).await,
        Vec::<neutrin0_consensus_types::signed_artifacts::SignedArtifactRef>::new()
    );
}

#[tokio::test]
async fn exact_artifacts_preserve_distinct_rejected_encodings_of_one_block() {
    use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
    let backend = fresh_backend();
    let block = signed_block(1, spec(2).genesis_block_hash, 1, &proposer(0));
    backend
        .verify_and_import_proven_blocks(vec![bundle_with(&block, &good_mock_proof(&block))])
        .await
        .unwrap();
    let first = bad_mock_proof(&block);
    let mut second = first.clone();
    second.proof_bytes = borsh::to_vec(&MockBlockProof {
        commitment: [0xDD; 32],
        prover_address: neutrin0_primitives::runtime_account([0x44; 20]),
    })
    .unwrap();
    let first = SignedArtifact::BlockProof(first);
    let second = SignedArtifact::BlockProof(second);
    assert_ne!(first.id(), second.id());
    // Rejected bytes are retained once a precommit names them; a manifest
    // lists one envelope per block, so each encoding needs its own signer.
    for (signer, source) in [(0, &first), (1, &second)] {
        let _ = backend
            .ingest_finality_vote(naming_precommit(signer, source.id()))
            .await;
    }
    assert_eq!(
        backend.ingest_signed_artifact(first.clone()).await,
        neutrin0_sync::EvidenceProofAcceptance::Accepted
    );
    assert_eq!(
        backend.ingest_signed_artifact(second.clone()).await,
        neutrin0_sync::EvidenceProofAcceptance::Accepted
    );
    assert_eq!(
        backend
            .signed_artifact_by_id(first.id())
            .await
            .unwrap()
            .artifact,
        first
    );
    assert_eq!(
        backend
            .signed_artifact_by_id(second.id())
            .await
            .unwrap()
            .artifact,
        second
    );
    // The accepted receipt of the publication is an exact source too, beside
    // the two distinct rejected encodings.
    let inventory = backend.signed_artifact_inventory(0, None).await.unwrap();
    assert_eq!(block_proof_entries(&inventory), 3);
}

#[tokio::test]
async fn rejected_envelopes_no_precommit_names_are_neither_retained_nor_relayed() {
    use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
    let backend = fresh_backend();
    let block = signed_block(1, spec(2).genesis_block_hash, 1, &proposer(0));
    backend
        .verify_and_import_proven_blocks(vec![bundle_with(&block, &good_mock_proof(&block))])
        .await
        .unwrap();
    // Anyone can fabricate rejected envelopes of a known header; unnamed ones
    // must not occupy the store that holds this node's votes.
    let junk = SignedArtifact::BlockProof(bad_mock_proof(&block));
    assert_eq!(
        backend.ingest_signed_artifact(junk.clone()).await,
        neutrin0_sync::EvidenceProofAcceptance::Deferred
    );
    let inventory = backend.signed_artifact_inventory(0, None).await.unwrap();
    assert_eq!(block_proof_entries(&inventory), 1);
    // The bytes wait in the bounded rejection cache: a precommit that later
    // accepts them is still an offence.
    let _ = backend
        .ingest_finality_vote(naming_precommit(1, junk.id()))
        .await;
    assert_eq!(backend.slashing_pool_len(), 1);
}

/// A precommit by validator `signer` whose proof manifest lists `id`.
fn naming_precommit(signer: u8, id: neutrin0_primitives::Hash) -> FinalityVote {
    let mut vote = partial_vote(0, FinalityVotePhase::Precommit, &proposer(signer), 2);
    vote.proof_manifests = vec![neutrin0_consensus_types::ProofManifest {
        proof_hashes: vec![id],
    }];
    vote.attestations.push(proposer(signer).attest_vote(
        spec(2).consensus_domain(),
        vote.data.clone(),
        vec![id],
        None,
    ));
    vote
}

fn block_proof_entries(
    inventory: &neutrin0_consensus_types::signed_artifacts::SignedArtifactInventory,
) -> usize {
    inventory
        .entries
        .iter()
        .filter(|entry| {
            entry.kind == neutrin0_consensus_types::signed_artifacts::SignedArtifactKind::BlockProof
        })
        .count()
}

#[tokio::test]
async fn forged_and_future_source_artifacts_never_enter_durable_inventory() {
    use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
    let backend = fresh_backend();
    let mut vote = partial_vote(0, FinalityVotePhase::Prevote, &proposer(1), 2);
    vote.attestations.push(proposer(1).attest_vote(
        spec(2).consensus_domain(),
        vote.data.clone(),
        Vec::new(),
        None,
    ));
    vote.signature[0] ^= 1;
    assert_eq!(
        backend
            .ingest_signed_artifact(SignedArtifact::Vote(vote))
            .await,
        neutrin0_sync::EvidenceProofAcceptance::Rejected
    );
    let mut future = partial_vote(u64::MAX, FinalityVotePhase::Prevote, &proposer(1), 2);
    future.attestations.push(proposer(1).attest_vote(
        spec(2).consensus_domain(),
        future.data.clone(),
        Vec::new(),
        None,
    ));
    assert_eq!(
        backend
            .ingest_signed_artifact(SignedArtifact::Vote(future))
            .await,
        neutrin0_sync::EvidenceProofAcceptance::Deferred
    );
    assert_eq!(
        backend
            .signed_artifact_inventory(0, None)
            .await
            .unwrap()
            .entries,
        Vec::<neutrin0_consensus_types::signed_artifacts::SignedArtifactRef>::new()
    );
}

#[tokio::test]
async fn accepted_source_rpc_uses_existing_immutable_receipt_bytes() {
    use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
    use neutrin0_storage::{Column, Database};
    let backend = fresh_backend();
    let block = signed_block(1, spec(2).genesis_block_hash, 1, &proposer(0));
    let proof = good_mock_proof(&block);
    backend
        .verify_and_import_proven_blocks(vec![bundle_with(&block, &proof)])
        .await
        .unwrap();
    let artifact = SignedArtifact::BlockProof(proof);
    assert_eq!(
        backend
            .signed_artifact_by_id(artifact.id())
            .await
            .unwrap()
            .artifact,
        artifact
    );
    let stored_bytes = backend.with_engine_mut_for_test(|engine| {
        engine
            .store()
            .db()
            .get(Column::SignedArtifacts, &artifact.id())
            .unwrap()
            .unwrap()
    });
    assert!(
        stored_bytes.len() < 64,
        "accepted sources store an immutable receipt pointer"
    );
}

#[tokio::test]
async fn delayed_lock_quorum_after_restart_revisits_later_signed_prevotes() {
    use neutrin0_consensus_types::{
        AggregatedVote, QuorumCertificate, signed_artifacts::SignedArtifact,
    };
    let backend = fresh_backend();
    let mut prior = partial_vote(0, FinalityVotePhase::Precommit, &proposer(1), 2);
    prior.data.chunk_hash = [0x41; 32];
    prior.signature = proposer(1).sign_finality_vote(spec(2).consensus_domain(), &prior.data);
    prior.proof_manifests = vec![neutrin0_consensus_types::ProofManifest {
        proof_hashes: vec![[9; 32]],
    }];
    prior.attestations.push(proposer(1).attest_vote(
        spec(2).consensus_domain(),
        prior.data.clone(),
        vec![[9; 32]],
        None,
    ));
    let mut later = partial_vote(0, FinalityVotePhase::Prevote, &proposer(1), 2);
    later.data.round = 2;
    later.signature = proposer(1).sign_finality_vote(spec(2).consensus_domain(), &later.data);
    later.attestations.push(proposer(1).attest_vote(
        spec(2).consensus_domain(),
        later.data.clone(),
        Vec::new(),
        None,
    ));
    let _ = backend.ingest_finality_vote(later).await;
    let _ = backend.ingest_finality_vote(prior.clone()).await;
    assert_eq!(backend.slashing_pool_len(), 0);
    let db = backend.with_engine_mut_for_test(|engine| engine.store().db().clone());
    let engine = Engine::open(spec(2), db).unwrap();
    let restarted = ChainBackend::new(engine, MockProofSystem::new());
    let mut data = prior.data;
    data.phase = FinalityVotePhase::Prevote;
    let signatures: Vec<_> = (0..2)
        .map(|index| {
            neutrin0_crypto::bls::Signature::from_bytes(
                &proposer(index).sign_finality_vote(spec(2).consensus_domain(), &data),
            )
            .unwrap()
        })
        .collect();
    let quorum = QuorumCertificate {
        data,
        aggregate: AggregatedVote {
            aggregation_bits: BitVec::from_bytes(2, vec![3]).unwrap(),
            signature: neutrin0_crypto::bls::aggregate_signatures(
                &signatures.iter().collect::<Vec<_>>(),
            )
            .unwrap()
            .to_bytes(),
        },
    };
    assert_eq!(
        restarted
            .ingest_signed_artifact(SignedArtifact::Quorum(quorum))
            .await,
        neutrin0_sync::EvidenceProofAcceptance::Accepted
    );
    assert_eq!(restarted.slashing_pool_len(), 1);
    assert!(matches!(
        &restarted.drain_slashing_pool(1)[0],
        SlashingEvidence::LockViolation { .. }
    ));
}

fn domain_value_vote(spec: &ChainSpec) -> FinalityVote {
    let signer = proposer(1);
    let data = FinalityVoteData {
        chunk_id: 0,
        round: 0,
        phase: FinalityVotePhase::Prevote,
        chunk_hash: [0x77; 32],
        selection: [0; 32],
    };
    let domain = spec.consensus_domain();
    FinalityVote {
        proof_manifests: Vec::new(),
        signature: signer.sign_finality_vote(domain, &data),
        aggregation_bits: BitVec::from_bytes(2, vec![2]).unwrap(),
        attestations: vec![signer.attest_vote(domain, data.clone(), Vec::new(), None)],
        data,
    }
}

fn domain_nil_vote(spec: &ChainSpec) -> neutrin0_consensus_types::NilVote {
    use neutrin0_consensus_types::{NilVote, NilVoteAttestation, NilVoteData};
    let signer = proposer(1);
    let domain = spec.consensus_domain();
    let data = NilVoteData {
        chunk_id: 0,
        round: 0,
        phase: FinalityVotePhase::Prevote,
    };
    let signature = signer.sign_raw(&data.signing_message(domain)).to_bytes();
    let mut claim = NilVoteAttestation {
        validator_index: 1,
        vote: data.clone(),
        vote_signature: signature,
        signature: [0; 96],
    };
    claim.signature = signer.sign_raw(&claim.signing_message(domain)).to_bytes();
    NilVote {
        data,
        aggregation_bits: BitVec::from_bytes(2, vec![2]).unwrap(),
        signature,
        attestations: vec![claim],
    }
}

#[tokio::test]
async fn late_sources_from_same_id_different_spec_cannot_synthesize_or_authorize_slashing() {
    use neutrin0_consensus_types::{IndexedNilVote, IndexedVote, signed_artifacts::SignedArtifact};
    use neutrin0_sync::EvidenceProofAcceptance::{Accepted, Rejected};
    let first = spec(2);
    let mut second = first.clone();
    second.genesis_time += 1;
    assert_eq!(first.chain_id, second.chain_id);
    assert_eq!(first.initial_validators, second.initial_validators);
    assert_ne!(first.hash(), second.hash());
    let foreign = domain_nil_vote(&first);
    let original = ChainBackend::new(
        Engine::genesis(first.clone(), MemoryDatabase::new()).unwrap(),
        MockProofSystem::new(),
    );
    assert_eq!(
        original
            .ingest_signed_artifact(SignedArtifact::NilVote(foreign.clone()))
            .await,
        Accepted
    );
    let backend = ChainBackend::new(
        Engine::genesis(second.clone(), MemoryDatabase::new()).unwrap(),
        MockProofSystem::new(),
    );
    let value = domain_value_vote(&second);
    assert_eq!(
        backend
            .ingest_signed_artifact(SignedArtifact::Vote(value.clone()))
            .await,
        Accepted
    );
    for source in [
        SignedArtifact::NilVote(foreign.clone()),
        SignedArtifact::Vote(domain_value_vote(&first)),
    ] {
        assert_eq!(
            backend.ingest_signed_artifact(source.clone()).await,
            Rejected
        );
        assert!(backend.signed_artifact_by_id(source.id()).await.is_err());
    }
    let mixed = SlashingEvidence::ConflictingNilVote {
        validator_index: 1,
        value_vote: IndexedVote {
            data: value.data,
            signature: value.signature,
        },
        nil_vote: IndexedNilVote {
            data: foreign.data.clone(),
            signature: foreign.signature,
        },
    };
    let _ = backend.ingest_slashing_evidence(mixed).await;
    assert_eq!(backend.slashing_pool_len(), 0);
    let restarted = ChainBackend::new(
        Engine::open(second.clone(), backend.snapshot_database()).unwrap(),
        MockProofSystem::new(),
    );
    assert_eq!(
        restarted
            .ingest_signed_artifact(SignedArtifact::NilVote(foreign))
            .await,
        Rejected
    );
    assert_eq!(restarted.slashing_pool_len(), 0);
    assert_eq!(
        backend
            .ingest_signed_artifact(SignedArtifact::NilVote(domain_nil_vote(&second)))
            .await,
        Accepted
    );
    assert!(matches!(
        backend.drain_slashing_pool(1).as_slice(),
        [SlashingEvidence::ConflictingNilVote { .. }]
    ));
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
