use super::*;
use crate::ProposerKey;
use crate::block_state::BlockState;
use crate::body::compute_body_roots;
use crate::engine::Engine;
use crate::signature::SignatureError;
use neutrin0_consensus_fork_choice::ProofStatus;
use neutrin0_consensus_types::{Block, BlockProof};
use neutrin0_consensus_types::{BlockProofPublicInputs, BlockStateDiff, Body, Header, ProvenBlock};
use neutrin0_primitives::{ChainSpec, Validator, ZERO_HASH};
use neutrin0_proof_system::{ErasedBlockExecutor, ProofError, ProofSystem};
use neutrin0_storage::Database;
use neutrin0_storage::MemoryDatabase;

const TEST_CHAIN_ID: u64 = 7;
const TEST_GENESIS_SEED: [u8; 32] = [0xDD; 32];
const TEST_IKM: [u8; 32] = [0xAA; 32];
/// Anchor for the in-test slot clock. Test fixtures use this to
/// build header timestamps the import validator accepts
/// (`header.timestamp == clock.timestamp_for(slot)`).
const TEST_GENESIS_TIME: u64 = 1_700_000_000;

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
    ChainSpec {
        genesis_execution: neutrin0_primitives::ExecutionPrograms {
            fact: [1; 8],
            evidence: [2; 8],
            block: [3; 8],
        },
        genesis_time: TEST_GENESIS_TIME,
        runtime_code_hash: [0xCC; 32],
        genesis_chunk: [7; 8],
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: TEST_GENESIS_SEED,
        ..crate::test_db::spec(b"m6-import-test", TEST_CHAIN_ID, validators())
    }
}

/// Build a fully signed, VRF-eligible block. `proposer_override` lets
/// individual tests use a key whose pubkey is NOT in the active set,
/// which is how the rejection paths are exercised.
fn signed_block(
    height: Height,
    slot: Slot,
    parent: BlockHash,
    state_root: [u8; 32],
    proposer_override: Option<&ProposerKey>,
) -> Block {
    let key = proposer();
    let signing_key = proposer_override.unwrap_or(&key);
    let body = Body::default();
    let roots = compute_body_roots(&body);

    let (vrf_proof, _) = neutrin0_vrf::eval(
        signing_key.secret_key(),
        spec().consensus_domain(),
        &TEST_GENESIS_SEED,
        slot,
    );

    let mut header = Header {
        height,
        slot,
        parent_hash: parent,
        proposer_index: signing_key.validator_index(),
        vrf_proof: vrf_proof.to_bytes(),
        state_root,
        transactions_root: roots.transactions_root,
        votes_root: roots.votes_root,
        da_root: roots.da_root,
        runtime_extra: ZERO_HASH,
        inputs_root: [0; 32],
        receipts_root: body.artifacts.commitment(),
        gas_used: 0,
        gas_limit: spec().genesis_gas_limit,
        timestamp: TEST_GENESIS_TIME + slot * 4,
        signature: [0; 96],
    };
    header.inputs_root = fixture_inputs_root(&header);
    let header_hash = header.hash();
    header.signature = signing_key.sign_proposer_message(spec().consensus_domain(), &header_hash);
    Block { header, body }
}

/// The inputs root these fixtures' engines derive for `header` (design
/// 08): chunk zero over the genesis boundary, no carried report or
/// acknowledgement, and the anchor of an engine without installed programs.
fn fixture_inputs_root(header: &Header) -> neutrin0_primitives::Hash {
    let engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    neutrin0_proof_system::execution_inputs_commitment(
        &neutrin0_consensus_types::runtime::ConsensusExecutionContext {
            slot: header.slot,
            timestamp: header.timestamp,
            parent_block_hash: header.parent_hash,
            proposer_vrf_output: neutrin0_vrf::proof_output(&header.vrf_proof),
            finalized: engine.canonical_boundary(0).unwrap(),
        },
        None,
        &[],
        None,
        &[],
        &neutrin0_consensus_types::evidence::EvidenceAnchor::default(),
    )
}

/// Convenience: signed by the canonical test proposer.
fn block(height: Height, slot: Slot, parent: BlockHash, state_root: [u8; 32]) -> Block {
    signed_block(height, slot, parent, state_root, None)
}

#[test]
fn a_header_misdeclaring_its_inputs_is_refused_with_or_without_execution() {
    for executing in [true, false] {
        let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
        let mut block = executed_block(1, 1, engine.head_hash(), engine.state());
        // A proposer that also lies about its inputs cannot be held to an
        // invalid execution claim, so no node admits such a header.
        block.header.inputs_root[0] ^= 1;
        block.header.signature =
            proposer().sign_proposer_message(spec().consensus_domain(), &block.header.hash());
        let result = if executing {
            engine.import_block(&block, &WitnessExecutor)
        } else {
            engine.set_state_source(crate::engine::StateSource::ReceiptDiffs);
            engine.import_candidate_block(
                &neutrin0_consensus_types::CandidateBlock {
                    block: block.clone(),
                    writes: Vec::new(),
                },
                None,
            )
        };
        assert!(
            matches!(result, Err(ImportError::InputsRootMismatch { .. })),
            "executing {executing}: {result:?}"
        );
        assert_eq!(engine.head_height(), 0);
        assert_eq!(engine.store().get_header(&block.hash()).unwrap(), None);
    }
}

#[test]
fn a_second_unproven_candidate_for_one_slot_is_refused_without_residue() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    engine.set_state_source(crate::engine::StateSource::ReceiptDiffs);
    let genesis = engine.head_hash();
    let candidate = |engine: &Engine<MemoryDatabase>, value: &[u8]| {
        let mut post = engine.state().clone();
        post.insert(b"key", value.to_vec()).unwrap();
        neutrin0_consensus_types::CandidateBlock {
            block: block(1, 1, genesis, post.root()),
            writes: vec![neutrin0_consensus_types::StateWrite {
                key: b"key".to_vec(),
                value: Some(value.to_vec()),
            }],
        }
    };
    let first = candidate(&engine, b"first");
    let second = candidate(&engine, b"second");
    engine.import_candidate_block(&first, None).unwrap();
    // The same publication again is a duplicate, not a second proposal.
    engine.import_candidate_block(&first, None).unwrap();
    let refused = engine.import_candidate_block(&second, None);
    assert!(
        matches!(refused, Err(ImportError::SlotAlreadyProposed { slot: 1, existing }) if existing == first.block.hash()),
        "{refused:?}"
    );
    assert_eq!(
        engine.store().get_header(&second.block.hash()).unwrap(),
        None
    );
    assert_eq!(engine.head_hash(), first.block.hash());
}

#[test]
fn import_block_extends_local_head() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();

    let genesis_hash = engine.head_hash();
    let block1 = executed_block(1, 1, genesis_hash, engine.state());

    let outcome = engine
        .import_block(&block1, &WitnessExecutor)
        .expect("first block extends genesis");
    assert_eq!(outcome.new_head_height, 1);
    assert_eq!(outcome.block_hash, block1.hash());
    assert_eq!(engine.head_height(), 1);
    assert_eq!(engine.head_state_root(), block1.header.state_root);

    // Chain into block 2.
    let block2 = executed_block(2, 2, outcome.block_hash, engine.state());
    let outcome = engine
        .import_block(&block2, &WitnessExecutor)
        .expect("second extends first");
    assert_eq!(outcome.new_head_height, 2);
    assert_eq!(engine.head_hash(), block2.hash());
}

#[test]
fn duplicate_import_reports_the_imported_block_and_the_unmoved_head() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let block1 = executed_block(1, 1, engine.head_hash(), engine.state());
    engine.import_block(&block1, &WitnessExecutor).unwrap();
    let block2 = executed_block(2, 2, block1.hash(), engine.state());
    engine.import_block(&block2, &WitnessExecutor).unwrap();

    // Replaying an archived ancestor names that ancestor, not the head.
    let outcome = engine.import_block(&block1, &WitnessExecutor).unwrap();
    assert_eq!(
        outcome,
        ImportBlockOutcome {
            block_hash: block1.hash(),
            new_head_hash: block2.hash(),
            new_head_height: 2,
            new_head_slot: 2,
        }
    );
}

#[test]
fn historical_header_and_proof_recipient_use_the_exact_incoming_boundary() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let historical = executed_block(1, 1, engine.head_hash(), engine.state());
    engine.import_block(&historical, &WitnessExecutor).unwrap();
    // Model a later compact committee with a different identity at index 0.
    // The retained genesis boundary still authenticates the original index.
    let mut later = validators();
    later[0].pubkey = *ProposerKey::from_ikm(&[0xBB; 32], 0)
        .unwrap()
        .public_key_bytes();
    later[0].withdrawal_credentials = [9; 32];
    engine.set_active_validator_set(1, later).unwrap();
    let (selected, seed) = engine.validator_context_for_height(1).unwrap();
    assert_eq!(selected, validators());
    assert_eq!(seed, TEST_GENESIS_SEED);
    engine
        .authenticate_import_header(&historical.header)
        .unwrap();
    let inputs = engine
        .block_public_inputs(&historical.header, ZERO_HASH, historical.hash())
        .unwrap();
    assert_eq!(
        inputs.proposer_address,
        neutrin0_primitives::runtime_account([2; 20])
    );
    assert_eq!(inputs.context.finalized.seed, TEST_GENESIS_SEED);
    assert_eq!(
        engine
            .import_block(&historical, &WitnessExecutor)
            .unwrap()
            .new_head_hash,
        historical.hash()
    );
    let successor = executed_block(2, 2, historical.hash(), engine.state());
    engine.import_block(&successor, &WitnessExecutor).unwrap();
    assert_eq!(engine.head_hash(), successor.hash());
}

#[test]
fn historical_validator_context_fails_closed_on_a_mismatched_snapshot() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let original = block(1, 1, engine.head_hash(), [5; 32]);
    let mut corrupt = validators();
    corrupt[0].withdrawal_credentials = [9; 32];
    engine
        .store_mut()
        .put_validator_set_snapshot(0, &corrupt)
        .unwrap();
    assert!(engine.validator_context_for_height(1).is_err());
    assert!(engine.authenticate_import_header(&original.header).is_err());
    assert!(
        engine
            .block_public_inputs(&original.header, ZERO_HASH, original.hash())
            .is_err()
    );
    assert_eq!(engine.head_height(), 0);
}

#[test]
fn import_refuses_a_gas_limit_other_than_the_chain_specification() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let mut raised = block(1, 1, engine.head_hash(), [5; 32]);
    raised.header.gas_limit = u64::MAX;
    let header_hash = raised.header.hash();
    raised.header.signature =
        proposer().sign_proposer_message(spec().consensus_domain(), &header_hash);
    assert!(matches!(
        engine.import_block(&raised, &WitnessExecutor),
        Err(ImportError::GasLimitMismatch {
            expected: 30_000_000,
            actual: u64::MAX,
        })
    ));
    assert_eq!(engine.head_height(), 0);
}

#[test]
fn import_refuses_slots_that_do_not_follow_the_parent() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let block1 = executed_block(1, 5, engine.head_hash(), engine.state());
    engine.import_block(&block1, &WitnessExecutor).unwrap();
    for slot in [4, 5] {
        let stale = block(2, slot, block1.hash(), [6; 32]);
        assert!(matches!(
            engine.import_block(&stale, &WitnessExecutor),
            Err(ImportError::SlotNotIncreasing { parent_slot: 5, slot: refused })
                if refused == slot
        ));
    }
    assert_eq!(engine.head_hash(), block1.hash());
}

#[test]
fn import_refuses_a_slot_until_the_local_clock_reaches_it() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    // Slot 1_000 starts 4_000 s after genesis. A head there would leave
    // every honest producer unable to extend it before that time.
    engine.set_wall_clock(|| TEST_GENESIS_TIME + 3_000);
    let early = executed_block(1, 1_000, engine.head_hash(), engine.state());
    assert!(matches!(
        engine.import_block(&early, &WitnessExecutor),
        Err(ImportError::FutureSlot { slot: 1_000, .. })
    ));
    assert_eq!(engine.head_height(), 0);
    // Within the drift tolerance of its start, the slot is acceptable.
    engine.set_wall_clock(|| TEST_GENESIS_TIME + 4_000 - MAX_CLOCK_DRIFT_SECS);
    engine.import_block(&early, &WitnessExecutor).unwrap();
    assert_eq!(engine.head_height(), 1);
}

#[test]
fn invalid_proof_signing_detects_a_rejected_sibling_envelope() {
    use neutrin0_consensus_types::{
        FinalityVote, FinalityVoteData, FinalityVotePhase, ProofRejectionReason, SlashingEvidence,
    };

    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let genesis_hash = engine.head_hash();
    let genesis_state = engine.state().clone();
    let canonical = executed_block(1, 1, genesis_hash, &genesis_state);
    let sibling = executed_block(1, 2, genesis_hash, &genesis_state);
    engine.import_block(&canonical, &WitnessExecutor).unwrap();
    engine.import_block(&sibling, &WitnessExecutor).unwrap();
    // Equal-weight siblings tie-break on their VRF outputs, which follow
    // the chain spec; the rejected envelope targets whichever sibling is
    // off the canonical height index.
    let (canonical, sibling) = if engine.head_hash() == canonical.hash() {
        (canonical, sibling)
    } else {
        (sibling, canonical)
    };
    let sibling_hash = sibling.hash();
    let backend = AlternateMockBlockProofSystem;
    let inputs = engine
        .block_public_inputs(&sibling.header, ZERO_HASH, sibling_hash)
        .unwrap();
    let mut decoded = backend
        .prove_block(&[], &inputs, inputs.proposer_address)
        .unwrap();
    decoded.0.commitment[0] ^= 1;
    let rejected = BlockProof {
        prover_address: inputs.proposer_address,
        statement_key: [0; 32],
        height: 1,
        block_hash: sibling_hash,
        public_inputs: inputs,
        proof_bytes: borsh::to_vec(&decoded).unwrap(),
    };
    assert!(matches!(
        engine.import_block_proof(&rejected, &backend),
        Err(ImportError::InvalidBlockProof(_))
    ));
    // The canonical height index names the other branch's block.
    assert_eq!(
        engine.store().get_block_hash_by_height(1).unwrap(),
        Some(canonical.hash())
    );

    // A precommit whose signer accepted the sibling's rejected envelope.
    let key = proposer();
    let domain = engine.consensus_domain();
    let data = FinalityVoteData {
        chunk_id: 0,
        round: 0,
        chunk_hash: [7; 32],
        selection: crate::bft_loop::fixture_selection(),
        phase: FinalityVotePhase::Precommit,
    };
    let mut proof_hashes = vec![[0; 32]; usize::try_from(engine.chunk_size()).unwrap()];
    proof_hashes[0] = neutrin0_consensus_types::evidence::commitment(&rejected);
    let manifest = neutrin0_consensus_types::ProofManifest {
        proof_hashes: proof_hashes.clone(),
    };
    let mut aggregation_bits = neutrin0_primitives::BitVec::default();
    aggregation_bits.push(true);
    let vote = FinalityVote {
        proof_manifests: vec![manifest],
        signature: key.sign_finality_vote(domain, &data),
        attestations: vec![key.attest_vote(domain, data.clone(), proof_hashes, None)],
        aggregation_bits,
        data,
    };
    let evidence = engine
        .observe_vote_for_invalid_proof_signing(&vote)
        .unwrap();
    assert!(matches!(
        evidence.as_slice(),
        [SlashingEvidence::InvalidProofSigning {
            rejected_proof,
            reason: ProofRejectionReason::PublicInputsMismatch,
            ..
        }] if rejected_proof == &rejected
    ));
}

/// Isolated mock receipts allow distinct encodings of the same statement;
/// this fixture does not implement chunk proving or finalization.
struct AlternateMockBlockProofSystem;

impl ProofSystem for AlternateMockBlockProofSystem {
    type BlockProof = (neutrin0_proof_system::MockBlockProof, u8);
    type ChunkProof = Vec<u8>;

    fn prove_block(
        &self,
        witness: &[u8],
        inputs: &BlockProofPublicInputs,
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::BlockProof, ProofError> {
        neutrin0_proof_system::MockProofSystem
            .prove_block(witness, inputs, prover_address)
            .map(|proof| (proof, 0))
    }

    fn block_statement(
        &self,
        proof: &Self::BlockProof,
    ) -> Result<neutrin0_runtime_abi::BlockReceiptStatement, ProofError> {
        neutrin0_proof_system::MockProofSystem.block_statement(&proof.0)
    }

    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        if proof.1 == u8::MAX {
            return Err(ProofError::MalformedProof);
        }
        neutrin0_proof_system::MockProofSystem.verify_block(&proof.0, inputs)
    }
}

#[test]
fn rejected_alternative_receipts_preserve_pending_branch_and_exact_evidence() {
    use neutrin0_consensus_types::ProofRejectionReason;

    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let block = executed_block(1, 1, engine.head_hash(), engine.state());
    engine.import_block(&block, &WitnessExecutor).unwrap();
    let hash = block.hash();
    let job = engine.prepare_block_proof(&hash).unwrap();
    let inputs = engine
        .block_public_inputs(&block.header, ZERO_HASH, hash)
        .unwrap();
    let backend = AlternateMockBlockProofSystem;
    let valid = backend
        .prove_block(&[], &inputs, inputs.proposer_address)
        .unwrap();
    let mut invalid = valid;
    invalid.0.commitment[0] ^= 1;
    let receipts = [
        (
            borsh::to_vec(&invalid).unwrap(),
            ProofRejectionReason::PublicInputsMismatch,
        ),
        (
            borsh::to_vec(&(valid.0, u8::MAX)).unwrap(),
            ProofRejectionReason::MalformedProof,
        ),
        (Vec::new(), ProofRejectionReason::MalformedProof),
    ];
    let state_root = engine.state().root();
    let witness = engine.store().get_witness(&hash).unwrap();
    for (proof_bytes, reason) in receipts {
        let rejected = BlockProof {
            prover_address: inputs.proposer_address,
            statement_key: [0; 32],
            height: block.header.height,
            block_hash: hash,
            public_inputs: inputs.clone(),
            proof_bytes,
        };
        assert!(
            engine
                .import_block_proof_with_dry_run(&rejected, &backend, &WitnessExecutor)
                .is_err()
        );
        assert_eq!(engine.head_hash(), hash);
        assert_eq!(engine.fork_choice_head(), hash);
        assert_eq!(engine.state().root(), state_root);
        assert_eq!(
            engine.store().get_block_hash_by_height(1).unwrap(),
            Some(hash)
        );
        assert_eq!(engine.store().get_witness(&hash).unwrap(), witness);
        assert_eq!(
            engine.store().get_block_state(&hash).unwrap(),
            Some(BlockState::PendingProof)
        );
        assert_eq!(
            engine.fork_choice.block(&hash).unwrap().proof_status,
            ProofStatus::PendingProof
        );
        assert_eq!(engine.rejected_proofs.get(&hash), Some(&(rejected, reason)));
    }
    // The snapshotted local job remains completable after every rejection.
    let completed = job.prove(&backend).unwrap();
    let result = engine.commit_block_proof(completed).unwrap();
    assert_eq!(result.state, BlockState::Proven);
    assert_eq!(engine.head_hash(), hash);
    assert_eq!(engine.fork_choice_head(), hash);
    assert_eq!(engine.rejected_proof_cache_len(), 1);
}

#[test]
fn honest_peer_receipt_after_rejected_alternative_proves_produced_block() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let block = executed_block(1, 1, engine.head_hash(), engine.state());
    engine.import_block(&block, &WitnessExecutor).unwrap();
    let hash = block.hash();
    let backend = AlternateMockBlockProofSystem;
    let inputs = engine
        .block_public_inputs(&block.header, ZERO_HASH, hash)
        .unwrap();
    let valid = backend
        .prove_block(&[], &inputs, inputs.proposer_address)
        .unwrap();
    let mut invalid = valid;
    invalid.0.commitment[0] ^= 1;
    let mut receipt = BlockProof {
        prover_address: inputs.proposer_address,
        statement_key: [0; 32],
        height: block.header.height,
        block_hash: hash,
        public_inputs: inputs,
        proof_bytes: borsh::to_vec(&invalid).unwrap(),
    };
    assert!(engine.import_block_proof(&receipt, &backend).is_err());
    assert_eq!(
        engine.store().get_block_state(&hash).unwrap(),
        Some(BlockState::BlockProduced)
    );
    assert_eq!(engine.fork_choice_head(), hash);
    receipt.proof_bytes = borsh::to_vec(&valid).unwrap();
    engine
        .import_block_proof_with_dry_run(&receipt, &backend, &WitnessExecutor)
        .unwrap();
    assert_eq!(
        engine.store().get_block_state(&hash).unwrap(),
        Some(BlockState::Proven)
    );
    assert_eq!(
        engine.store().get_block_proof(&hash).unwrap(),
        Some(attributed(receipt))
    );
    assert_eq!(engine.rejected_proof_cache_len(), 1);
}

/// `receipt` as the engine retains it: attributed with the statement key
/// of the mock backend's public values (design 08).
fn attributed(mut receipt: BlockProof) -> BlockProof {
    receipt.statement_key =
        crate::prove::statement_key(&neutrin0_runtime_abi::BlockReceiptStatement {
            output: neutrin0_runtime_abi::RuntimeBlockOutput::default(),
            prover_address: receipt.prover_address,
        });
    receipt
}

/// Deterministic native executor for persistence and scheduling regressions.
/// Mock receipts below test orchestration; they never finalize a chunk.
struct WitnessExecutor;

impl ErasedBlockExecutor for WitnessExecutor {
    fn execute_block(
        &self,
        ctx: &neutrin0_proof_system::BlockExecutionContext,
        body: &Body,
        state: &mut Trie,
    ) -> Result<neutrin0_proof_system::ExecutionOutcome, String> {
        let before = state.root();
        let value = ctx.context.slot.to_le_bytes().to_vec();
        state
            .insert(b"executed-slot", value.clone())
            .map_err(|error| error.to_string())?;
        let witness_bytes = borsh::to_vec(&(ctx.context, before, body.transactions.clone()))
            .map_err(|error| error.to_string())?;
        Ok(neutrin0_proof_system::ExecutionOutcome {
            artifacts: body.artifacts.clone(),
            state_root_after: state.root(),
            runtime_extra: ZERO_HASH,
            receipts_root: body.artifacts.commitment(),
            gas_used: 0,
            witness_bytes,
            state_writes: vec![neutrin0_consensus_types::StateWrite {
                key: b"executed-slot".to_vec(),
                value: Some(value),
            }],
        })
    }

    fn query(
        &self,
        _request: &neutrin0_runtime_abi::QueryRequest,
        _runtime_code_hash: [u8; 32],
        _state: &Trie,
    ) -> Result<neutrin0_runtime_abi::QueryResponse, String> {
        Err("unused fixture query".into())
    }

    fn validate_tx(
        &self,
        _bytes: &[u8],
        _chain_id: u64,
        _gas_limit: u64,
        _runtime_code_hash: [u8; 32],
        _state: &Trie,
    ) -> Result<neutrin0_runtime_abi::TxValidity, String> {
        Err("unused fixture admission".into())
    }

    fn install_runtime(&self, _wasm: &[u8]) -> Result<[u8; 32], String> {
        Err("unused fixture installation".into())
    }

    fn installed_runtimes(&self) -> Vec<[u8; 32]> {
        Vec::new()
    }
}

fn executed_block(height: Height, slot: Slot, parent: BlockHash, state: &Trie) -> Block {
    let mut post = state.clone();
    post.insert(b"executed-slot", slot.to_le_bytes().to_vec())
        .unwrap();
    block(height, slot, parent, post.root())
}

#[test]
fn checked_import_retains_authenticated_witness_and_state_across_restart() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let block = executed_block(1, 1, engine.head_hash(), engine.state());
    engine.import_block(&block, &WitnessExecutor).unwrap();
    let witness = engine.store().get_witness(&block.hash()).unwrap().unwrap();
    let (context, before, transactions): (
        neutrin0_consensus_types::runtime::ConsensusExecutionContext,
        [u8; 32],
        Vec<Vec<u8>>,
    ) = borsh::from_slice(&witness).unwrap();
    assert_eq!(context.slot, block.header.slot);
    assert_eq!(context.timestamp, block.header.timestamp);
    assert_eq!(context.parent_block_hash, block.header.parent_hash);
    assert_eq!(
        context.proposer_vrf_output,
        neutrin0_vrf::proof_output(&block.header.vrf_proof)
    );
    assert_eq!(context.finalized.height, 0);
    assert_eq!(before, spec().genesis_state_root);
    assert_eq!(transactions, block.body.transactions);
    let mut reopened = Engine::open(spec(), engine.store().db().clone()).unwrap();
    assert_eq!(reopened.head_hash(), block.hash());
    assert_eq!(reopened.state().root(), block.header.state_root);
    assert_eq!(
        reopened.store().get_witness(&block.hash()).unwrap(),
        Some(witness)
    );
    reopened
        .prove_block(&block.hash(), &neutrin0_proof_system::MockProofSystem)
        .unwrap();
    assert_eq!(
        reopened.store().get_block_state(&block.hash()).unwrap(),
        Some(BlockState::Proven)
    );
}

#[test]
fn failed_checked_import_commits_neither_witness_block_nor_state() {
    let mut engine = Engine::genesis(spec(), crate::test_db::FaultDb::default()).unwrap();
    let block = executed_block(1, 1, engine.head_hash(), engine.state());
    engine.store_mut().db_mut().fail_batch = true;
    assert!(engine.import_block(&block, &WitnessExecutor).is_err());
    assert_eq!(engine.head_hash(), spec().genesis_block_hash);
    assert_eq!(engine.state().root(), spec().genesis_state_root);
    assert_eq!(engine.store().get_header(&block.hash()).unwrap(), None);
    assert_eq!(engine.store().get_witness(&block.hash()).unwrap(), None);
    assert_eq!(engine.store().get_block_hash_by_height(1).unwrap(), None);
    engine.store_mut().db_mut().fail_batch = false;
    engine.import_block(&block, &WitnessExecutor).unwrap();
    let reopened = Engine::open(spec(), engine.store().db().clone()).unwrap();
    assert_eq!(reopened.head_hash(), block.hash());
    assert_eq!(reopened.state().root(), block.header.state_root);
    assert!(
        reopened
            .store()
            .get_witness(&block.hash())
            .unwrap()
            .is_some()
    );
}

#[test]
fn failed_execution_authentication_cannot_publish_a_witness() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let forged = block(1, 1, engine.head_hash(), [5; 32]);
    assert!(matches!(
        engine.import_block(&forged, &WitnessExecutor),
        Err(ImportError::StateRootMismatch { .. })
    ));
    assert_eq!(engine.head_hash(), spec().genesis_block_hash);
    assert_eq!(engine.state().root(), spec().genesis_state_root);
    assert_eq!(engine.store().get_header(&forged.hash()).unwrap(), None);
    assert_eq!(engine.store().get_witness(&forged.hash()).unwrap(), None);
}

#[test]
fn checked_sibling_archives_its_witness_without_replacing_retained_inputs() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let genesis = engine.state().clone();
    let canonical = executed_block(1, 1, engine.head_hash(), &genesis);
    engine.import_block(&canonical, &WitnessExecutor).unwrap();
    crate::test_db::support_block(&mut engine, canonical.hash());
    let sibling = executed_block(1, 2, spec().genesis_block_hash, &genesis);
    engine.import_block(&sibling, &WitnessExecutor).unwrap();
    assert_eq!(engine.head_hash(), canonical.hash());
    let retained = engine.store().get_witness(&sibling.hash()).unwrap();
    assert!(retained.is_some());
    crate::test_db::support_block(&mut engine, sibling.hash());
    engine
        .materialise_to_fork_choice_head(Some(&WitnessExecutor))
        .unwrap();
    assert_eq!(engine.head_hash(), sibling.hash());
    assert_eq!(
        engine.store().get_witness(&sibling.hash()).unwrap(),
        retained
    );
    let reopened = Engine::open(spec(), engine.store().db().clone()).unwrap();
    assert_eq!(reopened.state().root(), sibling.header.state_root);
    assert_eq!(
        reopened.store().get_witness(&sibling.hash()).unwrap(),
        retained
    );
}

#[test]
fn duplicate_pending_archive_recovers_missing_witness_without_demotion() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    // The block first arrives as a followed publication, so it is archived
    // with its diff but without a witness.
    let genesis_state = engine.state().clone();
    let (block, proof, diff) = proven_unit(
        &engine,
        &genesis_state,
        1,
        1,
        engine.head_hash(),
        vec![write(b"executed-slot", Some(&1_u64.to_le_bytes()))],
    );
    engine.set_state_source(crate::engine::StateSource::ReceiptDiffs);
    engine
        .import_proven_block(
            &bundle(&block, &proof, &diff),
            &neutrin0_proof_system::MockProofSystem,
            None,
        )
        .unwrap();
    engine.set_state_source(crate::engine::StateSource::Execution);
    engine
        .store_mut()
        .put_block_state(&block.hash(), BlockState::PendingProof)
        .unwrap();
    assert_eq!(engine.store().get_witness(&block.hash()).unwrap(), None);
    engine.import_block(&block, &WitnessExecutor).unwrap();
    assert_eq!(
        engine.store().get_block_state(&block.hash()).unwrap(),
        Some(BlockState::PendingProof)
    );
    assert_eq!(engine.state().root(), block.header.state_root);
    let retained = engine.store().get_witness(&block.hash()).unwrap();
    assert!(retained.is_some());
    engine.import_block(&block, &WitnessExecutor).unwrap();
    assert_eq!(engine.store().get_witness(&block.hash()).unwrap(), retained);
    let reopened = Engine::open(spec(), engine.store().db().clone()).unwrap();
    assert_eq!(reopened.state().root(), block.header.state_root);
}

#[test]
fn replay_commits_missing_witnesses_with_head_and_state_atomically() {
    let mut engine = Engine::genesis(spec(), crate::test_db::FaultDb::default()).unwrap();
    let genesis = engine.state().clone();
    let canonical = executed_block(1, 1, engine.head_hash(), &genesis);
    engine.import_block(&canonical, &WitnessExecutor).unwrap();
    crate::test_db::support_block(&mut engine, canonical.hash());
    // The sibling arrives as a followed publication: archived with its
    // diff, without a witness, and without moving the head.
    let (sibling, sibling_proof, sibling_diff) = proven_unit(
        &engine,
        &genesis,
        1,
        2,
        spec().genesis_block_hash,
        vec![write(b"executed-slot", Some(&2_u64.to_le_bytes()))],
    );
    engine.set_state_source(crate::engine::StateSource::ReceiptDiffs);
    engine
        .import_proven_block(
            &bundle(&sibling, &sibling_proof, &sibling_diff),
            &neutrin0_proof_system::MockProofSystem,
            None,
        )
        .unwrap();
    engine.set_state_source(crate::engine::StateSource::Execution);
    assert_eq!(engine.head_hash(), canonical.hash());
    assert_eq!(engine.store().get_witness(&sibling.hash()).unwrap(), None);
    crate::test_db::support_block(&mut engine, sibling.hash());
    engine.store_mut().db_mut().fail_batch = true;
    assert!(
        engine
            .materialise_to_fork_choice_head(Some(&WitnessExecutor))
            .is_err()
    );
    assert_eq!(engine.head_hash(), canonical.hash());
    assert_eq!(engine.state().root(), canonical.header.state_root);
    assert_eq!(
        engine.store().get_block_hash_by_height(1).unwrap(),
        Some(canonical.hash())
    );
    assert_eq!(engine.store().get_witness(&sibling.hash()).unwrap(), None);
    engine.store_mut().db_mut().fail_batch = false;
    engine
        .materialise_to_fork_choice_head(Some(&WitnessExecutor))
        .unwrap();
    assert_eq!(engine.head_hash(), sibling.hash());
    assert_eq!(engine.state().root(), sibling.header.state_root);
    assert_eq!(
        engine.store().get_block_hash_by_height(1).unwrap(),
        Some(sibling.hash())
    );
    let witness = engine.store().get_witness(&sibling.hash()).unwrap();
    assert!(witness.is_some());
    let reopened = Engine::open(spec(), engine.store().db().clone()).unwrap();
    assert_eq!(reopened.head_hash(), sibling.hash());
    assert_eq!(reopened.state().root(), sibling.header.state_root);
    assert_eq!(
        reopened.store().get_witness(&sibling.hash()).unwrap(),
        witness
    );
}

#[test]
fn alternate_receipts_cannot_replace_signed_bytes_or_invalidate_proven_branch() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let block = executed_block(1, 1, engine.head_hash(), engine.state());
    engine.import_block(&block, &WitnessExecutor).unwrap();
    let hash = block.hash();
    let inputs = engine
        .block_public_inputs(&block.header, ZERO_HASH, hash)
        .unwrap();
    let backend = AlternateMockBlockProofSystem;
    let mut decoded = backend
        .prove_block(&[], &inputs, inputs.proposer_address)
        .unwrap();
    let receipt = BlockProof {
        prover_address: inputs.proposer_address,
        statement_key: [0; 32],
        height: 1,
        block_hash: hash,
        public_inputs: inputs,
        proof_bytes: borsh::to_vec(&decoded).unwrap(),
    };
    engine.import_block_proof(&receipt, &backend).unwrap();

    decoded.1 = 1;
    let mut alternate = receipt.clone();
    alternate.proof_bytes = borsh::to_vec(&decoded).unwrap();
    assert_ne!(alternate.proof_bytes, receipt.proof_bytes);
    engine.import_block_proof(&alternate, &backend).unwrap();
    assert_eq!(
        engine.store().get_block_proof(&hash).unwrap(),
        Some(attributed(receipt.clone()))
    );

    decoded.0.commitment[0] ^= 1;
    alternate.proof_bytes = borsh::to_vec(&decoded).unwrap();
    assert!(matches!(
        engine.import_block_proof(&alternate, &backend),
        Err(ImportError::InvalidBlockProof(_))
    ));
    alternate.proof_bytes.clear();
    assert!(matches!(
        engine.import_block_proof(&alternate, &backend),
        Err(ImportError::Codec(_))
    ));
    assert_eq!(
        engine.rejected_proofs.get(&hash),
        Some(&(
            alternate,
            neutrin0_consensus_types::ProofRejectionReason::MalformedProof
        ))
    );
    engine.import_block_proof(&receipt, &backend).unwrap();
    assert_eq!(engine.rejected_proof_cache_len(), 1);
    assert_eq!(
        engine.store().get_block_proof(&hash).unwrap(),
        Some(attributed(receipt))
    );
    assert_eq!(
        engine.store().get_block_state(&hash).unwrap(),
        Some(BlockState::Proven)
    );
    assert_eq!(engine.fork_choice_head(), hash);
    assert_eq!(engine.head_hash(), hash);
    let reopened = Engine::open(spec(), engine.store().db().clone()).unwrap();
    assert_eq!(reopened.fork_choice_head(), hash);
}

#[test]
fn import_block_rejects_wrong_parent() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let block = block(1, 1, [0; 32], [5; 32]); // wrong parent
    match engine.import_block(&block, &WitnessExecutor) {
        Err(ImportError::ParentMismatch { .. }) => {}
        other => panic!("expected ParentMismatch, got {other:?}"),
    }
    assert_eq!(engine.head_height(), 0);
}

#[test]
fn import_block_rejects_skipped_height() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let block = block(2, 2, engine.head_hash(), [5; 32]); // skips height 1
    match engine.import_block(&block, &WitnessExecutor) {
        Err(ImportError::HeightMismatch { .. }) => {}
        other => panic!("expected HeightMismatch, got {other:?}"),
    }
}

#[test]
fn import_block_rejects_body_root_mismatch() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let mut block = block(1, 1, engine.head_hash(), [5; 32]);
    block.body.transactions.push(vec![1, 2, 3]);

    match engine.import_block(&block, &WitnessExecutor) {
        Err(ImportError::BodyRootsMismatch { .. }) => {}
        other => panic!("expected BodyRootsMismatch, got {other:?}"),
    }
}

#[test]
fn import_block_rejects_expired_participation_votes_before_storage() {
    use neutrin0_consensus_types::participation::ParticipationVote;
    use neutrin0_consensus_types::{FinalityVoteData, FinalityVotePhase};

    let mut spec = spec();
    spec.consensus.chunk_size = 1;
    let mut engine = Engine::genesis(spec.clone(), MemoryDatabase::new()).unwrap();
    // Chunk zero has no finalized history, so every historical
    // acknowledgement lies outside its window; blocks of later chunks cannot be
    // imported before their incoming boundary is finalized.
    let mut next = block(1, 1, engine.head_hash(), [5; 32]);
    next.header.vrf_proof = proposer().vrf_eval(spec.consensus_domain(), &spec.genesis_seed, 1);
    next.body.participation_acks.push(ParticipationVote {
        data: FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: [7; 32],
            selection: crate::bft_loop::fixture_selection(),
            phase: FinalityVotePhase::Precommit,
        },
        validator_index: 0,
        vote_signature: [0; 96],
    });
    let roots = compute_body_roots(&next.body);
    next.header.votes_root = roots.votes_root;
    next.header.da_root = roots.da_root;
    next.header.signature = proposer().sign_proposer_message(spec.consensus_domain(), &next.hash());
    assert!(matches!(
        engine.import_block(&next, &WitnessExecutor),
        Err(ImportError::HistoricalVoteOutsideWindow {
            chunk_id: 0,
            referenced_chunk: 0,
        })
    ));
    assert_eq!(engine.head_height(), 0);
    assert!(engine.store().get_header(&next.hash()).unwrap().is_none());
}

#[test]
fn import_block_requires_the_exact_slot_start_timestamp() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let mut late = block(1, 1, engine.head_hash(), [5; 32]);
    // One second past its slot start: a proposer may not move chain time.
    late.header.timestamp += 1;
    late.header.signature =
        proposer().sign_proposer_message(spec().consensus_domain(), &late.hash());
    match engine.import_block(&late, &WitnessExecutor) {
        Err(ImportError::HeaderTimestampMismatch { actual, expected }) => {
            assert_eq!(actual, expected + 1);
        }
        other => panic!("expected HeaderTimestampMismatch, got {other:?}"),
    }
    assert_eq!(engine.head_height(), 0);
}

#[test]
fn import_block_rejects_tampered_signature() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let mut block = block(1, 1, engine.head_hash(), [5; 32]);
    // Flip a bit in the signature so it no longer matches the
    // canonical signed message.
    block.header.signature[0] ^= 0x80;
    match engine.import_block(&block, &WitnessExecutor) {
        Err(ImportError::HeaderSignature(_)) => {}
        other => panic!("expected HeaderSignature error, got {other:?}"),
    }
    assert_eq!(engine.head_height(), 0);
}

#[test]
fn import_block_rejects_signature_from_foreign_key() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    // Build a block whose header signature comes from a key that
    // is NOT in the active set. The proposer_index still points at
    // slot 0 (the canonical validator), so the signature is checked
    // against the wrong pubkey and must fail.
    let attacker = ProposerKey::from_ikm(&[0xBE; 32], 0).expect("derive attacker");
    let mut block = signed_block(1, 1, engine.head_hash(), [5; 32], Some(&attacker));
    // Force the proposer index back to the legitimate validator so
    // the active-set lookup picks the wrong key for verification.
    block.header.proposer_index = 0;
    let header_hash = block.header.hash();
    // Re-sign with the attacker key under the legitimate proposer
    // index so the signature decodes but verifies against the
    // wrong public key.
    block.header.signature =
        attacker.sign_proposer_message(spec().consensus_domain(), &header_hash);

    match engine.import_block(&block, &WitnessExecutor) {
        Err(ImportError::HeaderSignature(_)) => {}
        other => panic!("expected HeaderSignature error, got {other:?}"),
    }
}

#[test]
fn import_block_rejects_tampered_vrf_proof() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let mut block = block(1, 1, engine.head_hash(), [5; 32]);
    // Replace the VRF proof with garbage that decodes as a BLS
    // signature but does not verify against the validator's key.
    let attacker = ProposerKey::from_ikm(&[0xCE; 32], 0).expect("derive attacker");
    let (bogus_vrf, _) = neutrin0_vrf::eval(
        attacker.secret_key(),
        spec().consensus_domain(),
        &TEST_GENESIS_SEED,
        block.header.slot,
    );
    block.header.vrf_proof = bogus_vrf.to_bytes();
    // Re-sign the header so the signature check passes; only the
    // VRF claim is bogus.
    let header_hash = block.header.hash();
    block.header.signature =
        proposer().sign_proposer_message(spec().consensus_domain(), &header_hash);

    match engine.import_block(&block, &WitnessExecutor) {
        Err(ImportError::HeaderVrf(_)) => {}
        other => panic!("expected HeaderVrf error, got {other:?}"),
    }
}

#[test]
fn import_block_rejects_proposer_index_out_of_range() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    let mut block = block(1, 1, engine.head_hash(), [5; 32]);
    // The active set has length 1, so index 5 is out of bounds.
    block.header.proposer_index = 5;
    let header_hash = block.header.hash();
    // Re-sign so signature decoding does not short-circuit; the
    // missing validator lookup must be the first failure.
    block.header.signature =
        proposer().sign_proposer_message(spec().consensus_domain(), &header_hash);

    match engine.import_block(&block, &WitnessExecutor) {
        Err(ImportError::HeaderSignature(SignatureError::ValidatorIndexOutOfBounds {
            index: 5,
            len: 1,
        })) => {}
        other => panic!("expected ValidatorIndexOutOfBounds, got {other:?}"),
    }
}

fn mock_receipt<DB: Database>(
    engine: &Engine<DB>,
    block: &Block,
    parent_root: StateRoot,
) -> BlockProof
where
    DB::Error: core::fmt::Debug,
{
    let inputs = engine
        .block_public_inputs(&block.header, parent_root, block.hash())
        .unwrap();
    let proof = neutrin0_proof_system::MockProofSystem
        .prove_block(&[], &inputs, inputs.proposer_address)
        .unwrap();
    BlockProof {
        prover_address: inputs.proposer_address,
        statement_key: [0; 32],
        height: block.header.height,
        block_hash: block.hash(),
        public_inputs: inputs,
        proof_bytes: borsh::to_vec(&proof).unwrap(),
    }
}

fn write(key: &[u8], value: Option<&[u8]>) -> neutrin0_consensus_types::StateWrite {
    neutrin0_consensus_types::StateWrite {
        key: key.to_vec(),
        value: value.map(<[u8]>::to_vec),
    }
}

/// The publication of a proven block whose canonical envelope and diff
/// a receiver derives from its header.
fn bundle(block: &Block, proof: &BlockProof, diff: &BlockStateDiff) -> ProvenBlock {
    ProvenBlock {
        block: block.clone(),
        proof_bytes: proof.proof_bytes.clone(),
        writes: diff.writes.clone(),
    }
}

/// A proven block over `parent` whose state root is exactly what
/// `writes` produce over `pre_state`, with its matching diff.
fn proven_unit<DB: Database>(
    engine: &Engine<DB>,
    pre_state: &Trie,
    height: Height,
    slot: Slot,
    parent: BlockHash,
    writes: Vec<neutrin0_consensus_types::StateWrite>,
) -> (Block, BlockProof, BlockStateDiff)
where
    DB::Error: core::fmt::Debug,
{
    let parent_root = pre_state.root();
    let mut post = pre_state.clone();
    let mut diff = BlockStateDiff {
        height,
        block_hash: [0; 32],
        state_root_before: parent_root,
        state_root_after: parent_root,
        writes,
    };
    diff.state_root_after = apply_state_diff::<()>(&mut post, &diff).unwrap();
    let block = block(height, slot, parent, diff.state_root_after);
    diff.block_hash = block.hash();
    let proof = mock_receipt(engine, &block, parent_root);
    (block, proof, diff)
}

#[test]
fn proven_block_import_applies_the_diff_without_an_executor() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    engine.set_state_source(crate::engine::StateSource::ReceiptDiffs);
    let genesis_hash = engine.head_hash();
    let genesis_state = engine.state().clone();

    let (block1, proof1, diff1) = proven_unit(
        &engine,
        &genesis_state,
        1,
        1,
        genesis_hash,
        vec![write(b"k1", Some(b"v1")), write(b"k2", Some(b"v2"))],
    );
    let outcome = engine
        .import_proven_block(
            &bundle(&block1, &proof1, &diff1),
            &neutrin0_proof_system::MockProofSystem,
            None,
        )
        .unwrap();
    assert_eq!(outcome.new_head_hash, block1.hash());
    assert_eq!(engine.head_state_root(), diff1.state_root_after);
    assert_eq!(engine.state().root(), engine.head_state_root());
    assert_eq!(engine.state().get(b"k1").unwrap(), Some(b"v1".to_vec()));
    assert_eq!(
        engine.store().get_block_state(&block1.hash()).unwrap(),
        Some(BlockState::Proven)
    );
    assert_eq!(
        engine.store().get_state_diff(&block1.hash()).unwrap(),
        Some(diff1.clone())
    );
    assert_eq!(
        engine.store().get_block_proof(&block1.hash()).unwrap(),
        Some(attributed(proof1.clone()))
    );

    // Replaying the same unit is idempotent.
    let again = engine
        .import_proven_block(
            &bundle(&block1, &proof1, &diff1),
            &neutrin0_proof_system::MockProofSystem,
            None,
        )
        .unwrap();
    assert_eq!(again.new_head_hash, block1.hash());

    // A delete travels as `None` and reproduces the next root.
    let state1 = engine.state().clone();
    let (block2, proof2, diff2) = proven_unit(
        &engine,
        &state1,
        2,
        2,
        block1.hash(),
        vec![write(b"k1", None), write(b"k3", Some(b""))],
    );
    engine
        .import_proven_block(
            &bundle(&block2, &proof2, &diff2),
            &neutrin0_proof_system::MockProofSystem,
            None,
        )
        .unwrap();
    assert_eq!(engine.head_height(), 2);
    assert_eq!(engine.state().root(), block2.header.state_root);
    assert_eq!(engine.state().get(b"k1").unwrap(), None);
    assert_eq!(engine.state().get(b"k3").unwrap(), Some(Vec::new()));
}

#[test]
fn proven_block_import_rejects_diffs_that_do_not_match_the_receipt() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    engine.set_state_source(crate::engine::StateSource::ReceiptDiffs);
    let genesis_hash = engine.head_hash();
    let genesis_state = engine.state().clone();
    let (block1, proof1, diff1) = proven_unit(
        &engine,
        &genesis_state,
        1,
        1,
        genesis_hash,
        vec![write(b"a", Some(b"1")), write(b"b", Some(b"2"))],
    );

    // Incomplete diff: the root check fails and nothing is stored.
    let mut partial = diff1.clone();
    partial.writes.pop();
    assert!(matches!(
        engine.import_proven_block(
            &bundle(&block1, &proof1, &partial),
            &neutrin0_proof_system::MockProofSystem,
            None,
        ),
        Err(ImportError::StateDiffRootMismatch { .. })
    ));
    assert_eq!(engine.head_hash(), genesis_hash);
    assert!(engine.store().get_header(&block1.hash()).unwrap().is_none());
    assert_eq!(engine.state().root(), genesis_state.root());

    // Non-canonical ordering is an envelope mismatch.
    let mut unsorted = diff1.clone();
    unsorted.writes.reverse();
    assert!(matches!(
        engine.import_proven_block(
            &bundle(&block1, &proof1, &unsorted),
            &neutrin0_proof_system::MockProofSystem,
            None,
        ),
        Err(ImportError::StateDiffMismatch { .. })
    ));

    // A broken receipt never lets a correct diff advance the head.
    let mut bad_proof = proof1.clone();
    let mut decoded: neutrin0_proof_system::MockBlockProof =
        borsh::from_slice(&bad_proof.proof_bytes).unwrap();
    decoded.commitment[0] ^= 1;
    bad_proof.proof_bytes = borsh::to_vec(&decoded).unwrap();
    assert!(matches!(
        engine.import_proven_block(
            &bundle(&block1, &bad_proof, &diff1),
            &neutrin0_proof_system::MockProofSystem,
            None,
        ),
        Err(ImportError::InvalidBlockProof(_))
    ));
    assert_eq!(engine.head_hash(), genesis_hash);

    // The exact unit still imports afterwards.
    engine
        .import_proven_block(
            &bundle(&block1, &proof1, &diff1),
            &neutrin0_proof_system::MockProofSystem,
            None,
        )
        .unwrap();
    assert_eq!(engine.head_hash(), block1.hash());
}

#[test]
fn receipt_diff_replay_reconstructs_an_archived_sibling_branch() {
    let mut engine = Engine::genesis(spec(), MemoryDatabase::new()).unwrap();
    engine.set_state_source(crate::engine::StateSource::ReceiptDiffs);
    let genesis_hash = engine.head_hash();
    let genesis_state = engine.state().clone();
    let (a1, a1_proof, a1_diff) = proven_unit(
        &engine,
        &genesis_state,
        1,
        1,
        genesis_hash,
        vec![write(b"branch", Some(b"a"))],
    );
    engine
        .import_proven_block(
            &bundle(&a1, &a1_proof, &a1_diff),
            &neutrin0_proof_system::MockProofSystem,
            None,
        )
        .unwrap();
    let (a2, a2_proof, a2_diff) = proven_unit(
        &engine,
        engine.state(),
        2,
        2,
        a1.hash(),
        vec![write(b"height", Some(b"2"))],
    );
    engine
        .import_proven_block(
            &bundle(&a2, &a2_proof, &a2_diff),
            &neutrin0_proof_system::MockProofSystem,
            None,
        )
        .unwrap();
    assert_eq!(engine.head_hash(), a2.hash());

    // A proven sibling at height 1 is archived with its own post-state.
    let (b1, b1_proof, b1_diff) = proven_unit(
        &engine,
        &genesis_state,
        1,
        3,
        genesis_hash,
        vec![write(b"branch", Some(b"b"))],
    );
    engine
        .import_proven_block(
            &bundle(&b1, &b1_proof, &b1_diff),
            &neutrin0_proof_system::MockProofSystem,
            None,
        )
        .unwrap();
    assert_eq!(
        engine.store().get_block_state(&b1.hash()).unwrap(),
        Some(BlockState::Proven)
    );
    assert_eq!(engine.state().root(), engine.head_state_root());

    // Replaying either branch from retained diffs reproduces its root.
    let replayed = engine.replay_to_head_with_diffs(b1.hash()).unwrap();
    assert_eq!(replayed.hash, b1.hash());
    assert_eq!(replayed.state.root(), b1.header.state_root);
    assert_eq!(replayed.state.get(b"branch").unwrap(), Some(b"b".to_vec()));
    let replayed = engine.replay_to_head_with_diffs(a2.hash()).unwrap();
    assert_eq!(replayed.state.root(), a2.header.state_root);

    // Replay refuses a branch block without a retained diff.
    let mut batch = Batch::new();
    batch.delete(Column::StateDiffs, b1.hash());
    engine
        .store_mut()
        .write_observed_batch(batch, false)
        .unwrap();
    assert!(matches!(
        engine.replay_to_head_with_diffs(b1.hash()),
        Err(ImportError::MissingStateDiff(_))
    ));
}
