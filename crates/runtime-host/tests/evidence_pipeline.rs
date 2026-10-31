//! Statement-bound evidence → block → chunk composition and fail-closed execution.
#[path = "support/acceptance.rs"]
pub mod acceptance;
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

#[cfg(feature = "cuda")]
use acceptance::{AcceptanceCache, StageIdentity};

use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::history::HistoryPath;
use neutrin0_consensus_types::runtime::Sanction;
use neutrin0_consensus_types::{
    Body, FinalityVoteData, FinalityVotePhase, IndexedVote, SlashingEvidence,
    evidence::{EvidenceArtifact, EvidenceBatch, EvidenceMembership, EvidenceSubmission},
};
use neutrin0_crypto::bls::SecretKey;
use neutrin0_primitives::{ConsensusDomain, DOMAIN_PROPOSER_SIG};
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_prover_chunk::{
    consensus::{
        ConsensusWitness, as_chunk, validate_consensus, validate_consensus_with_context,
        validate_successor,
    },
    evidence::{EvidenceClaim, EvidenceWitness, validate_evidence},
    history::{HistoricalChunk, history_commitment},
};
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_core::host::{LiveTrie, TracingState};
#[cfg(feature = "cuda")]
use neutrin0_runtime_host::proof_system::Sp1ChunkProof;
use neutrin0_runtime_host::{Sp1BlockProof, Sp1ProofSystem, wasm::WasmRuntime};
use sp1_sdk::{
    SP1Stdin,
    blocking::{Prover, ProverClient},
};

/// Attribution every receipt in this test names (design 08).
const PROVER_ADDRESS: [u8; 32] = [0x50; 32];

/// Public values the Block Guest commits for `output` under [`PROVER_ADDRESS`].
fn receipt_bytes(output: &neutrin0_runtime_abi::RuntimeBlockOutput) -> Vec<u8> {
    borsh::to_vec(&neutrin0_runtime_abi::BlockReceiptStatement {
        output: output.clone(),
        prover_address: PROVER_ADDRESS,
    })
    .unwrap()
}

/// Reporter rewards reach an Ethereum account, so the reporter is a
/// zero-padded 20-byte address.
const REPORTER: [u8; 32] = {
    let mut address = [0; 32];
    let mut index = 12;
    while index < 32 {
        address[index] = 55;
        index += 1;
    }
    address
};
/// The reporter's Ethereum account.
const REPORTER_ACCOUNT: alloy_primitives::Address = alloy_primitives::Address::new([55; 20]);

fn safety_keys() -> Vec<SecretKey> {
    [42, 43]
        .iter()
        .map(|byte| SecretKey::key_gen(&[*byte; 32], &[]).unwrap())
        .collect()
}

/// Two accountable genesis validators: ejecting one safety offender leaves
/// a funded survivor so the chain does not halt.
fn safety_validators() -> Vec<neutrin0_primitives::Validator> {
    safety_keys()
        .iter()
        .enumerate()
        .map(|(index, key)| neutrin0_primitives::Validator {
            pubkey: key.public_key().to_bytes(),
            withdrawal_credentials: support::credentials(u8::try_from(index + 8).unwrap()),
            effective_stake: 100,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
        })
        .collect()
}

/// Genesis state seating [`safety_validators`] under `active`.
fn safety_genesis(active: neutrin0_primitives::ProgramSet) -> LiveTrie {
    support::evm_genesis_live(&support::evm_genesis_input(
        active,
        30_000_000,
        0,
        &safety_validators(),
        1,
        neutrin0_primitives::RuntimeParams::default(),
    ))
}

/// Wei held by the reporter's Ethereum account in `live`.
fn reporter_balance(live: &LiveTrie) -> alloy_primitives::U256 {
    support::balance_of(live, REPORTER_ACCOUNT)
}

/// Wei held by the reporter's Ethereum account according to the WASM
/// runtime's account query over `live`.
fn queried_reporter_balance(runtime: &WasmRuntime, live: &LiveTrie) -> alloy_primitives::U256 {
    let response = runtime
        .query(
            &neutrin0_runtime_abi::QueryRequest {
                method: "evm:account".into(),
                args: borsh::to_vec(&REPORTER_ACCOUNT.into_array()).unwrap(),
            },
            live.trie(),
        )
        .unwrap();
    assert!(response.is_ok(), "account query {}", response.code);
    let account: neutrin0_evm_runtime_core::state::EvmAccount =
        borsh::from_slice(&response.payload).unwrap();
    alloy_primitives::U256::from_be_bytes(account.balance)
}

fn safety_fixture(
    active: neutrin0_primitives::ProgramSet,
    chunk_program: neutrin0_consensus_types::history_proof::VkDigest,
    live: &LiveTrie,
) -> (
    ConsensusWitness,
    RuntimeBlockInput,
    neutrin0_runtime_abi::StateWitness,
) {
    let keys = safety_keys();
    support::fixture_with_execution_and_validators(
        active,
        chunk_program,
        &safety_validators(),
        &keys,
        vec![],
        30_000_000,
        30_000_000,
        live,
        neutrin0_evm_runtime_core::execute_block,
        0,
    )
}

fn double_vote(domain: ConsensusDomain) -> SlashingEvidence {
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let sign = |hash| {
        let data = FinalityVoteData {
            chunk_id: 0,
            round: 2,
            chunk_hash: [hash; 32],
            selection: [0; 32],
            phase: FinalityVotePhase::Precommit,
        };
        let message = data.signing_message(domain);
        IndexedVote {
            data,
            signature: key.sign(&message).to_bytes(),
        }
    };
    SlashingEvidence::DoublePrecommit {
        validator_index: 0,
        vote_a: sign(1),
        vote_b: sign(2),
    }
}

fn evidence(witness: &ConsensusWitness) -> EvidenceWitness {
    let previous = validate_consensus(witness).unwrap();
    EvidenceWitness {
        reporter: Some(REPORTER),
        chain_spec: witness.chain_spec.clone(),
        source: HistoricalChunk {
            runtime_code_hash: witness.context.programs.runtime_code_hash,
            block_guest_vk_digest: witness.context.programs.execution.block,
            start_boundary: previous.start.commitment(),
            chunk: as_chunk(&previous.chunk),
            validators: witness.context.active_validators.clone(),
            seed: witness.seed,
            finality: witness.finality_cert.clone(),
        },
        claim: EvidenceClaim::Slash(double_vote(witness.chain_spec.consensus_domain())),
        block_guest_vk_digest: witness.context.programs.execution.block,
    }
}

fn submission_input(first: &ConsensusWitness, mut input: RuntimeBlockInput) -> RuntimeBlockInput {
    let evidence = evidence(first);
    let statement = validate_evidence(&evidence).unwrap();
    let leaves = [commitment(&statement.context)];
    let previous = validate_consensus(first).unwrap();
    // The incoming committee is the one the finalized boundary commits.
    input.active_validators =
        neutrin0_prover_chunk::consensus::validate_consensus_with_context(first)
            .unwrap()
            .next_context
            .active_validators;
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    input.context = neutrin0_consensus_types::runtime::ConsensusExecutionContext {
        slot: 2,
        timestamp: first.chain_spec.consensus.slot_duration_secs * 2,
        parent_block_hash: previous.end.block_hash,
        proposer_vrf_output: neutrin0_vrf::proof_output(
            &key.sign(&neutrin0_vrf::vrf_message(
                first.chain_spec.consensus_domain(),
                &previous.end.seed,
                2,
            ))
            .to_bytes(),
        ),
        finalized: previous.end,
    };
    input.block_height = 2;
    input.evidence_anchor.chunk_id = 1;
    input.evidence_anchor.history_root = history_commitment(&[evidence.source]);
    input.transactions = vec![neutrin0_runtime_abi::RuntimeTransaction::SubmitEvidence(
        Box::new(EvidenceSubmission {
            statement,
            history: HistoryPath::build(&leaves, 0).unwrap(),
        }),
    )];
    input
}

#[test]
fn invalid_and_missing_attachments_are_rejected_before_guest_execution() {
    let mock = ProverClient::builder().mock().build();
    let (first, input, _) =
        support::fixture([1; 8], neutrin0_runtime_host::embedded_runtime_code_hash());
    let genesis = support::fixture_genesis_live(
        [1; 8],
        neutrin0_runtime_host::embedded_runtime_code_hash(),
        30_000_000,
    );
    // The submission block follows the fixture's first block.
    let live = support::executed(&genesis, &input);
    let input = submission_input(&first, input);
    let attachments = vec![EvidenceArtifact {
        evidence_guest_vk_digest: input.evidence_anchor.evidence_guest_vk_digest,
        membership: EvidenceMembership::build(
            &[validate_evidence(&evidence(&first)).unwrap()],
            0,
            first.context.programs.execution.fact,
        )
        .unwrap(),
        statement: validate_evidence(&evidence(&first)).unwrap(),
        proof_bytes: vec![1, 2, 3],
    }];
    assert!(neutrin0_runtime_host::evidence::verify_input_receipts(&input, &attachments).is_err());
    assert!(
        WasmRuntime::embedded()
            .unwrap()
            .dry_run(&input, LiveTrie::default().trie(), &attachments)
            .is_err()
    );
    // Supply every state key the STF needs. Otherwise a missing-key panic
    // could hide a missing recursive-verification check in the block Guest.
    // The genesis offender holds slashable balance, so the claim is admissible.
    let mut trace = TracingState::new(&live);
    let expected = neutrin0_evm_runtime_core::apply_block(&input, &mut trace);
    let state = trace.into_witness().unwrap();
    let mut replay = neutrin0_runtime_core::WitnessState::new(&state).unwrap();
    assert_eq!(
        neutrin0_evm_runtime_core::apply_block(&input, &mut replay),
        expected
    );
    let execution = neutrin0_runtime_host::ProverCtx::new(mock).unwrap();
    assert!(
        execution
            .execute(&input, &state, &[], PROVER_ADDRESS)
            .is_err()
    );
    assert!(
        execution
            .execute(&input, &state, &attachments, PROVER_ADDRESS)
            .is_err()
    );
    assert!(execution.prove(&input, state, &[], PROVER_ADDRESS).is_err());
}

#[test]
fn malformed_field_receipts_fail_closed_without_a_slashable_verdict() {
    let (first, input, _) =
        support::fixture([1; 8], neutrin0_runtime_host::embedded_runtime_code_hash());
    let input = submission_input(&first, input);
    let mut malformed = 1_u32.to_le_bytes().to_vec();
    malformed.extend_from_slice(&[0xFF; 128]);
    let artifact = EvidenceArtifact {
        evidence_guest_vk_digest: input.evidence_anchor.evidence_guest_vk_digest,
        membership: EvidenceMembership::build(
            &[validate_evidence(&evidence(&first)).unwrap()],
            0,
            first.context.programs.execution.fact,
        )
        .unwrap(),
        statement: validate_evidence(&evidence(&first)).unwrap(),
        proof_bytes: malformed.clone(),
    };
    assert!(matches!(
        neutrin0_runtime_host::evidence::verify_input_receipts(&input, &[artifact]),
        Err(neutrin0_runtime_host::Sp1HostError::Sdk(_))
    ));
    let backend = Sp1ProofSystem::new(ProverClient::builder().mock().build()).unwrap();
    let block = &first.blocks[0];
    let signed_artifact = neutrin0_consensus_types::BlockProof {
        prover_address: block.public_inputs.proposer_address,
        statement_key: [0; 32],
        height: block.header.height,
        block_hash: block.header.hash(),
        public_inputs: block.public_inputs.clone(),
        proof_bytes: borsh::to_vec(&Sp1BlockProof { bytes: malformed }).unwrap(),
    };
    assert_eq!(
        backend.classify_block_rejection(&signed_artifact, &block.public_inputs.block_program),
        Err(ProofError::BackendRejected)
    );
}

#[test]
fn attachment_count_order_program_and_statement_are_checked_before_proof_decode() {
    let (first, input, _) =
        support::fixture([1; 8], neutrin0_runtime_host::embedded_runtime_code_hash());
    let mut input = submission_input(&first, input);
    let artifact = EvidenceArtifact {
        evidence_guest_vk_digest: input.evidence_anchor.evidence_guest_vk_digest,
        membership: EvidenceMembership::build(
            &[validate_evidence(&evidence(&first)).unwrap()],
            0,
            first.context.programs.execution.fact,
        )
        .unwrap(),
        statement: validate_evidence(&evidence(&first)).unwrap(),
        proof_bytes: vec![1],
    };
    let rejected_before_decode = |input: &RuntimeBlockInput, attachments: &[EvidenceArtifact]| {
        assert!(matches!(
            neutrin0_runtime_host::evidence::verify_input_receipts(input, attachments),
            Err(neutrin0_runtime_host::Sp1HostError::Codec(_))
        ));
    };
    rejected_before_decode(&input, &[]);
    rejected_before_decode(&input, &[artifact.clone(), artifact.clone()]);
    let mut wrong = artifact.clone();
    wrong.evidence_guest_vk_digest[0] ^= 1;
    rejected_before_decode(&input, &[wrong]);
    let mut wrong = artifact.clone();
    wrong.statement.facts_commitment[0] ^= 1;
    rejected_before_decode(&input, &[wrong]);
    let mut wrong = artifact.clone();
    wrong.statement.reporter = Some([99; 32]);
    rejected_before_decode(&input, &[wrong]);
    let mut second = input.transactions[0].clone();
    let neutrin0_runtime_abi::RuntimeTransaction::SubmitEvidence(submission) = &mut second else {
        unreachable!()
    };
    submission.statement.offence_id[0] ^= 1;
    let other = EvidenceArtifact {
        statement: submission.statement.clone(),
        ..artifact.clone()
    };
    input.transactions.push(second);
    rejected_before_decode(&input, &[other, artifact]);
}

#[test]
fn persisted_witness_roundtrips_attachments_and_rejects_trailing_bytes() {
    let (first, input, state) =
        support::fixture([1; 8], neutrin0_runtime_host::embedded_runtime_code_hash());
    let attachment = EvidenceArtifact {
        evidence_guest_vk_digest: input.evidence_anchor.evidence_guest_vk_digest,
        membership: EvidenceMembership::build(
            &[validate_evidence(&evidence(&first)).unwrap()],
            0,
            first.context.programs.execution.fact,
        )
        .unwrap(),
        statement: validate_evidence(&evidence(&first)).unwrap(),
        proof_bytes: vec![1],
    };
    let mut bytes = neutrin0_runtime_host::encode_witness_bundle(
        &input,
        &state,
        std::slice::from_ref(&attachment),
    )
    .unwrap();
    let decoded = neutrin0_runtime_host::decode_witness_bundle(&bytes).unwrap();
    assert_eq!(decoded.input, input);
    assert_eq!(decoded.state, state);
    assert_eq!(decoded.evidence_proofs, vec![attachment]);
    bytes.push(0);
    assert!(neutrin0_runtime_host::decode_witness_bundle(&bytes).is_err());
}

#[test]
fn evidence_guest_matches_native_statement_and_rejects_forgery() {
    let mock = ProverClient::builder().mock().build();
    let (first, _, _) =
        support::fixture([1; 8], neutrin0_runtime_host::embedded_runtime_code_hash());
    let witness = evidence(&first);
    let mut recorder = neutrin0_prover_chunk::facts::FactRecorder::default();
    let statement =
        neutrin0_prover_chunk::evidence::validate_evidence_using(&witness, &mut recorder).unwrap();
    assert_eq!(statement.reporter, Some(REPORTER));
    let checks = recorder.finish().unwrap();
    let fact_input = neutrin0_prover_chunk::facts::FactWitness {
        requests: checks.iter().map(|(request, _)| request.clone()).collect(),
        statement: neutrin0_prover_chunk::facts::FactStatement {
            facts: checks
                .iter()
                .map(
                    |(request, valid)| neutrin0_prover_chunk::facts::ProvenFact {
                        id: request.id(),
                        valid: *valid,
                    },
                )
                .collect(),
        },
    };
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(borsh::to_vec(&fact_input).unwrap());
    let (facts, report) = mock
        .execute(neutrin0_runtime_host::FACT_GUEST_ELF.clone(), stdin)
        .run()
        .unwrap();
    assert_eq!(report.exit_code, 0);
    assert_eq!(
        facts.as_slice(),
        borsh::to_vec(&fact_input.statement).unwrap()
    );
    let input = neutrin0_prover_chunk::evidence::EvidenceBatchWitness {
        witnesses: vec![witness],
        facts: vec![fact_input.statement],
        receipts: Vec::new(),
        fact_guest_vk_digest: [3; 8],
    };
    let expected = EvidenceBatch::new(&[statement], [3; 8]).unwrap();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(borsh::to_vec(&input).unwrap());
    let (values, report) = mock
        .execute(neutrin0_runtime_host::EVIDENCE_GUEST_ELF.clone(), stdin)
        .deferred_proof_verification(false)
        .run()
        .unwrap();
    assert_eq!(report.exit_code, 0);
    assert_eq!(values.as_slice(), borsh::to_vec(&expected).unwrap());
    let mut bad = input;
    if let EvidenceClaim::Slash(SlashingEvidence::DoublePrecommit { vote_b, .. }) =
        &mut bad.witnesses[0].claim
    {
        vote_b.signature[0] ^= 1;
    }
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(borsh::to_vec(&bad).unwrap());
    let result = mock
        .execute(neutrin0_runtime_host::EVIDENCE_GUEST_ELF.clone(), stdin)
        .deferred_proof_verification(false)
        .run();
    assert!(!result.is_ok_and(|(_, report)| report.exit_code == 0));
}

/// Proves evidence and its monetary/consensus effects from a trusted boundary,
/// then verifies each stage locally.
#[cfg(feature = "cuda")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Linux x86-64 and an NVIDIA GPU; real compressed CUDA proving"]
async fn evidence_block_chunk_cuda_compressed_recursion() {
    let device = std::env::var("NEUTRIN0_CUDA_DEVICE")
        .map_or(Ok(0), |value| value.parse::<u32>())
        .unwrap();
    tokio::task::spawn_blocking(move || {
        real_compressed_recursion(neutrin0_runtime_host::backend::cuda_prover(device).unwrap());
    })
    .await
    .unwrap();
}

#[cfg(feature = "cuda")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires NVIDIA CUDA: real Block receipt acceptance by Evidence recursion and worst-case rejection in the Fact Guest"]
async fn receipt_verdicts_real_compressed() {
    let device = std::env::var("NEUTRIN0_CUDA_DEVICE")
        .map_or(Ok(0), |value| value.parse::<u32>())
        .unwrap();
    tokio::task::spawn_blocking(move || {
        receipt_verdicts(neutrin0_runtime_host::backend::cuda_prover(device).unwrap());
    })
    .await
    .unwrap();
}

/// One real Block receipt yields both evidence polarities. An execution
/// claim needs the receipt valid, which the Evidence Guest establishes by
/// recursion; an acceptance of a rejected envelope needs a rejection, which
/// the Fact Guest establishes in software. The rejected envelope carries the
/// real proof with altered public values, which the verifier compares only
/// after verifying the whole proof: the most work a rejection can cost.
#[allow(clippy::too_many_lines)]
#[cfg(feature = "cuda")]
fn receipt_verdicts<P: neutrin0_runtime_host::ProgramProver>(prover: P) {
    use neutrin0_consensus_types::{BlockProof, ProofManifest, VoteAttestation};
    use neutrin0_prover_chunk::facts::{FactRequest, FactStatement, FactWitness, ProvenFact};

    let system = Sp1ProofSystem::new(prover).unwrap();
    let verifier = Sp1ProofSystem::new(ProverClient::builder().light().build()).unwrap();
    let cache = AcceptanceCache::from_env().unwrap();
    let programs = system
        .programs()
        .unwrap()
        .with_runtime(neutrin0_runtime_host::embedded_runtime_code_hash());
    let genesis = safety_genesis(programs);
    let (first, input, state) =
        safety_fixture(programs, system.programs().unwrap().chunk, &genesis);
    eprintln!("receipt verdicts: prove the first block");
    let block_bytes = prove_first_block(&system, &verifier, &cache, &first, &input, &state);
    let wire: Sp1BlockProof = borsh::from_slice(&block_bytes).unwrap();
    let mut bundle = wire.to_sp1().unwrap();
    let statement: neutrin0_runtime_abi::BlockReceiptStatement =
        borsh::from_slice(bundle.public_values.as_slice()).unwrap();
    let domain = first.chain_spec.consensus_domain();
    let keys = safety_keys();
    let key_of = |index: u32| {
        let validator = &first.context.active_validators[usize::try_from(index).unwrap()];
        keys.iter()
            .find(|key| key.public_key().to_bytes() == validator.pubkey)
            .unwrap()
    };
    let honest = &first.blocks[0];
    let source = evidence(&first).source;
    let witness = |claim| EvidenceWitness {
        reporter: Some(REPORTER),
        chain_spec: first.chain_spec.clone(),
        source: source.clone(),
        claim: EvidenceClaim::Slash(claim),
        block_guest_vk_digest: programs.execution.block,
    };

    // The proposer signs a header claiming another post-state over the same
    // inputs; the real receipt of that execution contradicts it.
    let mut forged = honest.header.clone();
    forged.state_root[0] ^= 1;
    forged.signature = key_of(forged.proposer_index)
        .sign(&domain.signing_message(DOMAIN_PROPOSER_SIG, &forged.hash()))
        .to_bytes();
    let mut public_inputs = honest.public_inputs.clone();
    public_inputs.block_hash = forged.hash();
    let execution_claim = witness(SlashingEvidence::InvalidExecutionClaim {
        proposer_index: forged.proposer_index,
        receipt: BlockProof {
            height: forged.height,
            block_hash: forged.hash(),
            public_inputs,
            proof_bytes: block_bytes,
            prover_address: statement.prover_address,
            statement_key: commitment(&statement),
        },
        header: forged,
        parent: None,
    });

    // Another validator accepts the real proof under altered public values.
    let mut altered = statement;
    altered.prover_address[31] ^= 1;
    bundle.public_values = sp1_sdk::SP1PublicValues::from(&borsh::to_vec(&altered).unwrap());
    let rejected = BlockProof {
        height: honest.public_inputs.height,
        block_hash: honest.public_inputs.block_hash,
        public_inputs: honest.public_inputs.clone(),
        proof_bytes: borsh::to_vec(&Sp1BlockProof::from_sp1(&bundle).unwrap()).unwrap(),
        prover_address: altered.prover_address,
        statement_key: commitment(&altered),
    };
    let signer_index = 1 - honest.header.proposer_index;
    let signer = key_of(signer_index);
    let manifest = ProofManifest {
        proof_hashes: vec![commitment(&rejected)],
    };
    let data = FinalityVoteData {
        chunk_id: 0,
        round: 3,
        chunk_hash: [7; 32],
        selection: [0; 32],
        phase: FinalityVotePhase::Precommit,
    };
    let vote = IndexedVote {
        signature: signer.sign(&data.signing_message(domain)).to_bytes(),
        data: data.clone(),
    };
    let mut attestation = VoteAttestation {
        validator_index: signer_index,
        vote_signature: vote.signature,
        vote: data,
        proof_acceptance: Some(manifest.commitment()),
        unlock_quorum: None,
        signature: [0; 96],
    };
    attestation.signature = signer.sign(&attestation.signing_message(domain)).to_bytes();
    let proof_signing = witness(SlashingEvidence::InvalidProofSigning {
        proof_opening: manifest.opening(0).unwrap(),
        validator_index: signer_index,
        vote,
        attestation,
        rejected_proof: rejected.clone(),
        reason: neutrin0_consensus_types::ProofRejectionReason::VerifierRejected,
    });

    // Execution profile of the worst-case rejection.
    let fact = FactRequest::Block {
        key: programs.execution.block,
        proof: rejected,
    };
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(
        borsh::to_vec(&FactWitness {
            statement: FactStatement {
                facts: vec![ProvenFact {
                    id: fact.id(),
                    valid: false,
                }],
            },
            requests: vec![fact],
        })
        .unwrap(),
    );
    let (_, report) = ProverClient::builder()
        .mock()
        .build()
        .execute(neutrin0_runtime_host::FACT_GUEST_ELF.clone(), stdin)
        .run()
        .unwrap();
    assert_eq!(report.exit_code, 0);
    eprintln!(
        "PROFILE fact case=worst-case block rejection instructions={}\n{report}",
        report.total_instruction_count()
    );

    let witnesses = [execution_claim, proof_signing];
    let statements: Vec<_> = witnesses
        .iter()
        .map(|witness| validate_evidence(witness).unwrap())
        .collect();
    let batch = EvidenceBatch::new(&statements, programs.execution.fact).unwrap();
    let identity = StageIdentity::new(
        "receipt-verdicts",
        &neutrin0_runtime_host::EVIDENCE_GUEST_ELF,
        &borsh::to_vec(&witnesses).unwrap(),
        &borsh::to_vec(&batch).unwrap(),
    );
    eprintln!("receipt verdicts: prove both polarities in one evidence batch");
    cache
        .prove_or_resume(
            &identity,
            |bytes| verifier.verify_evidence(bytes, &batch, &programs.execution.evidence),
            || {
                system
                    .prove_evidence_batch(&witnesses, &programs.execution)
                    .map(|artifacts| artifacts[0].proof_bytes.clone())
            },
        )
        .unwrap();
}

#[allow(clippy::too_many_lines)]
#[cfg(feature = "cuda")]
fn real_compressed_recursion(prover: impl neutrin0_runtime_host::ProgramProver) {
    let system = Sp1ProofSystem::new(prover).unwrap();
    // Independent local verification also checks CUDA-to-CPU interoperability.
    let verifier = Sp1ProofSystem::new(ProverClient::builder().light().build()).unwrap();
    assert_eq!(system.programs(), verifier.programs());
    assert!(system.programs().unwrap().is_complete());
    let cache = AcceptanceCache::from_env().unwrap();
    let programs = system
        .programs()
        .unwrap()
        .with_runtime(neutrin0_runtime_host::embedded_runtime_code_hash());
    let genesis = safety_genesis(programs);
    let (mut first, input, first_state) =
        safety_fixture(programs, system.programs().unwrap().chunk, &genesis);
    // Design 08: the successor's certificate ratifies the first chunk's proof,
    // which the successor's Guest verifies recursively.
    eprintln!("evidence gate: prove the ratified first chunk");
    let first_proof =
        prove_first_chunk(&system, &verifier, &cache, &mut first, &input, &first_state);
    // The submission block follows the first block.
    let live = support::executed(&genesis, &input);
    let previous = validate_consensus(&first).unwrap();
    let evidence = evidence(&first);
    let statement = validate_evidence(&evidence).unwrap();
    let batch = EvidenceBatch::new(
        std::slice::from_ref(&statement),
        first.context.programs.execution.fact,
    )
    .unwrap();
    eprintln!("evidence gate: prove objective misconduct");
    let evidence_identity = StageIdentity::new(
        "evidence",
        &neutrin0_runtime_host::EVIDENCE_GUEST_ELF,
        &borsh::to_vec(&evidence).unwrap(),
        &borsh::to_vec(&batch).unwrap(),
    );
    let bytes = cache
        .prove_or_resume(
            &evidence_identity,
            |bytes| {
                verifier.verify_evidence(bytes, &batch, &first.context.programs.execution.evidence)
            },
            || {
                system
                    .prove_evidence_batch(
                        std::slice::from_ref(&evidence),
                        &first.context.programs.execution,
                    )
                    .map(|artifacts| artifacts[0].proof_bytes.clone())
            },
        )
        .unwrap();
    let mut wrong = batch.clone();
    wrong.root[0] ^= 1;
    assert!(
        verifier
            .verify_evidence(&bytes, &wrong, &first.context.programs.execution.evidence)
            .is_err()
    );
    let mut corrupt = bytes.clone();
    corrupt.push(0);
    assert!(
        verifier
            .verify_evidence(&corrupt, &batch, &first.context.programs.execution.evidence)
            .is_err()
    );
    let mut input = submission_input(&first, input);
    input.participation = participation_of(&first);
    input.proving = proving_of(&first);
    let attachments = vec![EvidenceArtifact {
        evidence_guest_vk_digest: first.context.programs.execution.evidence,
        membership: EvidenceMembership::build(
            std::slice::from_ref(&statement),
            0,
            first.context.programs.execution.fact,
        )
        .unwrap(),
        statement,
        proof_bytes: bytes,
    }];
    let mut alternate = attachments[0].clone();
    let mut bundle: sp1_sdk::SP1ProofWithPublicValues =
        neutrin0_prover_chunk::receipt_codec::decode::<_, { 2 * 1024 * 1024 }>(
            &alternate.proof_bytes,
        )
        .unwrap();
    bundle.tee_proof = Some(vec![1]);
    alternate.proof_bytes = neutrin0_prover_chunk::receipt_codec::encode(&bundle).unwrap();
    assert_eq!(alternate.statement_id(), attachments[0].statement_id());
    assert_ne!(alternate.proof_bytes, attachments[0].proof_bytes);
    assert!(neutrin0_runtime_host::evidence::verify_input_receipts(&input, &[alternate]).is_err());
    let dry = WasmRuntime::embedded()
        .unwrap()
        .dry_run(&input, live.trie(), &attachments)
        .unwrap();
    assert_eq!(
        neutrin0_runtime_host::dry_run(&input, &live, &attachments)
            .expect("native dry run")
            .output,
        dry.output
    );
    assert_eq!(dry.output.accountability.executed.len(), 1);
    let rewarded = LiveTrie::from_trie(dry.post_state.clone());
    assert_eq!(
        queried_reporter_balance(&WasmRuntime::embedded().unwrap(), &rewarded),
        alloy_primitives::U256::from(10)
    );
    assert_eq!(
        reporter_balance(&rewarded),
        alloy_primitives::U256::from(10)
    );
    // The tombstoned offender leaves the candidate set; the survivor's
    // collateral is untouched.
    let mut candidates = neutrin0_consensus_types::runtime::ConsensusCandidates::default();
    candidates.upsert(neutrin0_consensus_types::runtime::ConsensusCandidate {
        address: support::credentials(9),
        stake: 100,
        identity: None,
    });
    assert_eq!(dry.output.consensus_candidates_root, candidates.root());
    let mut next = successor_fixture(&first, &input, &dry.output, &live);
    let execution =
        neutrin0_runtime_host::ProverCtx::new(ProverClient::builder().mock().build()).unwrap();
    let (values, report) = execution
        .execute(&input, &dry.witness, &attachments, PROVER_ADDRESS)
        .unwrap();
    assert_eq!(report.exit_code, 0);
    assert_eq!(values.as_slice(), receipt_bytes(&dry.output));
    eprintln!(
        "evidence gate: block guest instructions={}, syscalls={:?}",
        report.total_instruction_count(),
        report.syscall_counts
    );
    eprintln!("evidence gate: prove block with native statement recursion");
    let executor = neutrin0_runtime_host::WasmExecutor::embedded().unwrap();
    let body = Body {
        participation: next.bodies[0].participation.clone(),
        transactions: input
            .transactions
            .iter()
            .map(|tx| borsh::to_vec(tx).unwrap())
            .collect(),
        evidence_proofs: attachments,
        ..Body::default()
    };
    let context = neutrin0_proof_system::BlockExecutionContext {
        active_validators: input.active_validators.clone(),
        participation_acks: input.participation_acks.clone(),
        program_pieces: Vec::new(),
        context: input.context,
        evidence_anchor: input.evidence_anchor,
        runtime_code_hash: neutrin0_runtime_host::embedded_runtime_code_hash(),
        chain_id: input.chain_id,
        block_height: input.block_height,
        gas_limit: input.block_gas_limit,
        proposer_address: input.proposer_address,
        participation: input.participation,
        proving: input.proving,
    };
    let mut state = live.trie().clone();
    let produced =
        neutrin0_proof_system::BlockExecutor::execute_block(&executor, &context, &body, &mut state)
            .unwrap();
    assert_eq!(produced.state_root_after, dry.output.post_state_root);
    assert_eq!(produced.receipts_root, dry.output.receipts_root);
    assert_eq!(produced.gas_used, dry.output.gas_used);
    assert_eq!(produced.runtime_extra, dry.output.consensus_candidates_root);
    let block_input = produced.witness_bytes;
    let block_identity = StageIdentity::new(
        "block",
        &neutrin0_runtime_host::EVM_GUEST_ELF,
        &block_input,
        &borsh::to_vec(&(&next.blocks[0].public_inputs, &dry.output)).unwrap(),
    );
    let proof_bytes = cache
        .prove_or_resume(
            &block_identity,
            |bytes| {
                let proof: Sp1BlockProof =
                    borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
                verifier.verify_block(&proof, &next.blocks[0].public_inputs)?;
                if verifier.block_statement(&proof)?.output != dry.output {
                    return Err(ProofError::PublicInputMismatch);
                }
                Ok(())
            },
            || {
                let proof = system.prove_block(
                    &block_input,
                    &next.blocks[0].public_inputs,
                    next.blocks[0].public_inputs.proposer_address,
                )?;
                borsh::to_vec(&proof).map_err(|_| ProofError::MalformedProof)
            },
        )
        .unwrap();
    let proof: Sp1BlockProof = borsh::from_slice(&proof_bytes).unwrap();
    let proof_hash = commitment(&neutrin0_consensus_types::BlockProof {
        prover_address: next.blocks[0].public_inputs.proposer_address,
        statement_key: [0; 32],
        height: 2,
        block_hash: next.blocks[0].header.hash(),
        public_inputs: next.blocks[0].public_inputs.clone(),
        proof_bytes: borsh::to_vec(&proof).unwrap(),
    });
    let keys = safety_keys();
    let manifest = neutrin0_consensus_types::ProofManifest {
        proof_hashes: vec![proof_hash],
    };
    next.finality_cert.proof_manifests = vec![manifest.clone()];
    for claim in &mut next.finality_cert.precommit_attestations {
        claim.proof_acceptance = Some(manifest.commitment());
        claim.signature = keys[usize::try_from(claim.validator_index).unwrap()]
            .sign(&claim.signing_message(next.chain_spec.consensus_domain()))
            .to_bytes();
    }
    let expected = validate_successor(&previous, &next).unwrap();
    let outgoing = validate_consensus_with_context(&next).unwrap();
    assert_eq!(outgoing.next_context.active_validators.len(), 1);
    assert_eq!(
        outgoing.next_context.active_validators[0].pubkey,
        keys[1].public_key().to_bytes()
    );
    assert!(outgoing.next_context.active_validators[0].effective_stake > 0);
    assert_ne!(
        outgoing.statement.end.identity_sanctions_root,
        neutrin0_runtime_core::EMPTY_STATE_ROOT
    );
    eprintln!("evidence gate: prove and verify consensus chunk");
    let chunk_identity = StageIdentity::new(
        "chunk",
        &neutrin0_runtime_host::CONSENSUS_CHUNK_GUEST_ELF,
        &borsh::to_vec(&(&next, &proof_bytes)).unwrap(),
        &borsh::to_vec(&expected).unwrap(),
    );
    let chunk_bytes = cache
        .prove_or_resume(
            &chunk_identity,
            |bytes| {
                let proof: Sp1ChunkProof =
                    borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
                verifier.verify_consensus_chunk(
                    &proof,
                    &neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
                        statement: expected.clone(),
                        chunk_prover_address: [0; 32],
                    },
                )
            },
            || {
                let proof = system.prove_consensus_chunk(
                    std::slice::from_ref(&proof),
                    std::slice::from_ref(&first_proof),
                    &next,
                    [0; 32],
                )?;
                borsh::to_vec(&proof).map_err(|_| ProofError::MalformedProof)
            },
        )
        .unwrap();
    // Same chunk with every signature check answered by Fact receipts: the
    // early worker's path. Receipts are proven first, then the chunk guest
    // only verifies them recursively. The committed statement must not change.
    eprintln!("evidence gate: prove the same chunk with fact-covered signature checks");
    let mut recorder = neutrin0_prover_chunk::facts::FactRecorder::default();
    neutrin0_prover_chunk::consensus::validate_consensus_using(&next, &mut recorder).unwrap();
    let requests: Vec<_> = recorder
        .finish()
        .unwrap()
        .into_iter()
        .map(|(request, _)| request)
        .collect();
    let covered_identity = StageIdentity::new(
        "chunk-facts",
        &neutrin0_runtime_host::CONSENSUS_CHUNK_GUEST_ELF,
        &borsh::to_vec(&(&next, &proof_bytes, requests.len())).unwrap(),
        &borsh::to_vec(&expected).unwrap(),
    );
    let covered_bytes = cache
        .prove_or_resume(
            &covered_identity,
            |bytes| {
                let proof: Sp1ChunkProof =
                    borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
                verifier.verify_consensus_chunk(
                    &proof,
                    &neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
                        statement: expected.clone(),
                        chunk_prover_address: [0; 32],
                    },
                )
            },
            || {
                let started = std::time::Instant::now();
                system.preprove_facts(&next.context.programs.execution.fact, &requests)?;
                eprintln!(
                    "evidence gate: {} fact requests proven in {:?}",
                    requests.len(),
                    started.elapsed()
                );
                let started = std::time::Instant::now();
                let proof = system.prove_consensus_chunk(
                    std::slice::from_ref(&proof),
                    std::slice::from_ref(&first_proof),
                    &next,
                    [0; 32],
                )?;
                let (covered, total) = system.last_chunk_fact_coverage().unwrap_or((0, 0));
                eprintln!(
                    "evidence gate: fact-covered chunk proved in {:?}; coverage {covered}/{total}",
                    started.elapsed()
                );
                if covered != total || total == 0 {
                    return Err(ProofError::InvalidWitness);
                }
                borsh::to_vec(&proof).map_err(|_| ProofError::MalformedProof)
            },
        )
        .unwrap();
    let covered: Sp1ChunkProof = borsh::from_slice(&covered_bytes).unwrap();
    verifier
        .verify_consensus_chunk(
            &covered,
            &neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
                statement: expected.clone(),
                chunk_prover_address: [0; 32],
            },
        )
        .unwrap();
    // The accepted offence and mandatory deduction are part of the History
    // this receipt proves from genesis: it verified the first chunk's receipt
    // recursively, and that chunk started at genesis.
    assert_eq!(expected.start, previous.end);
    let history = neutrin0_consensus_types::history_proof::HistoryProof {
        statement: neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
            statement: expected,
            chunk_prover_address: [0; 32],
        },
        receipt: neutrin0_primitives::BoundedBytes::new(chunk_bytes).unwrap(),
    };
    let authenticated =
        neutrin0_proof_system::verify_history_proof(&verifier, &next.chain_spec, history).unwrap();
    assert_eq!(
        authenticated.proof().end().next_chunk_id,
        previous.end.next_chunk_id + 1
    );
}

/// Prove the first chunk's block and chunk, crediting the zero account, after
/// re-signing its acceptance claims over the real block receipt.
#[cfg(feature = "cuda")]
fn prove_first_chunk<P, V>(
    system: &Sp1ProofSystem<P>,
    verifier: &Sp1ProofSystem<V>,
    cache: &AcceptanceCache,
    first: &mut ConsensusWitness,
    input: &RuntimeBlockInput,
    state: &neutrin0_runtime_abi::StateWitness,
) -> Sp1ChunkProof
where
    P: neutrin0_runtime_host::ProgramProver,
    V: neutrin0_runtime_host::ProgramProver,
{
    let block_bytes = prove_first_block(system, verifier, cache, first, input, state);
    let inputs = first.blocks[0].public_inputs.clone();
    let block: Sp1BlockProof = borsh::from_slice(&block_bytes).unwrap();
    let manifest = neutrin0_consensus_types::ProofManifest {
        proof_hashes: vec![commitment(&neutrin0_consensus_types::BlockProof {
            prover_address: inputs.proposer_address,
            statement_key: [0; 32],
            height: inputs.height,
            block_hash: inputs.block_hash,
            public_inputs: inputs,
            proof_bytes: block_bytes.clone(),
        })],
    };
    first.finality_cert.proof_manifests = vec![manifest.clone()];
    let available = safety_keys();
    let validators = first.context.active_validators.clone();
    let domain = first.chain_spec.consensus_domain();
    for claim in &mut first.finality_cert.precommit_attestations {
        let validator = &validators[usize::try_from(claim.validator_index).unwrap()];
        let key = available
            .iter()
            .find(|key| key.public_key().to_bytes() == validator.pubkey)
            .unwrap();
        claim.proof_acceptance = Some(manifest.commitment());
        claim.signature = key.sign(&claim.signing_message(domain)).to_bytes();
    }
    let expected = neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
        statement: validate_consensus(first).unwrap(),
        chunk_prover_address: [0; 32],
    };
    let identity = StageIdentity::new(
        "first-chunk",
        &neutrin0_runtime_host::CONSENSUS_CHUNK_GUEST_ELF,
        &borsh::to_vec(&(&*first, &block_bytes)).unwrap(),
        &borsh::to_vec(&expected).unwrap(),
    );
    let witness: &ConsensusWitness = first;
    let chunk_bytes = cache
        .prove_or_resume(
            &identity,
            |bytes| {
                let proof: Sp1ChunkProof =
                    borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
                verifier.verify_consensus_chunk(&proof, &expected)
            },
            || {
                let proof = system.prove_consensus_chunk(&[block], &[], witness, [0; 32])?;
                borsh::to_vec(&proof).map_err(|_| ProofError::MalformedProof)
            },
        )
        .unwrap();
    borsh::from_slice(&chunk_bytes).unwrap()
}

/// The real compressed receipt of `first`'s only block, as wire bytes.
#[cfg(feature = "cuda")]
fn prove_first_block<P, V>(
    system: &Sp1ProofSystem<P>,
    verifier: &Sp1ProofSystem<V>,
    cache: &AcceptanceCache,
    first: &ConsensusWitness,
    input: &RuntimeBlockInput,
    state: &neutrin0_runtime_abi::StateWitness,
) -> Vec<u8>
where
    P: neutrin0_runtime_host::ProgramProver,
    V: neutrin0_runtime_host::ProgramProver,
{
    let block_input = neutrin0_runtime_host::encode_witness_bundle(input, state, &[]).unwrap();
    let inputs = first.blocks[0].public_inputs.clone();
    let identity = StageIdentity::new(
        "first-block",
        &neutrin0_runtime_host::EVM_GUEST_ELF,
        &block_input,
        &borsh::to_vec(&inputs).unwrap(),
    );
    cache
        .prove_or_resume(
            &identity,
            |bytes| {
                let proof: Sp1BlockProof =
                    borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
                verifier.verify_block(&proof, &inputs)
            },
            || {
                let proof = system.prove_block(&block_input, &inputs, inputs.proposer_address)?;
                borsh::to_vec(&proof).map_err(|_| ProofError::MalformedProof)
            },
        )
        .unwrap()
}

/// The report every block of the chunk after `first` hands to the runtime.
/// The proving report the successor consumes from `first`'s carried
/// certificate (design 08).
fn proving_of(
    first: &ConsensusWitness,
) -> Option<neutrin0_consensus_types::proving::ProvingReport> {
    let chunk = neutrin0_prover_chunk::consensus::as_chunk(
        &neutrin0_prover_chunk::consensus::validate_candidate(first)
            .ok()?
            .execution
            .chunk,
    );
    neutrin0_consensus_types::proving::ProvingReport::from_certificate(
        &chunk,
        &first.context.active_validators,
        &first.finality_cert.carried_certificate(),
    )
}

fn participation_of(
    first: &ConsensusWitness,
) -> Option<neutrin0_consensus_types::participation::ParticipationReport> {
    neutrin0_consensus_types::participation::ParticipationReport::from_certificate(
        first.context.chunk_id,
        &first.context.active_validators,
        &first.finality_cert.precommit.aggregation_bits,
    )
}

#[allow(clippy::too_many_lines)] // Full signed successor fixture shared by native and real-proof gates.
fn successor_fixture(
    first: &ConsensusWitness,
    input: &RuntimeBlockInput,
    output: &neutrin0_runtime_abi::RuntimeBlockOutput,
    live: &LiveTrie,
) -> ConsensusWitness {
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let previous = validate_consensus(first).unwrap();
    let mut next = first.clone();
    next.context = validate_consensus_with_context(first).unwrap().next_context;
    next.seed = previous.end.seed;
    next.history = neutrin0_prover_chunk::history::HistoryWitness::from_history(
        &[evidence(first).source],
        &[first.context.chunk_id],
    )
    .unwrap();
    let body = Body {
        participation: Some(first.finality_cert.carried_certificate()),
        transactions: input
            .transactions
            .iter()
            .map(|tx| borsh::to_vec(tx).unwrap())
            .collect(),
        ..Body::default()
    };
    next.bodies = vec![neutrin0_prover_chunk::body::ConsensusBody::from_body(&body).unwrap()];
    let block = &mut next.blocks[0];
    block.output = output.clone();
    block.header.height = 2;
    block.header.slot = 2;
    block.header.parent_hash = next.context.parent_block_hash;
    block.header.timestamp = next.chain_spec.consensus.slot_duration_secs * 2;
    block.header.vrf_proof = key
        .sign(&neutrin0_vrf::vrf_message(
            next.chain_spec.consensus_domain(),
            &next.seed,
            2,
        ))
        .to_bytes();
    block.header.state_root = output.post_state_root;
    block.header.transactions_root = output.transactions_root;
    block.header.receipts_root = output.receipts_root;
    block.header.gas_used = output.gas_used;
    block.header.runtime_extra = output.consensus_candidates_root;
    block.header.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(output);
    block.header.da_root = neutrin0_prover_chunk::consensus::body_da_root(&body);
    let message = next
        .chain_spec
        .consensus_domain()
        .signing_message(DOMAIN_PROPOSER_SIG, &block.header.hash());
    block.header.signature = key.sign(&message).to_bytes();
    block.public_inputs.context = output.context.into();
    block.public_inputs.height = 2;
    block.public_inputs.block_hash = block.header.hash();
    block.public_inputs.parent_block_hash = block.header.parent_hash;
    block.public_inputs.state_root_before = output.pre_state_root;
    block.public_inputs.state_root_after = output.post_state_root;
    block.public_inputs.transactions_root = output.transactions_root;
    block.public_inputs.receipt_root = output.receipts_root;
    block.public_inputs.gas_used = output.gas_used;
    block.public_inputs.runtime_extra = output.consensus_candidates_root;
    block.public_inputs.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(output);
    block.public_inputs.da_root = block.header.da_root;
    let mut state = TracingState::new(live);
    neutrin0_evm_runtime_core::apply_block(input, &mut state);
    let (post, _) = state.into_committed_and_witness().unwrap();
    let post = LiveTrie::from_trie(post);
    let mut trace = TracingState::new(&post);
    neutrin0_prover_chunk::rotation::witness_keys_from(&mut trace);
    next.post_state = trace.into_witness().unwrap();
    let available = safety_keys();
    let keys: Vec<_> = next
        .context
        .active_validators
        .iter()
        .map(|validator| {
            available
                .iter()
                .find(|key| key.public_key().to_bytes() == validator.pubkey)
                .unwrap()
                .clone()
        })
        .collect();
    // Design 08: the certificate ratifies `first`'s proof, which the real
    // gate proves crediting the zero account.
    next.ratified = vec![
        neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
            statement: previous,
            chunk_prover_address: [0; 32],
        },
    ];
    let signers: Vec<_> = (0..keys.len()).collect();
    next.finality_cert = support::certificate_with_precommitters(&next, &keys, &signers);
    next
}

#[test]
fn block_proven_sanction_changes_consensus_without_rechecking_raw_evidence() {
    // Pure STF composition fixture. The real gate above authenticates the
    // attachment and the same effects through block and chunk proofs.
    let genesis = safety_genesis(support::programs([1; 8], [4; 32]));
    let (first, input, _) = safety_fixture(
        support::programs([1; 8], [4; 32]),
        support::chunk_program(),
        &genesis,
    );
    let live = support::executed(&genesis, &input);
    let mut input = submission_input(&first, input);
    input.participation = participation_of(&first);
    input.proving = proving_of(&first);
    let mut trace = TracingState::new(&live);
    let output = neutrin0_evm_runtime_core::apply_block(&input, &mut trace);
    assert_eq!(output.accountability.executed.len(), 1);
    let (rewarded, _) = trace.into_committed_and_witness().unwrap();
    assert_eq!(
        reporter_balance(&LiveTrie::from_trie(rewarded)),
        alloy_primitives::U256::from(10)
    );
    let next = successor_fixture(&first, &input, &output, &live);
    let previous = validate_consensus(&first).unwrap();
    let statement = validate_successor(&previous, &next).unwrap();
    let full = validate_consensus_with_context(&next).unwrap();
    assert_eq!(full.statement, statement);
    assert_eq!(full.next_context.active_validators.len(), 1);
    assert_eq!(
        full.next_context.active_validators[0].pubkey,
        safety_keys()[1].public_key().to_bytes()
    );
    assert!(full.next_context.active_validators[0].effective_stake > 0);
    assert_ne!(
        full.statement.end.identity_sanctions_root,
        neutrin0_runtime_core::EMPTY_STATE_ROOT
    );
    let mut forged = next;
    forged.blocks[0].output.accountability.anchor.history_root[0] ^= 1;
    assert!(validate_successor(&previous, &forged).is_err());
}

#[test]
fn pending_reporter_reward_matches_native_wasm_and_block_guest() {
    use neutrin0_runtime_system::{
        Validator,
        accountability::{PendingSanction, QUEUE_KEY, slashed_key},
        encode_validator, validator_key,
    };

    // A queued obligation is authenticated pre-state. This ordinary empty
    // block exercises reward execution without substituting a mock evidence
    // receipt for the separately tested real compressed proof.
    let (first, mut input, _) =
        support::fixture([1; 8], neutrin0_runtime_host::embedded_runtime_code_hash());
    let genesis = support::fixture_genesis_live(
        [1; 8],
        neutrin0_runtime_host::embedded_runtime_code_hash(),
        30_000_000,
    );
    // The empty block follows the fixture's first block.
    let mut live = support::executed(&genesis, &input);
    let statement = validate_evidence(&evidence(&first)).unwrap();
    input.transactions.clear();
    input.block_height = 2;
    input.context.slot = 2;
    input.context.timestamp = first.chain_spec.consensus.slot_duration_secs * 2;
    input.context.parent_block_hash = first.blocks[0].header.hash();
    let obligation = PendingSanction {
        sanction: Sanction {
            offence_id: statement.offence_id,
            offender: statement.offender,
            kind: statement.kind,
        },
        amount: 1_000,
        reporter: statement.reporter,
        reporter_reward_bps: 1_000,
    };
    live.insert(
        &validator_key(&support::credentials(8)),
        encode_validator(&Validator { stake: 73 }),
    );
    live.insert(QUEUE_KEY, borsh::to_vec(&vec![obligation.clone()]).unwrap());
    live.insert(&slashed_key(&obligation.sanction.offender.pubkey), vec![0]);
    let runtime = WasmRuntime::embedded().unwrap();
    let wasm = runtime.dry_run(&input, live.trie(), &[]).unwrap();
    let native = neutrin0_runtime_host::dry_run(&input, &live, &[]).expect("native dry run");
    assert_eq!(wasm.output, native.output);
    assert_eq!(wasm.output.accountability.executed.len(), 1);
    let post = LiveTrie::from_trie(wasm.post_state);
    assert_eq!(
        queried_reporter_balance(&runtime, &post),
        alloy_primitives::U256::from(7)
    );
    let request = neutrin0_runtime_abi::QueryRequest {
        method: neutrin0_runtime_system::QUERY_METHOD_ACCOUNTABILITY_METRICS.into(),
        args: Vec::new(),
    };
    let response = runtime.query(&request, post.trie()).unwrap();
    let mut native_state = TracingState::new(&post);
    assert_eq!(
        response,
        neutrin0_evm_runtime_core::query(&request, &mut native_state)
    );
    let totals: neutrin0_runtime_system::accountability::settlement::SettlementSnapshot =
        borsh::from_slice(&response.payload).unwrap();
    assert_eq!(totals.totals.slash.executed.value, 1);
    assert_eq!(totals.totals.slash.deducted.value, 73);
    assert_eq!(totals.totals.slash.rewarded.value, 7);
    assert_eq!(totals.totals.slash.burned.value, 66);
    assert_eq!(totals.pending_slash, 0);
    let execution =
        neutrin0_runtime_host::ProverCtx::new(ProverClient::builder().mock().build()).unwrap();
    let (values, report) = execution
        .execute(&input, &wasm.witness, &[], PROVER_ADDRESS)
        .unwrap();
    assert_eq!(report.exit_code, 0);
    assert_eq!(values.as_slice(), receipt_bytes(&wasm.output));
}
