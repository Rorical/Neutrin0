//! The chunk receipt chain as the History proof, and opt-in real
//! compressed-STARK recursion.
//!
//! Every chunk Guest after chunk zero recursively verifies the previous chunk's
//! receipt, so the latest receipt proves the whole chain from genesis (design
//! 13). Execution-only tests intentionally disable deferred proof
//! verification: they establish the statement chaining, never receipt
//! authenticity or node finalization.
#[path = "support/acceptance.rs"]
pub mod acceptance;
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::history_proof::{
    ChunkReceiptStatement, ConsensusBoundary, HistoryProof,
};
use neutrin0_primitives::BoundedBytes;
use neutrin0_proof_system::{ProofError, ProofSystem, verify_history_proof};
use neutrin0_prover_chunk::consensus::{
    ConsensusWitness, as_chunk, validate_candidate, validate_consensus,
    validate_consensus_with_context,
};
use neutrin0_runtime_core::host::{LiveTrie, TracingState};
use neutrin0_runtime_host::{
    ProgramProver, Sp1BlockProof, Sp1ProofSystem, proof_system::Sp1ChunkProof,
};
use sp1_sdk::{
    ProvingKey, SP1Proof, SP1Stdin,
    blocking::{ProveRequest, Prover, ProverClient},
};

/// Chunks 0, 1 and 2, each certificate after the first ratifying the
/// previous chunk's receipt.
fn execution_fixture() -> Vec<ConsensusWitness> {
    let (first, input, _) = support::fixture([1; 8], [4; 32]);
    // Successors continue from the fixture block's post-state.
    let live = support::executed(
        &support::fixture_genesis_live([1; 8], [4; 32], 30_000_000),
        &input,
    );
    let (second, input, _, live) = empty_successor(&first, &input, &live);
    let (third, _, _, _) = empty_successor(&second, &input, &live);
    vec![first, second, third]
}

/// Public values the chunk Guest commits for `witness`, or `None` when it
/// rejects it. Deferred receipts are not verified here.
fn execute_chunk_guest(witness: &ConsensusWitness) -> Option<Vec<u8>> {
    let prover = ProverClient::builder().light().build();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(borsh::to_vec(witness).unwrap());
    stdin.write_vec(vec![0; 32]);
    let (values, report) = prover
        .execute(
            neutrin0_runtime_host::CONSENSUS_CHUNK_GUEST_ELF.clone(),
            stdin,
        )
        .deferred_proof_verification(false)
        .run()
        .ok()?;
    (report.exit_code == 0).then(|| values.as_slice().to_vec())
}

fn receipt_statement(witness: &ConsensusWitness) -> ChunkReceiptStatement {
    ChunkReceiptStatement {
        statement: validate_consensus(witness).unwrap(),
        chunk_prover_address: [0; 32],
    }
}

#[test]
fn chunk_guest_execution_chains_every_receipt_to_genesis() {
    let witnesses = execution_fixture();
    let statements: Vec<_> = witnesses.iter().map(receipt_statement).collect();
    assert_eq!(
        statements[0].statement.start,
        ConsensusBoundary::genesis(&witnesses[0].chain_spec)
    );
    let mut previous: Option<&ChunkReceiptStatement> = None;
    for (witness, statement) in witnesses.iter().zip(&statements) {
        assert_eq!(
            execute_chunk_guest(witness).unwrap(),
            borsh::to_vec(statement).unwrap()
        );
        // Every receipt after the first verifies exactly the previous one,
        // which ends where this one starts.
        assert_eq!(
            witness.ratified,
            previous.cloned().into_iter().collect::<Vec<_>>()
        );
        if let Some(previous) = previous {
            assert_eq!(previous.statement.end, statement.statement.start);
        }
        previous = Some(statement);
    }
}

#[test]
fn chunk_guest_execution_rejects_a_ratified_receipt_off_the_chain() {
    let witnesses = execution_fixture();
    let mut wrong_end = witnesses[2].clone();
    wrong_end.ratified[0].statement.end.history_root[0] ^= 1;
    let mut wrong_start = witnesses[2].clone();
    wrong_start.ratified[0].statement.start.state_root[0] ^= 1;
    let mut missing = witnesses[2].clone();
    missing.ratified.clear();
    let mut earlier = witnesses[2].clone();
    earlier.ratified.clone_from(&witnesses[1].ratified);
    let mut genesis_with_ratified = witnesses[0].clone();
    genesis_with_ratified
        .ratified
        .clone_from(&witnesses[1].ratified);
    for witness in [
        wrong_end,
        wrong_start,
        missing,
        earlier,
        genesis_with_ratified,
    ] {
        assert!(validate_consensus(&witness).is_err());
        assert!(execute_chunk_guest(&witness).is_none());
    }
}

#[test]
fn production_history_verification_rejects_mock_receipts() {
    let mock = ProverClient::builder().mock().build();
    let system = Sp1ProofSystem::new(mock.clone()).unwrap();
    // The trusted domain names the embedded fact program, so the fixture's
    // specification must carry the system's complete program set.
    let programs = system
        .programs()
        .unwrap()
        .with_runtime(neutrin0_runtime_host::embedded_runtime_code_hash());
    let (witness, _, _) = support::fixture_with_execution(
        programs,
        system.embedded_guests().chunk,
        support::credentials(8),
        vec![],
        30_000_000,
        30_000_000,
        &support::genesis_for(programs, 30_000_000),
        neutrin0_evm_runtime_core::execute_block,
    );
    let domain = system.history_domain(&witness.chain_spec).unwrap();
    let statement = receipt_statement(&witness);
    assert_eq!(statement.statement.chain, domain.chain);
    let key = mock
        .setup(neutrin0_runtime_host::CONSENSUS_CHUNK_GUEST_ELF.clone())
        .unwrap();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(borsh::to_vec(&witness).unwrap());
    stdin.write_vec(statement.chunk_prover_address.to_vec());
    let bundle = mock
        .prove(&key, stdin)
        .compressed()
        .deferred_proof_verification(false)
        .run()
        .unwrap();
    assert_eq!(
        bundle.public_values.as_slice(),
        borsh::to_vec(&statement).unwrap()
    );
    let proof = HistoryProof {
        statement,
        receipt: BoundedBytes::new(
            borsh::to_vec(&Sp1ChunkProof::from_sp1(&bundle).unwrap()).unwrap(),
        )
        .unwrap(),
    };
    assert_eq!(
        system.verify_history(&proof, &domain.chunk),
        Err(ProofError::BackendRejected)
    );
}

/// Advance an empty, one-block chunk, executing its block over `prior_state`
/// so the participation record it writes is reflected in every root.
#[allow(clippy::too_many_lines)]
fn empty_successor(
    first: &ConsensusWitness,
    prior_input: &neutrin0_runtime_abi::RuntimeBlockInput,
    prior_state: &LiveTrie,
) -> (
    ConsensusWitness,
    neutrin0_runtime_abi::RuntimeBlockInput,
    neutrin0_runtime_abi::StateWitness,
    LiveTrie,
) {
    use neutrin0_consensus_types::{FinalityVoteData, FinalityVotePhase};
    use neutrin0_crypto::bls::SecretKey;
    use neutrin0_primitives::DOMAIN_PROPOSER_SIG;
    assert_eq!(first.context.chunk_size, 1);
    assert_eq!(
        prior_input.transactions,
        [] as [neutrin0_runtime_abi::RuntimeTransaction; 0]
    );

    let validated = validate_consensus_with_context(first).unwrap();
    let mut next = first.clone();
    next.context = validated.next_context;
    next.seed = validated.statement.end.seed;
    // Design 08: the certificate ratifies the previous chunk's proof, which
    // this gate proves crediting the zero account.
    let ratified = neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
        statement: validated.statement.clone(),
        chunk_prover_address: [0; 32],
    };
    next.finality_cert.proposal.ratified_chunk_proofs =
        vec![neutrin0_consensus_types::bft::ChunkRatification {
            chunk_id: validated.statement.chunk.chunk_id,
            prover_address: ratified.chunk_prover_address,
            finality_cert_hash: ratified.statement.finality_cert_hash,
            statement_key: ratified.statement_key(),
        }];
    next.ratified = vec![ratified];
    let source = neutrin0_prover_chunk::history::HistoricalChunk {
        runtime_code_hash: first.context.programs.runtime_code_hash,
        block_guest_vk_digest: first.context.programs.execution.block,
        start_boundary: validated.statement.start.commitment(),
        chunk: as_chunk(&validated.statement.chunk),
        validators: first.context.active_validators.clone(),
        seed: first.seed,
        finality: first.finality_cert.clone(),
    };
    let leaf = neutrin0_consensus_types::evidence::commitment(&source.evidence_context());
    let path = next.history.frontier.append_path(leaf).unwrap();
    next.history.frontier.append(leaf).unwrap();
    next.history.records = vec![neutrin0_prover_chunk::history::HistoricalContextOpening {
        record: (&source).into(),
        path,
    }];
    let mut input = prior_input.clone();
    input.block_height = validated.statement.end.height + 1;
    input
        .active_validators
        .clone_from(&next.context.active_validators);
    input.evidence_anchor.chunk_id = next.context.chunk_id;
    input.evidence_anchor.history_root = next.context.history_root;
    // The next first block selects this exact valid previous certificate.
    input.participation =
        neutrin0_consensus_types::participation::ParticipationReport::from_certificate(
            validated.statement.chunk.chunk_id,
            &first.context.active_validators,
            &first.finality_cert.precommit.aggregation_bits,
        );
    // Design 08: the same carried certificate yields the proving report.
    input.proving = neutrin0_consensus_types::proving::ProvingReport::from_certificate(
        &source.chunk,
        &first.context.active_validators,
        &first.finality_cert.carried_certificate(),
    );
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let slot = first.blocks[0].header.slot + 1;
    input.context = neutrin0_consensus_types::runtime::ConsensusExecutionContext {
        slot,
        timestamp: next.chain_spec.genesis_time
            + next.chain_spec.consensus.slot_duration_secs * slot,
        parent_block_hash: validated.statement.end.block_hash,
        proposer_vrf_output: neutrin0_vrf::proof_output(
            &key.sign(&neutrin0_vrf::vrf_message(
                next.chain_spec.consensus_domain(),
                &next.seed,
                slot,
            ))
            .to_bytes(),
        ),
        finalized: validated.statement.end,
    };
    let mut tracing = TracingState::new(prior_state);
    let output = neutrin0_evm_runtime_core::apply_block(&input, &mut tracing);
    let (post_state, execution_witness) = tracing.into_committed_and_witness().unwrap();
    let post_live = LiveTrie::from_trie(post_state);
    assert_eq!(
        output.participation,
        input.participation.as_ref().unwrap().commitment(),
    );
    let body = neutrin0_consensus_types::Body {
        participation: Some(first.finality_cert.carried_certificate()),
        ..neutrin0_consensus_types::Body::default()
    };
    next.bodies = vec![neutrin0_prover_chunk::body::ConsensusBody::from_body(&body).unwrap()];
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let block = &mut next.blocks[0];
    block.output = output.clone();
    block.header.height = input.block_height;
    block.header.slot += 1;
    block.header.parent_hash = next.context.parent_block_hash;
    block.header.timestamp = next.chain_spec.genesis_time
        + next.chain_spec.consensus.slot_duration_secs * block.header.slot;
    block.header.state_root = output.post_state_root;
    block.header.transactions_root = output.transactions_root;
    block.header.receipts_root = output.receipts_root;
    block.header.gas_used = output.gas_used;
    block.header.runtime_extra = output.consensus_candidates_root;
    block.header.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
    block.header.da_root = neutrin0_prover_chunk::consensus::body_da_root(&body);
    block.header.vrf_proof = key
        .sign(&neutrin0_vrf::vrf_message(
            next.chain_spec.consensus_domain(),
            &next.seed,
            block.header.slot,
        ))
        .to_bytes();
    let message = next
        .chain_spec
        .consensus_domain()
        .signing_message(DOMAIN_PROPOSER_SIG, &block.header.hash());
    block.header.signature = key.sign(&message).to_bytes();
    block.public_inputs.context = input.context.into();
    block.public_inputs.height = input.block_height;
    block.public_inputs.parent_block_hash = block.header.parent_hash;
    block.public_inputs.block_hash = block.header.hash();
    block.public_inputs.state_root_before = output.pre_state_root;
    block.public_inputs.state_root_after = output.post_state_root;
    block.public_inputs.transactions_root = output.transactions_root;
    block.public_inputs.receipt_root = output.receipts_root;
    block.public_inputs.gas_used = output.gas_used;
    block.public_inputs.runtime_extra = output.consensus_candidates_root;
    block.public_inputs.inputs_root = neutrin0_prover_chunk::execution::output_inputs_root(&output);
    block.public_inputs.da_root = block.header.da_root;
    let mut trace = TracingState::new(&post_live);
    neutrin0_prover_chunk::rotation::witness_keys_from(&mut trace);
    next.post_state = trace.into_witness().unwrap();
    let chunk = as_chunk(&validate_candidate(&next).unwrap().execution.chunk);
    next.finality_cert.chunk_id = chunk.chunk_id;
    next.finality_cert.chunk_hash = chunk.hash();
    next.finality_cert.active_validator_set_root = chunk.active_validator_set_root;
    next.finality_cert.proposal.chunk = chunk.clone();
    // The proposal names this chunk's receipt at a slot no earlier than its
    // block (design 08).
    next.finality_cert.proposal.proposal_slot = next.blocks[0].header.slot;
    next.finality_cert.proposal.receipts = next
        .blocks
        .iter()
        .map(|block| neutrin0_consensus_types::bft::ReceiptChoice {
            prover_address: block.prover_address,
            statement_key: neutrin0_consensus_types::evidence::commitment(&block.statement()),
        })
        .collect();
    next.finality_cert.proposal.signature = key
        .sign(
            &next
                .finality_cert
                .proposal
                .signing_message(next.chain_spec.consensus_domain()),
        )
        .to_bytes();
    let selection = next.finality_cert.proposal.selection();
    for (phase, aggregate) in [
        (FinalityVotePhase::Prevote, &mut next.finality_cert.prevote),
        (
            FinalityVotePhase::Precommit,
            &mut next.finality_cert.precommit,
        ),
    ] {
        let data = FinalityVoteData {
            chunk_id: chunk.chunk_id,
            round: 0,
            chunk_hash: chunk.hash(),
            selection,
            phase,
        };
        let message = data.signing_message(next.chain_spec.consensus_domain());
        aggregate.signature = key.sign(&message).to_bytes();
    }
    let prevote = next.finality_cert.prevote_vote();
    // The precommit declares the lock this chunk's own prevote quorum created.
    let unlock = neutrin0_consensus_types::QuorumCertificate {
        data: prevote.data.clone(),
        aggregate: next.finality_cert.prevote.clone(),
    };
    let claim = &mut next.finality_cert.prevote_attestations[0];
    claim.vote = prevote.data;
    claim.vote_signature = prevote.signature;
    claim.signature = key
        .sign(&claim.signing_message(next.chain_spec.consensus_domain()))
        .to_bytes();
    let vote = next.finality_cert.precommit_vote();
    let manifest = neutrin0_consensus_types::ProofManifest {
        proof_hashes: vec![[1; 32]],
    };
    next.finality_cert.proof_manifests = vec![manifest.clone()];
    let claim = &mut next.finality_cert.precommit_attestations[0];
    claim.vote = vote.data;
    claim.vote_signature = vote.signature;
    claim.proof_acceptance = Some(manifest.commitment());
    claim.unlock_quorum = Some(unlock);
    claim.signature = key
        .sign(&claim.signing_message(next.chain_spec.consensus_domain()))
        .to_bytes();
    (next, input, execution_witness, post_live)
}

fn cached_stage<T: BorshDeserialize + BorshSerialize>(
    cache: &acceptance::AcceptanceCache,
    identity: &acceptance::StageIdentity,
    verify: impl Fn(&T) -> Result<(), ProofError>,
    prove: impl FnOnce() -> Result<T, ProofError>,
) -> T {
    let bytes = cache
        .prove_or_resume(
            identity,
            |bytes| {
                let proof: T = borsh::from_slice(bytes).map_err(|_| ProofError::MalformedProof)?;
                verify(&proof)
            },
            || borsh::to_vec(&prove()?).map_err(|_| ProofError::MalformedProof),
        )
        .unwrap();
    borsh::from_slice(&bytes).unwrap()
}

#[allow(clippy::too_many_lines)]
fn real_pipeline<P: ProgramProver>(prover: P) {
    let challenge_prover = prover.clone();
    let system = Sp1ProofSystem::new(prover).unwrap();
    let verifier = Sp1ProofSystem::new(ProverClient::builder().light().build()).unwrap();
    let directory = std::env::var_os("NEUTRIN0_HISTORY_GATE_DIR").map_or_else(
        || {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/proof-acceptance/history")
        },
        std::path::PathBuf::from,
    );
    let cache = acceptance::AcceptanceCache::new(directory).unwrap();
    let programs = system
        .programs()
        .unwrap()
        .with_runtime(neutrin0_runtime_host::embedded_runtime_code_hash());
    let genesis = support::genesis_for(programs, 30_000_000);
    let (mut witness, mut input, mut state) = support::fixture_with_execution(
        programs,
        system.programs().unwrap().chunk,
        support::credentials(8),
        vec![],
        30_000_000,
        30_000_000,
        &genesis,
        neutrin0_evm_runtime_core::execute_block,
    );
    // Each successor continues from the previous block's post-state.
    let mut live = support::executed(&genesis, &input);
    let spec = witness.chain_spec.clone();
    let mut chunks: Vec<Sp1ChunkProof> = Vec::new();
    let mut statements = Vec::new();
    let mut challenge = None;
    for _ in 0..3 {
        let block_input =
            neutrin0_runtime_host::encode_witness_bundle(&input, &state, &[]).unwrap();
        let inputs = &witness.blocks[0].public_inputs;
        let identity = acceptance::StageIdentity::new(
            "history-block",
            &neutrin0_runtime_host::EVM_GUEST_ELF,
            &block_input,
            &borsh::to_vec(inputs).unwrap(),
        );
        let block: Sp1BlockProof = cached_stage(
            &cache,
            &identity,
            |proof| verifier.verify_block(proof, inputs),
            || system.prove_block(&block_input, inputs, inputs.proposer_address),
        );
        let manifest = neutrin0_consensus_types::ProofManifest {
            proof_hashes: vec![neutrin0_consensus_types::evidence::commitment(
                &neutrin0_consensus_types::BlockProof {
                    prover_address: inputs.proposer_address,
                    statement_key: [0; 32],
                    height: inputs.height,
                    block_hash: inputs.block_hash,
                    public_inputs: inputs.clone(),
                    proof_bytes: borsh::to_vec(&block).unwrap(),
                },
            )],
        };
        witness.finality_cert.proof_manifests = vec![manifest.clone()];
        let claim = &mut witness.finality_cert.precommit_attestations[0];
        claim.proof_acceptance = Some(manifest.commitment());
        claim.signature = neutrin0_crypto::bls::SecretKey::key_gen(&[42; 32], &[])
            .unwrap()
            .sign(&claim.signing_message(spec.consensus_domain()))
            .to_bytes();
        let expected = receipt_statement(&witness);
        // The previous chunk's proof, which this chunk's certificate ratifies.
        let ratified: Vec<Sp1ChunkProof> = chunks.last().cloned().into_iter().collect();
        let identity = acceptance::StageIdentity::new(
            "history-chunk",
            &neutrin0_runtime_host::CONSENSUS_CHUNK_GUEST_ELF,
            &borsh::to_vec(&(&witness, &block)).unwrap(),
            &borsh::to_vec(&expected).unwrap(),
        );
        let chunk: Sp1ChunkProof = cached_stage(
            &cache,
            &identity,
            |proof| verifier.verify_consensus_chunk(proof, &expected),
            || {
                system.prove_consensus_chunk(
                    std::slice::from_ref(&block),
                    &ratified,
                    &witness,
                    [0; 32],
                )
            },
        );
        if let Some(previous) = ratified.first() {
            challenge.get_or_insert_with(|| (witness.clone(), block, previous.clone()));
        }
        chunks.push(chunk);
        statements.push(expected);
        (witness, input, state, live) = empty_successor(&witness, &input, &live);
    }
    // The latest receipt alone is the History proof of the whole chain.
    assert_eq!(
        statements[0].statement.start,
        ConsensusBoundary::genesis(&spec)
    );
    let history = |index: usize| HistoryProof {
        statement: statements[index].clone(),
        receipt: BoundedBytes::new(borsh::to_vec(&chunks[index]).unwrap()).unwrap(),
    };
    let latest = history(2);
    let authenticated = verify_history_proof(&verifier, &spec, latest.clone()).unwrap();
    assert_eq!(authenticated.proof().end().next_chunk_id, 3);
    // A receipt never selects its own key and never vouches for other values.
    let chunk = verifier.history_domain(&spec).unwrap().chunk;
    let mut wrong = latest.clone();
    wrong.statement.statement.end.state_root[0] ^= 1;
    assert!(verifier.verify_history(&wrong, &chunk).is_err());
    let mut wrong = latest.clone();
    wrong.statement.chunk_prover_address[0] ^= 1;
    assert!(verifier.verify_history(&wrong, &chunk).is_err());
    let mut wrong_chunk = chunk;
    wrong_chunk[0] ^= 1;
    assert!(verifier.verify_history(&latest, &wrong_chunk).is_err());
    let mut earlier = history(1);
    earlier.statement = latest.statement;
    assert!(verifier.verify_history(&earlier, &chunk).is_err());
    let (witness, block, previous) = challenge.unwrap();
    reject_false_ratified_receipts(&challenge_prover, &witness, &block, &previous);
}

/// Only real compression authenticates the ratified receipt a chunk verifies,
/// and every later History proof rests on it: a missing receipt, another
/// program's receipt in its place or a duplicated one must not prove.
fn reject_false_ratified_receipts<P: ProgramProver>(
    prover: &P,
    witness: &ConsensusWitness,
    block: &Sp1BlockProof,
    previous: &Sp1ChunkProof,
) {
    let chunk_key = prover
        .setup_program(neutrin0_runtime_host::CONSENSUS_CHUNK_GUEST_ELF.clone())
        .unwrap();
    let block_key = prover
        .setup_program(neutrin0_runtime_host::EVM_GUEST_ELF.clone())
        .unwrap();
    let SP1Proof::Compressed(block_receipt) = block.to_sp1().unwrap().proof else {
        panic!("compressed block")
    };
    let SP1Proof::Compressed(previous_receipt) = previous.to_sp1().unwrap().proof else {
        panic!("compressed chunk")
    };
    for attack in 0..3 {
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(borsh::to_vec(witness).unwrap());
        stdin.write_vec(vec![0; 32]);
        stdin.write_proof(*block_receipt.clone(), block_key.verifying_key().vk.clone());
        match attack {
            0 => {}
            // Deferred digests take each proof's own program key from its
            // public values, never the label it is written with: another
            // program's receipt labelled as a chunk receipt cannot stand in
            // for the ratified one.
            1 => stdin.write_proof(*block_receipt.clone(), chunk_key.verifying_key().vk.clone()),
            _ => {
                for _ in 0..2 {
                    stdin.write_proof(
                        *previous_receipt.clone(),
                        chunk_key.verifying_key().vk.clone(),
                    );
                }
            }
        }
        assert!(
            prover
                .prove(&chunk_key, stdin)
                .deferred_proof_verification(true)
                .compressed()
                .run()
                .is_err(),
            "compressed recursion accepted a missing, misattributed or extra ratified receipt ({attack})"
        );
    }
}

#[test]
#[ignore = "real compressed Block/Chunk recursion requires a suitable prover"]
fn history_real_compressed_chunk_recursion() {
    real_pipeline(ProverClient::builder().cpu().build());
}

#[cfg(feature = "cuda")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Linux x86-64 NVIDIA CUDA proving hardware"]
async fn history_cuda_compressed_chunk_recursion() {
    let device = std::env::var("NEUTRIN0_CUDA_DEVICE")
        .map_or(Ok(0), |value| value.parse::<u32>())
        .unwrap();
    tokio::task::spawn_blocking(move || {
        real_pipeline(neutrin0_runtime_host::backend::cuda_prover(device).unwrap());
    })
    .await
    .unwrap();
}
