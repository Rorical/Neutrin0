//! Consensus Guest integration with an explicit CUDA proving gate.
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use neutrin0_crypto::bls::SecretKey;
use neutrin0_proof_system::ProofSystem;
use neutrin0_prover_chunk::consensus::validate_consensus;
use neutrin0_runtime_host::Sp1ProofSystem;
use sp1_sdk::blocking::{Prover, ProverClient};

#[allow(
    clippy::too_many_lines,
    reason = "Executes and signs two complete blocks of one recursion fixture."
)]
fn two_block_fixture(
    programs: neutrin0_primitives::ProgramSet,
    chunk_program: neutrin0_consensus_types::history_proof::VkDigest,
) -> (
    neutrin0_prover_chunk::consensus::ConsensusWitness,
    Vec<(
        neutrin0_runtime_abi::RuntimeBlockInput,
        neutrin0_runtime_abi::StateWitness,
    )>,
) {
    use neutrin0_consensus_types::Body;
    use neutrin0_consensus_types::{FinalityVoteData, FinalityVotePhase};
    use neutrin0_prover_chunk::body::ConsensusBody;
    use neutrin0_prover_chunk::consensus::{as_chunk, validate_candidate};
    use neutrin0_runtime_core::host::{LiveTrie, TracingState};
    // Ordinary transactions are present in the block proofs but absent from
    // the compact chunk witness: eight signed transfers per block.
    let genesis = support::genesis_for(programs, 30_000_000);
    let (mut witness, mut input, _) = support::fixture_with_execution(
        programs,
        chunk_program,
        support::credentials(8),
        (0..8).map(support::transfer).collect(),
        30_000_000,
        30_000_000,
        &genesis,
        neutrin0_evm_runtime_core::execute_block,
    );
    witness.chain_spec.consensus.chunk_size = 2;
    witness.context.chunk_size = 2;
    witness.context.chain_spec_hash = witness.chain_spec.hash();
    input.evidence_anchor.chain_spec_hash = witness.chain_spec.hash();
    input.evidence_anchor.chunk_size = 2;
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let domain = witness.chain_spec.consensus_domain();
    let body_of = |input: &neutrin0_runtime_abi::RuntimeBlockInput,
                   artifacts: neutrin0_runtime_abi::ExecutionArtifacts| Body {
        artifacts,
        transactions: input
            .transactions
            .iter()
            .map(|tx| borsh::to_vec(tx).unwrap())
            .collect(),
        ..Body::default()
    };
    // The changed specification changes the VRF domain, so the first block
    // is re-executed under its exact authenticated context.
    let first = &mut witness.blocks[0];
    first.header.vrf_proof = key
        .sign(&neutrin0_vrf::vrf_message(
            domain,
            &witness.seed,
            first.header.slot,
        ))
        .to_bytes();
    input.context = neutrin0_prover_chunk::execution::runtime_context(
        &first.header,
        neutrin0_consensus_types::history_proof::ConsensusBoundary::genesis(&witness.chain_spec),
    );
    let mut trace = TracingState::new(&genesis);
    let result = neutrin0_evm_runtime_core::execute_block(&input, &mut trace);
    let (post, state) = trace.into_committed_and_witness().unwrap();
    let body = body_of(&input, result.artifacts);
    support::bind_executed_block(
        first,
        &input,
        result.output,
        &body,
        &key,
        &witness.chain_spec,
    );
    witness.bodies = vec![ConsensusBody::from_body(&body).unwrap()];
    let post = LiveTrie::from_trie(post);
    // The second block continues from the first block's state with fresh
    // nonces.
    let mut second_input = input.clone();
    second_input.block_height = 2;
    second_input.transactions = (8..16).map(support::transfer).collect();
    let mut second = witness.blocks[0].clone();
    second.header.height = 2;
    second.header.slot = 2;
    second.header.timestamp = witness.chain_spec.consensus.slot_duration_secs * 2;
    second.header.parent_hash = witness.blocks[0].header.hash();
    second.header.vrf_proof = key
        .sign(&neutrin0_vrf::vrf_message(domain, &witness.seed, 2))
        .to_bytes();
    second_input.context = neutrin0_prover_chunk::execution::runtime_context(
        &second.header,
        neutrin0_consensus_types::history_proof::ConsensusBoundary::genesis(&witness.chain_spec),
    );
    let mut trace = TracingState::new(&post);
    let result = neutrin0_evm_runtime_core::execute_block(&second_input, &mut trace);
    let (committed, second_state) = trace.into_committed_and_witness().unwrap();
    let body = body_of(&second_input, result.artifacts);
    support::bind_executed_block(
        &mut second,
        &second_input,
        result.output,
        &body,
        &key,
        &witness.chain_spec,
    );
    witness.blocks.push(second);
    witness
        .bodies
        .push(ConsensusBody::from_body(&body).unwrap());
    // The candidate's post-state witness opens the rotation records of the
    // chunk-end state, which the second block moved.
    let post_second = LiveTrie::from_trie(committed);
    let mut rotation = TracingState::new(&post_second);
    neutrin0_prover_chunk::rotation::witness_keys_from(&mut rotation);
    witness.post_state = rotation.into_witness().unwrap();
    let chunk = as_chunk(&validate_candidate(&witness).unwrap().execution.chunk);
    witness.finality_cert.chunk_hash = chunk.hash();
    witness.finality_cert.proposal.chunk = chunk.clone();
    // The proposal names each block's receipt and signs a slot no earlier
    // than the range's last block (design 08).
    witness.finality_cert.proposal.proposal_slot = 2;
    witness.finality_cert.proposal.receipts = witness
        .blocks
        .iter()
        .map(|block| neutrin0_consensus_types::bft::ReceiptChoice {
            prover_address: block.prover_address,
            statement_key: neutrin0_consensus_types::evidence::commitment(&block.statement()),
        })
        .collect();
    witness.finality_cert.proposal.signature = key
        .sign(&witness.finality_cert.proposal.signing_message(domain))
        .to_bytes();
    let selection = witness.finality_cert.proposal.selection();
    for (phase, aggregate) in [
        (
            FinalityVotePhase::Prevote,
            &mut witness.finality_cert.prevote,
        ),
        (
            FinalityVotePhase::Precommit,
            &mut witness.finality_cert.precommit,
        ),
    ] {
        let vote = FinalityVoteData {
            chunk_id: 0,
            round: 0,
            chunk_hash: chunk.hash(),
            selection,
            phase,
        };
        let message = vote.signing_message(domain);
        aggregate.signature = key.sign(&message).to_bytes();
    }
    let count = usize::try_from(witness.context.chunk_size).unwrap();
    sign_fixture_attestations(&mut witness.finality_cert, &key, count, domain);
    (witness, vec![(input, state), (second_input, second_state)])
}

fn sign_fixture_attestations(
    certificate: &mut neutrin0_consensus_types::FinalityCert,
    key: &SecretKey,
    block_count: usize,
    domain: neutrin0_primitives::ConsensusDomain,
) {
    let prevote = certificate.prevote_vote();
    let claim = &mut certificate.prevote_attestations[0];
    claim.vote = prevote.data.clone();
    claim.vote_signature = prevote.signature;
    claim.signature = key.sign(&claim.signing_message(domain)).to_bytes();
    let precommit = certificate.precommit_vote();
    let manifest = neutrin0_consensus_types::ProofManifest {
        proof_hashes: vec![[1; 32]; block_count],
    };
    certificate.proof_manifests = vec![manifest.clone()];
    // The precommit declares the lock the refreshed prevote quorum created.
    let unlock = neutrin0_consensus_types::QuorumCertificate {
        data: prevote.data,
        aggregate: certificate.prevote.clone(),
    };
    let claim = &mut certificate.precommit_attestations[0];
    claim.vote = precommit.data;
    claim.vote_signature = precommit.signature;
    claim.proof_acceptance = Some(manifest.commitment());
    claim.unlock_quorum = Some(unlock);
    claim.signature = key.sign(&claim.signing_message(domain)).to_bytes();
}

#[allow(clippy::too_many_lines)] // Explicit end-to-end proving stages and their negative assertions.
fn pipeline<P: neutrin0_runtime_host::ProgramProver>(prover: P, real: bool) {
    eprintln!("consensus gate: initialize block program");
    let system = Sp1ProofSystem::new(prover).unwrap();
    let runtime_hash = neutrin0_runtime_host::embedded_runtime_code_hash();
    let (mut witness, inputs) = two_block_fixture(
        system.programs().unwrap().with_runtime(runtime_hash),
        system.embedded_guests().chunk,
    );
    let blocks: Vec<_> = inputs
        .into_iter()
        .zip(&witness.blocks)
        .map(|((input, state), block)| {
            eprintln!("consensus gate: prove block {}", block.header.height);
            system
                .prove_block(
                    &neutrin0_runtime_host::encode_witness_bundle(&input, &state, &[]).unwrap(),
                    &block.public_inputs,
                    block.prover_address,
                )
                .unwrap()
        })
        .collect();
    let hashes = blocks
        .iter()
        .zip(&witness.blocks)
        .map(|(proof, block)| {
            neutrin0_consensus_types::evidence::commitment(&neutrin0_consensus_types::BlockProof {
                prover_address: block.prover_address,
                statement_key: neutrin0_consensus_types::evidence::commitment(&block.statement()),
                height: block.header.height,
                block_hash: block.header.hash(),
                public_inputs: block.public_inputs.clone(),
                proof_bytes: borsh::to_vec(proof).unwrap(),
            })
        })
        .collect();
    let manifest = neutrin0_consensus_types::ProofManifest {
        proof_hashes: hashes,
    };
    witness.finality_cert.proof_manifests = vec![manifest.clone()];
    let claim = &mut witness.finality_cert.precommit_attestations[0];
    claim.proof_acceptance = Some(manifest.commitment());
    claim.signature = neutrin0_crypto::bls::SecretKey::key_gen(&[42; 32], &[])
        .unwrap()
        .sign(&claim.signing_message(witness.chain_spec.consensus_domain()))
        .to_bytes();
    let expected = validate_consensus(&witness).unwrap();
    assert!(
        system
            .prove_consensus_chunk(&blocks[..1], &[], &witness, [0; 32])
            .is_err()
    );
    let mut reordered = blocks.clone();
    reordered.reverse();
    assert!(
        system
            .prove_consensus_chunk(&reordered, &[], &witness, [0; 32])
            .is_err()
    );
    if real {
        check_rejection_classifier(&system, &blocks[0], &witness.blocks[0]);
    }
    eprintln!("consensus gate: prove consensus chunk");
    let proof = if real {
        system
            .prove_consensus_chunk(&blocks, &[], &witness, [0; 32])
            .unwrap()
    } else {
        // Mock artifacts cannot satisfy recursive verification. Disable it only
        // in this execution-only test; the production adapter always verifies.
        use sp1_sdk::{SP1Proof, SP1Stdin, blocking::ProveRequest};
        let mock = ProverClient::builder().mock().build();
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(borsh::to_vec(&witness).unwrap());
        stdin.write_vec([0_u8; 32].to_vec());
        for block in blocks {
            let SP1Proof::Compressed(inner) = block.to_sp1().unwrap().proof else {
                panic!("compressed")
            };
            stdin.write_proof(*inner, system.verifying_key().vk.clone());
        }
        if std::env::var_os("NEUTRIN0_REPORT_GUEST_CYCLES").is_some() {
            let (_, report) = mock
                .execute(
                    neutrin0_runtime_host::CONSENSUS_CHUNK_GUEST_ELF.clone(),
                    stdin.clone(),
                )
                .deferred_proof_verification(false)
                .run()
                .unwrap();
            assert_eq!(report.exit_code, 0);
            eprintln!(
                "consensus guest instructions: {}",
                report.total_instruction_count()
            );
            eprintln!("consensus guest syscalls: {:?}", report.syscall_counts);
        }
        check_guest_rejections(&mock, &witness, &stdin);
        let pk = mock
            .setup(neutrin0_runtime_host::CONSENSUS_CHUNK_GUEST_ELF.clone())
            .unwrap();
        let proof = mock
            .prove(&pk, stdin)
            .compressed()
            .deferred_proof_verification(false)
            .run()
            .unwrap();
        neutrin0_runtime_host::proof_system::Sp1ChunkProof::from_sp1(&proof).unwrap()
    };
    eprintln!("consensus gate: verify consensus chunk and negative bindings");
    system
        .verify_consensus_chunk(
            &proof,
            &neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
                statement: expected.clone(),
                chunk_prover_address: [0; 32],
            },
        )
        .unwrap();
    if real {
        let verifier = Sp1ProofSystem::new(ProverClient::builder().light().build()).unwrap();
        verifier
            .verify_consensus_chunk(
                &proof,
                &neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
                    statement: expected.clone(),
                    chunk_prover_address: [0; 32],
                },
            )
            .unwrap();
    }
    // The cached verdict answers again, and binds only that statement.
    system
        .verify_consensus_chunk(
            &proof,
            &neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
                statement: expected.clone(),
                chunk_prover_address: [0; 32],
            },
        )
        .unwrap();
    let mut wrong_anchor = expected.clone();
    wrong_anchor.start.state_root[0] ^= 1;
    assert!(
        system
            .verify_consensus_chunk(
                &proof,
                &neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
                    statement: wrong_anchor,
                    chunk_prover_address: [0; 32],
                }
            )
            .is_err()
    );
    let mut wrong_chain = expected;
    wrong_chain.chain.chain_spec_hash[0] ^= 1;
    assert!(
        system
            .verify_consensus_chunk(
                &proof,
                &neutrin0_consensus_types::history_proof::ChunkReceiptStatement {
                    statement: wrong_chain,
                    chunk_prover_address: [0; 32],
                }
            )
            .is_err()
    );
}

fn check_guest_rejections<P: Prover>(
    prover: &P,
    witness: &neutrin0_prover_chunk::consensus::ConsensusWitness,
    stdin: &sp1_sdk::SP1Stdin,
) {
    // Exercise the accelerated Guest's rejection paths, including a valid
    // curve point signing the wrong message and an identity aggregate.
    let mut wrong_signature = witness.clone();
    wrong_signature.blocks[0].header.signature = witness.blocks[1].header.signature;
    let mut wrong_da = witness.clone();
    wrong_da.blocks[0]
        .output
        .transaction_summary
        .transaction_count ^= 1;
    let mut identity_vote = witness.clone();
    identity_vote.finality_cert.precommit.signature = [0; 96];
    identity_vote.finality_cert.precommit.signature[0] = 0xc0;
    let mut missing_attestation = witness.clone();
    missing_attestation
        .finality_cert
        .precommit_attestations
        .clear();
    let mut missing_prevote = witness.clone();
    missing_prevote.finality_cert.prevote_attestations.clear();
    let mut circular_unlock = witness.clone();
    let certificate = &mut circular_unlock.finality_cert;
    let claim = &mut certificate.prevote_attestations[0];
    claim.unlock_quorum = Some(neutrin0_consensus_types::QuorumCertificate {
        data: claim.vote.clone(),
        aggregate: certificate.prevote.clone(),
    });
    let key = SecretKey::key_gen(&[42; 32], &[]).unwrap();
    claim.signature = key
        .sign(&claim.signing_message(witness.chain_spec.consensus_domain()))
        .to_bytes();
    let mut other_spec = witness.chain_spec.clone();
    other_spec.genesis_time += 1;
    assert_eq!(other_spec.chain_id, witness.chain_spec.chain_id);
    assert_ne!(other_spec.hash(), witness.chain_spec.hash());
    let foreign_domain = other_spec.consensus_domain();
    let mut foreign_proposal = witness.clone();
    foreign_proposal.finality_cert.proposal.signature = key
        .sign(
            &foreign_proposal
                .finality_cert
                .proposal
                .signing_message(foreign_domain),
        )
        .to_bytes();
    let mut foreign_header = witness.clone();
    foreign_header.blocks[0].header.signature = key
        .sign(&foreign_domain.signing_message(
            neutrin0_primitives::DOMAIN_PROPOSER_SIG,
            &foreign_header.blocks[0].header.hash(),
        ))
        .to_bytes();
    let mut bad_individual = witness.clone();
    bad_individual.finality_cert.precommit_attestations[0].vote_signature[0] ^= 1;
    let mut incomplete_proofs = witness.clone();
    incomplete_proofs.finality_cert.proof_manifests[0]
        .proof_hashes
        .pop();
    for invalid in [
        Box::new(missing_attestation),
        Box::new(missing_prevote),
        Box::new(circular_unlock),
        Box::new(bad_individual),
        Box::new(incomplete_proofs),
        Box::new(wrong_signature),
        Box::new(identity_vote),
        Box::new(wrong_da),
        Box::new(foreign_proposal),
        Box::new(foreign_header),
    ] {
        assert!(validate_consensus(&invalid).is_err());
        let mut invalid_stdin = stdin.clone();
        invalid_stdin.buffer[0] = borsh::to_vec(&invalid).unwrap();
        let (output, report) = prover
            .execute(
                neutrin0_runtime_host::CONSENSUS_CHUNK_GUEST_ELF.clone(),
                invalid_stdin,
            )
            .deferred_proof_verification(false)
            .run()
            .unwrap();
        assert_ne!(report.exit_code, 0);
        assert_eq!(output.as_slice(), [] as [u8; 0]);
    }
}

fn check_rejection_classifier<P: neutrin0_runtime_host::ProgramProver>(
    system: &Sp1ProofSystem<P>,
    proof: &neutrin0_runtime_host::proof_system::Sp1BlockProof,
    block: &neutrin0_prover_chunk::execution::ProvenBlock,
) {
    use neutrin0_consensus_types::ProofRejectionReason;
    eprintln!("consensus gate: verify exact proof rejection classifier");
    let envelope = neutrin0_consensus_types::BlockProof {
        prover_address: block.public_inputs.proposer_address,
        statement_key: [0; 32],
        height: block.header.height,
        block_hash: block.header.hash(),
        public_inputs: block.public_inputs.clone(),
        proof_bytes: borsh::to_vec(proof).unwrap(),
    };
    let program = block.public_inputs.block_program;
    assert_eq!(
        system.classify_block_rejection(&envelope, &program),
        Ok(None)
    );
    // A signer naming its own program never selects the verifier's key.
    let mut foreign = envelope.clone();
    foreign.public_inputs.block_program[0] ^= 1;
    assert_eq!(
        system.classify_block_rejection(&foreign, &program),
        Ok(Some(ProofRejectionReason::PublicInputsMismatch))
    );
    // The compact summary is part of the exact authenticated public values,
    // even though it is not copied into the wire BlockProofPublicInputs.
    let mut forged_summary = proof.to_sp1().unwrap();
    let mut statement = block.statement();
    statement.output.transaction_summary.transaction_count ^= 1;
    forged_summary.public_values =
        sp1_sdk::SP1PublicValues::from(&borsh::to_vec(&statement).unwrap());
    let mut forged_envelope = envelope.clone();
    forged_envelope.proof_bytes = borsh::to_vec(
        &neutrin0_runtime_host::proof_system::Sp1BlockProof::from_sp1(&forged_summary).unwrap(),
    )
    .unwrap();
    assert_eq!(
        system.classify_block_rejection(&forged_envelope, &program),
        Ok(Some(ProofRejectionReason::VerifierRejected))
    );
    let mut bad = envelope;
    bad.public_inputs.state_root_after[0] ^= 1;
    assert_eq!(
        system.classify_block_rejection(&bad, &program),
        Ok(Some(ProofRejectionReason::PublicInputsMismatch))
    );
    // Make the envelope and decoded public output agree again, while retaining
    // the original cryptographic proof. Only proof verification catches this.
    let mut bundle = proof.to_sp1().unwrap();
    let mut statement = block.statement();
    statement.output.post_state_root = bad.public_inputs.state_root_after;
    bundle.public_values = sp1_sdk::SP1PublicValues::from(&borsh::to_vec(&statement).unwrap());
    bad.proof_bytes = borsh::to_vec(
        &neutrin0_runtime_host::proof_system::Sp1BlockProof::from_sp1(&bundle).unwrap(),
    )
    .unwrap();
    assert_eq!(
        system.classify_block_rejection(&bad, &program),
        Ok(Some(ProofRejectionReason::VerifierRejected))
    );
}

#[test]
fn consensus_guest_execution_and_public_bindings_mock() {
    pipeline(ProverClient::builder().mock().build(), false);
}

#[cfg(feature = "cuda")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Linux x86-64 and an NVIDIA GPU; real compressed CUDA proving"]
async fn consensus_guest_cuda_compressed_recursion() {
    let device = std::env::var("NEUTRIN0_CUDA_DEVICE")
        .map_or(Ok(0), |value| value.parse::<u32>())
        .unwrap();
    tokio::task::spawn_blocking(move || {
        pipeline(
            neutrin0_runtime_host::backend::cuda_prover(device).unwrap(),
            true,
        );
    })
    .await
    .unwrap();
}

#[test]
fn pinned_portable_verifier_matches_sdk_circuit_version() {
    assert_eq!(
        neutrin0_prover_chunk::proof_verification::CIRCUIT_VERSION,
        sp1_sdk::SP1_CIRCUIT_VERSION
    );
}

#[test]
fn host_bundle_decoder_rejects_trailing_bytes_like_the_guest_classifier() {
    use neutrin0_runtime_host::proof_system::{Sp1BlockProof, Sp1ChunkProof};
    let bundle = sp1_sdk::SP1ProofWithPublicValues {
        proof: sp1_sdk::SP1Proof::Core(vec![]),
        public_values: sp1_sdk::SP1PublicValues::new(),
        sp1_version: sp1_sdk::SP1_CIRCUIT_VERSION.to_owned(),
        tee_proof: None,
    };
    let mut block = Sp1BlockProof::from_sp1(&bundle).unwrap();
    let mut chunk = Sp1ChunkProof::from_sp1(&bundle).unwrap();
    assert!(block.to_sp1().is_ok());
    assert!(chunk.to_sp1().is_ok());
    block.bytes.push(0);
    chunk.bytes.push(0);
    assert!(block.to_sp1().is_err());
    assert!(chunk.to_sp1().is_err());
}
