//! Full native composition, including actual STF execution and signed finality.
pub mod support;
use neutrin0_prover_chunk::consensus::{ConsensusError, validate_consensus};

#[test]
fn an_omitted_genuine_precommit_is_authenticated_as_positive_participation() {
    use neutrin0_consensus_types::FinalityVote;
    use neutrin0_consensus_types::participation::acknowledgement_commitment;
    use neutrin0_crypto::bls::SecretKey;
    use neutrin0_primitives::BitVec;
    let keys: Vec<_> = (1..=4)
        .map(|tag| SecretKey::key_gen(&[tag; 32], &[]).unwrap())
        .collect();
    let (mut first, input, _, post) = support::fixture_with_validator_keys([1; 8], [4; 32], &keys);
    let complete = support::certificate_with_precommitters(&first, &keys, &[0, 1, 2, 3]);
    first.finality_cert = support::certificate_with_precommitters(&first, &keys, &[0, 1, 2]);
    let claim = complete.precommit_attestations[3].clone();
    let vote = FinalityVote {
        proof_manifests: complete.proof_manifests,
        data: claim.vote.clone(),
        signature: claim.vote_signature,
        aggregation_bits: BitVec::from_bytes(4, vec![0b1000]).unwrap(),
        attestations: vec![claim],
    };
    let (next, runtime, _, _) = support::successor_with_participation_and_votes(
        &first,
        &input,
        &post,
        &keys,
        first.finality_cert.carried_certificate(),
        &[vote],
    );
    assert_eq!(runtime.participation_acks.len(), 1);
    assert_eq!(
        runtime.participation_acks[0].identity,
        keys[3].public_key().to_bytes()
    );
    assert_eq!(
        next.blocks[0].output.participation_acks,
        acknowledgement_commitment(&runtime.participation_acks)
    );
    validate_consensus(&next).unwrap();
    // A seat acknowledged twice adds nothing but a signature to verify. The
    // resealed lane commits the same acknowledgements, so only the seat rule
    // refuses it.
    let mut repeated = next.clone();
    let repeat = repeated.bodies[0].participation_acks[0].clone();
    repeated.bodies[0].participation_acks.push(repeat);
    reseal_selected_body(&mut repeated, 0, &keys[0]);
    assert_eq!(
        neutrin0_prover_chunk::consensus::validate_candidate(&repeated),
        Err(ConsensusError::Context)
    );
    // The header's inputs root binds the acknowledgements (design 08), so
    // the execution binding refuses the forged output first.
    let mut forged = next.clone();
    forged.blocks[0].output.participation_acks[0] ^= 1;
    assert_eq!(validate_consensus(&forged), Err(ConsensusError::Execution));
    let mut forged = next;
    forged.bodies[0].participation_acks[0].vote_signature[0] ^= 1;
    assert!(validate_consensus(&forged).is_err());
}

#[test]
fn a_block_under_any_gas_limit_but_the_chains_is_refused() {
    // Header, proof inputs and execution all agree on a raised limit; only
    // the chain specification refuses it.
    let (input, _, _) = support::fixture_with_block_gas_limit(
        [1; 8],
        [4; 32],
        vec![],
        30_000_000,
        u64::MAX,
        &support::fixture_genesis_live([1; 8], [4; 32], 30_000_000),
    );
    assert_eq!(validate_consensus(&input), Err(ConsensusError::Header));
}

#[test]
fn a_header_timestamp_off_its_slot_start_is_refused() {
    // Chain time is the slot schedule: even one second off is refused, so no
    // proposer can move time forward and stall the producers after it. The
    // execution binding already covers the header, so either check refuses.
    let (mut input, _, _) = support::fixture([1; 8], [4; 32]);
    validate_consensus(&input).unwrap();
    input.blocks[0].header.timestamp += 1;
    assert!(validate_consensus(&input).is_err());
}

#[test]
fn voters_refuse_a_candidate_the_guest_could_not_accept() {
    use neutrin0_prover_chunk::consensus::{MAX_CHUNK_WITNESS_BYTES, provable_candidate};
    let (mut input, _, _) = support::fixture([1; 8], [4; 32]);
    assert!(provable_candidate(&input));
    // Inflate the candidate past the Guest's input bound, less the room the
    // certificate and fact statements still need.
    let descriptor = neutrin0_consensus_types::ProgramPieceDescriptor {
        root: [0; 32],
        total_len: 1,
        offset: 0,
        bytes_hash: [0; 32],
        opening: neutrin0_consensus_types::evidence::MerkleOpening {
            index: 0,
            count: 1,
            siblings: Vec::new(),
        },
    };
    input.bodies[0].program_pieces = vec![descriptor; MAX_CHUNK_WITNESS_BYTES / 64];
    assert!(!provable_candidate(&input));
}

#[test]
fn voters_refuse_a_candidate_whose_successor_the_guest_cannot_derive() {
    use neutrin0_prover_chunk::consensus::validate_candidate;
    let (mut input, _, _) = support::fixture([1; 8], [4; 32]);
    validate_candidate(&input).unwrap();
    // Only the successor derivation reads the upgrade key; without it the
    // candidate could be certified and never proven.
    input
        .post_state
        .witnessed_keys
        .retain(|key| key != neutrin0_consensus_types::runtime::UPGRADE_KEY);
    assert_eq!(validate_candidate(&input), Err(ConsensusError::Rotation));
}

#[test]
fn composes_executed_block_proposer_rotation_and_both_finality_phases() {
    use sha2::{Digest, Sha256};

    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let statement = validate_consensus(&input).unwrap();
    assert_eq!(statement.chunk.chunk_id, 0);
    assert_ne!(statement.end.seed, statement.start.seed);
    let full = neutrin0_prover_chunk::consensus::validate_consensus_with_context(&input).unwrap();
    assert_eq!(full.statement, statement);
    // The public boundary and resumed execution context must use the exact
    // finalized-seed framing: prior seed followed by raw, ordered VRF proofs.
    let mut seed_material = input.seed.to_vec();
    for block in &input.blocks {
        seed_material.extend_from_slice(&block.header.vrf_proof);
    }
    let expected_seed: [u8; 32] = Sha256::digest(&seed_material).into();
    assert_eq!(statement.end.seed, expected_seed);
    assert_eq!(full.next_context.seed, expected_seed);
    let mut output_material = input.seed.to_vec();
    for block in &input.blocks {
        output_material.extend_from_slice(&neutrin0_vrf::proof_output(&block.header.vrf_proof));
    }
    assert_ne!(
        expected_seed,
        <[u8; 32]>::from(Sha256::digest(&output_material))
    );
    assert_eq!(
        neutrin0_prover_chunk::consensus::context_boundary(&full.next_context, statement.end.seed)
            .unwrap(),
        statement.end
    );
    let mut corrupt = input.clone();
    corrupt.finality_cert.precommit.signature[0] ^= 1;
    assert_eq!(validate_consensus(&corrupt), Err(ConsensusError::Finality));
    let mut corrupt = input.clone();
    corrupt.seed[0] ^= 1;
    assert_eq!(validate_consensus(&corrupt), Err(ConsensusError::Context));
    let mut corrupt = input.clone();
    corrupt.post_state.pre_state_root[0] ^= 1;
    assert_eq!(validate_consensus(&corrupt), Err(ConsensusError::Rotation));
    // Genesis blocks consume no previous-certificate selection; the header's
    // inputs root binds the report, so the execution binding refuses first.
    let mut corrupt = input.clone();
    corrupt.blocks[0].output.participation[0] ^= 1;
    assert_eq!(validate_consensus(&corrupt), Err(ConsensusError::Execution));
    // The outgoing boundary records only the report already consumed by the
    // executed chunk; its own finality certificate cannot change that report.
    assert_eq!(
        statement.end.participation,
        neutrin0_consensus_types::participation::NO_PARTICIPATION,
    );
    assert_eq!(full.next_context.participation, statement.end.participation);
    let mut corrupt = input;
    corrupt.blocks[0]
        .output
        .transaction_summary
        .transaction_count ^= 1;
    assert_eq!(validate_consensus(&corrupt), Err(ConsensusError::Header));
}

type ContextForgery = fn(&mut neutrin0_consensus_types::runtime::ConsensusExecutionContext);

fn validator_keys() -> Vec<neutrin0_crypto::bls::SecretKey> {
    (42..46)
        .map(|byte| neutrin0_crypto::bls::SecretKey::key_gen(&[byte; 32], &[]).unwrap())
        .collect()
}

#[test]
fn alternative_valid_current_certificate_subsets_have_identical_outgoing_boundaries() {
    use neutrin0_consensus_types::participation::NO_PARTICIPATION;
    use neutrin0_prover_chunk::consensus::validate_consensus_with_context;

    let keys = validator_keys();
    let (mut first, input, _, post) = support::fixture_with_validator_keys([1; 8], [4; 32], &keys);
    let abc = support::certificate_with_precommitters(&first, &keys, &[0, 1, 2]);
    let abd = support::certificate_with_precommitters(&first, &keys, &[0, 1, 3]);
    assert_eq!(abc.proposal, abd.proposal);
    assert_eq!(abc.prevote, abd.prevote);
    assert_eq!(
        abc.precommit_attestations[..2],
        abd.precommit_attestations[..2]
    );
    first.finality_cert = abc.clone();
    let a = validate_consensus_with_context(&first).unwrap();
    let mut alternate = first.clone();
    alternate.finality_cert = abd;
    let b = validate_consensus_with_context(&alternate).unwrap();
    assert_eq!(a.statement.chunk, b.statement.chunk);
    assert_eq!(a.statement.start, b.statement.start);
    assert_eq!(a.statement.end, b.statement.end);
    assert_eq!(a.next_context, b.next_context);
    assert_ne!(
        a.statement.finality_cert_hash,
        b.statement.finality_cert_hash
    );
    assert_eq!(a.statement.end.participation, NO_PARTICIPATION);

    // The same invariance holds after a report has actually been consumed.
    let (mut next, next_input, _, next_post) = support::successor_with_participation(
        &first,
        &input,
        &post,
        &keys,
        abc.carried_certificate(),
    );
    next.finality_cert = support::certificate_with_precommitters(&next, &keys, &[0, 1, 2]);
    let next_a = validate_consensus_with_context(&next).unwrap();
    let mut alternate_next = next.clone();
    alternate_next.finality_cert =
        support::certificate_with_precommitters(&next, &keys, &[0, 1, 3]);
    let next_b = validate_consensus_with_context(&alternate_next).unwrap();
    assert_eq!(next_a.statement.end, next_b.statement.end);
    assert_eq!(next_a.next_context, next_b.next_context);
    assert_ne!(
        next_a.statement.finality_cert_hash,
        next_b.statement.finality_cert_hash
    );
    assert_eq!(
        next_a.statement.end.participation,
        next_input.participation.as_ref().unwrap().commitment()
    );

    // A further chunk anchors to that common boundary even when the source
    // record happens to carry the alternative valid current certificate.
    let selected = next.finality_cert.carried_certificate();
    let (third, _, _, _) = support::successor_with_participation(
        &alternate_next,
        &next_input,
        &next_post,
        &keys,
        selected,
    );
    let third = validate_consensus(&third).unwrap();
    assert_eq!(third.start, next_a.statement.end);
}

#[test]
fn previous_certificate_selection_is_signed_and_consumed_before_chunk_agreement() {
    use neutrin0_prover_chunk::consensus::validate_consensus_with_context;

    let keys = validator_keys();
    let (first, input, _, post) = support::fixture_with_validator_keys([1; 8], [4; 32], &keys);
    let abc = support::certificate_with_precommitters(&first, &keys, &[0, 1, 2]);
    let abd = support::certificate_with_precommitters(&first, &keys, &[0, 1, 3]);
    let (next_a, input_a, _, post_a) = support::successor_with_participation(
        &first,
        &input,
        &post,
        &keys,
        abc.carried_certificate(),
    );
    let (next_b, input_b, _, post_b) = support::successor_with_participation(
        &first,
        &input,
        &post,
        &keys,
        abd.carried_certificate(),
    );
    let a = validate_consensus_with_context(&next_a).unwrap();
    let b = validate_consensus_with_context(&next_b).unwrap();
    assert_eq!(a.statement.start, b.statement.start);
    assert_ne!(
        next_a.blocks[0].header.da_root,
        next_b.blocks[0].header.da_root
    );
    assert_ne!(a.statement.chunk, b.statement.chunk);
    assert_ne!(post_a.state_root(), post_b.state_root());
    let report_a = input_a.participation.as_ref().unwrap();
    let report_b = input_b.participation.as_ref().unwrap();
    assert_ne!(report_a, report_b);
    assert_eq!(a.statement.end.participation, report_a.commitment());
    assert_eq!(b.statement.end.participation, report_b.commitment());
    assert_eq!(next_a.blocks[0].output.participation, report_a.commitment());
    assert_eq!(next_b.blocks[0].output.participation, report_b.commitment());
    let mut state_a = neutrin0_runtime_core::host::TracingState::new(&post_a);
    let mut state_b = neutrin0_runtime_core::host::TracingState::new(&post_b);
    assert_eq!(
        neutrin0_runtime_system::load_participation(&mut state_a),
        Some(report_a.clone())
    );
    assert_eq!(
        neutrin0_runtime_system::load_participation(&mut state_b),
        Some(report_b.clone())
    );
}

#[test]
fn participation_uses_the_precommit_threshold_even_when_prevote_threshold_is_lower() {
    use neutrin0_crypto::bls::aggregate_signatures;
    use neutrin0_prover_chunk::{
        consensus::as_chunk,
        history::{HistoricalChunk, verify_participation},
    };

    let keys = validator_keys();
    let (first, _, _, _) = support::fixture_with_validator_keys([1; 8], [4; 32], &keys);
    let statement = validate_consensus(&first).unwrap();
    let record = HistoricalChunk {
        chunk: as_chunk(&statement.chunk),
        validators: first.context.active_validators.clone(),
        seed: first.seed,
        block_guest_vk_digest: first.context.programs.execution.block,
        runtime_code_hash: first.context.programs.runtime_code_hash,
        start_boundary: statement.start.commitment(),
        finality: first.finality_cert.clone(),
    };
    let three = support::certificate_with_precommitters(&first, &keys, &[0, 1, 2])
        .participation_certificate();
    assert!(verify_participation(&first.chain_spec, &record, &three).is_ok());

    let mut stricter = first.chain_spec.clone();
    stricter.consensus.bft_precommit_quorum_numerator = 4;
    stricter.consensus.bft_precommit_quorum_denominator = 5;
    assert_eq!(stricter.consensus.bft_prevote_quorum_numerator, 2);
    assert_eq!(stricter.consensus.bft_prevote_quorum_denominator, 3);
    // The public helper derives its signature domain from the complete spec.
    // Re-sign both aggregates under the stricter domain so rejection cannot
    // be caused by a stale chain-spec signature rather than quorum weight.
    let resign = |mut certificate: neutrin0_consensus_types::QuorumCertificate,
                  indices: &[usize]| {
        let message = certificate
            .data
            .signing_message(stricter.consensus_domain());
        let signatures: Vec<_> = indices
            .iter()
            .map(|index| keys[*index].sign(&message))
            .collect();
        certificate.aggregate.signature =
            aggregate_signatures(&signatures.iter().collect::<Vec<_>>())
                .unwrap()
                .to_bytes();
        certificate
    };
    let three = resign(three, &[0, 1, 2]);
    assert!(verify_participation(&stricter, &record, &three).is_err());
    let four = resign(
        first.finality_cert.participation_certificate(),
        &[0, 1, 2, 3],
    );
    assert!(verify_participation(&stricter, &record, &four).is_ok());
}

fn reseal_selected_body(
    witness: &mut neutrin0_prover_chunk::consensus::ConsensusWitness,
    index: usize,
    key: &neutrin0_crypto::bls::SecretKey,
) {
    let compact = &witness.bodies[index];
    assert_eq!(
        compact.program_pieces,
        Vec::<neutrin0_consensus_types::ProgramPieceDescriptor>::new()
    );
    assert_eq!(
        witness.blocks[index]
            .output
            .transaction_summary
            .transaction_count,
        0
    );
    let body = neutrin0_consensus_types::Body {
        participation: compact.participation.clone(),
        participation_acks: compact.participation_acks.clone(),
        ..neutrin0_consensus_types::Body::default()
    };
    let block = &mut witness.blocks[index];
    block.header.votes_root =
        neutrin0_consensus_types::participation::vote_lane_root(&body.participation_acks);
    block.header.da_root = neutrin0_prover_chunk::consensus::body_da_root(&body);
    block.header.signature = key
        .sign(&witness.chain_spec.consensus_domain().signing_message(
            neutrin0_primitives::DOMAIN_PROPOSER_SIG,
            &block.header.hash(),
        ))
        .to_bytes();
    block.public_inputs.da_root = block.header.da_root;
    block.public_inputs.block_hash = block.header.hash();
}

#[test]
fn selected_participation_requires_exact_source_history_signatures_and_output() {
    use neutrin0_prover_chunk::consensus::validate_candidate;

    let keys = validator_keys();
    let (first, input, _, post) = support::fixture_with_validator_keys([1; 8], [4; 32], &keys);
    let selected =
        support::certificate_with_precommitters(&first, &keys, &[0, 1, 2]).carried_certificate();
    let (next, _, _, _) =
        support::successor_with_participation(&first, &input, &post, &keys, selected);
    validate_candidate(&next).unwrap();

    let mut missing = next.clone();
    missing.bodies[0].participation = None;
    reseal_selected_body(&mut missing, 0, &keys[0]);
    assert!(validate_candidate(&missing).is_err());

    let mut bad_signature = next.clone();
    bad_signature.bodies[0]
        .participation
        .as_mut()
        .unwrap()
        .quorum
        .aggregate
        .signature[0] ^= 1;
    reseal_selected_body(&mut bad_signature, 0, &keys[0]);
    assert!(validate_candidate(&bad_signature).is_err());

    let mut wrong_target = next.clone();
    wrong_target.bodies[0]
        .participation
        .as_mut()
        .unwrap()
        .quorum
        .data
        .chunk_id += 1;
    reseal_selected_body(&mut wrong_target, 0, &keys[0]);
    assert!(validate_candidate(&wrong_target).is_err());

    let mut wrong_phase = next.clone();
    wrong_phase.bodies[0].participation =
        Some(neutrin0_consensus_types::proving::CarriedCertificate {
            quorum: neutrin0_consensus_types::QuorumCertificate {
                data: first.finality_cert.prevote_vote().data,
                aggregate: first.finality_cert.prevote.clone(),
            },
            proposal: first.finality_cert.proposal.compact(),
        });
    reseal_selected_body(&mut wrong_phase, 0, &keys[0]);
    assert!(validate_candidate(&wrong_phase).is_err());

    let mut insufficient_quorum = next.clone();
    insufficient_quorum.bodies[0].participation =
        Some(support::certificate_with_precommitters(&first, &keys, &[0]).carried_certificate());
    reseal_selected_body(&mut insufficient_quorum, 0, &keys[0]);
    assert!(validate_candidate(&insufficient_quorum).is_err());

    let mut unbound_bytes = next.clone();
    unbound_bytes.bodies[0]
        .participation
        .as_mut()
        .unwrap()
        .quorum
        .aggregate
        .signature[0] ^= 1;
    assert!(validate_candidate(&unbound_bytes).is_err());

    let mut missing_opening = next.clone();
    missing_opening.history.records.clear();
    assert!(validate_candidate(&missing_opening).is_err());
    let mut forged_opening = next.clone();
    forged_opening.history.records[0].path.siblings[0][0] ^= 1;
    assert!(validate_candidate(&forged_opening).is_err());
    let mut forged_membership = next.clone();
    forged_membership.history.records[0].record.validators[0].withdrawal_credentials[0] ^= 1;
    assert!(validate_candidate(&forged_membership).is_err());

    let mut substituted_output = next;
    substituted_output.blocks[0].output.participation = substituted_output.context.participation;
    assert!(validate_candidate(&substituted_output).is_err());

    let mut genesis_selection = first;
    genesis_selection.bodies[0].participation =
        Some(genesis_selection.finality_cert.carried_certificate());
    reseal_selected_body(&mut genesis_selection, 0, &keys[0]);
    assert!(validate_candidate(&genesis_selection).is_err());
}

#[test]
fn later_blocks_inherit_one_selection_and_cannot_select_another_certificate() {
    use neutrin0_prover_chunk::consensus::validate_candidate;

    let keys = validator_keys();
    let (first, input, _, post) =
        support::fixture_with_validator_keys_and_chunk_size([1; 8], [4; 32], &keys, 2);
    let selected =
        support::certificate_with_precommitters(&first, &keys, &[0, 1, 2]).carried_certificate();
    let (next, input, _, _) =
        support::successor_with_participation(&first, &input, &post, &keys, selected.clone());
    validate_consensus(&next).unwrap();
    assert!(next.bodies[0].participation.is_some());
    assert!(next.bodies[1].participation.is_none());
    for block in &next.blocks {
        assert_eq!(
            block.output.participation,
            input.participation.as_ref().unwrap().commitment()
        );
    }
    let mut repeated = next.clone();
    repeated.bodies[1].participation = Some(selected);
    reseal_selected_body(&mut repeated, 1, &keys[0]);
    assert!(validate_candidate(&repeated).is_err());
    let mut conflicting = next;
    conflicting.blocks[1].output.participation[0] ^= 1;
    assert!(validate_candidate(&conflicting).is_err());
}

#[test]
fn a_later_chunk_cannot_select_another_fact_program_even_with_coherent_echoes() {
    let (first, _, _) = support::fixture([1; 8], [4; 32]);
    let mut next = successor(&first);
    assert!(next.context.chunk_id > 0);
    validate_consensus(&next).unwrap();
    next.context.programs.execution.fact = [9; 8];
    for block in &mut next.blocks {
        block.output.context.finalized.programs.execution.fact = [9; 8];
        *block.public_inputs.context = block.output.context;
        block.output.accountability.anchor.fact_guest_vk_digest = [9; 8];
    }
    assert_eq!(validate_consensus(&next), Err(ConsensusError::Context));
}

fn execution_context_forgeries() -> Vec<ContextForgery> {
    vec![
        |context| context.slot += 1,
        |context| context.timestamp += 1,
        |context| context.parent_block_hash[0] ^= 1,
        |context| context.proposer_vrf_output[0] ^= 1,
        |context| context.finalized.seed[0] ^= 1,
        |context| context.finalized.next_chunk_id += 1,
        |context| context.finalized.height += 1,
        |context| context.finalized.slot += 1,
        |context| context.finalized.block_hash[0] ^= 1,
        |context| context.finalized.state_root[0] ^= 1,
        |context| context.finalized.validators_root[0] ^= 1,
        |context| context.finalized.history_root[0] ^= 1,
        |context| context.finalized.participation[0] ^= 1,
        |context| context.finalized.programs.runtime_code_hash[0] ^= 1,
        |context| context.finalized.programs.execution.fact[0] ^= 1,
        |context| context.finalized.programs.execution.evidence[0] ^= 1,
        |context| context.finalized.programs.execution.block[0] ^= 1,
    ]
}

#[test]
fn chunk_independently_rejects_coherent_forged_execution_context_under_signed_headers() {
    let (original, _, _) = support::fixture([1; 8], [4; 32]);
    validate_consensus(&original).unwrap();
    for (index, forge) in execution_context_forgeries().iter().enumerate() {
        let mut wrong = original.clone();
        let block = &mut wrong.blocks[0];
        forge(&mut block.output.context);
        *block.public_inputs.context = block.output.context;
        block.public_inputs.inputs_root =
            neutrin0_prover_chunk::execution::output_inputs_root(&block.output);
        // Both forms of the supplied Block statement agree. Rejecting this
        // must therefore use the authenticated boundary and signed header,
        // not merely compare the runtime output to the supplied public input.
        assert!(neutrin0_prover_chunk::execution::output_binds(
            &block.output,
            &block.public_inputs,
        ));
        assert_eq!(block.header, original.blocks[0].header);
        assert_eq!(wrong.finality_cert, original.finality_cert);
        assert_eq!(
            validate_consensus(&wrong),
            Err(ConsensusError::Execution),
            "forgery {index}"
        );
    }
}

fn successor(
    first: &neutrin0_prover_chunk::consensus::ConsensusWitness,
) -> neutrin0_prover_chunk::consensus::ConsensusWitness {
    let (_, input, _) = support::fixture(
        first.context.programs.execution.block,
        first.context.programs.runtime_code_hash,
    );
    let genesis = support::fixture_genesis_live(
        first.context.programs.execution.block,
        first.context.programs.runtime_code_hash,
        30_000_000,
    );
    let mut trace = neutrin0_runtime_core::host::TracingState::new(&genesis);
    neutrin0_evm_runtime_core::execute_block(&input, &mut trace);
    let (post, _) = trace.into_committed_and_witness().unwrap();
    let post = neutrin0_runtime_core::host::LiveTrie::from_trie(post);
    let key = neutrin0_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    support::successor_with_participation(
        first,
        &input,
        &post,
        &[key],
        first.finality_cert.carried_certificate(),
    )
    .0
}

#[test]
fn successor_requires_exact_previous_consensus_boundary() {
    use neutrin0_prover_chunk::consensus::{ConsensusWitness, validate_successor};
    type Mutation = fn(&mut ConsensusWitness);
    let (first, _, _) = support::fixture([1; 8], [4; 32]);
    let previous = validate_consensus(&first).unwrap();
    let next = successor(&first);
    let statement = validate_successor(&previous, &next).unwrap();
    assert_eq!(statement.chunk.chunk_id, 1);
    assert_eq!(statement.chunk.start_height, 2);
    let mutations: &[Mutation] = &[
        |w| w.context.parent_block_hash[0] ^= 1,
        |w| w.context.pre_state_root[0] ^= 1,
        |w| w.context.chain_id += 1,
        |w| w.context.chunk_id += 1,
        |w| w.context.parent_slot += 1,
        |w| w.context.active_validators[0].effective_stake += 1,
        |w| w.context.history_root[0] ^= 1,
        |w| w.seed[0] ^= 1,
        |w| w.context.programs.execution.block[0] ^= 1,
        |w| w.context.programs.execution.fact[0] ^= 1,
        |w| w.context.programs.execution.evidence[0] ^= 1,
    ];
    for mutate in mutations {
        let mut wrong = next.clone();
        mutate(&mut wrong);
        assert_eq!(
            validate_successor(&previous, &wrong),
            Err(ConsensusError::Context)
        );
    }
    let mut wrong = next;
    wrong.history.frontier = neutrin0_consensus_types::history::HistoryFrontier::empty();
    assert!(validate_successor(&previous, &wrong).is_err());
}

#[test]
fn successor_blocks_cannot_substitute_an_agreeing_but_untrusted_incoming_boundary() {
    let (first, _, _) = support::fixture([1; 8], [4; 32]);
    let previous = validate_consensus(&first).unwrap();
    let original = successor(&first);
    neutrin0_prover_chunk::consensus::validate_successor(&previous, &original).unwrap();
    for (index, forge) in execution_context_forgeries().iter().enumerate() {
        let mut wrong = original.clone();
        let block = &mut wrong.blocks[0];
        forge(&mut block.output.context);
        *block.public_inputs.context = block.output.context;
        block.public_inputs.inputs_root =
            neutrin0_prover_chunk::execution::output_inputs_root(&block.output);
        assert!(neutrin0_prover_chunk::execution::output_binds(
            &block.output,
            &block.public_inputs
        ));
        assert_eq!(
            neutrin0_prover_chunk::consensus::validate_successor(&previous, &wrong),
            Err(ConsensusError::Execution),
            "forgery {index}",
        );
    }
}

#[test]
fn finality_requires_complete_authentic_accountability() {
    type Mutation = fn(&mut neutrin0_consensus_types::FinalityCert);
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    let mutations: &[Mutation] = &[
        |c| c.prevote_attestations.clear(),
        |c| {
            c.prevote_attestations
                .push(c.prevote_attestations[0].clone());
        },
        |c| c.prevote_attestations[0].validator_index = 1,
        |c| {
            c.prevote_attestations[0].proof_acceptance = Some(
                neutrin0_consensus_types::ProofManifest {
                    proof_hashes: vec![[2; 32]],
                }
                .commitment(),
            );
        },
        |c| c.prevote_attestations[0].vote.round += 1,
        |c| c.prevote_attestations[0].vote_signature[0] ^= 1,
        |c| c.prevote_attestations[0].signature[0] ^= 1,
        |c| c.precommit_attestations.clear(),
        |c| {
            c.precommit_attestations
                .push(c.precommit_attestations[0].clone());
        },
        |c| c.precommit_attestations[0].validator_index = 1,
        |c| c.proof_manifests.clear(),
        |c| c.proof_manifests.push(c.proof_manifests[0].clone()),
        |c| {
            c.proof_manifests[0].proof_hashes[0][0] ^= 1;
        },
        |c| {
            c.proof_manifests
                .push(neutrin0_consensus_types::ProofManifest {
                    proof_hashes: vec![[9; 32]],
                });
            c.proof_manifests
                .sort_by_key(neutrin0_consensus_types::ProofManifest::commitment);
        },
        |c| c.precommit_attestations[0].proof_acceptance = None,
        |c| {
            c.precommit_attestations[0]
                .proof_acceptance
                .as_mut()
                .unwrap()
                .count += 1;
        },
        |c| {
            c.precommit_attestations[0]
                .proof_acceptance
                .as_mut()
                .unwrap()
                .root[0] ^= 1;
        },
        |c| c.precommit_attestations[0].vote.round += 1,
        |c| c.precommit_attestations[0].vote_signature[0] ^= 1,
        |c| c.precommit_attestations[0].signature[0] ^= 1,
    ];
    for mutate in mutations {
        let mut invalid = input.clone();
        mutate(&mut invalid.finality_cert);
        assert_eq!(validate_consensus(&invalid), Err(ConsensusError::Finality));
    }
}

#[test]
fn fact_statements_replace_in_circuit_signature_checks() {
    use neutrin0_prover_chunk::consensus::{fact_coverage, validate_consensus_using};
    use neutrin0_prover_chunk::facts::{FactRecorder, FactStatement, ProvenFact};
    let (input, _, _) = support::fixture([1; 8], [4; 32]);
    // Without facts every check runs in-circuit.
    let (hits, misses) = fact_coverage(&input).unwrap();
    assert_eq!(hits, 0);
    assert!(misses > 0, "fixture performs signature checks");
    // Record the exact requests the chunk performs, as the host does.
    let mut recorder = FactRecorder::default();
    validate_consensus_using(&input, &mut recorder).unwrap();
    let requests = recorder.finish().unwrap();
    assert!(requests.iter().all(|(_, valid)| *valid));
    let statement = FactStatement {
        facts: requests
            .iter()
            .map(|(request, valid)| ProvenFact {
                id: request.id(),
                valid: *valid,
            })
            .collect(),
    };
    let mut covered = input.clone();
    covered.facts = vec![statement.clone()];
    // Full coverage: no BLS work remains and the statement is unchanged.
    let (hits, misses) = fact_coverage(&covered).unwrap();
    assert_eq!(misses, 0);
    assert_eq!(hits, requests.len());
    assert_eq!(validate_consensus(&covered), validate_consensus(&input));
    // Partial coverage still succeeds with the remainder in-circuit.
    let mut partial = input.clone();
    partial.facts = vec![FactStatement {
        facts: statement.facts[..1].to_vec(),
    }];
    let (hits, misses) = fact_coverage(&partial).unwrap();
    assert_eq!(hits, 1);
    assert_eq!(misses, requests.len() - 1);
    // A proven negative verdict for a needed check fails the chunk.
    let mut negative = covered.clone();
    negative.facts[0].facts[0].valid = false;
    assert!(validate_consensus(&negative).is_err());
    // Conflicting verdicts across statements are rejected outright.
    let mut conflicting = covered;
    let mut flipped = statement;
    flipped.facts[0].valid = false;
    conflicting.facts.push(flipped);
    assert!(validate_consensus(&conflicting).is_err());
}

#[test]
fn enacted_upgrade_switches_the_end_boundary_at_its_activation_chunk() {
    use neutrin0_consensus_types::history_proof::{
        ExecutionPrograms, ProgramArtifacts, ProgramSet, ScheduledUpgrade,
    };
    use neutrin0_consensus_types::runtime::UPGRADE_KEY;
    // Governance enacted this switch at least its unbonding lead earlier; the
    // chunk Guest consumes only the authenticated record, whatever wrote it.
    let next = ProgramSet {
        runtime_code_hash: [5; 32],
        execution: ExecutionPrograms {
            fact: [3; 8],
            evidence: [12; 8],
            block: [11; 8],
        },
    };
    let with_record = |record: Vec<u8>| {
        let mut live = support::fixture_genesis_live([1; 8], [4; 32], 30_000_000);
        live.insert(UPGRADE_KEY, record);
        live
    };
    let scheduled = |activate_at_chunk| {
        with_record(
            borsh::to_vec(&ScheduledUpgrade {
                activate_at_chunk,
                programs: next,
                artifacts: ProgramArtifacts::default(),
                available: true,
            })
            .unwrap(),
        )
    };
    // Activation at the next chunk: this chunk's end boundary adopts the set
    // and the next context executes under it.
    let (witness, _, _) =
        support::fixture_with_live([1; 8], [4; 32], Vec::new(), 30_000_000, &scheduled(1));
    let validated =
        neutrin0_prover_chunk::consensus::validate_consensus_with_context(&witness).unwrap();
    assert_eq!(validated.statement.start.programs, witness.context.programs);
    assert_eq!(validated.statement.end.programs, next);
    assert_eq!(validated.next_context.programs, next);
    assert_eq!(validated.next_context.vm_code_hash, next.runtime_code_hash);
    assert_ne!(
        validated.statement.end.programs,
        validated.statement.start.programs
    );
    // A later activation leaves this boundary under the current set.
    let (witness, _, _) =
        support::fixture_with_live([1; 8], [4; 32], Vec::new(), 30_000_000, &scheduled(2));
    let validated =
        neutrin0_prover_chunk::consensus::validate_consensus_with_context(&witness).unwrap();
    assert_eq!(validated.statement.end.programs, witness.context.programs);
    assert_eq!(validated.next_context.programs, witness.context.programs);
    // A record the Guest cannot apply is void rather than fatal: one in
    // another layout, or one replacing the immutable Fact Guest, leaves the
    // current set in force and the chunk provable.
    let mut foreign_fact = scheduled(1);
    let mut replacing = next;
    replacing.execution.fact = [9; 8];
    foreign_fact.insert(
        UPGRADE_KEY,
        borsh::to_vec(&ScheduledUpgrade {
            activate_at_chunk: 1,
            programs: replacing,
            artifacts: ProgramArtifacts::default(),
            available: true,
        })
        .unwrap(),
    );
    let mut extended = borsh::to_vec(&ScheduledUpgrade {
        activate_at_chunk: 1,
        programs: next,
        artifacts: ProgramArtifacts::default(),
        available: true,
    })
    .unwrap();
    extended.push(1);
    for live in [foreign_fact, with_record(extended)] {
        let (witness, _, _) =
            support::fixture_with_live([1; 8], [4; 32], Vec::new(), 30_000_000, &live);
        let validated =
            neutrin0_prover_chunk::consensus::validate_consensus_with_context(&witness).unwrap();
        assert_eq!(validated.statement.end.programs, witness.context.programs);
        assert_eq!(validated.next_context.programs, witness.context.programs);
    }
}

/// Governance's hard fork travels in every boundary up to its count, where
/// the chain ends: the boundary entering the count is the endpoint, and no
/// chunk of this chain starts from it.
#[test]
fn a_scheduled_fork_ends_the_chain_at_its_count() {
    use neutrin0_consensus_types::history_proof::ScheduledFork;
    use neutrin0_consensus_types::runtime::FORK_KEY;
    let scheduled = |fork: &ScheduledFork| {
        let mut live = support::fixture_genesis_live([1; 8], [4; 32], 30_000_000);
        live.insert(FORK_KEY, borsh::to_vec(fork).unwrap());
        support::fixture_with_live([1; 8], [4; 32], Vec::new(), 30_000_000, &live).0
    };
    let later = ScheduledFork {
        count: 5,
        successor: [6; 32],
    };
    let at_end = ScheduledFork {
        count: 1,
        successor: [6; 32],
    };
    for fork in [later, at_end] {
        let validated =
            neutrin0_prover_chunk::consensus::validate_consensus_with_context(&scheduled(&fork))
                .unwrap();
        assert_eq!(validated.statement.start.fork, None);
        assert_eq!(validated.statement.end.fork, Some(fork));
        assert_eq!(validated.next_context.fork, Some(fork));
        assert_eq!(validated.statement.end.proves(1), fork.count > 1);
    }
    // A chunk starting at the count is refused.
    let (first, _, _) = support::fixture([1; 8], [4; 32]);
    let mut ended = successor(&first);
    validate_consensus(&ended).unwrap();
    ended.context.fork = Some(ScheduledFork {
        count: 1,
        successor: [6; 32],
    });
    assert_eq!(validate_consensus(&ended), Err(ConsensusError::Context));
    // The successor derivation needs the fork key witnessed.
    let mut unwitnessed = scheduled(&later);
    unwitnessed
        .post_state
        .witnessed_keys
        .retain(|key| key != FORK_KEY);
    assert_eq!(
        neutrin0_prover_chunk::consensus::validate_candidate(&unwitnessed).map(drop),
        Err(ConsensusError::Rotation)
    );
}

fn candidate_state(
    key: &neutrin0_crypto::bls::SecretKey,
    address: [u8; 32],
    stake: u128,
) -> (
    neutrin0_runtime_core::host::LiveTrie,
    neutrin0_consensus_types::runtime::ConsensusCandidates,
) {
    use neutrin0_consensus_types::runtime::{
        BlsIdentity, CONSENSUS_CANDIDATES_KEY, ConsensusCandidate, ConsensusCandidates,
    };
    let mut candidates = ConsensusCandidates::default();
    candidates.upsert(ConsensusCandidate {
        address,
        stake,
        identity: Some(BlsIdentity {
            pubkey: key.public_key().to_bytes(),
            pop_signature: key.prove_registration(&address).to_bytes(),
        }),
    });
    let mut live = support::fixture_genesis_live([1; 8], [4; 32], 30_000_000);
    live.insert(
        CONSENSUS_CANDIDATES_KEY,
        borsh::to_vec(&candidates).unwrap(),
    );
    (live, candidates)
}

#[test]
fn historical_slash_ejects_the_same_identity_at_a_changed_withdrawal_account() {
    use neutrin0_consensus_types::evidence::SanctionKind;
    use neutrin0_consensus_types::runtime::Sanction;
    use neutrin0_prover_chunk::consensus::validate_candidate;
    let keys: Vec<_> = [42, 43]
        .iter()
        .map(|byte| neutrin0_crypto::bls::SecretKey::key_gen(&[*byte; 32], &[]).unwrap())
        .collect();
    let (mut input, _, _, _) = support::fixture_with_validator_keys([1; 8], [4; 32], &keys);
    let before = validate_candidate(&input).unwrap();
    assert_eq!(before.next_validators.len(), 2);
    let mut historical = input.context.active_validators[0].clone();
    historical.withdrawal_credentials = [19; 32];
    // Native composition seam: production recursively authenticates this
    // admitted effect with the containing Block receipt.
    input.blocks[0]
        .output
        .accountability
        .admitted
        .push(Sanction {
            offence_id: [91; 32],
            offender: historical,
            kind: SanctionKind::Slash,
        });
    let after = validate_candidate(&input).unwrap();
    assert_eq!(
        after.next_validators,
        vec![before.next_validators[1].clone()]
    );
    assert_ne!(
        after.execution.chunk.next_identity_sanctions_root,
        input.context.identity_sanctions_root
    );
}

#[test]
fn historical_slash_of_a_retired_identity_blocks_its_queued_new_account() {
    use neutrin0_consensus_types::evidence::SanctionKind;
    use neutrin0_consensus_types::runtime::Sanction;
    use neutrin0_prover_chunk::consensus::validate_candidate;
    let key = neutrin0_crypto::bls::SecretKey::key_gen(&[43; 32], &[]).unwrap();
    let (live, _) = candidate_state(&key, [10; 32], 300);
    let (mut input, _, _) = support::fixture_with_live([1; 8], [4; 32], vec![], 30_000_000, &live);
    let before = validate_candidate(&input).unwrap();
    assert_eq!(before.next_validators.len(), 2);
    assert_eq!(before.next_validators[1].withdrawal_credentials, [10; 32]);
    let mut historical = input.context.active_validators[0].clone();
    historical.pubkey = key.public_key().to_bytes();
    historical.withdrawal_credentials = [9; 32];
    historical.exit_epoch = 0;
    input.blocks[0]
        .output
        .accountability
        .admitted
        .push(Sanction {
            offence_id: [92; 32],
            offender: historical,
            kind: SanctionKind::Slash,
        });
    let after = validate_candidate(&input).unwrap();
    assert_eq!(
        after.next_validators,
        vec![before.next_validators[0].clone()]
    );
    assert_ne!(
        after.execution.chunk.next_identity_sanctions_root,
        input.context.identity_sanctions_root
    );
}

#[test]
fn the_ratified_chunk_proof_must_be_the_previous_chunks_exact_statement() {
    use neutrin0_prover_chunk::consensus::ChunkReceiptStatement;
    type Mutation = fn(&mut ChunkReceiptStatement);
    let (first, _, _) = support::fixture([1; 8], [4; 32]);
    let key = neutrin0_crypto::bls::SecretKey::key_gen(&[42; 32], &[]).unwrap();
    let next = successor(&first);
    validate_consensus(&next).unwrap();
    // The certificate is re-signed over each mutated statement, so only its
    // binding to this chain and these boundaries can reject it (design 08).
    let mutations: [Mutation; 4] = [
        |ratified| ratified.statement.end.history_root[0] ^= 1,
        |ratified| ratified.statement.end.next_chunk_id += 1,
        |ratified| ratified.statement.chain.chain_spec_hash[0] ^= 1,
        |ratified| ratified.statement.chunk.chunk_id += 1,
    ];
    for mutate in mutations {
        let mut wrong = next.clone();
        mutate(&mut wrong.ratified[0]);
        wrong.finality_cert =
            support::certificate_with_precommitters(&wrong, core::slice::from_ref(&key), &[0]);
        assert_eq!(validate_consensus(&wrong), Err(ConsensusError::Finality));
    }
    // Every certificate after chunk zero ratifies exactly the previous chunk.
    let mut missing = next.clone();
    missing.ratified.clear();
    missing.finality_cert =
        support::certificate_with_precommitters(&missing, core::slice::from_ref(&key), &[0]);
    assert_eq!(validate_consensus(&missing), Err(ConsensusError::Finality));
    // A statement or prover the signed entry does not name.
    let mut swapped = next;
    swapped.ratified[0].chunk_prover_address[0] ^= 1;
    assert_eq!(validate_consensus(&swapped), Err(ConsensusError::Finality));
}
