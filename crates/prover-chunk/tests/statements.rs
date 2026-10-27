//! Adversarial statement and portable-crypto tests independent of SP1 mocks.

use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::{
    AggregatedVote, BlockProofPublicInputs, Chunk, FinalityCert, FinalityVoteData,
    FinalityVotePhase, Header,
};
use neutrin0_crypto::bls::SecretKey;
use neutrin0_primitives::{
    BitVec, ConsensusParams, DOMAIN_PROPOSER_SIG, Validator, fixed_u128_from_integer,
};
use neutrin0_prover_chunk::{
    execution::{ExecutionContext, ProvenBlock, validate_execution},
    finality::{FinalityError, verify_finality},
    proposer::{ProposerError, verify_proposer},
    rotation::derive_next_validators,
};
use neutrin0_runtime_abi::RuntimeBlockOutput;

fn test_domain() -> neutrin0_primitives::ConsensusDomain {
    let context = context();
    neutrin0_primitives::ConsensusDomain::new(context.chain_id, context.chain_spec_hash)
}

fn key() -> SecretKey {
    SecretKey::key_gen(&[42; 32], &[]).unwrap()
}

fn validator() -> Validator {
    Validator {
        pubkey: key().public_key().to_bytes(),
        withdrawal_credentials: neutrin0_primitives::runtime_account([8; 20]),
        effective_stake: 100,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }
}

fn context() -> ExecutionContext {
    ExecutionContext {
        identity_sanctions_root: [0; 32],

        seed: [0; 32],
        chain_id: 7,
        chain_spec_hash: [1; 32],
        chunk_id: 0,
        chunk_size: 2,
        parent_block_hash: [2; 32],
        pre_state_root: [3; 32],
        parent_slot: 0,
        vm_code_hash: [4; 32],
        programs: neutrin0_consensus_types::history_proof::ProgramSet {
            runtime_code_hash: [4; 32],
            execution: neutrin0_consensus_types::history_proof::ExecutionPrograms {
                fact: [3; 8],
                evidence: [2; 8],
                block: [1; 8],
            },
        },
        participation: neutrin0_consensus_types::participation::NO_PARTICIPATION,
        proving: neutrin0_consensus_types::proving::NO_PROVING,
        active_validators: vec![validator()],
        history_root: neutrin0_consensus_types::tagged_commitment(b"history", &Vec::<u8>::new()),
        fork: None,
    }
}

fn block(height: u64, parent: [u8; 32], state: [u8; 32]) -> ProvenBlock {
    let context = context();
    let mut header = Header {
        height,
        slot: height,
        parent_hash: parent,
        proposer_index: 0,
        vrf_proof: [0; 96],
        state_root: [u8::try_from(height + 10).unwrap(); 32],
        transactions_root: [5; 32],
        votes_root: [0; 32],
        da_root: [6; 32],
        runtime_extra: [7; 32],
        inputs_root: [0; 32],
        receipts_root: [9; 32],
        gas_used: 10,
        gas_limit: 100,
        timestamp: height * 6,
        signature: [0; 96],
    };
    let execution_context = neutrin0_prover_chunk::execution::runtime_context(
        &header,
        neutrin0_prover_chunk::consensus::context_boundary(&context, context.seed).unwrap(),
    );
    header.inputs_root = neutrin0_consensus_types::runtime::execution_inputs_root(
        &execution_context,
        neutrin0_consensus_types::participation::NO_PARTICIPATION,
        [0; 32],
        neutrin0_consensus_types::proving::NO_PROVING,
        [0; 32],
        &neutrin0_consensus_types::runtime::AccountabilityOutput::default().anchor,
    );
    let public_inputs = BlockProofPublicInputs {
        context: execution_context.into(),
        chain_id: context.chain_id,
        height,
        parent_block_hash: parent,
        block_hash: header.hash(),
        state_root_before: state,
        state_root_after: header.state_root,
        transactions_root: header.transactions_root,
        receipt_root: header.receipts_root,
        da_root: header.da_root,
        vm_code_hash: context.vm_code_hash,
        block_program: context.programs.execution.block,
        gas_used: header.gas_used,
        gas_limit: header.gas_limit,
        proposer_address: validator().withdrawal_credentials,
        runtime_extra: header.runtime_extra,
        inputs_root: header.inputs_root,
    };
    let output = RuntimeBlockOutput {
        participation_acks: [0; 32],
        program_pieces: [0; 32],

        context: *public_inputs.context,
        accountability: neutrin0_consensus_types::runtime::AccountabilityOutput::default(),
        chain_id: context.chain_id,
        block_height: height,
        block_gas_limit: header.gas_limit,
        proposer_address: public_inputs.proposer_address,
        participation: neutrin0_consensus_types::participation::NO_PARTICIPATION,
        proving: neutrin0_consensus_types::proving::NO_PROVING,
        transactions_root: header.transactions_root,
        transaction_summary: neutrin0_runtime_abi::TransactionSummary::default(),
        pre_state_root: state,
        post_state_root: header.state_root,
        applied: 1,
        failed: 0,
        consensus_candidates_root: header.runtime_extra,
        gas_used: header.gas_used,
        receipts_root: header.receipts_root,
    };
    ProvenBlock {
        header,
        prover_address: public_inputs.proposer_address,
        public_inputs,
        output,
    }
}

fn blocks() -> Vec<ProvenBlock> {
    let context = context();
    let first = block(1, context.parent_block_hash, context.pre_state_root);
    let second = block(2, first.header.hash(), first.output.post_state_root);
    vec![first, second]
}

/// Incoming seed of the hand-built test chunks.
const TEST_SEED: neutrin0_primitives::Seed = [0x5e; 32];
#[test]
fn every_block_keeps_the_incoming_chunk_boundary_despite_parent_progress() {
    let context = context();
    let original = blocks();
    let incoming =
        neutrin0_prover_chunk::consensus::context_boundary(&context, context.seed).unwrap();
    let statement = validate_execution(&context, &original).unwrap();
    assert_eq!(
        statement.chunk.active_validator_set_root,
        commitment(&context.active_validators)
    );
    for block in &original {
        assert_eq!(block.output.context.finalized, incoming);
    }
    assert_ne!(original[1].header.parent_hash, incoming.block_hash);
    assert_ne!(original[1].output.pre_state_root, incoming.state_root);

    // A block can agree internally while trying to use the preceding block
    // as its finalized source. It must still consume the chunk's start boundary.
    let mut advanced = original.clone();
    let first = &original[0];
    advanced[1].output.context.finalized.height = first.header.height;
    advanced[1].output.context.finalized.slot = first.header.slot;
    advanced[1].output.context.finalized.block_hash = first.header.hash();
    advanced[1].output.context.finalized.state_root = first.output.post_state_root;
    *advanced[1].public_inputs.context = advanced[1].output.context;
    advanced[1].public_inputs.inputs_root =
        neutrin0_prover_chunk::execution::output_inputs_root(&advanced[1].output);
    assert!(neutrin0_prover_chunk::execution::output_binds(
        &advanced[1].output,
        &advanced[1].public_inputs
    ));
    assert_eq!(
        validate_execution(&context, &advanced),
        Err(neutrin0_prover_chunk::execution::ExecutionError::BlockBinding)
    );

    // Reusing one computed root must not authorize another validator commitment
    // in either the first or any later block's public values.
    for index in 0..original.len() {
        let mut wrong = original.clone();
        wrong[index].output.context.finalized.validators_root[0] ^= 1;
        *wrong[index].public_inputs.context = wrong[index].output.context;
        wrong[index].public_inputs.inputs_root =
            neutrin0_prover_chunk::execution::output_inputs_root(&wrong[index].output);
        assert!(neutrin0_prover_chunk::execution::output_binds(
            &wrong[index].output,
            &wrong[index].public_inputs
        ));
        assert_eq!(
            validate_execution(&context, &wrong),
            Err(neutrin0_prover_chunk::execution::ExecutionError::BlockBinding)
        );
    }
}

#[test]
fn binds_headers_and_all_inner_execution_fields() {
    type Mutation = fn(&mut ProvenBlock);
    let mutations: &[Mutation] = &[
        |b| b.header.transactions_root[0] ^= 1,
        |b| b.header.receipts_root[0] ^= 1,
        |b| b.header.state_root[0] ^= 1,
        |b| b.header.runtime_extra[0] ^= 1,
        |b| b.header.gas_used += 1,
        |b| b.header.gas_limit += 1,
        |b| b.header.height += 1,
        |b| b.header.parent_hash[0] ^= 1,
        |b| b.output.transactions_root[0] ^= 1,
        |b| b.output.receipts_root[0] ^= 1,
        |b| b.output.post_state_root[0] ^= 1,
        |b| b.output.pre_state_root[0] ^= 1,
        |b| b.output.consensus_candidates_root[0] ^= 1,
        |b| b.output.chain_id += 1,
        |b| b.output.block_height += 1,
        |b| b.output.gas_used += 1,
        |b| b.output.block_gas_limit += 1,
        |b| b.output.proposer_address[0] ^= 1,
        |b| b.public_inputs.block_hash[0] ^= 1,
        |b| b.public_inputs.vm_code_hash[0] ^= 1,
        |b| b.public_inputs.da_root[0] ^= 1,
        |b| b.public_inputs.context.timestamp += 1,
        |b| b.public_inputs.context.parent_block_hash[0] ^= 1,
        |b| b.public_inputs.context.finalized.seed[0] ^= 1,
        |b| b.public_inputs.context.proposer_vrf_output[0] ^= 1,
        |b| b.public_inputs.context.finalized.programs.execution.block[0] ^= 1,
        |b| b.output.context.timestamp += 1,
        |b| b.output.context.finalized.seed[0] ^= 1,
        |b| b.output.context.proposer_vrf_output[0] ^= 1,
    ];
    assert!(validate_execution(&context(), &blocks()).is_ok());
    for (index, mutate) in mutations.iter().enumerate() {
        let mut blocks = blocks();
        mutate(&mut blocks[0]);
        assert!(
            validate_execution(&context(), &blocks).is_err(),
            "mutation {index}"
        );
    }
}

#[test]
fn rejects_fabricated_header_hash_even_when_host_metadata_agrees() {
    let mut blocks = blocks();
    blocks[0].public_inputs.block_hash = [90; 32];
    blocks[1].header.parent_hash = [90; 32];
    blocks[1].public_inputs.parent_block_hash = [90; 32];
    blocks[1].public_inputs.block_hash = blocks[1].header.hash();
    assert!(validate_execution(&context(), &blocks).is_err());
}

#[test]
fn rejects_missing_duplicate_reordered_and_overflowing_ranges() {
    let valid = blocks();
    for blocks in [
        vec![],
        vec![valid[0].clone()],
        vec![valid[0].clone(), valid[0].clone()],
        vec![valid[1].clone(), valid[0].clone()],
    ] {
        assert!(validate_execution(&context(), &blocks).is_err());
    }
    let mut ctx = context();
    ctx.chunk_id = u64::MAX;
    assert!(validate_execution(&ctx, &valid).is_err());
}

#[test]
fn authenticates_incoming_boundaries_and_commits_program_identity() {
    let valid = blocks();
    let mut ctx = context();
    ctx.parent_block_hash[0] ^= 1;
    assert!(validate_execution(&ctx, &valid).is_err());
    ctx = context();
    ctx.pre_state_root[0] ^= 1;
    assert!(validate_execution(&ctx, &valid).is_err());
}

fn chunk() -> Chunk {
    let pi = validate_execution(&context(), &blocks()).unwrap().chunk;
    Chunk {
        next_identity_sanctions_root: [0; 32],

        chunk_id: pi.chunk_id,
        start_height: pi.start_height,
        end_height: pi.end_height,
        start_state_root: pi.start_state_root,
        end_state_root: pi.end_state_root,
        start_block_hash: pi.start_block_hash,
        end_block_hash: pi.end_block_hash,
        block_hash_root: pi.block_hash_root,
        block_proof_root: pi.block_proof_root,
        vrf_proof_root: pi.vrf_proof_root,
        active_validator_set_root: pi.active_validator_set_root,
        next_validator_set_root: pi.next_validator_set_root,
        da_root: pi.da_root,
    }
}

fn certificate(chunk: &Chunk) -> FinalityCert {
    let mut proposal = neutrin0_consensus_types::BftProposal {
        chunk: chunk.clone(),
        round: 0,
        proposer_index: 0,
        valid_quorum: None,
        round_change_certificate: None,
        proposal_slot: 0,
        receipts: Vec::new(),
        ratified_chunk_proofs: Vec::new(),
        signature: [0; 96],
    };
    proposal.signature = key()
        .sign(&proposal.signing_message(test_domain()))
        .to_bytes();
    let selection = proposal.selection();
    let sign = |phase| {
        let data = FinalityVoteData {
            chunk_id: chunk.chunk_id,
            round: 0,
            chunk_hash: chunk.hash(),
            selection,
            phase,
        };
        let message = data.signing_message(test_domain());
        AggregatedVote {
            aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
            signature: key().sign(&message).to_bytes(),
        }
    };
    FinalityCert {
        proof_manifests: vec![neutrin0_consensus_types::ProofManifest {
            proof_hashes: vec![
                [1; 32];
                usize::try_from(chunk.end_height - chunk.start_height + 1).unwrap()
            ],
        }],
        proposal,
        prevote_attestations: vec![signed_attestation(
            FinalityVoteData {
                chunk_id: chunk.chunk_id,
                round: 0,
                chunk_hash: chunk.hash(),
                selection,
                phase: FinalityVotePhase::Prevote,
            },
            Vec::new(),
            None,
        )],
        precommit_attestations: vec![signed_attestation(
            FinalityVoteData {
                chunk_id: chunk.chunk_id,
                round: 0,
                chunk_hash: chunk.hash(),
                selection,
                phase: FinalityVotePhase::Precommit,
            },
            vec![[1; 32]; usize::try_from(chunk.end_height - chunk.start_height + 1).unwrap()],
            None,
        )],
        chunk_id: chunk.chunk_id,
        round: 0,
        chunk_hash: chunk.hash(),
        prevote: sign(FinalityVotePhase::Prevote),
        precommit: sign(FinalityVotePhase::Precommit),
        active_validator_set_root: chunk.active_validator_set_root,
    }
}

#[test]
fn verifies_both_bft_phases_and_rejects_replay_and_bad_signers() {
    let chunk = chunk();
    let cert = certificate(&chunk);
    let params = ConsensusParams {
        chunk_size: 2,
        ..ConsensusParams::default()
    };
    let validators = vec![validator()];
    assert_eq!(
        verify_finality(
            test_domain(),
            &params,
            &validators,
            &TEST_SEED,
            &chunk,
            &cert
        ),
        Ok(())
    );
    assert_eq!(
        verify_finality(
            neutrin0_primitives::ConsensusDomain {
                chain_id: 8,
                ..test_domain()
            },
            &params,
            &validators,
            &TEST_SEED,
            &chunk,
            &cert
        ),
        Err(FinalityError::Signature)
    );
    let mut bad = cert.clone();
    bad.precommit.signature = bad.prevote.signature;
    assert_eq!(
        verify_finality(
            test_domain(),
            &params,
            &validators,
            &TEST_SEED,
            &chunk,
            &bad
        ),
        Err(FinalityError::Signature)
    );
    let mut minority_chunk = chunk.clone();
    let mut heavier = validator();
    heavier.pubkey = SecretKey::key_gen(&[43; 32], &[])
        .unwrap()
        .public_key()
        .to_bytes();
    heavier.effective_stake = 200;
    let weighted = vec![validator(), heavier];
    minority_chunk.active_validator_set_root = commitment(&weighted);
    let mut minority = certificate(&minority_chunk);
    let leader =
        neutrin0_consensus_types::bft_leader(7, chunk.chunk_id, 0, &TEST_SEED, &weighted).unwrap();
    minority.proposal.proposer_index = leader;
    let leader_key = if leader == 0 {
        key()
    } else {
        SecretKey::key_gen(&[43; 32], &[]).unwrap()
    };
    minority.proposal.signature = leader_key
        .sign(&minority.proposal.signing_message(test_domain()))
        .to_bytes();
    // A complete, authentic claim covers the one signer. Its 100 stake out of
    // 300 still falls below quorum, independently of attestation coverage.
    minority.prevote.aggregation_bits = BitVec::from_bytes(2, vec![1]).unwrap();
    minority.precommit.aggregation_bits = BitVec::from_bytes(2, vec![1]).unwrap();
    assert_eq!(
        verify_finality(
            test_domain(),
            &params,
            &weighted,
            &TEST_SEED,
            &minority_chunk,
            &minority
        ),
        Err(FinalityError::Quorum)
    );
    bad = cert;
    bad.chunk_hash[0] ^= 1;
    assert_eq!(
        verify_finality(
            test_domain(),
            &params,
            &validators,
            &TEST_SEED,
            &chunk,
            &bad
        ),
        Err(FinalityError::Target)
    );
}

#[test]
fn verifies_header_signature_vrf_domain_and_threshold() {
    let mut header = blocks().remove(0).header;
    let seed = [17; 32];
    header.vrf_proof = key()
        .sign(&neutrin0_vrf::vrf_message(
            test_domain(),
            &seed,
            header.slot,
        ))
        .to_bytes();
    let message = test_domain().signing_message(DOMAIN_PROPOSER_SIG, &header.hash());
    header.signature = key().sign(&message).to_bytes();
    let validators = vec![validator()];
    let expected = fixed_u128_from_integer(1);
    assert_eq!(
        verify_proposer(&header, test_domain(), &validators, &seed, expected),
        Ok(())
    );
    assert_eq!(
        verify_proposer(&header, test_domain(), &validators, &[18; 32], expected),
        Err(ProposerError::Vrf)
    );
    assert_eq!(
        verify_proposer(&header, test_domain(), &validators, &seed, 0),
        Err(ProposerError::Ineligible)
    );
    header.transactions_root[0] ^= 1;
    assert_eq!(
        verify_proposer(&header, test_domain(), &validators, &seed, expected),
        Err(ProposerError::Signature)
    );
}

#[test]
fn rotation_authenticates_possession_and_delays_activation_and_exit() {
    use neutrin0_consensus_types::runtime::{BlsIdentity, ConsensusCandidate, ConsensusCandidates};
    let key = SecretKey::key_gen(&[43; 32], &[]).unwrap();
    let identity = BlsIdentity {
        pubkey: key.public_key().to_bytes(),
        pop_signature: key.prove_registration(&[12; 32]).to_bytes(),
    };
    let candidate = |stake, identity| ConsensusCandidate {
        address: [12; 32],
        stake,
        identity,
    };
    let with = |entry: ConsensusCandidate| {
        let mut candidates = ConsensusCandidates::default();
        candidates.upsert(entry);
        candidates
    };
    let staked = with(candidate(300, Some(identity)));
    let params = ConsensusParams {
        epoch_length_in_chunks: 1,
        activation_delay_epochs: 2,
        exit_delay_epochs: 2,
        ..ConsensusParams::default()
    };
    let unbonding = params.exit_accountability_blocks().unwrap();
    let initial = vec![validator()];
    let next = derive_next_validators(&initial, &staked, &params, unbonding, 0).unwrap();
    assert_eq!(next.len(), 2);
    assert_eq!(next[1].activation_epoch, 3);
    assert_eq!(next[1].effective_stake, 0);
    // Seated identities are not registered again on later chunks.
    let active = derive_next_validators(&next, &staked, &params, unbonding, 2).unwrap();
    assert_eq!(active.len(), 2);
    assert_eq!(active[1].effective_stake, 300);
    // A zero candidate stake exits the seat.
    let drained = with(candidate(0, Some(identity)));
    let exited = derive_next_validators(&active, &drained, &params, unbonding, 3).unwrap();
    assert_eq!(exited[1].effective_stake, 300);
    assert_eq!(exited[1].exit_epoch, 6);
    // The weight remains usable until handoff, even after runtime withdrawal
    // projections disappear. Its collateral delay exceeds this exit delay.
    let empty = ConsensusCandidates::default();
    let early = derive_next_validators(&exited, &empty, &params, unbonding, 4).unwrap();
    assert_eq!(early.len(), 2);
    assert_eq!(early[1].effective_stake, 300);
    let retired = derive_next_validators(&exited, &drained, &params, unbonding, 5).unwrap();
    assert_eq!(retired, vec![initial[0].clone()]);
    // Permanent identity exclusion is tested against the independent
    // sanctions trie; a seat carries no slashed flag.
    // An invalid possession proof never seats, and a candidate without an
    // identity is a genesis validator's runtime record, not a registration.
    let bad = with(candidate(
        300,
        Some(BlsIdentity {
            pop_signature: [0; 96],
            ..identity
        }),
    ));
    assert_eq!(
        derive_next_validators(&initial, &bad, &params, unbonding, 0)
            .unwrap()
            .len(),
        1
    );
    let anonymous = with(candidate(300, None));
    assert_eq!(
        derive_next_validators(&initial, &anonymous, &params, unbonding, 0)
            .unwrap()
            .len(),
        1
    );
}

/// A key rotation the runtime recorded gives a seat its address's new key at
/// the next boundary, keeping stake and position, only for a key proven at
/// that address and seated nowhere else; a leaving seat keeps its key.
#[test]
fn a_rotated_key_takes_its_seat_at_the_next_boundary() {
    use neutrin0_consensus_types::runtime::{BlsIdentity, ConsensusCandidate, ConsensusCandidates};
    let params = ConsensusParams {
        epoch_length_in_chunks: 1,
        activation_delay_epochs: 1,
        exit_delay_epochs: 1,
        ..ConsensusParams::default()
    };
    let unbonding = params.exit_accountability_blocks().unwrap();
    let seat = validator();
    let address = seat.withdrawal_credentials;
    let rotated = SecretKey::key_gen(&[44; 32], &[]).unwrap();
    let identity = |key: &SecretKey, at: &[u8; 32]| BlsIdentity {
        pubkey: key.public_key().to_bytes(),
        pop_signature: key.prove_registration(at).to_bytes(),
    };
    let record = |stake, identity| {
        let mut candidates = ConsensusCandidates::default();
        candidates.upsert(ConsensusCandidate {
            address,
            stake,
            identity: Some(identity),
        });
        candidates
    };
    let next = derive_next_validators(
        std::slice::from_ref(&seat),
        &record(seat.effective_stake, identity(&rotated, &address)),
        &params,
        unbonding,
        0,
    )
    .unwrap();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0].pubkey, rotated.public_key().to_bytes());
    assert_eq!(
        (next[0].withdrawal_credentials, next[0].effective_stake),
        (address, seat.effective_stake)
    );
    // A proof made for another address does not rotate the seat.
    let elsewhere = record(seat.effective_stake, identity(&rotated, &[99; 32]));
    assert_eq!(
        derive_next_validators(
            std::slice::from_ref(&seat),
            &elsewhere,
            &params,
            unbonding,
            0
        )
        .unwrap()[0]
            .pubkey,
        seat.pubkey
    );
    // A seat leaving for zero stake keeps the key it is accountable under.
    let leaving = derive_next_validators(
        std::slice::from_ref(&seat),
        &record(0, identity(&rotated, &address)),
        &params,
        unbonding,
        0,
    )
    .unwrap();
    assert_eq!(leaving[0].pubkey, seat.pubkey);
}

#[test]
fn waiting_candidates_take_free_seats_by_stake_within_the_committee_bound() {
    use neutrin0_consensus_types::runtime::{BlsIdentity, ConsensusCandidate, ConsensusCandidates};
    // Two seats at this chunk size; one is held, so one candidate enters.
    let params = ConsensusParams {
        chunk_size: neutrin0_primitives::MAX_CONSENSUS_COMMITTEE_BLOCKS / 2,
        epoch_length_in_chunks: 1,
        activation_delay_epochs: 1,
        exit_delay_epochs: 1,
        ..ConsensusParams::default()
    };
    let unbonding = params.exit_accountability_blocks().unwrap();
    let mut candidates = ConsensusCandidates::default();
    for (tag, stake) in [(21_u8, 200_u128), (22, 500), (23, 300)] {
        let address = [tag; 32];
        let key = SecretKey::key_gen(&[tag; 32], &[]).unwrap();
        candidates.upsert(ConsensusCandidate {
            address,
            stake,
            identity: Some(BlsIdentity {
                pubkey: key.public_key().to_bytes(),
                pop_signature: key.prove_registration(&address).to_bytes(),
            }),
        });
    }
    let next = derive_next_validators(&[validator()], &candidates, &params, unbonding, 0).unwrap();
    // The highest stake enters first, whatever its address or arrival.
    assert_eq!(next.len(), 2);
    assert_eq!(next[1].withdrawal_credentials, [22; 32]);
    // Once active, the seat (500) outranks every waiting candidate, so the
    // full committee keeps it.
    let active = derive_next_validators(&next, &candidates, &params, unbonding, 1).unwrap();
    assert_eq!(active[1].exit_epoch, u64::MAX);
    // A waiting candidate with more stake starts the lowest seat's handoff;
    // the seat keeps its stake and weight until the exit epoch.
    let mut richer = candidates.clone();
    let mut challenger = richer.get(&[21; 32]).unwrap().clone();
    challenger.stake = 900;
    richer.upsert(challenger);
    let handoff = derive_next_validators(&active, &richer, &params, unbonding, 2).unwrap();
    assert_eq!(handoff.len(), 2);
    assert_eq!(handoff[1].exit_epoch, 4);
    assert_eq!(handoff[1].effective_stake, 500);
    // A challenger that unstakes again before the seat frees evicts nobody:
    // the handoff is cancelled at the next boundary.
    assert_eq!(
        derive_next_validators(&handoff, &candidates, &params, unbonding, 2).unwrap()[1].exit_epoch,
        u64::MAX
    );
    // A challenger whose key was not registered at its own address neither
    // starts a handoff nor keeps one alive.
    let mut forged = richer.clone();
    let mut impostor = forged.get(&[21; 32]).unwrap().clone();
    impostor.identity = forged.get(&[23; 32]).unwrap().identity;
    forged.upsert(impostor);
    assert_eq!(
        derive_next_validators(&active, &forged, &params, unbonding, 2).unwrap()[1].exit_epoch,
        u64::MAX
    );
    assert_eq!(
        derive_next_validators(&handoff, &forged, &params, unbonding, 2).unwrap()[1].exit_epoch,
        u64::MAX
    );
    // At the exit epoch the freed seat goes to the highest waiting stake.
    let replaced = derive_next_validators(&handoff, &richer, &params, unbonding, 3).unwrap();
    assert_eq!(replaced.len(), 2);
    assert_eq!(replaced[1].withdrawal_credentials, [21; 32]);
}

#[test]
fn a_copied_registration_cannot_claim_the_key_at_another_address() {
    use neutrin0_consensus_types::runtime::{BlsIdentity, ConsensusCandidate, ConsensusCandidates};
    let key = SecretKey::key_gen(&[44; 32], &[]).unwrap();
    let owner = [12; 32];
    let identity = BlsIdentity {
        pubkey: key.public_key().to_bytes(),
        pop_signature: key.prove_registration(&owner).to_bytes(),
    };
    // A squatter replays the owner's public identity from a lower address,
    // which rotation reaches first.
    let mut candidates = ConsensusCandidates::default();
    for address in [[11; 32], owner] {
        candidates.upsert(ConsensusCandidate {
            address,
            stake: 300,
            identity: Some(identity),
        });
    }
    let params = ConsensusParams {
        epoch_length_in_chunks: 1,
        ..ConsensusParams::default()
    };
    let next = derive_next_validators(
        &[validator()],
        &candidates,
        &params,
        params.exit_accountability_blocks().unwrap(),
        0,
    )
    .unwrap();
    assert_eq!(next.len(), 2);
    assert_eq!(next[1].pubkey, identity.pubkey);
    assert_eq!(next[1].withdrawal_credentials, owner);
}

fn signed_attestation(
    vote: FinalityVoteData,
    hashes: Vec<[u8; 32]>,
    unlock_quorum: Option<neutrin0_consensus_types::QuorumCertificate>,
) -> neutrin0_consensus_types::VoteAttestation {
    let message = vote.signing_message(test_domain());
    let mut claim = neutrin0_consensus_types::VoteAttestation {
        vote_signature: key().sign(&message).to_bytes(),
        validator_index: 0,
        vote,
        proof_acceptance: (!hashes.is_empty()).then(|| {
            neutrin0_consensus_types::ProofManifest {
                proof_hashes: hashes,
            }
            .commitment()
        }),
        unlock_quorum,
        signature: [0; 96],
    };
    claim.signature = key().sign(&claim.signing_message(test_domain())).to_bytes();
    claim
}

fn signed_vote(
    round: u32,
    hash: u8,
    phase: FinalityVotePhase,
) -> neutrin0_consensus_types::IndexedVote {
    let data = FinalityVoteData {
        chunk_id: 0,
        round,
        chunk_hash: [hash; 32],
        selection: [0; 32],
        phase,
    };
    let message = data.signing_message(test_domain());
    neutrin0_consensus_types::IndexedVote {
        data,
        signature: key().sign(&message).to_bytes(),
    }
}

fn signed_quorum(round: u32, hash: u8) -> neutrin0_consensus_types::QuorumCertificate {
    let vote = signed_vote(round, hash, FinalityVotePhase::Prevote);
    neutrin0_consensus_types::QuorumCertificate {
        data: vote.data,
        aggregate: AggregatedVote {
            aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
            signature: vote.signature,
        },
    }
}

#[test]
fn proof_acceptance_rejects_substitution_metadata_and_cross_chain_replay() {
    use neutrin0_prover_chunk::slashing::{verify_attestation, verify_proof_acceptance};
    let b = blocks().remove(0);
    let proof = neutrin0_consensus_types::BlockProof {
        prover_address: b.public_inputs.proposer_address,
        statement_key: [0; 32],
        height: 1,
        block_hash: b.header.hash(),
        public_inputs: b.public_inputs,
        proof_bytes: vec![11, 22, 33],
    };
    let manifest = neutrin0_consensus_types::ProofManifest {
        proof_hashes: vec![commitment(&proof), [0; 32]],
    };
    let opening = manifest.opening(0).unwrap();
    let claim = signed_attestation(
        signed_vote(0, 1, FinalityVotePhase::Precommit).data,
        manifest.proof_hashes,
        None,
    );
    assert!(verify_attestation(test_domain(), &[validator()], 0, &claim.vote, &claim).is_ok());
    assert!(verify_proof_acceptance(&claim, &proof, &opening, 2).is_ok());
    let mut other = proof.clone();
    other.proof_bytes[0] ^= 1;
    assert!(verify_proof_acceptance(&claim, &other, &opening, 2).is_err());
    other = proof.clone();
    other.public_inputs.state_root_after[0] ^= 1;
    assert!(verify_proof_acceptance(&claim, &other, &opening, 2).is_err());
    other = proof;
    other.height = 2;
    assert!(verify_proof_acceptance(&claim, &other, &opening, 2).is_err());
    assert!(
        verify_attestation(
            neutrin0_primitives::ConsensusDomain {
                chain_id: 8,
                ..test_domain()
            },
            &[validator()],
            0,
            &claim.vote,
            &claim
        )
        .is_err()
    );
    assert!(verify_proof_acceptance(&claim, &other, &opening, 0).is_err());
    let mut forged = claim;
    forged.proof_acceptance.as_mut().unwrap().root[0] ^= 1;
    assert!(verify_attestation(test_domain(), &[validator()], 0, &forged.vote, &forged).is_err());
}

#[test]
fn signed_unlock_cannot_be_omitted_or_substituted_to_slash_an_honest_voter() {
    use neutrin0_consensus_types::LockEvidence;
    use neutrin0_prover_chunk::slashing::{EvidenceError, verify_lock_violation};
    let first = signed_vote(0, 1, FinalityVotePhase::Precommit);
    let later = signed_vote(2, 2, FinalityVotePhase::Precommit);
    let mut evidence = LockEvidence {
        locked_prevote_quorum: signed_quorum(0, 1),
        attestation: signed_attestation(later.data.clone(), vec![], Some(signed_quorum(1, 2))),
    };
    let check = |evidence: &LockEvidence| {
        verify_lock_violation(
            test_domain(),
            &[validator()],
            0,
            (&first, &later),
            evidence,
            (2, 3),
        )
    };
    assert_eq!(check(&evidence), Err(EvidenceError::HonestUnlock));
    evidence.attestation.unlock_quorum = None;
    assert_eq!(check(&evidence), Err(EvidenceError::Signature));
    evidence.attestation.unlock_quorum = Some(signed_quorum(0, 1));
    assert_eq!(check(&evidence), Err(EvidenceError::Signature));
    // An explicit signed denial of any unlock is objectively different from
    // a relayer deleting someone else's valid certificate.
    evidence.attestation = signed_attestation(later.data.clone(), vec![], None);
    assert!(check(&evidence).is_ok());
    assert!(
        verify_lock_violation(
            test_domain(),
            &[validator()],
            0,
            (&later, &first),
            &evidence,
            (2, 3)
        )
        .is_err()
    );
    assert!(
        verify_lock_violation(
            test_domain(),
            &[validator()],
            0,
            (&first, &later),
            &evidence,
            (3, 2)
        )
        .is_err()
    );
}

fn attested_vote(
    data: FinalityVoteData,
    unlock: Option<neutrin0_consensus_types::QuorumCertificate>,
) -> neutrin0_consensus_types::FinalityVote {
    let hashes = if data.phase == FinalityVotePhase::Precommit {
        vec![[1; 32]; 2]
    } else {
        Vec::new()
    };
    let manifest = neutrin0_consensus_types::ProofManifest {
        proof_hashes: hashes.clone(),
    };
    let claim = signed_attestation(data.clone(), hashes, unlock);
    neutrin0_consensus_types::FinalityVote {
        proof_manifests: if data.phase == FinalityVotePhase::Precommit {
            vec![manifest]
        } else {
            Vec::new()
        },
        data,
        signature: claim.vote_signature,
        aggregation_bits: BitVec::from_bytes(1, vec![1]).unwrap(),
        attestations: vec![claim],
    }
}

#[test]
fn prevote_unlock_must_precede_its_round_while_precommit_can_use_the_current_quorum() {
    use neutrin0_prover_chunk::finality::verify_vote;
    let params = ConsensusParams {
        chunk_size: 2,
        ..ConsensusParams::default()
    };
    let active = [validator()];
    let prevote = signed_vote(2, 2, FinalityVotePhase::Prevote).data;
    let precommit = signed_vote(2, 2, FinalityVotePhase::Precommit).data;
    assert!(
        verify_vote(
            test_domain(),
            &active,
            &attested_vote(prevote.clone(), None),
            &params
        )
        .is_ok()
    );
    for data in [prevote.clone(), precommit.clone()] {
        let vote = attested_vote(data, Some(signed_quorum(1, 2)));
        verify_vote(test_domain(), &active, &vote, &params).unwrap();
        assert!(
            verify_vote(
                neutrin0_primitives::ConsensusDomain {
                    chain_id: 8,
                    ..test_domain()
                },
                &active,
                &vote,
                &params
            )
            .is_err()
        );
    }
    let self_authorizing = attested_vote(prevote, Some(signed_quorum(2, 2)));
    assert_eq!(
        verify_vote(test_domain(), &active, &self_authorizing, &params),
        Err(FinalityError::Target)
    );
    let current_precommit = attested_vote(precommit, Some(signed_quorum(2, 2)));
    verify_vote(test_domain(), &active, &current_precommit, &params).unwrap();
}

#[test]
fn signed_unlock_declarations_authenticate_every_quorum_condition() {
    use neutrin0_prover_chunk::finality::verify_vote;
    type Mutation = fn(&mut neutrin0_consensus_types::QuorumCertificate);
    let mutations: &[Mutation] = &[
        |qc| qc.data.chunk_id += 1,
        |qc| qc.data.chunk_hash[0] ^= 1,
        |qc| qc.data.round = 3,
        |qc| qc.data.phase = FinalityVotePhase::Precommit,
        |qc| qc.aggregate.signature[0] ^= 1,
        |qc| qc.aggregate.aggregation_bits = BitVec::from_bytes(1, vec![0]).unwrap(),
        |qc| qc.aggregate.aggregation_bits = BitVec::from_bytes(2, vec![1]).unwrap(),
    ];
    let params = ConsensusParams {
        chunk_size: 2,
        ..ConsensusParams::default()
    };
    for mutate in mutations {
        let mut quorum = signed_quorum(1, 2);
        mutate(&mut quorum);
        // Re-sign the declaration so its signature is valid: only the QC fails.
        let vote = attested_vote(
            signed_vote(2, 2, FinalityVotePhase::Prevote).data,
            Some(quorum),
        );
        assert!(verify_vote(test_domain(), &[validator()], &vote, &params).is_err());
    }
    let vote = attested_vote(
        signed_vote(2, 2, FinalityVotePhase::Prevote).data,
        Some(signed_quorum(1, 2)),
    );
    let mut inactive = validator();
    inactive.effective_stake = 0;
    assert!(verify_vote(test_domain(), &[inactive], &vote, &params).is_err());
    let mut wrong = vote.clone();
    wrong.attestations[0].unlock_quorum = None;
    assert!(verify_vote(test_domain(), &[validator()], &wrong, &params).is_err());
    wrong = vote;
    wrong.attestations[0].proof_acceptance = Some(
        neutrin0_consensus_types::ProofManifest {
            proof_hashes: vec![[9; 32]],
        }
        .commitment(),
    );
    assert!(verify_vote(test_domain(), &[validator()], &wrong, &params).is_err());
}

#[test]
fn authenticates_signed_bad_unlocks_for_attribution_without_admitting_them() {
    use neutrin0_prover_chunk::finality::{verify_vote, verify_vote_signatures};
    let params = ConsensusParams {
        chunk_size: 2,
        ..ConsensusParams::default()
    };
    let mut invalid = signed_quorum(1, 2);
    invalid.aggregate.signature = signed_quorum(1, 3).aggregate.signature;
    for phase in [FinalityVotePhase::Prevote, FinalityVotePhase::Precommit] {
        let vote = attested_vote(signed_vote(2, 2, phase).data, Some(invalid.clone()));
        // The signer authenticated the malformed QC; its invalidity is not a
        // reason to discard the individual evidence needed for accountability.
        verify_vote_signatures(test_domain(), &[validator()], &vote, &params).unwrap();
        assert_eq!(
            verify_vote(test_domain(), &[validator()], &vote, &params),
            Err(FinalityError::Target)
        );
        assert_eq!(
            verify_vote_signatures(
                neutrin0_primitives::ConsensusDomain {
                    chain_id: 8,
                    ..test_domain()
                },
                &[validator()],
                &vote,
                &params
            ),
            Err(FinalityError::Signature)
        );
        let mut bad = vote.clone();
        bad.attestations[0].signature[0] ^= 1;
        assert_eq!(
            verify_vote_signatures(test_domain(), &[validator()], &bad, &params),
            Err(FinalityError::Signature)
        );
        bad = vote.clone();
        bad.signature = signed_vote(2, 3, phase).signature;
        assert_eq!(
            verify_vote_signatures(test_domain(), &[validator()], &bad, &params),
            Err(FinalityError::Signature)
        );
        bad = vote;
        bad.attestations.clear();
        assert_eq!(
            verify_vote_signatures(test_domain(), &[validator()], &bad, &params),
            Err(FinalityError::Membership)
        );
    }
}

#[test]
fn conflicting_locked_prevotes_are_objectively_proven_with_direct_and_fact_verifiers() {
    use neutrin0_consensus_types::LockEvidence;
    use neutrin0_prover_chunk::{
        facts::{FactReader, FactRecorder, FactStatement, FactWitness, ProvenFact, validate_facts},
        slashing::{EvidenceError, verify_lock_violation, verify_lock_violation_using},
    };
    let first = signed_vote(0, 1, FinalityVotePhase::Precommit);
    let later = signed_vote(2, 2, FinalityVotePhase::Prevote);
    let mut false_signature = signed_quorum(1, 2);
    false_signature.aggregate.signature = signed_quorum(1, 3).aggregate.signature;
    for unlock in [
        None,
        Some(signed_quorum(0, 2)),
        Some(signed_quorum(2, 2)),
        Some(signed_quorum(3, 2)),
        Some(false_signature),
    ] {
        let evidence = LockEvidence {
            locked_prevote_quorum: signed_quorum(0, 1),
            attestation: signed_attestation(later.data.clone(), Vec::new(), unlock),
        };
        verify_lock_violation(
            test_domain(),
            &[validator()],
            0,
            (&first, &later),
            &evidence,
            (2, 3),
        )
        .unwrap();
        let mut recorder = FactRecorder::default();
        verify_lock_violation_using(
            test_domain(),
            &[validator()],
            0,
            (&first, &later),
            &evidence,
            (2, 3),
            &mut recorder,
        )
        .unwrap();
        let checks = recorder.finish().unwrap();
        let facts = validate_facts(&FactWitness {
            requests: checks.iter().map(|(request, _)| request.clone()).collect(),
            statement: FactStatement {
                facts: checks
                    .iter()
                    .map(|(request, valid)| ProvenFact {
                        id: request.id(),
                        valid: *valid,
                    })
                    .collect(),
            },
        })
        .unwrap();
        let mut reader = FactReader::new(&[facts]).unwrap();
        verify_lock_violation_using(
            test_domain(),
            &[validator()],
            0,
            (&first, &later),
            &evidence,
            (2, 3),
            &mut reader,
        )
        .unwrap();
        assert!(reader.complete());
    }
    let mut honest = LockEvidence {
        locked_prevote_quorum: signed_quorum(0, 1),
        attestation: signed_attestation(later.data.clone(), Vec::new(), Some(signed_quorum(1, 2))),
    };
    assert_eq!(
        verify_lock_violation(
            test_domain(),
            &[validator()],
            0,
            (&first, &later),
            &honest,
            (2, 3)
        ),
        Err(EvidenceError::HonestUnlock)
    );
    honest.attestation.unlock_quorum = None;
    assert_eq!(
        verify_lock_violation(
            test_domain(),
            &[validator()],
            0,
            (&first, &later),
            &honest,
            (2, 3)
        ),
        Err(EvidenceError::Signature)
    );
}

#[test]
fn quorum_thresholds_cannot_bypass_the_bft_intersection_requirement() {
    use neutrin0_prover_chunk::slashing::verify_quorum;
    let candidate = chunk();
    let cert = certificate(&candidate);
    let quorum = signed_quorum(0, 1);
    for (numerator, denominator) in [(1, 2), (1, 3), (0, 1), (2, 1)] {
        let params = ConsensusParams {
            chunk_size: 2,
            bft_prevote_quorum_numerator: numerator,
            bft_prevote_quorum_denominator: denominator,
            ..ConsensusParams::default()
        };
        assert!(
            verify_finality(
                test_domain(),
                &params,
                &[validator()],
                &TEST_SEED,
                &candidate,
                &cert
            )
            .is_err()
        );
        assert!(
            verify_quorum(
                test_domain(),
                &[validator()],
                &quorum,
                (numerator, denominator)
            )
            .is_err()
        );
    }
    for fraction in [(2, 3), (3, 4), (u64::MAX, u64::MAX)] {
        verify_quorum(test_domain(), &[validator()], &quorum, fraction).unwrap();
    }
}

#[test]
fn unlock_quorum_crypto_obeys_the_same_batched_and_direct_decision() {
    use neutrin0_prover_chunk::{
        bls::BatchVerifier,
        finality::{verify_vote, verify_vote_using},
    };
    let params = ConsensusParams {
        chunk_size: 2,
        ..ConsensusParams::default()
    };
    for valid in [true, false] {
        let mut quorum = signed_quorum(1, 2);
        if !valid {
            // Both are valid curve points, but the replacement signs another target.
            quorum.aggregate.signature = signed_quorum(1, 3).aggregate.signature;
        }
        let vote = attested_vote(
            signed_vote(2, 2, FinalityVotePhase::Prevote).data,
            Some(quorum),
        );
        let mut batch = BatchVerifier::default();
        let framed =
            verify_vote_using(test_domain(), &[validator()], &vote, &params, &mut batch).is_ok();
        assert_eq!(framed && batch.finish(), valid);
        assert_eq!(
            verify_vote(test_domain(), &[validator()], &vote, &params).is_ok(),
            valid
        );
    }
}

#[test]
fn exhausted_genesis_account_cannot_recover_declared_genesis_stake() {
    use neutrin0_consensus_types::runtime::{
        CONSENSUS_CANDIDATES_KEY, ConsensusCandidate, ConsensusCandidates,
    };
    use neutrin0_prover_chunk::rotation::{rotate_from_witness, witness_keys_from};
    use neutrin0_runtime_core::host::{LiveTrie, TracingState};
    let previous = vec![validator()];
    // The runtime projects an exhausted record as an authenticated zero.
    let mut candidates = ConsensusCandidates::default();
    candidates.upsert(ConsensusCandidate {
        address: previous[0].withdrawal_credentials,
        stake: 0,
        identity: None,
    });
    let mut live = LiveTrie::default();
    live.insert(
        CONSENSUS_CANDIDATES_KEY,
        borsh::to_vec(&candidates).unwrap(),
    );
    let mut state = TracingState::new(&live);
    witness_keys_from(&mut state);
    let witness = state.into_witness().unwrap();
    let next = rotate_from_witness(
        &previous,
        &ConsensusParams::default(),
        ConsensusParams::default()
            .exit_accountability_blocks()
            .unwrap(),
        0,
        witness.pre_state_root,
        &witness,
    )
    .unwrap();
    assert_eq!(next[0].effective_stake, previous[0].effective_stake);
    assert_ne!(next[0].exit_epoch, u64::MAX);
}

#[test]
fn epoch_zero_registration_exits_even_with_zero_activation_delay() {
    use neutrin0_consensus_types::runtime::{ConsensusCandidate, ConsensusCandidates};
    let registered = validator();
    let mut candidates = ConsensusCandidates::default();
    candidates.upsert(ConsensusCandidate {
        address: registered.withdrawal_credentials,
        stake: 0,
        identity: None,
    });
    let params = ConsensusParams {
        epoch_length_in_chunks: 10,
        activation_delay_epochs: 0,
        ..ConsensusParams::default()
    };
    let next = derive_next_validators(
        &[registered],
        &candidates,
        &params,
        params.exit_accountability_blocks().unwrap(),
        0,
    )
    .unwrap();
    assert_eq!(next[0].effective_stake, validator().effective_stake);
    assert_eq!(next[0].exit_epoch, params.exit_delay_epochs);
}

/// A seated genesis validator, runtime-backed when the candidate record lists it.
const fn staked_seat(byte: u8) -> Validator {
    Validator {
        pubkey: [byte; 48],
        withdrawal_credentials: neutrin0_primitives::runtime_account([byte; 20]),
        effective_stake: 1,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }
}

/// Genesis runtime records, without BLS identities, for `(address byte, stake)`.
fn runtime_stakes(stakes: &[(u8, u128)]) -> neutrin0_consensus_types::runtime::ConsensusCandidates {
    let mut candidates = neutrin0_consensus_types::runtime::ConsensusCandidates::default();
    for &(byte, stake) in stakes {
        candidates.upsert(neutrin0_consensus_types::runtime::ConsensusCandidate {
            address: neutrin0_primitives::runtime_account([byte; 20]),
            stake,
            identity: None,
        });
    }
    candidates
}

fn weights(seats: &[Validator]) -> Vec<u128> {
    seats.iter().map(|seat| seat.effective_stake).collect()
}

#[test]
fn rotation_weights_runtime_stake_in_wei_unchanged() {
    let params = ConsensusParams::default();
    let unbonding = params.exit_accountability_blocks().unwrap();
    let previous = [staked_seat(1), staked_seat(2), staked_seat(3)];
    // 32-token stakes exceed `u64`; weights keep them exactly, dust included.
    let token = neutrin0_primitives::WEI_PER_TOKEN;
    let candidates = runtime_stakes(&[(1, 96 * token), (2, 32 * token), (3, 1)]);
    let next = derive_next_validators(&previous, &candidates, &params, unbonding, 0).unwrap();
    assert_eq!(weights(&next), [96 * token, 32 * token, 1]);
    assert!(next.iter().all(|seat| seat.exit_epoch == u64::MAX));
    let maximal = runtime_stakes(&[(1, u128::MAX)]);
    let next = derive_next_validators(&previous[..1], &maximal, &params, unbonding, 0).unwrap();
    assert_eq!(weights(&next), [u128::MAX]);
}

#[test]
fn rotation_refuses_a_set_whose_total_exceeds_u128() {
    use neutrin0_prover_chunk::rotation::RotationError;
    let params = ConsensusParams::default();
    let unbonding = params.exit_accountability_blocks().unwrap();
    // Seat 9 has no runtime record, so it keeps its specification weight
    // beside the runtime stake.
    let mut genesis = staked_seat(9);
    genesis.effective_stake = neutrin0_primitives::MAX_TOTAL_STAKE;
    let previous = [staked_seat(1), genesis];
    let fits = runtime_stakes(&[(1, neutrin0_primitives::MAX_TOTAL_STAKE)]);
    let next = derive_next_validators(&previous, &fits, &params, unbonding, 0).unwrap();
    assert_eq!(
        weights(&next),
        [
            neutrin0_primitives::MAX_TOTAL_STAKE,
            neutrin0_primitives::MAX_TOTAL_STAKE
        ]
    );
    let over = runtime_stakes(&[(1, neutrin0_primitives::MAX_TOTAL_STAKE + 2)]);
    assert_eq!(
        derive_next_validators(&previous, &over, &params, unbonding, 0),
        Err(RotationError::Stake)
    );
}

#[test]
fn program_rotation_reads_only_the_proven_end_state() {
    use neutrin0_consensus_types::history_proof::{
        ExecutionPrograms, ProgramArtifacts, ProgramSet, ScheduledUpgrade,
    };
    use neutrin0_consensus_types::runtime::UPGRADE_KEY;
    use neutrin0_prover_chunk::rotation::{
        RotationError, next_programs_from_witness, rotate_from_witness, witness_keys_from,
    };
    use neutrin0_runtime_core::host::{LiveTrie, TracingState};
    let programs = |byte: u8| ProgramSet {
        runtime_code_hash: [byte; 32],
        execution: ExecutionPrograms {
            fact: [1; 8],
            evidence: [u32::from(byte); 8],
            block: [u32::from(byte); 8],
        },
    };
    let witness_of = |live: &LiveTrie| {
        let mut state = TracingState::new(live);
        witness_keys_from(&mut state);
        state.into_witness().unwrap()
    };
    let current = programs(1);
    let mut honest = LiveTrie::default();
    honest.insert(b"unrelated", vec![1]);
    let root = honest.state_root();
    assert_eq!(
        next_programs_from_witness(current, 5, root, &witness_of(&honest)),
        Ok(current)
    );
    // A forged state schedules its own programs and yields a self-consistent
    // witness, but that witness is not rooted at the proven end state.
    let mut forged = LiveTrie::default();
    let upgrade = ScheduledUpgrade {
        activate_at_chunk: 5,
        programs: programs(2),
        artifacts: ProgramArtifacts::default(),
        available: true,
    };
    forged.insert(UPGRADE_KEY, borsh::to_vec(&upgrade).unwrap());
    let forged_witness = witness_of(&forged);
    let forged_root = forged_witness.pre_state_root;
    assert_eq!(
        next_programs_from_witness(current, 5, forged_root, &forged_witness),
        Ok(programs(2))
    );
    assert_eq!(
        next_programs_from_witness(current, 5, root, &forged_witness),
        Err(RotationError::StateRoot)
    );
    // A schedule whose artifacts were never completely published is void at
    // its activation boundary.
    let mut unpublished = LiveTrie::default();
    unpublished.insert(
        UPGRADE_KEY,
        borsh::to_vec(&ScheduledUpgrade {
            available: false,
            ..upgrade
        })
        .unwrap(),
    );
    let unpublished = witness_of(&unpublished);
    assert_eq!(
        next_programs_from_witness(current, 5, unpublished.pre_state_root, &unpublished),
        Ok(current)
    );
    // Both readers of the chunk-end witness reject it with the same error.
    let params = ConsensusParams::default();
    let unbonding = params.exit_accountability_blocks().unwrap();
    let previous = [validator()];
    assert_eq!(
        rotate_from_witness(&previous, &params, unbonding, 4, root, &forged_witness),
        Err(RotationError::StateRoot)
    );
    // Even genuinely authenticated runtime state cannot schedule new crypto
    // semantics. The incoming Fact identity is an immutable chain pin, so a
    // schedule replacing it is void, as is one that does not decode.
    let mut forbidden = upgrade;
    forbidden.programs.execution.fact = [9; 8];
    let mut undecodable = borsh::to_vec(&upgrade).unwrap();
    undecodable.push(0);
    for record in [borsh::to_vec(&forbidden).unwrap(), undecodable] {
        forged.insert(UPGRADE_KEY, record);
        let witness = witness_of(&forged);
        for next_chunk in [4, 5, 6] {
            assert_eq!(
                next_programs_from_witness(current, next_chunk, witness.pre_state_root, &witness),
                Ok(current),
            );
        }
    }
}

#[test]
fn rotation_rejects_zero_successor_and_certificate_budget_overflow() {
    use neutrin0_prover_chunk::rotation::RotationError;
    let params = ConsensusParams::default();
    let unbonding = params.exit_accountability_blocks().unwrap();
    let drained = runtime_stakes(&[(1, 0)]);
    // The unbonding delay must cover the exit delay and the two chunks the
    // exiting seat still signs into.
    assert_eq!(
        derive_next_validators(&[staked_seat(1)], &drained, &params, unbonding - 1, 0),
        Err(RotationError::Epoch)
    );
    let exiting =
        derive_next_validators(&[staked_seat(1)], &drained, &params, unbonding, 0).unwrap();
    assert_eq!(exiting[0].effective_stake, 1);
    let last_chunk = exiting[0].exit_epoch * params.epoch_length_in_chunks - 1;
    assert_eq!(
        derive_next_validators(&exiting, &drained, &params, unbonding, last_chunk),
        Err(RotationError::Committee)
    );
    let too_many = vec![staked_seat(1); neutrin0_primitives::MAX_CONSENSUS_VALIDATORS + 1];
    assert_eq!(
        derive_next_validators(&too_many, &runtime_stakes(&[]), &params, unbonding, 0),
        Err(RotationError::Committee)
    );
    let oversized = ConsensusParams {
        chunk_size: 8193,
        ..params
    };
    assert_eq!(
        derive_next_validators(
            &[staked_seat(1), staked_seat(2)],
            &runtime_stakes(&[]),
            &oversized,
            oversized.chunk_size * 3,
            0
        ),
        Err(RotationError::Committee)
    );
}
