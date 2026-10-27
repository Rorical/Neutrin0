use super::*;
use alloc::{vec, vec::Vec};

fn input() -> RuntimeBlockInput {
    RuntimeBlockInput {
        context: neutrin0_consensus_types::runtime::ConsensusExecutionContext::default(),
        active_validators: Vec::new(),
        evidence_anchor: neutrin0_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: 7,
        block_height: 1,
        block_gas_limit: 1_000_000,
        proposer_address: [0; 32],
        participation: None,
        proving: None,
        participation_acks: Vec::new(),
        program_pieces: Vec::new(),
        transactions: Vec::new(),
    }
}

#[test]
fn forged_committee_and_late_or_duplicate_acknowledgements_fail_before_execution() {
    let mut forged = input();
    forged.context.finalized.validators_root[0] ^= 1;
    assert_eq!(
        check_runtime_input(&forged),
        Err(RuntimeInputError::Validators)
    );
    let mut input = input();
    input.context.finalized.next_chunk_id = 2;
    input.participation_acks.push(
        neutrin0_consensus_types::participation::ParticipationAcknowledgement {
            chunk_id: 0,
            identity: [1; 48],
            address: [2; 32],
        },
    );
    assert!(check_runtime_input(&input).is_ok());
    let mut late = input.clone();
    late.context.finalized.next_chunk_id = 3;
    assert_eq!(
        check_runtime_input(&late),
        Err(RuntimeInputError::Participation)
    );
    input
        .participation_acks
        .push(input.participation_acks[0].clone());
    assert_eq!(
        check_runtime_input(&input),
        Err(RuntimeInputError::Participation)
    );
}

#[test]
fn one_source_chunk_cannot_carry_more_acknowledgements_than_a_committee() {
    let ack = |chunk_id, index: u16| {
        let mut identity = [0; 48];
        identity[..2].copy_from_slice(&index.to_be_bytes());
        neutrin0_consensus_types::participation::ParticipationAcknowledgement {
            chunk_id,
            identity,
            address: [2; 32],
        }
    };
    let committee = u16::try_from(neutrin0_primitives::MAX_CONSENSUS_VALIDATORS).unwrap();
    let mut input = input();
    input.context.finalized.next_chunk_id = 2;
    // Two source chunks may each hold a full committee.
    input.participation_acks = (0..committee)
        .map(|index| ack(0, index))
        .chain((0..committee).map(|index| ack(1, index)))
        .collect();
    assert!(check_runtime_input(&input).is_ok());
    input.participation_acks = (0..=committee).map(|index| ack(0, index)).collect();
    assert_eq!(
        check_runtime_input(&input),
        Err(RuntimeInputError::Participation)
    );
}

#[test]
fn a_block_without_reports_binds_the_start_boundarys_commitments() {
    use neutrin0_consensus_types::participation::{
        NO_PARTICIPATION, ParticipationReport, acknowledgement_commitment,
    };
    use neutrin0_consensus_types::proving::{NO_PROVING, ProvingReport};
    let mut input = input();
    input.context.finalized.participation = [3; 32];
    input.context.finalized.proving = [4; 32];
    let (transactions_root, transaction_summary) = transaction_commitments(&input.transactions);
    let mut output = neutrin0_runtime_abi::RuntimeBlockOutput {
        context: input.context,
        chain_id: input.chain_id,
        block_height: input.block_height,
        block_gas_limit: input.block_gas_limit,
        proposer_address: input.proposer_address,
        participation: [3; 32],
        proving: [4; 32],
        participation_acks: acknowledgement_commitment(&input.participation_acks),
        transactions_root,
        transaction_summary,
        pre_state_root: [1; 32],
        post_state_root: [2; 32],
        ..Default::default()
    };
    output.accountability.anchor = input.evidence_anchor;
    // A block before its chunk's carrier commits the start boundary's
    // reports, not the empty commitments of a missing report.
    assert!(output_binds_input(&input, &output, [1; 32], [2; 32]));
    let mut empty = output.clone();
    empty.participation = NO_PARTICIPATION;
    assert!(!output_binds_input(&input, &empty, [1; 32], [2; 32]));
    let mut empty = output.clone();
    empty.proving = NO_PROVING;
    assert!(!output_binds_input(&input, &empty, [1; 32], [2; 32]));
    // The carrier and later blocks bind the reports they consume.
    let participation = ParticipationReport {
        chunk_id: 5,
        ..ParticipationReport::default()
    };
    let proving = ProvingReport {
        chunk_id: 5,
        ..ProvingReport::default()
    };
    output.participation = participation.commitment();
    output.proving = proving.commitment();
    assert!(!output_binds_input(&input, &output, [1; 32], [2; 32]));
    input.participation = Some(participation);
    input.proving = Some(proving);
    assert!(output_binds_input(&input, &output, [1; 32], [2; 32]));
}

#[test]
fn commitments_match_body_roots_and_bind_count() {
    let tx = RuntimeTransaction::User(b"application:transfer".to_vec());
    for transactions in [vec![], vec![tx.clone()], vec![tx.clone(), tx]] {
        let blobs: Vec<_> = transactions
            .iter()
            .map(|tx| borsh::to_vec(tx).unwrap())
            .collect();
        let (root, summary) = transaction_commitments(&transactions);
        assert_eq!(
            root,
            neutrin0_primitives::transactions_root_of_blobs(&blobs)
        );
        assert_eq!(summary.transaction_count as usize, transactions.len());
    }
}
