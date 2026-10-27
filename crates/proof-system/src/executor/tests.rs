use super::*;

fn context() -> BlockExecutionContext {
    let mut context = neutrin0_consensus_types::runtime::ConsensusExecutionContext::default();
    context.finalized.participation = [3; 32];
    context.finalized.proving = [4; 32];
    BlockExecutionContext {
        context,
        active_validators: Vec::new(),
        evidence_anchor: neutrin0_consensus_types::evidence::EvidenceAnchor::default(),
        runtime_code_hash: [0; 32],
        chain_id: 7,
        block_height: 9,
        gas_limit: 1_000_000,
        proposer_address: [2; 32],
        participation: None,
        proving: None,
        participation_acks: Vec::new(),
        program_pieces: Vec::new(),
    }
}

#[test]
fn a_block_before_the_carrier_declares_the_start_boundarys_reports() {
    let mut ctx = context();
    let acks = neutrin0_consensus_types::participation::acknowledgement_commitment(&[]);
    assert_eq!(
        ctx.inputs_root(),
        neutrin0_consensus_types::runtime::execution_inputs_root(
            &ctx.context,
            [3; 32],
            acks,
            [4; 32],
            [0; 32],
            &ctx.evidence_anchor,
        )
    );
    let participation = neutrin0_consensus_types::participation::ParticipationReport {
        chunk_id: 5,
        ..Default::default()
    };
    let proving = neutrin0_consensus_types::proving::ProvingReport {
        chunk_id: 5,
        ..Default::default()
    };
    let expected = neutrin0_consensus_types::runtime::execution_inputs_root(
        &ctx.context,
        participation.commitment(),
        acks,
        proving.commitment(),
        [0; 32],
        &ctx.evidence_anchor,
    );
    ctx.participation = Some(participation);
    ctx.proving = Some(proving);
    assert_eq!(ctx.inputs_root(), expected);
}
