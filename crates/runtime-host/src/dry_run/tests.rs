use super::*;

#[test]
fn dry_run_of_empty_block_touches_only_block_records() {
    use neutrin0_runtime_abi::{RuntimeGenesisInput, ethereum::EvmGenesisConfig};
    // The runtime needs its genesis records (fee state, environment and
    // the system policy) before any block executes.
    let genesis = RuntimeGenesisInput {
        max_block_proving_input_bytes: neutrin0_primitives::DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES,
        chain_id: 1,
        timestamp: 0,
        seed: [0; 32],
        genesis_block_hash: [0; 32],
        chunk_size: neutrin0_primitives::DEFAULT_CHUNK_SIZE,
        programs: neutrin0_primitives::ProgramSet {
            runtime_code_hash: [0; 32],
            execution: neutrin0_primitives::ExecutionPrograms {
                fact: [0; 8],
                evidence: [0; 8],
                block: [0; 8],
            },
        },
        block_gas_limit: 30_000_000,
        runtime_params: neutrin0_primitives::RuntimeParams::default(),
        validators: Vec::new(),
        configuration: borsh::to_vec(&EvmGenesisConfig {
            initial_base_fee: 1_000_000_000,
            accounts: Vec::new(),
        })
        .unwrap(),
    };
    let empty = LiveTrie::default();
    let mut tracer = TracingState::new(&empty);
    neutrin0_evm_runtime_core::init_genesis(&genesis, &mut tracer);
    let (trie, _) = tracer.into_committed_and_witness().unwrap();
    let live = LiveTrie::from_trie(trie);
    let context = neutrin0_consensus_types::runtime::ConsensusExecutionContext {
        timestamp: 1,
        slot: 1,
        ..Default::default()
    };
    let DryRun {
        artifacts: _,
        output,
        witness,
        post_state,
        writes,
    } = dry_run(
        &RuntimeBlockInput {
            active_validators: Vec::new(),
            participation_acks: Vec::new(),
            program_pieces: Vec::new(),
            context,
            evidence_anchor: neutrin0_consensus_types::evidence::EvidenceAnchor::default(),
            chain_id: 1,
            block_height: 1,
            block_gas_limit: 30_000_000,
            proposer_address: [0u8; 32],
            participation: None,
            proving: None,
            transactions: Vec::new(),
        },
        &live,
        &[],
    )
    .unwrap();
    assert_eq!(output.applied, 0);
    assert_eq!(output.failed, 0);
    assert_eq!(output.pre_state_root, live.state_root());
    assert_eq!(output.post_state_root, post_state.root());
    // The recorded diff replays the exact post-state over the pre-state.
    let mut replayed = live.trie().clone();
    for write in &writes {
        match &write.value {
            Some(value) => replayed.insert(&write.key, value.clone()).unwrap(),
            None => {
                replayed.remove(&write.key).unwrap();
            }
        }
    }
    assert_eq!(replayed.root(), post_state.root());
    // Empty blocks still inspect pending mandatory sanctions, the runtime
    // policy, the consensus candidate record they commit and the
    // schedule, fork and piece records block-start housekeeping expires.
    // The governance slots are read only by transactions acting on them.
    for key in [
        neutrin0_runtime_system::accountability::QUEUE_KEY,
        neutrin0_consensus_types::runtime::CONSENSUS_CANDIDATES_KEY,
        neutrin0_runtime_system::RUNTIME_POLICY_KEY,
        neutrin0_consensus_types::runtime::UPGRADE_KEY,
        neutrin0_consensus_types::runtime::FORK_KEY,
        neutrin0_runtime_system::governance::UPGRADE_PIECES_KEY,
    ] {
        assert!(witness.witnessed_keys.contains(&key.to_vec()));
    }
    for key in [
        neutrin0_runtime_system::governance::UPGRADE_PROPOSALS_KEY,
        neutrin0_runtime_system::governance::POLICY_PROPOSALS_KEY,
        neutrin0_runtime_system::governance::FORK_PROPOSALS_KEY,
    ] {
        assert!(!witness.witnessed_keys.contains(&key.to_vec()));
    }
}
