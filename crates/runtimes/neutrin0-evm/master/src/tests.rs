use super::*;
use neutrin0_runtime_abi::{RuntimeGenesisInput, ethereum::EvmGenesisConfig};
use neutrin0_runtime_core::host::{LiveTrie, TracingState};

#[test]
fn apply_block_with_witness_replays_the_native_empty_block() {
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
    runtime::init_genesis(&genesis, &mut tracer);
    let (trie, _) = tracer.into_committed_and_witness().unwrap();
    let live = LiveTrie::from_trie(trie);
    let context = neutrin0_consensus_types::runtime::ConsensusExecutionContext {
        timestamp: 1,
        slot: 1,
        ..Default::default()
    };
    let input = RuntimeBlockInput {
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
        transactions: alloc::vec![],
    };
    // Trace the native execution to obtain the witness the Guest replays.
    let mut tracer = TracingState::new(&live);
    let native = runtime::apply_block(&input, &mut tracer);
    let (_, witness) = tracer.into_committed_and_witness().unwrap();
    let bytes = borsh::to_vec(&(input, witness)).unwrap();
    let out_bytes = apply_block_with_witness(&bytes);
    let out: RuntimeBlockOutput = borsh::from_slice(&out_bytes).unwrap();
    assert_eq!(out, native);
    assert_eq!(out.applied, 0);
    assert_eq!(out.failed, 0);
    assert_eq!(out.pre_state_root, live.state_root());
}
