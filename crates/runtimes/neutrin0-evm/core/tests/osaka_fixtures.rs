//! Independently filled Osaka transitions from official EEST v5.4.0.
//! Ethereum system-block operations and MPT roots are outside the Neutrin0 runtime;
//! exact signed transactions, application state and EVM gas remain unchanged.
use alloy_primitives::{Address, U256, keccak256};
use neutrin0_runtime_abi::{
    RuntimeBlockInput, RuntimeGenesisInput, RuntimeTransaction,
    ethereum::{EvmGenesisConfig, GenesisAccount},
};
use neutrin0_runtime_core::{
    StateBackend, WitnessState,
    host::{LiveTrie, TracingState},
};
use serde_json::Value;

fn quantity(value: &Value) -> U256 {
    U256::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}
fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn address(value: &str) -> Address {
    Address::from_slice(&hex::decode(value.trim_start_matches("0x")).unwrap())
}
fn accounts(value: &Value) -> Vec<GenesisAccount> {
    value
        .as_object()
        .unwrap()
        .iter()
        .map(|(key, account)| GenesisAccount {
            address: address(key).into_array(),
            balance: quantity(&account["balance"]).to_be_bytes(),
            nonce: quantity(&account["nonce"]).try_into().unwrap(),
            code: bytes(&account["code"]),
            storage: account["storage"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| {
                    (
                        quantity(&Value::String(key.clone())).to_be_bytes(),
                        quantity(value).to_be_bytes(),
                    )
                })
                .collect(),
        })
        .collect()
}
#[test]
#[allow(clippy::too_many_lines)] // One independent transition compares gas, all application accounts and witness replay.
fn official_osaka_application_state_and_gas_match_with_witness_replay() {
    let fixtures: Vec<Value> = serde_json::from_str(include_str!("fixtures/osaka.json")).unwrap();
    assert_eq!(fixtures.len(), 22);
    for fixture in fixtures {
        let name = fixture["name"].as_str().unwrap();
        let gas_limit: u64 = quantity(&fixture["gas_limit"]).try_into().unwrap();
        let empty = LiveTrie::default();
        let mut state = TracingState::new(&empty);
        let genesis = RuntimeGenesisInput {
            max_block_proving_input_bytes:
                neutrin0_primitives::DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES,
            chain_id: 1,
            timestamp: 0,
            seed: bytes(&fixture["seed"]).try_into().unwrap(),
            genesis_block_hash: bytes(&fixture["parent"]).try_into().unwrap(),
            chunk_size: 64,
            programs: neutrin0_primitives::ProgramSet {
                runtime_code_hash: [1; 32],
                execution: neutrin0_primitives::ExecutionPrograms {
                    fact: [1; 8],
                    evidence: [2; 8],
                    block: [3; 8],
                },
            },
            block_gas_limit: gas_limit,
            runtime_params: neutrin0_primitives::RuntimeParams::default(),
            validators: vec![],
            configuration: borsh::to_vec(&EvmGenesisConfig {
                initial_base_fee: quantity(&fixture["base_fee"]).try_into().unwrap(),
                accounts: accounts(&fixture["pre"]),
            })
            .unwrap(),
        };
        neutrin0_evm_runtime_core::init_genesis(&genesis, &mut state);
        let pre = LiveTrie::from_trie(state.into_committed_and_witness().unwrap().0);
        let context = neutrin0_consensus_types::runtime::ConsensusExecutionContext {
            slot: 1,
            timestamp: quantity(&fixture["timestamp"]).try_into().unwrap(),
            parent_block_hash: genesis.genesis_block_hash,
            finalized: neutrin0_consensus_types::history_proof::ConsensusBoundary {
                seed: genesis.seed,
                ..neutrin0_consensus_types::runtime::ConsensusExecutionContext::default().finalized
            },
            ..neutrin0_consensus_types::runtime::ConsensusExecutionContext::default()
        };
        let input = RuntimeBlockInput {
            active_validators: Vec::new(),
            participation_acks: Vec::new(),
            program_pieces: Vec::new(),

            context,
            evidence_anchor: neutrin0_consensus_types::evidence::EvidenceAnchor::default(),
            chain_id: 1,
            block_height: 1,
            block_gas_limit: gas_limit,
            proposer_address: neutrin0_evm_runtime_core::state::consensus_address(address(
                fixture["coinbase"].as_str().unwrap(),
            )),
            participation: None,
            proving: None,
            transactions: fixture["transactions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|raw| RuntimeTransaction::User(bytes(raw)))
                .collect(),
        };
        let mut trace = TracingState::new(&pre);
        let result = neutrin0_evm_runtime_core::execute_block(&input, &mut trace);
        assert_eq!(
            U256::from(result.output.gas_used),
            quantity(&fixture["gas"]),
            "{name}: gas"
        );
        let (post, witness) = trace.into_committed_and_witness().unwrap();
        let mut replay = WitnessState::new(&witness).unwrap();
        assert_eq!(
            neutrin0_evm_runtime_core::execute_block(&input, &mut replay),
            result,
            "{name}: replay"
        );
        assert_eq!(replay.post_state_root(), post.root(), "{name}: root");
        // Design 08: the coinbase keeps only the tips, exactly as in
        // Ethereum, and the base fee leaves the burned supply for the proof
        // market's escrow, so every account matches the Ethereum post-state.
        let post = LiveTrie::from_trie(post);
        let mut trace = TracingState::new(&post);
        for expected in accounts(&fixture["post"]) {
            let account = neutrin0_evm_runtime_core::state::load_account(
                &mut trace,
                Address::from(expected.address),
            )
            .unwrap()
            .unwrap_or_default();
            assert_eq!(
                account.balance, expected.balance,
                "{name}: balance {:?}",
                expected.address
            );
            assert_eq!(
                account.nonce, expected.nonce,
                "{name}: nonce {:?}",
                expected.address
            );
            assert_eq!(
                account.code_hash,
                keccak256(&expected.code).0,
                "{name}: code {:?}",
                expected.address
            );
            for (slot, value) in expected.storage {
                let actual = trace
                    .read(&neutrin0_evm_runtime_core::state::storage_key(
                        Address::from(expected.address),
                        U256::from_be_bytes(slot),
                    ))
                    .unwrap_or_else(|| vec![0; 32]);
                assert_eq!(actual, value, "{name}: storage {slot:?}");
            }
        }
    }
}
