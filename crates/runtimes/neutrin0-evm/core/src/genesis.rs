//! Deterministic EVM allocations and system state initialization.

use crate::state::{EvmAccount, store_account, write_record};
use alloc::{collections::BTreeSet, vec::Vec};
pub use neutrin0_runtime_abi::ethereum::{EvmGenesisConfig, GenesisAccount};
use neutrin0_runtime_abi::{RuntimeGenesisInput, RuntimeGenesisOutput};
use neutrin0_runtime_core::StateBackend;
use revm::primitives::{Address, U256, keccak256};

/// Initialize EVM accounts, bounded history and native consensus economics.
pub fn init_genesis<B: StateBackend>(
    input: &RuntimeGenesisInput,
    state: &mut B,
) -> RuntimeGenesisOutput {
    assert!(
        input.max_block_proving_input_bytes > 0
            && input.max_block_proving_input_bytes
                <= neutrin0_primitives::MAX_BLOCK_PROVING_INPUT_BYTES,
        "valid genesis proving allocation limit"
    );
    assert_eq!(
        state.pre_state_root(),
        neutrin0_runtime_core::empty_state_root(),
        "genesis requires empty state"
    );
    let config: EvmGenesisConfig =
        borsh::from_slice(&input.configuration).expect("canonical EVM genesis configuration");
    assert!(
        config.initial_base_fee > 0 && input.block_gas_limit >= 2,
        "positive EVM fee environment"
    );
    let mut supply = U256::ZERO;
    allocate_accounts(state, config.accounts, &mut supply);
    let escrow = genesis_collateral(input, &mut supply);
    seed_reserved_accounts(state, escrow);
    write_record(state, b"evm:genesis_supply", &supply.to_be_bytes::<32>());
    write_record(
        state,
        crate::fees::FEE_STATE_KEY,
        &crate::fees::FeeState {
            height: 0,
            next_base_fee: config.initial_base_fee,
        },
    );
    seed_environment(input, state);
    neutrin0_runtime_system::system::initialize_genesis(
        state,
        &input.validators,
        &neutrin0_runtime_system::system::genesis_policy(input),
    );
    RuntimeGenesisOutput {
        state_root: state.post_state_root(),
        consensus_candidates_root: neutrin0_runtime_system::load_consensus_candidates(state).root(),
    }
}

fn allocate_accounts<B: StateBackend>(
    state: &mut B,
    accounts: Vec<GenesisAccount>,
    supply: &mut U256,
) {
    let mut seen = BTreeSet::new();
    for entry in accounts {
        assert!(
            seen.insert(entry.address),
            "duplicate Ethereum genesis account"
        );
        assert!(entry.code.len() <= 24_576, "genesis contract code limit");
        assert!(
            revm::bytecode::Bytecode::new_raw_checked(entry.code.clone().into()).is_ok(),
            "canonical genesis Ethereum bytecode"
        );
        assert!(
            !entry.code.is_empty() || entry.storage.is_empty(),
            "EOA cannot carry storage"
        );
        let address = Address::from(entry.address);
        assert!(
            !crate::addresses::RESERVED.contains(&address),
            "genesis allocation cannot replace a system account"
        );
        let hash = keccak256(&entry.code);
        let balance = U256::from_be_bytes(entry.balance);
        *supply = supply
            .checked_add(balance)
            .expect("genesis supply overflow");
        store_account(
            state,
            address,
            &EvmAccount {
                balance: entry.balance,
                nonce: entry.nonce,
                code_hash: hash.0,
            },
        );
        if !entry.code.is_empty() {
            state.write(&crate::state::code_key(hash), entry.code);
        }
        let mut slots = BTreeSet::new();
        for (slot, value) in entry.storage {
            assert!(slots.insert(slot), "duplicate genesis storage slot");
            if value != [0; 32] {
                state.write(
                    &crate::state::storage_key(address, U256::from_be_bytes(slot)),
                    value.to_vec(),
                );
            }
        }
    }
}

fn seed_reserved_accounts<B: StateBackend>(state: &mut B, escrow: U256) {
    let marker = alloc::vec![0]; // STOP: native dispatch handles protected entrypoints.
    let marker_hash = keccak256(&marker);
    state.write(&crate::state::code_key(marker_hash), marker);
    for address in crate::addresses::RESERVED {
        store_account(
            state,
            address,
            &EvmAccount {
                nonce: 1,
                balance: if address == crate::addresses::ESCROW {
                    escrow.to_be_bytes()
                } else {
                    [0; 32]
                },
                code_hash: marker_hash.0,
            },
        );
    }
}

fn seed_environment<B: StateBackend>(input: &RuntimeGenesisInput, state: &mut B) {
    let context = neutrin0_consensus_types::runtime::ConsensusExecutionContext {
        timestamp: input.timestamp,
        finalized: neutrin0_consensus_types::history_proof::ConsensusBoundary {
            seed: input.seed,
            block_hash: input.genesis_block_hash,
            programs: input.programs,
            validators_root: neutrin0_consensus_types::evidence::commitment(&input.validators),
            history_root: neutrin0_consensus_types::history::empty_history_root(),
            ..neutrin0_consensus_types::runtime::ConsensusExecutionContext::default().finalized
        },
        ..neutrin0_consensus_types::runtime::ConsensusExecutionContext::default()
    };
    let anchor = neutrin0_consensus_types::evidence::EvidenceAnchor {
        fact_guest_vk_digest: input.programs.execution.fact,
        block_guest_vk_digest: input.programs.execution.block,
        evidence_guest_vk_digest: input.programs.execution.evidence,
        unbonding_delay_blocks: input.runtime_params.unbonding_delay_blocks,
        chunk_size: input.chunk_size,
        max_block_proving_input_bytes: input.max_block_proving_input_bytes,
        block_gas_limit: input.block_gas_limit,
        ..Default::default()
    };
    let environment = neutrin0_runtime_abi::RuntimeBlockInput {
        active_validators: input.validators.clone(),
        participation_acks: Vec::new(),
        program_pieces: Vec::new(),

        context,
        evidence_anchor: anchor,
        chain_id: input.chain_id,
        block_height: 0,
        block_gas_limit: input.block_gas_limit,
        proposer_address: [0; 32],
        participation: None,
        proving: None,
        transactions: Vec::new(),
    };
    crate::environment::store(state, &environment, None);
}

fn genesis_collateral(input: &RuntimeGenesisInput, supply: &mut U256) -> U256 {
    let mut escrow = U256::ZERO;
    for validator in &input.validators {
        assert!(
            validator.withdrawal_credentials != [0; 32],
            "EVM genesis validator requires an accountable Ethereum account"
        );
        if validator.withdrawal_credentials != [0; 32] {
            let address = crate::state::ethereum_address(&validator.withdrawal_credentials)
                .expect("canonical validator withdrawal account");
            assert!(
                !crate::addresses::RESERVED.contains(&address),
                "validator cannot withdraw to a reserved system address"
            );
            *supply = (*supply)
                .checked_add(U256::from(validator.effective_stake))
                .expect("genesis supply overflow");
            escrow += U256::from(validator.effective_stake);
        }
    }
    escrow
}
