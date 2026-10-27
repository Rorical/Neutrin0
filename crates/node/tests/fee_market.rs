//! Fee end-to-end: EIP-1559 pricing through real block production.
//!
//! Drives a full production + SP1 mock-prove cycle. After the transfer block
//! commits:
//!
//! - The signer's balance drops by `amount + gas_used * effective_gas_price`.
//! - The receiver's balance grows by `amount`.
//! - The proposer's Ethereum account grows by the priority fee alone; the
//!   base fee is escrowed for the chunk prover and the committee.
//!
//! The base fee is runtime state (seeded from genesis configuration) and the
//! `Sp1ProofSystem` cross-check binds the per-block `proposer_address` into
//! `BlockProofPublicInputs`, so the balance movements above plus a successful
//! `prove_block` confirm the runtime applied the fee rules and did not divert
//! the tip.

use std::sync::Arc;

use alloy_primitives::{Address, U256};
use neutrin0_consensus_engine::{Engine, ProposerKey};
use neutrin0_node::ChainBackend;
use neutrin0_primitives::{
    BoundedBytes, ChainSpec, ConsensusParams, LightClientParams, ProofParams, RuntimeInfo,
    RuntimeParams, Validator, fixed_u128_from_integer,
};
use neutrin0_rpc::{BlockId, RpcBackend};
use neutrin0_runtime_host::{Sp1ProofSystem, WasmExecutor};
use neutrin0_storage::MemoryDatabase;
use sp1_sdk::blocking::MockProver;
#[path = "support/evm.rs"]
pub mod evm;

const CHAIN_ID: u64 = 7777;
/// Gas a plain transfer consumes.
const TRANSFER_GAS: u128 = 21_000;
/// Genesis base fee of every fixture chain, in wei per gas.
const BASE_FEE: u128 = 10;
/// Priority fee the fixture transfers offer, in wei per gas.
const TIP: u128 = 1;

type FeeBackend = ChainBackend<MemoryDatabase, Sp1ProofSystem<MockProver>>;

fn proposer_key() -> ProposerKey {
    ProposerKey::from_ikm(&[0x99; 32], 0).expect("derive proposer")
}

/// The proposer's Ethereum account, bound through the chain spec's
/// `initial_validators` entry so the test can probe its balance after the
/// tip credit.
fn proposer_account() -> Address {
    Address::from([0xCC; 20])
}

fn validators() -> Vec<Validator> {
    vec![Validator {
        pubkey: *proposer_key().public_key_bytes(),
        withdrawal_credentials: evm::system_address(proposer_account()),
        effective_stake: 32_000_000_000_000_000_000,
        activation_epoch: 0,
        exit_epoch: u64::MAX,
    }]
}

fn seeded_chain_spec(accounts: &[(Address, u128)]) -> (ChainSpec, neutrin0_trie::Trie) {
    let vs_root = neutrin0_consensus_engine::validator_set_root(&validators());
    let genesis_block_hash = [0xCC; 32];
    let proof = ProofParams::default();
    let consensus = ConsensusParams {
        chunk_size: 1,
        expected_proposers_per_slot: fixed_u128_from_integer(8),
        ..ConsensusParams::default()
    };
    let mut spec = ChainSpec {
        genesis_execution: neutrin0_runtime_host::package::RuntimePackage::embedded(Vec::new())
            .expect("authenticated fixture programs")
            .programs
            .execution,
        name: BoundedBytes::new(b"fee-market".to_vec()).expect("name fits"),
        chain_id: CHAIN_ID,
        genesis_time: 1_700_000_000,
        genesis_gas_limit: 30_000_000,
        runtime_info: RuntimeInfo::default(),
        runtime_code_hash: neutrin0_runtime_host::embedded_runtime_code_hash(),
        genesis_chunk: neutrin0_runtime_host::package::embedded_chunk_program()
            .expect("embedded chunk Guest"),
        genesis_artifacts: neutrin0_primitives::GenesisArtifacts::default(),
        fork: None,
        genesis_seed: [0xAB; 32],
        genesis_state_root: neutrin0_primitives::ZERO_HASH,
        genesis_block_hash,
        genesis_validator_set_root: vs_root,
        consensus,
        proof,
        light_client: LightClientParams::default(),
        runtime: RuntimeParams::default(),
        initial_validators: validators(),
        metadata: BoundedBytes::new(Vec::new()).expect("empty fits"),
    };
    let allocation = accounts
        .iter()
        .map(
            |(address, balance)| neutrin0_runtime_abi::ethereum::GenesisAccount {
                address: address.into_array(),
                balance: U256::from(*balance).to_be_bytes(),
                nonce: 0,
                code: Vec::new(),
                storage: Vec::new(),
            },
        )
        .collect();
    let trie = evm::seal_genesis(&mut spec, allocation);
    (spec, trie)
}

fn seeded_backend(accounts: &[(Address, u128)]) -> Arc<FeeBackend> {
    let (spec, trie) = seeded_chain_spec(accounts);
    let mut engine = Engine::genesis(spec, MemoryDatabase::new()).expect("genesis");
    engine.install_genesis_state(trie).expect("genesis state");
    let proof_system = Sp1ProofSystem::mock().expect("mock SP1 setup");
    let backend = Arc::new(ChainBackend::new(engine, proof_system));
    backend.set_block_executor(WasmExecutor::embedded().expect("wasm runtime"));
    backend
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("rt")
}

fn query_account(
    backend: &FeeBackend,
    address: Address,
) -> neutrin0_runtime_abi::ethereum::EvmAccount {
    let resp = rt().block_on(async {
        backend
            .runtime_call(
                "evm:account".to_string(),
                address.into_array().to_vec(),
                &BlockId::Latest,
            )
            .await
            .expect("runtime_call")
    });
    borsh::from_slice(&resp.payload).expect("decode EvmAccount")
}

fn balance(backend: &FeeBackend, address: Address) -> U256 {
    U256::from_be_bytes(query_account(backend, address).balance)
}

#[test]
fn transfer_block_charges_fee_and_credits_proposer_through_sp1_pipeline() {
    let alice_addr = evm::address_of(1);
    let bob_addr = Address::from([0xBB; 20]);

    // Alice has enough for the transfer amount + gas. Bob and the proposer
    // start at zero. The proposer's Ethereum account is bound to
    // validator[0].withdrawal_credentials in the chain spec.
    let alice_initial = evm::FUNDS;
    let backend = seeded_backend(&[(alice_addr, alice_initial)]);
    let proposer = proposer_key();
    assert_eq!(balance(&backend, proposer_account()), U256::ZERO);

    // Submit + produce + prove a single transfer.
    let bytes = evm::transfer(1, 0, bob_addr, 30, CHAIN_ID);
    backend
        .submit_transaction(bytes)
        .expect("transfer admits under the chain's base fee");
    let outcome = backend
        .try_produce_block(1, &proposer)
        .expect("try_produce_block")
        .expect("validator eligible");
    assert_eq!(outcome.block.header.height, 1);
    assert_eq!(u128::from(outcome.block.header.gas_used), TRANSFER_GAS);

    // Prove the block. The Sp1ProofSystem cross-check binds the committed
    // RuntimeBlockOutput's state roots, gas_used, and receipts_root against
    // the consensus public inputs, plus the STF input's proposer_address
    // against the chain spec.
    let proven = backend
        .prove_block(&outcome.block_hash)
        .expect("prove_block accepts the matching proposer");
    assert_eq!(
        proven.public_inputs.proposer_address,
        evm::system_address(proposer_account())
    );
    assert_eq!(u128::from(proven.public_inputs.gas_used), TRANSFER_GAS);

    // Confirm the runtime state shifted as expected.
    let effective_price = BASE_FEE + TIP;
    let alice_after = query_account(&backend, alice_addr);
    assert_eq!(
        U256::from_be_bytes(alice_after.balance),
        U256::from(alice_initial - 30 - TRANSFER_GAS * effective_price),
        "alice paid amount + gas at the effective price",
    );
    assert_eq!(alice_after.nonce, 1);
    assert_eq!(
        balance(&backend, bob_addr),
        U256::from(30),
        "bob received the amount only"
    );
    // Design 08 does not burn the base fee: the proposer keeps the priority
    // fee alone and the base fee is escrowed for the chunk prover and the
    // committee.
    assert_eq!(
        balance(&backend, proposer_account()),
        U256::from(TRANSFER_GAS * TIP),
        "the proposer's account received the priority fee only",
    );
}
