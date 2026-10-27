//! EVM genesis and transaction fixtures for node integration tests.
//!
//! Every chain the embedded runtime executes needs its genesis records (fee
//! environment, system accounts, policy and seated validators) before the
//! first block; these helpers derive them from a test's `ChainSpec` so the
//! engine's genesis state root and the executed state agree.
#![allow(dead_code)] // Each integration test binary uses a subset.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Signature, TxKind, U256, keccak256};
use neutrin0_primitives::{ChainSpec, Hash};
use neutrin0_runtime_abi::{
    RuntimeGenesisInput, RuntimeTransaction,
    ethereum::{EvmGenesisConfig, GenesisAccount},
};
use neutrin0_runtime_core::host::{LiveTrie, TracingState};
use neutrin0_runtime_host::wasm::WasmRuntime;
use neutrin0_trie::Trie;

/// Wei each funded development account starts with.
pub const FUNDS: u128 = 1_000_000_000_000_000_000;

/// Zero-padded system address of the Ethereum account `[byte; 20]`, the
/// only validator credential shape the EVM runtime seats.
pub fn padded(byte: u8) -> Hash {
    let mut address = [0; 32];
    address[12..].copy_from_slice(&[byte; 20]);
    address
}

/// Zero-padded system address of `address`.
pub fn system_address(address: Address) -> Hash {
    neutrin0_evm_runtime_core::state::consensus_address(address)
}

/// Deterministic development secp256k1 key for `seed`.
pub fn signing_key(seed: u8) -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap()
}

/// Ethereum address of the key for `seed`.
pub fn address_of(seed: u8) -> Address {
    let point = signing_key(seed).verifying_key().to_sec1_point(false);
    Address::from_slice(&keccak256(&point.as_bytes()[1..])[12..])
}

/// Genesis allocation funding `accounts` with [`FUNDS`] each.
pub fn funded(accounts: &[Address]) -> Vec<GenesisAccount> {
    accounts
        .iter()
        .map(|address| GenesisAccount {
            address: address.into_array(),
            balance: U256::from(FUNDS).to_be_bytes(),
            nonce: 0,
            code: Vec::new(),
            storage: Vec::new(),
        })
        .collect()
}

/// The runtime's genesis input for `spec` with `accounts` funded.
pub fn genesis_input(spec: &ChainSpec, accounts: Vec<GenesisAccount>) -> RuntimeGenesisInput {
    RuntimeGenesisInput {
        max_block_proving_input_bytes: neutrin0_primitives::DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES,
        chain_id: spec.chain_id,
        timestamp: spec.genesis_time,
        seed: spec.genesis_seed,
        genesis_block_hash: spec.genesis_block_hash,
        chunk_size: spec.consensus.chunk_size,
        programs: neutrin0_primitives::ProgramSet {
            runtime_code_hash: spec.runtime_code_hash,
            execution: spec.genesis_execution,
        },
        block_gas_limit: spec.genesis_gas_limit,
        runtime_params: spec.runtime,
        validators: spec.initial_validators.clone(),
        configuration: borsh::to_vec(&EvmGenesisConfig {
            initial_base_fee: 10,
            accounts,
        })
        .unwrap(),
    }
}

/// Genesis state of `spec` with `accounts` funded, initialized by the
/// embedded WASM runtime exactly as node bootstrap does.
pub fn genesis_trie(spec: &ChainSpec, accounts: Vec<GenesisAccount>) -> Trie {
    WasmRuntime::embedded()
        .expect("embedded runtime")
        .init_genesis(&genesis_input(spec, accounts))
        .expect("runtime genesis")
        .1
}

/// Pin `spec`'s genesis state root to the runtime's genesis for `accounts`
/// and return that state.
pub fn seal_genesis(spec: &mut ChainSpec, accounts: Vec<GenesisAccount>) -> Trie {
    let trie = genesis_trie(spec, accounts);
    spec.genesis_state_root = trie.root();
    trie
}

/// Nonce and wei of `address` in `trie`; a missing account is `(0, 0)`.
pub fn account_in(trie: &Trie, address: Address) -> (u64, U256) {
    let live = LiveTrie::from_trie(trie.clone());
    let mut state = TracingState::new(&live);
    neutrin0_evm_runtime_core::state::load_account(&mut state, address)
        .unwrap()
        .map_or((0, U256::ZERO), |account| {
            (account.nonce, U256::from_be_bytes(account.balance))
        })
}

/// Wei held by `address` in `trie`.
pub fn balance_in(trie: &Trie, address: Address) -> U256 {
    account_in(trie, address).1
}

/// Calldata of `registerValidator(bytes,bytes,uint256)`: the BLS identity
/// `pubkey`, its proof of possession `pop` and the initial collateral.
pub fn register_calldata(pubkey: &[u8; 48], pop: &[u8; 96], amount: u128) -> Vec<u8> {
    let mut data = keccak256(b"registerValidator(bytes,bytes,uint256)")[..4].to_vec();
    // Three head words; bytes48 occupies 96 bytes, bytes96 occupies 128.
    data.extend_from_slice(&U256::from(96).to_be_bytes::<32>());
    data.extend_from_slice(&U256::from(192).to_be_bytes::<32>());
    data.extend_from_slice(&word(amount));
    data.extend_from_slice(&U256::from(48).to_be_bytes::<32>());
    data.extend_from_slice(pubkey);
    data.extend_from_slice(&[0; 16]);
    data.extend_from_slice(&U256::from(96).to_be_bytes::<32>());
    data.extend_from_slice(pop);
    data
}

/// Sign `tx` with the key for `seed` into the runtime's encoded user
/// envelope, the bytes a node accepts over RPC or gossip.
pub fn signed(seed: u8, tx: TxEip1559) -> Vec<u8> {
    let (signature, recovery) =
        signing_key(seed).sign_prehash_recoverable(tx.signature_hash().as_slice());
    let bytes = signature.to_bytes();
    let signature = Signature::from_scalars_and_parity(
        B256::from_slice(&bytes[..32]),
        B256::from_slice(&bytes[32..]),
        recovery.is_y_odd(),
    );
    borsh::to_vec(&RuntimeTransaction::User(
        TxEnvelope::from(tx.into_signed(signature)).encoded_2718(),
    ))
    .unwrap()
}

/// Encoded 21,000-gas transfer of `value` wei from the key for `seed`.
pub fn transfer(seed: u8, nonce: u64, to: Address, value: u128, chain_id: u64) -> Vec<u8> {
    signed(
        seed,
        TxEip1559 {
            chain_id,
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: 1_000,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(to),
            value: U256::from(value),
            ..Default::default()
        },
    )
}

/// Encoded call of a runtime-owned system interface from the key for `seed`.
pub fn system_call(seed: u8, nonce: u64, to: Address, data: Vec<u8>, chain_id: u64) -> Vec<u8> {
    signed(
        seed,
        TxEip1559 {
            chain_id,
            nonce,
            gas_limit: 400_000,
            max_fee_per_gas: 1_000,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: data.into(),
            ..Default::default()
        },
    )
}

/// Calldata of a system method taking the given 32-byte words.
pub fn calldata(signature: &[u8], words: &[[u8; 32]]) -> Vec<u8> {
    let mut data = keccak256(signature)[..4].to_vec();
    for word in words {
        data.extend_from_slice(word);
    }
    data
}

/// A 32-byte ABI word holding `value`.
pub fn word(value: u128) -> [u8; 32] {
    U256::from(value).to_be_bytes()
}

/// `spec` with its genesis state root pinned to the runtime's genesis for an
/// empty allocation.
pub fn sealed(mut spec: ChainSpec) -> ChainSpec {
    seal_genesis(&mut spec, Vec::new());
    spec
}

/// Engine at the genesis of `spec` (sealed with [`seal_genesis`] or
/// [`sealed`]) with the runtime's genesis state for `accounts` installed.
pub fn genesis_engine<DB>(
    spec: ChainSpec,
    db: DB,
    accounts: Vec<GenesisAccount>,
) -> neutrin0_consensus_engine::Engine<DB>
where
    DB: neutrin0_storage::Database,
    DB::Error: std::fmt::Debug,
{
    let trie = genesis_trie(&spec, accounts);
    assert_eq!(
        trie.root(),
        spec.genesis_state_root,
        "chain spec must be sealed to the runtime genesis"
    );
    let mut engine = neutrin0_consensus_engine::Engine::genesis(spec, db).expect("genesis");
    engine
        .install_genesis_state(trie)
        .expect("install genesis state");
    engine
}

/// Consensus candidate commitment the runtime emits while `validators` hold
/// exactly their genesis collateral and no registration.
pub fn genesis_candidates_root(validators: &[neutrin0_primitives::Validator]) -> Hash {
    let mut candidates = neutrin0_consensus_types::runtime::ConsensusCandidates::default();
    for validator in validators {
        candidates.upsert(neutrin0_consensus_types::runtime::ConsensusCandidate {
            address: validator.withdrawal_credentials,
            stake: validator.effective_stake,
            identity: None,
        });
    }
    candidates.root()
}

/// `spec` with its genesis state root pinned to the runtime's genesis for
/// `accounts`.
pub fn sealed_with(mut spec: ChainSpec, accounts: Vec<GenesisAccount>) -> ChainSpec {
    seal_genesis(&mut spec, accounts);
    spec
}
