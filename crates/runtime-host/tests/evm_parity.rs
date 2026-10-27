//! Unified semantic parity gates for the final public-chain execution package.
//! Opt-in SP1 execution is separate from compressed/recursive proof acceptance.
//! No test in this file generates proofs or substitutes a mock execution result.

#[path = "support/osaka.rs"]
mod osaka;
#[path = "support/evm_parity.rs"]
mod support;

use alloy_consensus::{
    SignableTransaction, TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxEnvelope, TxLegacy,
};
use alloy_eips::{
    eip2718::Encodable2718,
    eip2930::{AccessList, AccessListItem},
    eip7702::Authorization,
};
use alloy_primitives::{Address, B256, Signature, TxKind, U256, keccak256};
use neutrin0_runtime_abi::{
    RuntimeBlockInput, RuntimeGenesisInput, RuntimeTransaction,
    ethereum::{CallRequest, CallResult, EvmGenesisConfig, GenesisAccount},
};
use neutrin0_runtime_core::host::{LiveTrie, TracingState};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};
use support::{
    Harness, Transition, account, contract, funded_sender, receipts, sender, signed, storage,
};

static HARNESS: OnceLock<Harness> = OnceLock::new();
fn harness() -> &'static Harness {
    HARNESS.get_or_init(Harness::new)
}

static EXECUTION: OnceLock<Harness> = OnceLock::new();
fn execution_harness() -> &'static Harness {
    EXECUTION.get_or_init(Harness::execution_only)
}

fn dynamic(nonce: u64, to: Address, value: U256, data: Vec<u8>) -> RuntimeTransaction {
    signed(TxEip1559 {
        chain_id: support::CHAIN_ID,
        nonce,
        gas_limit: 900_000,
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 3,
        to: TxKind::Call(to),
        value,
        input: data.into(),
        ..Default::default()
    })
}

fn calldata(signature: &[u8], value: U256) -> Vec<u8> {
    let mut data = keccak256(signature)[..4].to_vec();
    data.extend(value.to_be_bytes::<32>());
    data
}

struct Chain {
    harness: &'static Harness,
    state: neutrin0_trie::Trie,
    genesis: RuntimeGenesisInput,
    genesis_root: [u8; 32],
    parent: [u8; 32],
    height: u64,
}
impl Chain {
    fn new(accounts: Vec<GenesisAccount>) -> Self {
        Self::on(harness(), accounts)
    }
    fn on(harness: &'static Harness, accounts: Vec<GenesisAccount>) -> Self {
        let (state, genesis) = harness.genesis(accounts);
        let genesis_root = state.root();
        Self {
            harness,
            state,
            genesis,
            genesis_root,
            parent: support::GENESIS_HASH,
            height: 0,
        }
    }
    fn block(&mut self, name: &str, transactions: Vec<RuntimeTransaction>) -> Transition {
        self.height += 1;
        let input = self.harness.input(
            &self.genesis,
            self.genesis_root,
            self.height,
            self.parent,
            transactions,
        );
        let result = self.harness.transition(name, &self.state, &input);
        self.state = result.post.clone();
        self.parent = result.native_hash;
        result
    }
}

/// Forward the calldata to `target` and log whatever it returned, so a system
/// call's revert data reaches the receipts root.
fn returndata_logger(target: Address) -> Vec<u8> {
    // CALLDATACOPY(0, 0, size); CALL(gas, target, 0, 0, size, 0, 0); POP
    let mut code = vec![0x36, 0x5f, 0x5f, 0x37, 0x5f, 0x5f, 0x36, 0x5f, 0x5f, 0x73];
    code.extend(target.as_slice());
    // RETURNDATACOPY(0, 0, size); LOG0(0, size); STOP
    code.extend([
        0x5a, 0xf1, 0x50, 0x3d, 0x5f, 0x5f, 0x3e, 0x3d, 0x5f, 0xa0, 0x00,
    ]);
    code
}

/// Dynamic-ABI system calls and MODEXP inputs whose offsets and lengths
/// straddle the 32-bit and 64-bit pointer widths, each through a contract that
/// logs what the call returned.
fn system_call_width_cases() -> Vec<(&'static str, Vec<u8>)> {
    let edges = [
        U256::from(0x60),
        U256::from(u32::MAX),
        U256::from(1_u64 << 32),
        U256::from((1_u64 << 32) + 1),
        U256::from((1_u64 << 32) + 0x60),
        U256::from(u64::MAX),
        U256::from(1) << 64,
        U256::MAX,
    ];
    let mut cases = Vec::new();
    for offset in edges {
        for length in [U256::from(48), U256::from(1_u64 << 32), U256::MAX] {
            let mut register = keccak256(b"registerValidator(bytes,bytes,uint256)")[..4].to_vec();
            for word in [offset, U256::from(0x60), U256::from(1), length] {
                register.extend(word.to_be_bytes::<32>());
            }
            register.extend([0; 96]);
            cases.push(("registerValidator", register));
            let mut rotate = keccak256(b"rotateKey(bytes,bytes)")[..4].to_vec();
            for word in [offset, U256::from(0x40), length] {
                rotate.extend(word.to_be_bytes::<32>());
            }
            rotate.extend([0; 96]);
            cases.push(("rotateKey", rotate));
            let mut policy = keccak256(b"proposePolicy(bytes)")[..4].to_vec();
            for word in [offset, length] {
                policy.extend(word.to_be_bytes::<32>());
            }
            cases.push(("proposePolicy", policy));
        }
    }
    let lengths = [
        U256::ZERO,
        U256::from(1),
        U256::from(1_u64 << 32),
        U256::from((1_u64 << 32) + 1),
        U256::from(1) << 64,
        U256::MAX,
    ];
    for base in lengths {
        for exponent in [U256::from(1), U256::from(1_u64 << 32), U256::MAX] {
            let mut modexp = Vec::new();
            for word in [base, exponent, U256::from(1)] {
                modexp.extend(word.to_be_bytes::<32>());
            }
            modexp.extend([3, 5, 7]);
            cases.push(("modexp", modexp));
        }
    }
    cases
}

/// Execute every width case on `chain`, a few per block, and require that
/// each logged its revert data. The harness compares the executions.
fn assert_system_call_width_parity(mut chain: Chain) {
    let staking = Address::repeat_byte(0x51);
    let governance = Address::repeat_byte(0x52);
    let mut nonce = 0;
    for (index, batch) in system_call_width_cases().chunks(8).enumerate() {
        let transactions = batch
            .iter()
            .map(|(function, data)| {
                let to = match *function {
                    "proposePolicy" => governance,
                    "modexp" => Address::repeat_byte(0x53),
                    _ => staking,
                };
                let transaction = signed(TxEip1559 {
                    chain_id: support::CHAIN_ID,
                    nonce,
                    gas_limit: 100_000,
                    max_fee_per_gas: 100,
                    max_priority_fee_per_gas: 3,
                    to: TxKind::Call(to),
                    input: data.clone().into(),
                    ..Default::default()
                });
                nonce += 1;
                transaction
            })
            .collect();
        let transition = chain.block(&format!("system call width {index}"), transactions);
        assert!(
            receipts(&transition.result)
                .iter()
                .all(|receipt| receipt.success && receipt.logs.len() == 1),
            "every malformed call returns into a logged result"
        );
    }
}

fn width_parity_accounts() -> Vec<GenesisAccount> {
    vec![
        funded_sender(),
        contract(
            Address::repeat_byte(0x51),
            returndata_logger(neutrin0_evm_runtime_core::addresses::STAKING),
            Vec::new(),
        ),
        contract(
            Address::repeat_byte(0x52),
            returndata_logger(neutrin0_evm_runtime_core::addresses::GOVERNANCE),
            Vec::new(),
        ),
        contract(
            Address::repeat_byte(0x53),
            returndata_logger(Address::with_last_byte(5)),
            Vec::new(),
        ),
    ]
}

/// WASM producers run 32-bit pointers, the Block Guest 64-bit ones (native
/// code shares the Guest's width). Revert data of a malformed system call and
/// precompile gas are observable, so any width-dependent decoding would let a
/// receipt contradict an honest header.
#[test]
fn malformed_system_calls_revert_identically_at_both_pointer_widths() {
    assert_system_call_width_parity(Chain::on(execution_harness(), width_parity_accounts()));
}

#[test]
#[ignore = "system-call pointer-width parity including the final ELF; no proving"]
fn malformed_system_calls_revert_identically_in_the_final_elf() {
    assert_system_call_width_parity(Chain::new(width_parity_accounts()));
}

fn nested_reverting_inner() -> Vec<u8> {
    // Write and emit, then revert the frame. Neither effect may survive CALL.
    vec![
        0x60, 99, 0x5f, 0x55, 0x60, 99, 0x5f, 0x52, 0x60, 1, 0x60, 32, 0x5f, 0xa1, 0x60, 32, 0x5f,
        0xfd,
    ]
}
fn outer_preserving_inner_revert(inner: Address) -> Vec<u8> {
    let mut code = vec![0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x73];
    code.extend(inner.as_slice());
    code.extend([0x5a, 0xf1, 0x15, 0x60, 0, 0x57, 0xfe]);
    let destination = code.len();
    code[destination - 3] = u8::try_from(destination).unwrap();
    code.extend([
        0x5b, 0x60, 7, 0x5f, 0x55, 0x60, 7, 0x5f, 0x52, 0x60, 0xaa, 0x60, 32, 0x5f, 0xa1, 0x00,
    ]);
    code
}
fn transient_reader_writer() -> Vec<u8> {
    // Nonempty input sets transient slot zero. Empty input reads it without
    // writing; transaction two must observe zero even in the same block.
    vec![
        0x36, 0x15, 0x60, 9, 0x57, 0x5f, 0x35, 0x5f, 0x5d, 0x5b, 0x5f, 0x5c, 0x80, 0x60, 1, 0x55,
        0x5f, 0x52, 0x60, 0xbb, 0x60, 32, 0x5f, 0xa1, 0x00,
    ]
}
fn context_recorder() -> Vec<u8> {
    // Store NUMBER, TIMESTAMP, COINBASE, CHAINID, PREVRANDAO and BLOCKHASH.
    // The queried block number comes from calldata; all returned facts come
    // from the runtime's authenticated environment and witnessed hash ring.
    vec![
        0x43, 0x5f, 0x55, 0x42, 0x60, 1, 0x55, 0x41, 0x60, 2, 0x55, 0x46, 0x60, 3, 0x55, 0x44,
        0x60, 4, 0x55, 0x5f, 0x35, 0x40, 0x60, 5, 0x55, 0x00,
    ]
}

#[test]
#[ignore = "native/WASM/final ELF execution parity; no proving"]
#[allow(
    clippy::too_many_lines,
    reason = "One ordered chain keeps deployment addresses, transaction nonces, refunds and delegated execution connected."
)]
fn evm_native_wasm_sp1_semantics_parity() {
    let inner = Address::from([0x31; 20]);
    let outer = Address::from([0x32; 20]);
    let refund = Address::from([0x33; 20]);
    let no_refund = Address::from([0x34; 20]);
    let transient = Address::from([0x35; 20]);
    let implementation = Address::from([0x36; 20]);
    let context = Address::from([0x37; 20]);
    let mut chain = Chain::new(vec![
        funded_sender(),
        contract(inner, nested_reverting_inner(), Vec::new()),
        contract(outer, outer_preserving_inner_revert(inner), Vec::new()),
        contract(
            refund,
            vec![0x5f, 0x5f, 0x55, 0x00],
            vec![([0; 32], U256::from(1).to_be_bytes())],
        ),
        contract(no_refund, vec![0x5f, 0x5f, 0x55, 0x00], Vec::new()),
        contract(transient, transient_reader_writer(), Vec::new()),
        contract(implementation, vec![0x60, 42, 0x5f, 0x55, 0x00], Vec::new()),
        contract(context, context_recorder(), Vec::new()),
    ]);
    let creation =
        hex::decode(include_str!("../../node/tests/fixtures/wallet_fixture_creation.hex").trim())
            .unwrap();
    let deployed = chain.block(
        "protected legacy Solidity deployment",
        vec![signed(TxLegacy {
            chain_id: Some(support::CHAIN_ID),
            nonce: 0,
            gas_limit: 900_000,
            gas_price: 13,
            to: TxKind::Create,
            input: creation.into(),
            ..Default::default()
        })],
    );
    let receipt = &receipts(&deployed.result)[0];
    assert!(receipt.success);
    assert_eq!(receipt.transaction_type, 0);
    let wallet = Address::from(receipt.contract_address.unwrap());
    assert_eq!(wallet, sender().create(0));
    assert_ne!(account(&chain.state, wallet).code_hash, keccak256([]).0);
    let stored = chain.block(
        "type 1 storage and event with access list",
        vec![signed(TxEip2930 {
            chain_id: support::CHAIN_ID,
            nonce: 1,
            gas_limit: 300_000,
            gas_price: 13,
            to: TxKind::Call(wallet),
            input: calldata(b"set(uint256)", U256::from(42)).into(),
            access_list: AccessList(vec![AccessListItem {
                address: wallet,
                storage_keys: vec![B256::ZERO],
            }]),
            ..Default::default()
        })],
    );
    let stored_receipts = receipts(&stored.result);
    assert!(stored_receipts[0].success);
    assert_eq!(stored_receipts[0].transaction_type, 1);
    assert_eq!(storage(&chain.state, wallet, 0), U256::from(42));
    assert_eq!(stored_receipts[0].logs.len(), 1);
    assert_eq!(
        stored_receipts[0].logs[0].topics[0],
        keccak256(b"Changed(uint256,address)").0
    );
    assert_eq!(
        stored_receipts[0].logs[0].topics[1],
        U256::from(42).to_be_bytes::<32>()
    );
    assert_eq!(
        &stored_receipts[0].logs[0].topics[2][12..],
        sender().as_slice()
    );
    let reverted = chain.block(
        "type 2 Solidity revert preserves nonce and gas",
        vec![dynamic(
            2,
            wallet,
            U256::ZERO,
            calldata(b"rollback(uint256)", U256::from(99)),
        )],
    );
    let reverted_receipts = receipts(&reverted.result);
    assert!(!reverted_receipts[0].success);
    assert_eq!(reverted_receipts[0].transaction_type, 2);
    assert!(reverted_receipts[0].gas_used > 21_000 && reverted_receipts[0].gas_used < 900_000);
    assert_eq!(reverted_receipts[0].logs, Vec::new());
    assert_eq!(storage(&chain.state, wallet, 0), U256::from(42));
    assert_eq!(account(&chain.state, sender()).nonce, 3);
    let nested = chain.block(
        "nested CALL reverts only callee state and logs",
        vec![dynamic(3, outer, U256::ZERO, Vec::new())],
    );
    let nested_receipts = receipts(&nested.result);
    assert!(nested_receipts[0].success);
    assert_eq!(storage(&chain.state, inner, 0), U256::ZERO);
    assert_eq!(storage(&chain.state, outer, 0), U256::from(7));
    assert_eq!(nested_receipts[0].logs.len(), 1);
    assert_eq!(nested_receipts[0].logs[0].address, outer.into_array());
    assert_eq!(
        nested_receipts[0].logs[0].data,
        U256::from(7).to_be_bytes::<32>()
    );
    let refunded = chain.block(
        "EIP-3529 charged gas refund",
        vec![
            dynamic(4, refund, U256::ZERO, Vec::new()),
            dynamic(5, no_refund, U256::ZERO, Vec::new()),
        ],
    );
    let refunded_receipts = receipts(&refunded.result);
    // Cold reset 5000 + two PUSH0 (4) + intrinsic 21000 - clear refund 4800.
    assert_eq!(refunded_receipts[0].gas_used, 21_204);
    assert_eq!(refunded_receipts[1].gas_used, 23_204);
    assert_eq!(storage(&chain.state, refund, 0), U256::ZERO);
    assert_eq!(refunded_receipts[1].cumulative_gas_used, 44_408);
    let temporary = chain.block(
        "transient storage clears between transactions",
        vec![
            dynamic(
                6,
                transient,
                U256::ZERO,
                U256::from(42).to_be_bytes::<32>().to_vec(),
            ),
            dynamic(7, transient, U256::ZERO, Vec::new()),
        ],
    );
    let temporary_receipts = receipts(&temporary.result);
    assert!(temporary_receipts.iter().all(|receipt| receipt.success));
    assert_eq!(
        temporary_receipts[0].logs[0].data,
        U256::from(42).to_be_bytes::<32>()
    );
    assert_eq!(temporary_receipts[1].logs[0].data, [0; 32]);
    assert_eq!(storage(&chain.state, transient, 1), U256::ZERO);
    let authorization = Authorization {
        chain_id: U256::from(support::CHAIN_ID),
        address: implementation,
        nonce: 9,
    };
    let auth_signature = support::signature(authorization.signature_hash());
    let delegated = chain.block(
        "type 4 EIP-7702 executes authority storage",
        vec![signed(TxEip7702 {
            chain_id: support::CHAIN_ID,
            nonce: 8,
            gas_limit: 300_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 3,
            to: sender(),
            authorization_list: vec![authorization.into_signed(auth_signature)],
            ..Default::default()
        })],
    );
    assert!(receipts(&delegated.result)[0].success);
    assert_eq!(receipts(&delegated.result)[0].transaction_type, 4);
    assert_eq!(account(&chain.state, sender()).nonce, 10);
    assert_eq!(storage(&chain.state, sender(), 0), U256::from(42));
    assert_eq!(storage(&chain.state, implementation, 0), U256::ZERO);
    let mut delegation = vec![0xef, 0x01, 0x00];
    delegation.extend(implementation.as_slice());
    let sender_record = account(&chain.state, sender());
    assert_eq!(
        chain
            .state
            .get(&neutrin0_evm_runtime_core::state::code_key(B256::from(
                sender_record.code_hash
            )))
            .unwrap(),
        Some(delegation)
    );
    let destination = Address::from([4; 20]);
    let followup = chain.block(
        "delegated signer remains admissible",
        vec![dynamic(10, destination, U256::from(17), Vec::new())],
    );
    assert!(receipts(&followup.result)[0].success);
    assert_eq!(
        account(&chain.state, destination).balance,
        U256::from(17).to_be_bytes::<32>()
    );
    let parent = chain.parent;
    let previous_height = chain.height;
    let recorded = chain.block(
        "native BLOCKHASH and authenticated EVM context",
        vec![dynamic(
            11,
            context,
            U256::ZERO,
            U256::from(previous_height).to_be_bytes::<32>().to_vec(),
        )],
    );
    assert!(receipts(&recorded.result)[0].success);
    assert_eq!(storage(&chain.state, context, 0), U256::from(chain.height));
    assert_eq!(
        storage(&chain.state, context, 1),
        U256::from(chain.height * 12)
    );
    assert_eq!(
        storage(&chain.state, context, 2),
        U256::from_be_slice(&[9; 20])
    );
    assert_eq!(
        storage(&chain.state, context, 3),
        U256::from(support::CHAIN_ID)
    );
    assert_eq!(
        storage(&chain.state, context, 4),
        U256::from_be_bytes(support::SEED)
    );
    assert_eq!(
        storage(&chain.state, context, 5),
        U256::from_be_bytes(parent)
    );
}

fn fixture_word(value: &Value) -> U256 {
    U256::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}
fn fixture_bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn fixture_address(value: &str) -> Address {
    Address::from_slice(&hex::decode(value.trim_start_matches("0x")).unwrap())
}
fn fixture_accounts(value: &Value) -> Vec<GenesisAccount> {
    value
        .as_object()
        .unwrap()
        .iter()
        .map(|(address, account)| GenesisAccount {
            address: fixture_address(address).into_array(),
            balance: fixture_word(&account["balance"]).to_be_bytes(),
            nonce: fixture_word(&account["nonce"]).try_into().unwrap(),
            code: fixture_bytes(&account["code"]),
            storage: account["storage"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| {
                    (
                        fixture_word(&Value::String(key.clone())).to_be_bytes(),
                        fixture_word(value).to_be_bytes(),
                    )
                })
                .collect(),
        })
        .collect()
}
fn assert_fixture_state(
    name: &str,
    state: &neutrin0_trie::Trie,
    before: &[GenesisAccount],
    expected: &[GenesisAccount],
) {
    let pre: BTreeMap<_, _> = before
        .iter()
        .map(|account| (account.address, account))
        .collect();
    let post: BTreeMap<_, _> = expected
        .iter()
        .map(|account| (account.address, account))
        .collect();
    let addresses = pre
        .keys()
        .chain(post.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    for address in addresses {
        let actual = account(state, Address::from(address));
        if let Some(expected) = post.get(&address) {
            assert_eq!(
                actual.balance, expected.balance,
                "{name}: balance {address:?}"
            );
            assert_eq!(actual.nonce, expected.nonce, "{name}: nonce {address:?}");
            assert_eq!(
                actual.code_hash,
                keccak256(&expected.code).0,
                "{name}: code {address:?}"
            );
        } else {
            assert_eq!(
                actual,
                neutrin0_runtime_abi::ethereum::EvmAccount::default(),
                "{name}: deleted account {address:?}"
            );
        }
        let mut slots = BTreeSet::new();
        if let Some(account) = pre.get(&address) {
            slots.extend(account.storage.iter().map(|(slot, _)| *slot));
        }
        if let Some(account) = post.get(&address) {
            slots.extend(account.storage.iter().map(|(slot, _)| *slot));
        }
        for slot in slots {
            let expected = post
                .get(&address)
                .and_then(|account| account.storage.iter().find(|(key, _)| *key == slot))
                .map_or(U256::ZERO, |(_, value)| U256::from_be_bytes(*value));
            let actual = state
                .get(&neutrin0_evm_runtime_core::state::storage_key(
                    Address::from(address),
                    U256::from_be_bytes(slot),
                ))
                .unwrap()
                .map_or(U256::ZERO, |value| U256::from_be_slice(&value));
            assert_eq!(actual, expected, "{name}: storage {address:?} {slot:?}");
        }
    }
}

#[test]
#[ignore = "official Osaka native/WASM/final ELF execution parity; no proving"]
fn official_osaka_native_wasm_sp1_parity() {
    let fixtures: Vec<Value> = serde_json::from_str(include_str!(
        "../../runtimes/neutrin0-evm/core/tests/fixtures/osaka.json"
    ))
    .unwrap();
    assert_eq!(
        fixtures.len(),
        22,
        "pinned independently filled fixture selection"
    );
    for fixture in fixtures {
        let name = fixture["name"].as_str().unwrap();
        let pre = fixture_accounts(&fixture["pre"]);
        let expected = fixture_accounts(&fixture["post"]);
        let genesis = RuntimeGenesisInput {
            max_block_proving_input_bytes:
                neutrin0_primitives::DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES,
            chain_id: 1,
            timestamp: 0,
            seed: fixture_bytes(&fixture["seed"]).try_into().unwrap(),
            genesis_block_hash: fixture_bytes(&fixture["parent"]).try_into().unwrap(),
            chunk_size: neutrin0_primitives::DEFAULT_CHUNK_SIZE,
            programs: harness().programs,
            block_gas_limit: fixture_word(&fixture["gas_limit"]).try_into().unwrap(),
            runtime_params: neutrin0_primitives::RuntimeParams::default(),
            validators: Vec::new(),
            configuration: borsh::to_vec(&EvmGenesisConfig {
                initial_base_fee: fixture_word(&fixture["base_fee"]).try_into().unwrap(),
                accounts: pre.clone(),
            })
            .unwrap(),
        };
        let state = harness().genesis_input(&genesis);
        let mut input = harness().input(
            &genesis,
            state.root(),
            1,
            genesis.genesis_block_hash,
            fixture["transactions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|raw| RuntimeTransaction::User(fixture_bytes(raw)))
                .collect(),
        );
        input.context.timestamp = fixture_word(&fixture["timestamp"]).try_into().unwrap();
        input.proposer_address = neutrin0_evm_runtime_core::state::consensus_address(
            fixture_address(fixture["coinbase"].as_str().unwrap()),
        );
        let transition = harness().transition(name, &state, &input);
        assert_eq!(
            U256::from(transition.result.output.gas_used),
            fixture_word(&fixture["gas"]),
            "{name}: independently filled Osaka gas"
        );
        assert_fixture_state(name, &transition.post, &pre, &expected);
        if name.contains("delegation_clearing_failing_tx") {
            assert!(
                receipts(&transition.result)
                    .iter()
                    .all(|receipt| !receipt.success && receipt.logs.is_empty()),
                "{name}: authorization changes survive transaction failure"
            );
        }
    }
}

fn wrapper_address(id: u16) -> Address {
    let mut address = [0; 20];
    address[18..].copy_from_slice(&(0x1000 + id).to_be_bytes());
    Address::from(address)
}
fn precompile_wrapper(id: u16) -> Vec<u8> {
    let mut code = vec![0x36, 0x5f, 0x5f, 0x37, 0x5f, 0x5f, 0x36, 0x5f, 0x5f, 0x61];
    code.extend(id.to_be_bytes());
    code.extend([0x5a, 0xf1, 0x15, 0x60, 0, 0x57]);
    let branch = code.len() - 2;
    code.extend([
        0x3d, 0x5f, 0x5f, 0x3e, 0x3d, 0x5f, 0x20, 0x5f, 0x55, 0x3d, 0x60, 1, 0x55, 0x00,
    ]);
    code[branch] = u8::try_from(code.len()).unwrap();
    code.extend([0x5b, 0x5f, 0x5f, 0xfd]);
    code
}

/// Every Osaka precompile, natively and in WASM: the producers' and the
/// Block Guest's arithmetic must agree on each output, exceptional inputs
/// (such as the zero field element) included.
#[test]
fn osaka_precompile_native_wasm_parity() {
    assert_osaka_precompile_parity(Chain::on(execution_harness(), osaka_accounts()));
}

#[test]
#[ignore = "all Osaka precompiles native/WASM/final ELF execution parity; no proving"]
fn osaka_precompile_native_wasm_sp1_parity() {
    assert_osaka_precompile_parity(Chain::new(osaka_accounts()));
}

fn osaka_accounts() -> Vec<GenesisAccount> {
    let mut accounts = vec![funded_sender()];
    accounts.extend(
        osaka::vectors()
            .iter()
            .map(|(id, _)| contract(wrapper_address(*id), precompile_wrapper(*id), Vec::new())),
    );
    accounts
}

fn assert_osaka_precompile_parity(mut chain: Chain) {
    let vectors = osaka::vectors();
    assert_eq!(vectors.len(), 18);
    let harness = chain.harness;
    for (nonce, (id, data)) in vectors.into_iter().enumerate() {
        let mut destination = [0; 20];
        destination[18..].copy_from_slice(&id.to_be_bytes());
        let request = CallRequest {
            from: sender().into_array(),
            to: Some(destination),
            value: [0; 32],
            data: data.clone(),
            gas_limit: support::GAS_LIMIT,
            fee_cap: None,
            tip_cap: None,
            access_list: Vec::new(),
            transaction_type: None,
            authorization_list: Vec::new(),
        };
        let live = LiveTrie::from_trie(chain.state.clone());
        let native =
            neutrin0_evm_runtime_core::query::simulate(&request, &mut TracingState::new(&live))
                .unwrap();
        let response = harness
            .wasm
            .query(
                &neutrin0_runtime_abi::QueryRequest {
                    method: "evm:call".into(),
                    args: borsh::to_vec(&request).unwrap(),
                },
                &chain.state,
            )
            .unwrap();
        assert!(response.is_ok());
        let wasm: CallResult = borsh::from_slice(&response.payload).unwrap();
        assert_eq!(native, wasm, "precompile {id}: output and gas");
        assert!(native.success, "precompile {id}");
        match id {
            1 => assert_eq!(&native.output[12..], sender().as_slice()),
            2 => assert_eq!(native.output, neutrin0_crypto::sha256(b"abc")),
            3 => assert_eq!(
                native.output,
                hex::decode("0000000000000000000000008eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
                    .unwrap()
            ),
            4 => assert_eq!(native.output, b"abc"),
            5 => assert_eq!(native.output, [6]),
            256 => assert_eq!(native.output, U256::from(1).to_be_bytes::<32>()),
            _ => {}
        }
        let transition = chain.block(
            &format!("Osaka precompile {id}"),
            vec![dynamic(
                u64::try_from(nonce).unwrap(),
                wrapper_address(id),
                U256::ZERO,
                data,
            )],
        );
        assert!(receipts(&transition.result)[0].success);
        assert_eq!(
            storage(&chain.state, wrapper_address(id), 0),
            U256::from_be_bytes(keccak256(&native.output).0),
            "precompile {id}: return-data commitment in witnessed state"
        );
        assert_eq!(
            storage(&chain.state, wrapper_address(id), 1),
            U256::from(native.output.len()),
            "precompile {id}: return-data length"
        );
    }
    let previous_hash = storage(&chain.state, wrapper_address(10), 0);
    let previous_length = storage(&chain.state, wrapper_address(10), 1);
    let invalid = chain.block(
        "malformed KZG precompile rolls back wrapper",
        vec![dynamic(18, wrapper_address(10), U256::ZERO, vec![0])],
    );
    assert!(!receipts(&invalid.result)[0].success);
    assert_eq!(receipts(&invalid.result)[0].logs, Vec::new());
    assert_eq!(storage(&chain.state, wrapper_address(10), 0), previous_hash);
    assert_eq!(
        storage(&chain.state, wrapper_address(10), 1),
        previous_length
    );
}

/// The block transition is total: each invalid transaction is skipped with no
/// effects and no receipt, identically on every target, so a block holding one
/// still has exactly one provable execution and a header claiming other
/// results is contradicted by its receipt.
#[test]
fn invalid_evm_transactions_are_skipped_identically_at_both_pointer_widths() {
    assert_invalid_transactions_skipped(execution_harness());
}

#[test]
#[ignore = "invalid transaction skip parity including the final ELF; no proving"]
fn invalid_evm_transactions_are_skipped_in_the_final_elf() {
    assert_invalid_transactions_skipped(harness());
}

/// Envelope indexes of the transactions `transition` executed.
fn executed(transition: &Transition) -> Vec<u32> {
    receipts(&transition.result)
        .iter()
        .map(|receipt| receipt.envelope_index)
        .collect()
}

#[allow(
    clippy::too_many_lines,
    reason = "One table covers each invalid transaction rule against the same funded genesis."
)]
fn assert_invalid_transactions_skipped(harness: &Harness) {
    let (state, genesis) = harness.genesis(vec![funded_sender()]);
    let destination = Address::from([4; 20]);
    let second = Address::from([5; 20]);
    let baseline = harness.input(
        &genesis,
        state.root(),
        1,
        genesis.genesis_block_hash,
        vec![
            dynamic(0, destination, U256::from(1), Vec::new()),
            dynamic(1, second, U256::from(1), Vec::new()),
        ],
    );
    let ordinary = TxEip1559 {
        chain_id: support::CHAIN_ID,
        nonce: 0,
        gas_limit: 900_000,
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 3,
        to: TxKind::Call(destination),
        ..Default::default()
    };
    let unprotected = signed(TxLegacy {
        chain_id: None,
        nonce: 0,
        gas_limit: 21_000,
        gas_price: 13,
        to: TxKind::Call(destination),
        ..Default::default()
    });
    let blob = signed(TxEip4844 {
        chain_id: support::CHAIN_ID,
        nonce: 0,
        gas_limit: 100_000,
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 3,
        max_fee_per_blob_gas: 100,
        blob_versioned_hashes: vec![B256::from([1; 32])],
        to: destination,
        ..Default::default()
    });
    let raw_trailing = match dynamic(0, destination, U256::ZERO, Vec::new()) {
        RuntimeTransaction::User(mut bytes) => {
            bytes.push(0);
            RuntimeTransaction::User(bytes)
        }
        RuntimeTransaction::SubmitEvidence(_) => unreachable!(),
    };
    let scalar_order = U256::from_str_radix(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap();
    let signature = support::signature(ordinary.signature_hash());
    let high_s = Signature::from_scalars_and_parity(
        B256::from(signature.r().to_be_bytes::<32>()),
        B256::from((scalar_order - signature.s()).to_be_bytes::<32>()),
        !signature.v(),
    );
    let noncanonical = RuntimeTransaction::User(
        TxEnvelope::from(ordinary.clone().into_signed(high_s)).encoded_2718(),
    );
    let cases = vec![
        ("unprotected legacy", vec![unprotected]),
        ("unsupported blob", vec![blob]),
        ("trailing transaction bytes", vec![raw_trailing]),
        (
            "malformed typed envelope",
            vec![RuntimeTransaction::User(vec![2, 0xc0])],
        ),
        ("high-s signature", vec![noncanonical]),
        (
            "wrong chain",
            vec![signed(TxEip1559 {
                chain_id: 8,
                ..ordinary.clone()
            })],
        ),
        (
            "nonce gap",
            vec![signed(TxEip1559 {
                nonce: 1,
                ..ordinary.clone()
            })],
        ),
        (
            "intrinsic gas",
            vec![signed(TxEip1559 {
                gas_limit: 20_999,
                ..ordinary.clone()
            })],
        ),
        (
            "fee below base",
            vec![signed(TxEip1559 {
                max_fee_per_gas: 9,
                max_priority_fee_per_gas: 0,
                ..ordinary.clone()
            })],
        ),
        (
            "tip exceeds fee cap",
            vec![signed(TxEip1559 {
                max_fee_per_gas: 100,
                max_priority_fee_per_gas: 101,
                ..ordinary.clone()
            })],
        ),
        (
            "insufficient value balance",
            vec![signed(TxEip1559 {
                value: U256::MAX,
                ..ordinary
            })],
        ),
        (
            "type 4 requires an authorization list",
            vec![signed(TxEip7702 {
                chain_id: support::CHAIN_ID,
                nonce: 0,
                gas_limit: 100_000,
                max_fee_per_gas: 100,
                max_priority_fee_per_gas: 3,
                to: destination,
                ..Default::default()
            })],
        ),
    ];
    for (name, transactions) in cases {
        let input = RuntimeBlockInput {
            transactions,
            ..baseline.clone()
        };
        let skipped = harness.transition(name, &state, &input);
        assert_eq!(executed(&skipped), Vec::<u32>::new(), "{name}");
        assert_eq!(
            (skipped.result.output.applied, skipped.result.output.failed),
            (0, 0),
            "{name}"
        );
    }
    // A valid first transaction still executes beside an invalid second one.
    for (name, invalid) in [
        (
            "nonce gap after a valid transaction",
            dynamic(2, second, U256::from(1), Vec::new()),
        ),
        (
            "second gas allowance exceeds remaining native ceiling",
            signed(TxEip1559 {
                chain_id: support::CHAIN_ID,
                nonce: 1,
                gas_limit: support::GAS_LIMIT,
                max_fee_per_gas: 100,
                max_priority_fee_per_gas: 3,
                to: TxKind::Call(second),
                ..Default::default()
            }),
        ),
    ] {
        let input = RuntimeBlockInput {
            transactions: vec![dynamic(0, destination, U256::from(1), Vec::new()), invalid],
            ..baseline.clone()
        };
        assert_eq!(
            executed(&harness.transition(name, &state, &input)),
            vec![0],
            "{name}"
        );
    }
    // Use a native ceiling above the transaction cap, so the skip exercises
    // Osaka's EIP-7825 rule rather than the independent block gas ceiling.
    let mut cap_genesis = genesis;
    cap_genesis.block_gas_limit = 20_000_000;
    let cap_state = harness.genesis_input(&cap_genesis);
    let cap_baseline = harness.input(
        &cap_genesis,
        cap_state.root(),
        1,
        cap_genesis.genesis_block_hash,
        vec![dynamic(0, destination, U256::ZERO, Vec::new())],
    );
    let cap_input = RuntimeBlockInput {
        transactions: vec![signed(TxEip1559 {
            chain_id: support::CHAIN_ID,
            nonce: 0,
            gas_limit: 16_777_217,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 3,
            to: TxKind::Call(destination),
            ..Default::default()
        })],
        ..cap_baseline
    };
    let capped = harness.transition("Osaka transaction gas cap", &cap_state, &cap_input);
    assert_eq!(executed(&capped), Vec::<u32>::new());
}
