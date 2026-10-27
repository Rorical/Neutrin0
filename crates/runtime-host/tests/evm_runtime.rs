//! Native/WASM/SP1 parity for the public-chain execution package.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, B256, Signature, TxKind, U256, keccak256};
use neutrin0_consensus_types::{
    evidence::EvidenceAnchor, history_proof::ConsensusBoundary, runtime::ConsensusExecutionContext,
};
use neutrin0_runtime_abi::{
    RuntimeBlockInput, RuntimeGenesisInput, RuntimeTransaction,
    ethereum::{CallRequest, CallResult, EvmGenesisConfig, GenesisAccount},
};
use neutrin0_runtime_core::host::{LiveTrie, TracingState};
use neutrin0_runtime_host::{
    EVM_GUEST_ELF, ProverCtx,
    wasm::{EVM_MASTER_WASM, WasmRuntime},
};

/// Attribution every receipt in this test names (design 08).
const PROVER_ADDRESS: [u8; 32] = [0x50; 32];

/// Public values the Block Guest commits for `output` under [`PROVER_ADDRESS`].
fn receipt_bytes(output: &neutrin0_runtime_abi::RuntimeBlockOutput) -> Vec<u8> {
    borsh::to_vec(&neutrin0_runtime_abi::BlockReceiptStatement {
        output: output.clone(),
        prover_address: PROVER_ADDRESS,
    })
    .unwrap()
}

fn signer() -> (k256::ecdsa::SigningKey, Address) {
    let key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let address = Address::from_slice(&keccak256(&point.as_bytes()[1..])[12..]);
    (key, address)
}
fn transaction(nonce: u64, kind: TxKind, value: u64, data: Vec<u8>) -> RuntimeTransaction {
    transaction_with_gas(nonce, kind, value, data, 900_000)
}
fn transaction_with_gas(
    nonce: u64,
    kind: TxKind,
    value: u64,
    data: Vec<u8>,
    gas_limit: u64,
) -> RuntimeTransaction {
    let tx = TxEip1559 {
        chain_id: 7,
        nonce,
        gas_limit,
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 3,
        to: kind,
        value: U256::from(value),
        input: data.into(),
        access_list: AccessList::default(),
    };
    let (key, _) = signer();
    let (signature, recovery) = key.sign_prehash_recoverable(tx.signature_hash().as_slice());
    let bytes = signature.to_bytes();
    let signature = Signature::from_scalars_and_parity(
        B256::from_slice(&bytes[..32]),
        B256::from_slice(&bytes[32..]),
        recovery.is_y_odd(),
    );
    RuntimeTransaction::User(TxEnvelope::from(tx.into_signed(signature)).encoded_2718())
}
fn genesis(runtime: &WasmRuntime) -> neutrin0_trie::Trie {
    genesis_with_accounts(runtime, Vec::new())
}
fn genesis_with_accounts(
    runtime: &WasmRuntime,
    additional: Vec<GenesisAccount>,
) -> neutrin0_trie::Trie {
    genesis_with_accounts_and_gas_limit(runtime, additional, 1_000_000)
}

/// Genesis whose head environment admits simulations up to `block_gas_limit`.
fn genesis_with_accounts_and_gas_limit(
    runtime: &WasmRuntime,
    additional: Vec<GenesisAccount>,
    block_gas_limit: u64,
) -> neutrin0_trie::Trie {
    let (_, sender) = signer();
    let mut config = EvmGenesisConfig {
        initial_base_fee: 10,
        accounts: vec![GenesisAccount {
            address: sender.into_array(),
            balance: U256::from(1_000_000_000_000_000_000_u64).to_be_bytes(),
            nonce: 0,
            code: Vec::new(),
            storage: Vec::new(),
        }],
    };
    config.accounts.extend(additional);
    let input = RuntimeGenesisInput {
        max_block_proving_input_bytes: neutrin0_primitives::DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES,
        chain_id: 7,
        timestamp: 0,
        seed: [8; 32],
        genesis_block_hash: [0; 32],
        chunk_size: 64,
        programs: neutrin0_primitives::ProgramSet {
            runtime_code_hash: neutrin0_primitives::blake3_256(EVM_MASTER_WASM),
            execution: neutrin0_primitives::ExecutionPrograms {
                fact: [1; 8],
                evidence: [2; 8],
                block: [3; 8],
            },
        },
        block_gas_limit,
        runtime_params: neutrin0_primitives::RuntimeParams::default(),
        validators: Vec::new(),
        configuration: borsh::to_vec(&config).unwrap(),
    };
    runtime.init_genesis(&input).unwrap().1
}
fn input(transactions: Vec<RuntimeTransaction>) -> RuntimeBlockInput {
    let context = ConsensusExecutionContext {
        slot: 1,
        timestamp: 100,
        parent_block_hash: [6; 32],
        finalized: ConsensusBoundary {
            seed: [8; 32],
            ..ConsensusBoundary::default()
        },
        ..ConsensusExecutionContext::default()
    };
    RuntimeBlockInput {
        active_validators: Vec::new(),
        participation_acks: Vec::new(),
        program_pieces: Vec::new(),
        context,
        evidence_anchor: EvidenceAnchor::default(),
        chain_id: 7,
        block_height: 1,
        block_gas_limit: 1_000_000,
        proposer_address: neutrin0_evm_runtime_core::state::consensus_address(Address::from(
            [9; 20],
        )),
        participation: None,
        proving: None,
        transactions,
    }
}
#[test]
fn evm_wasm_native_parity_deploy_storage_call_and_artifacts() {
    let runtime = WasmRuntime::new(EVM_MASTER_WASM).unwrap();
    let state = genesis(&runtime);
    // Runtime writes and returns storage slot zero.
    let code = vec![
        0x60, 0x2a, 0x5f, 0x55, 0x5f, 0x54, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3,
    ];
    let mut init = vec![0x60, 12, 0x60, 10, 0x5f, 0x39, 0x60, 12, 0x5f, 0xf3];
    init.extend(code);
    let input = input(vec![transaction(0, TxKind::Create, 0, init)]);
    let dry = runtime.dry_run(&input, &state, &[]).unwrap();
    let live = LiveTrie::from_trie(state);
    let mut tracing = TracingState::new(&live);
    let native = neutrin0_evm_runtime_core::execute_block(&input, &mut tracing);
    assert_eq!(native.output, dry.output);
    assert_eq!(native.artifacts, dry.artifacts);
    let receipts: neutrin0_evm_runtime_core::execution::ExecutionReceipt =
        borsh::from_slice(dry.artifacts.receipts.last().unwrap()).unwrap();
    let neutrin0_evm_runtime_core::execution::ExecutionReceipt::Ethereum(receipt) = receipts else {
        panic!("Ethereum receipt")
    };
    let contract = receipt.contract_address.unwrap();
    let call = CallRequest {
        from: signer().1.into_array(),
        to: Some(contract),
        value: [0; 32],
        data: Vec::new(),
        gas_limit: 100_000,
        fee_cap: None,
        tip_cap: None,
        access_list: Vec::new(),
        transaction_type: None,
        authorization_list: Vec::new(),
    };
    let response = runtime
        .query(
            &neutrin0_runtime_abi::QueryRequest {
                method: "evm:call".into(),
                args: borsh::to_vec(&call).unwrap(),
            },
            &dry.post_state,
        )
        .unwrap();
    assert!(response.is_ok());
    let result: CallResult = borsh::from_slice(&response.payload).unwrap();
    assert!(result.success);
    assert_eq!(result.output, U256::from(42).to_be_bytes::<32>());
    assert!(
        dry.post_state
            .get(&neutrin0_evm_runtime_core::state::storage_key(
                Address::from(contract),
                U256::ZERO
            ))
            .unwrap()
            .is_none(),
        "simulation never commits storage"
    );
}

#[test]
fn evm_guest_state_backend_rejects_forged_or_missing_ethereum_account_openings() {
    use neutrin0_runtime_core::{WitnessError, WitnessState};
    use neutrin0_trie::{Hasher, Poseidon2Hasher};
    let runtime = WasmRuntime::new(EVM_MASTER_WASM).unwrap();
    let state = genesis(&runtime);
    let input = input(vec![transaction(
        0,
        TxKind::Call(Address::from([4; 20])),
        123,
        Vec::new(),
    )]);
    let dry = runtime.dry_run(&input, &state, &[]).unwrap();
    let account_key = neutrin0_evm_runtime_core::state::account_key(signer().1);
    let account_bytes = state.get(&account_key).unwrap().unwrap();
    let mut honest = WitnessState::new(&dry.witness).unwrap();
    assert_eq!(
        neutrin0_evm_runtime_core::execute_block(&input, &mut honest).output,
        dry.output
    );

    let value_index = dry
        .witness
        .values
        .iter()
        .position(|value| value.bytes == account_bytes)
        .unwrap();
    let mut forged = dry.witness.clone();
    let mut account: neutrin0_runtime_abi::ethereum::EvmAccount =
        borsh::from_slice(&account_bytes).unwrap();
    account.balance = U256::MAX.to_be_bytes();
    forged.values[value_index].bytes = borsh::to_vec(&account).unwrap();
    assert!(matches!(
        WitnessState::new(&forged),
        Err(WitnessError::ValueHashMismatch { .. })
    ));

    // Rehashing the supplied account cannot change the authenticated leaf's
    // value reference. The declared account lookup no longer resolves, so the
    // guest-side state backend refuses the witness before any execution could
    // invent an account.
    forged.values[value_index].hash =
        Poseidon2Hasher::hash_value(&forged.values[value_index].bytes);
    assert!(matches!(
        WitnessState::new(&forged),
        Err(WitnessError::IncompletePath { key }) if key == account_key
    ));

    let mut missing_key = dry.witness;
    missing_key.witnessed_keys.retain(|key| key != &account_key);
    let mut missing_opening = WitnessState::new(&missing_key).unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            neutrin0_evm_runtime_core::execute_block(&input, &mut missing_opening)
        }))
        .is_err()
    );
}
#[test]
#[ignore = "executes the final EVM ELF in the real CPU SP1 executor"]
fn evm_sp1_execution_matches_wasm_public_values() {
    let runtime = WasmRuntime::new(EVM_MASTER_WASM).unwrap();
    let state = genesis(&runtime);
    let input = input(vec![transaction(
        0,
        TxKind::Call(Address::from([4; 20])),
        123,
        Vec::new(),
    )]);
    let dry = runtime.dry_run(&input, &state, &[]).unwrap();
    let prover = sp1_sdk::blocking::ProverClient::builder().cpu().build();
    let context = ProverCtx::new_cached_for(prover, EVM_GUEST_ELF.clone()).unwrap();
    let (public, report) = context
        .execute(&input, &dry.witness, &[], PROVER_ADDRESS)
        .unwrap();
    let statement: neutrin0_runtime_abi::BlockReceiptStatement =
        borsh::from_slice(public.as_slice()).unwrap();
    assert_eq!(statement.output, dry.output);
    assert_eq!(statement.prover_address, PROVER_ADDRESS);
    eprintln!("EVM SP1 cycles: {}", report.total_instruction_count());
}

#[path = "support/osaka.rs"]
mod osaka;

#[test]
fn every_osaka_precompile_has_identical_native_and_wasm_result_and_gas() {
    let runtime = WasmRuntime::new(EVM_MASTER_WASM).unwrap();
    let state = genesis(&runtime);
    for (id, data) in osaka::vectors() {
        let mut destination = [0; 20];
        destination[18..].copy_from_slice(&id.to_be_bytes());
        let call = CallRequest {
            from: signer().1.into_array(),
            to: Some(destination),
            value: [0; 32],
            data,
            gas_limit: 1_000_000,
            fee_cap: None,
            tip_cap: None,
            access_list: Vec::new(),
            transaction_type: None,
            authorization_list: Vec::new(),
        };
        let live = LiveTrie::from_trie(state.clone());
        let mut native = TracingState::new(&live);
        let expected = neutrin0_evm_runtime_core::query::simulate(&call, &mut native).unwrap();
        assert!(expected.success, "precompile {id} failed");
        let response = runtime
            .query(
                &neutrin0_runtime_abi::QueryRequest {
                    method: "evm:call".into(),
                    args: borsh::to_vec(&call).unwrap(),
                },
                &state,
            )
            .unwrap();
        assert!(response.is_ok(), "precompile {id}: {response:?}");
        let actual: CallResult = borsh::from_slice(&response.payload).unwrap();
        assert_eq!(actual, expected, "precompile {id}");
        if id == 4 {
            assert_eq!(actual.output, b"abc");
        }
        if id == 5 {
            assert_eq!(actual.output, vec![6]);
        }
        if id == 256 {
            assert_eq!(actual.output, U256::from(1).to_be_bytes::<32>());
        }
    }
}

#[test]
#[ignore = "executes every Osaka precompile in the real CPU SP1 executor"]
fn every_osaka_precompile_executes_in_sp1() {
    let runtime = WasmRuntime::new(EVM_MASTER_WASM).unwrap();
    let vectors = osaka::vectors();
    let extra = vectors
        .iter()
        .map(|(id, _)| {
            let address = wrapper_address(*id);
            GenesisAccount {
                address: address.into_array(),
                balance: [0; 32],
                nonce: 1,
                code: wrapper(*id),
                storage: Vec::new(),
            }
        })
        .collect();
    let mut state = genesis_with_accounts(&runtime, extra);
    let prover = sp1_sdk::blocking::ProverClient::builder().cpu().build();
    let context = ProverCtx::new_cached_for(prover, EVM_GUEST_ELF.clone()).unwrap();
    for (nonce, (id, data)) in vectors.into_iter().enumerate() {
        let nonce = u64::try_from(nonce).unwrap();
        let mut input = input(vec![transaction(
            nonce,
            TxKind::Call(wrapper_address(id)),
            0,
            data,
        )]);
        // Pairing/map execution needs a larger per-transaction gas allowance.
        if let RuntimeTransaction::User(raw) = &input.transactions[0] {
            assert_ne!(raw.len(), 0);
        }
        input.block_height = nonce + 1;
        input.context.slot = nonce + 1;
        input.context.timestamp = 100 + nonce;
        let dry = runtime.dry_run(&input, &state, &[]).unwrap();
        let receipt: neutrin0_evm_runtime_core::execution::ExecutionReceipt =
            borsh::from_slice(dry.artifacts.receipts.last().unwrap()).unwrap();
        let neutrin0_evm_runtime_core::execution::ExecutionReceipt::Ethereum(receipt) = receipt
        else {
            panic!("Ethereum receipt")
        };
        assert!(receipt.success, "precompile {id}");
        let (public, report) = context
            .execute(&input, &dry.witness, &[], PROVER_ADDRESS)
            .unwrap();
        assert_eq!(public.as_slice(), receipt_bytes(&dry.output));
        // A semver-incompatible patch silently falls back to software. This
        // ignored test checks that the final ELF actually reaches
        // SP1's constrained circuits, while retaining the WASM public output.
        let syscall_count = |name: &str| {
            report
                .syscall_counts
                .iter()
                .find_map(|(code, count)| (format!("{code:?}") == name).then_some(*count))
                .unwrap_or(0)
        };
        assert!(syscall_count("KECCAK_PERMUTE") > 0, "Keccak patch inactive");
        assert!(
            syscall_count("SECP256K1_ADD") > 0,
            "transaction recovery patch inactive"
        );
        if id == 2 {
            assert!(
                syscall_count("SHA_EXTEND") > 0,
                "SHA-256 extend patch inactive"
            );
            assert!(
                syscall_count("SHA_COMPRESS") > 0,
                "SHA-256 compress patch inactive"
            );
        }
        if id == 256 {
            assert!(syscall_count("SECP256R1_ADD") > 0, "P-256 patch inactive");
        }
        if id == 5 {
            assert!(
                syscall_count("UINT256_MUL") > 0,
                "modexp BIGINT path inactive"
            );
        }
        if (6..=8).contains(&id) {
            assert!(syscall_count("BN254_FP_MUL") > 0, "BN254 patch inactive");
        }
        // MAP_FP2_TO_G2 (17) keeps REVM's reference implementation in the
        // Guest so the zero element maps as in WASM (0b871cb), so it reaches
        // no Fp2 circuit.
        if matches!(id, 10 | 13..=15) {
            assert!(
                syscall_count("BLS12381_FP2_MUL") > 0,
                "BLS Fp2 path inactive"
            );
        }
        if matches!(id, 11 | 12) {
            assert!(syscall_count("BLS12381_DOUBLE") > 0, "BLS G1 path inactive");
        }

        eprintln!(
            "precompile {id}: cycles={} evm_gas={} prover_gas={:?} witness_bytes={} touched_words={} syscalls={:?}",
            report.total_instruction_count(),
            receipt.gas_used,
            report.gas(),
            borsh::object_length(&dry.witness).unwrap(),
            report.touched_memory_addresses,
            report.syscall_counts
        );
        state = dry.post_state;
    }
}

#[test]
fn osaka_arithmetic_adversarial_native_wasm_parity() {
    let runtime = WasmRuntime::new(EVM_MASTER_WASM).unwrap();
    // Simulations are capped by the head environment's block gas limit.
    let state = genesis_with_accounts_and_gas_limit(&runtime, Vec::new(), 8_000_000);
    for (name, id, data, success) in osaka::arithmetic_adversarial_vectors() {
        let mut destination = [0; 20];
        destination[18..].copy_from_slice(&id.to_be_bytes());
        let call = CallRequest {
            from: signer().1.into_array(),
            to: Some(destination),
            value: [0; 32],
            data,
            gas_limit: 8_000_000,
            fee_cap: None,
            tip_cap: None,
            access_list: Vec::new(),
            transaction_type: None,
            authorization_list: Vec::new(),
        };
        let live = LiveTrie::from_trie(state.clone());
        let mut native = TracingState::new(&live);
        let expected = neutrin0_evm_runtime_core::query::simulate(&call, &mut native).unwrap();
        assert_eq!(expected.success, success, "{name}");
        let response = runtime
            .query(
                &neutrin0_runtime_abi::QueryRequest {
                    method: "evm:call".into(),
                    args: borsh::to_vec(&call).unwrap(),
                },
                &state,
            )
            .unwrap();
        assert!(response.is_ok(), "{name}: {response:?}");
        let actual: CallResult = borsh::from_slice(&response.payload).unwrap();
        assert_eq!(actual, expected, "{name}");
    }
}

#[test]
#[ignore = "real SP1 differential arithmetic test, including adversarial inputs"]
#[allow(
    clippy::too_many_lines,
    reason = "Keep exact native/WASM artifacts, both Guest outputs and per-case reports together in the differential test."
)]
fn osaka_arithmetic_adversarial_cross_backend_parity() {
    let runtime = WasmRuntime::new(EVM_MASTER_WASM).unwrap();
    let extra = [5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17]
        .into_iter()
        .map(|id| GenesisAccount {
            address: wrapper_address(id).into_array(),
            balance: [0; 32],
            nonce: 1,
            code: wrapper(id),
            storage: Vec::new(),
        })
        .collect();
    let mut state = genesis_with_accounts(&runtime, extra);
    let context = ProverCtx::new_cached_for(
        sp1_sdk::blocking::ProverClient::builder().cpu().build(),
        EVM_GUEST_ELF.clone(),
    )
    .unwrap();
    for (nonce, (name, id, data, success)) in osaka::arithmetic_adversarial_vectors()
        .into_iter()
        .enumerate()
    {
        let nonce = u64::try_from(nonce).unwrap();
        let mut input = input(vec![transaction_with_gas(
            nonce,
            TxKind::Call(wrapper_address(id)),
            0,
            data,
            8_000_000,
        )]);
        input.block_height = nonce + 1;
        // A transaction above the block gas limit is skipped, not executed.
        input.block_gas_limit = 8_000_000;
        input.context.slot = nonce + 1;
        input.context.timestamp = 100 + nonce;
        let dry = runtime.dry_run(&input, &state, &[]).unwrap();
        let live = LiveTrie::from_trie(state.clone());
        let mut native = TracingState::new(&live);
        let expected = neutrin0_evm_runtime_core::execute_block(&input, &mut native);
        assert_eq!(expected.output, dry.output, "{name}: native/WASM output");
        assert_eq!(
            expected.artifacts, dry.artifacts,
            "{name}: native/WASM artifacts"
        );
        let receipt: neutrin0_evm_runtime_core::execution::ExecutionReceipt =
            borsh::from_slice(dry.artifacts.receipts.last().unwrap()).unwrap();
        let neutrin0_evm_runtime_core::execution::ExecutionReceipt::Ethereum(receipt) = receipt
        else {
            panic!("Ethereum receipt")
        };
        assert_eq!(receipt.success, success, "{name}");
        let expected_public = receipt_bytes(&dry.output);
        let (public, report) = context
            .execute(&input, &dry.witness, &[], PROVER_ADDRESS)
            .unwrap();
        assert_eq!(
            public.as_slice(),
            expected_public,
            "{name}: accelerated SP1"
        );
        eprintln!(
            "{name}: accelerated_cycles={} syscalls={:?}",
            report.total_instruction_count(),
            report.syscall_counts
        );
        state = dry.post_state;
    }
}

fn wrapper_address(id: u16) -> Address {
    let mut address = [0; 20];
    address[18..].copy_from_slice(&(0x1000 + id).to_be_bytes());
    Address::from(address)
}
fn wrapper(id: u16) -> Vec<u8> {
    // Copy calldata; CALL precompile; reject failed calls; commit RETURN bytes'
    // Keccak and length into slots 0/1 so the Block Guest binds its exact verdict.
    let mut code = vec![0x36, 0x5f, 0x5f, 0x37, 0x5f, 0x5f, 0x36, 0x5f, 0x5f, 0x61];
    code.extend(id.to_be_bytes());
    code.extend([0x5a, 0xf1, 0x15, 0x60, 0, 0x57]);
    let branch = code.len() - 2;
    code.extend([
        0x3d, 0x5f, 0x5f, 0x3e, 0x3d, 0x5f, 0x20, 0x5f, 0x55, 0x3d, 0x60, 0x01, 0x55, 0x00,
    ]);
    code[branch] = u8::try_from(code.len()).unwrap();
    code.extend([0x5b, 0x5f, 0x5f, 0xfd]);
    code
}
