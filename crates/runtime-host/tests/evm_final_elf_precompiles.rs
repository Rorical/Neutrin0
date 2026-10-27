//! Every Osaka precompile executes identically in WASM, which producers run,
//! and in the final Block Guest ELF, which proves their blocks. SP1 executes
//! the ELF for real; the mock prover only skips proving. A divergence would
//! let a valid receipt contradict an honest header.

#[path = "support/osaka.rs"]
mod osaka;

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::{eip2718::Encodable2718, eip2930::AccessList};
use alloy_primitives::{Address, B256, Signature, TxKind, U256, keccak256};
use neutrin0_consensus_types::{evidence::EvidenceAnchor, runtime::ConsensusExecutionContext};
use neutrin0_runtime_abi::{
    RuntimeBlockInput, RuntimeGenesisInput, RuntimeTransaction,
    ethereum::{EvmGenesisConfig, GenesisAccount},
};
use neutrin0_runtime_host::{
    EVM_GUEST_ELF, ProverCtx,
    wasm::{EVM_MASTER_WASM, WasmRuntime},
};
use sp1_sdk::blocking::ProverClient;

const PROVER_ADDRESS: [u8; 32] = [0x50; 32];

fn signing_key() -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap()
}

fn sender() -> Address {
    Address::from_slice(
        &keccak256(
            &signing_key()
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes()[1..],
        )[12..],
    )
}

fn transaction(destination: Address, data: Vec<u8>) -> RuntimeTransaction {
    let transaction = TxEip1559 {
        chain_id: 7,
        nonce: 0,
        gas_limit: 1_500_000,
        max_fee_per_gas: 100,
        max_priority_fee_per_gas: 3,
        to: TxKind::Call(destination),
        value: U256::ZERO,
        input: data.into(),
        access_list: AccessList::default(),
    };
    let (signature, recovery) =
        signing_key().sign_prehash_recoverable(transaction.signature_hash().as_slice());
    let bytes = signature.to_bytes();
    let signature = Signature::from_scalars_and_parity(
        B256::from_slice(&bytes[..32]),
        B256::from_slice(&bytes[32..]),
        recovery.is_y_odd(),
    );
    RuntimeTransaction::User(TxEnvelope::from(transaction.into_signed(signature)).encoded_2718())
}

/// Call precompile `id` with the calldata and store the return data's hash
/// and length, so the output reaches the post-state root.
fn wrapper(id: u16) -> Vec<u8> {
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

fn genesis(runtime: &WasmRuntime, id: u16, destination: Address) -> neutrin0_trie::Trie {
    runtime
        .init_genesis(&RuntimeGenesisInput {
            max_block_proving_input_bytes:
                neutrin0_primitives::DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES,
            chain_id: 7,
            timestamp: 0,
            seed: [8; 32],
            genesis_block_hash: [6; 32],
            chunk_size: 128,
            programs: neutrin0_primitives::ProgramSet {
                runtime_code_hash: neutrin0_primitives::blake3_256(EVM_MASTER_WASM),
                execution: neutrin0_primitives::ExecutionPrograms {
                    fact: [1; 8],
                    evidence: [2; 8],
                    block: [3; 8],
                },
            },
            block_gas_limit: 2_000_000,
            runtime_params: neutrin0_primitives::RuntimeParams::default(),
            validators: Vec::new(),
            configuration: borsh::to_vec(&EvmGenesisConfig {
                initial_base_fee: 10,
                accounts: vec![
                    GenesisAccount {
                        address: sender().into_array(),
                        balance: U256::from(1_000_000_000_000_000_000_u64).to_be_bytes(),
                        nonce: 0,
                        code: Vec::new(),
                        storage: Vec::new(),
                    },
                    GenesisAccount {
                        address: destination.into_array(),
                        balance: [0; 32],
                        nonce: 1,
                        code: wrapper(id),
                        storage: Vec::new(),
                    },
                ],
            })
            .unwrap(),
        })
        .unwrap()
        .1
}

#[test]
fn every_osaka_precompile_matches_wasm_in_the_final_elf() {
    let runtime = WasmRuntime::new(EVM_MASTER_WASM).unwrap();
    let guest = ProverCtx::new_cached_for(
        ProverClient::builder().mock().build(),
        EVM_GUEST_ELF.clone(),
    )
    .unwrap();
    let mut diverged = Vec::new();
    for (id, data) in osaka::vectors() {
        let mut address = [0x41; 20];
        address[18..].copy_from_slice(&id.to_be_bytes());
        let destination = Address::from(address);
        let state = genesis(&runtime, id, destination);
        let input = RuntimeBlockInput {
            active_validators: Vec::new(),
            participation_acks: Vec::new(),
            program_pieces: Vec::new(),
            context: ConsensusExecutionContext {
                slot: 1,
                timestamp: 100,
                parent_block_hash: [6; 32],
                finalized: neutrin0_consensus_types::history_proof::ConsensusBoundary {
                    seed: [8; 32],
                    ..Default::default()
                },
                ..ConsensusExecutionContext::default()
            },
            evidence_anchor: EvidenceAnchor::default(),
            chain_id: 7,
            block_height: 1,
            block_gas_limit: 2_000_000,
            proposer_address: neutrin0_evm_runtime_core::state::consensus_address(Address::from(
                [9; 20],
            )),
            participation: None,
            proving: None,
            transactions: vec![transaction(destination, data)],
        };
        let dry = runtime.dry_run(&input, &state, &[]).unwrap();
        assert_eq!(dry.output.applied, 1, "precompile {id}");
        let (public, report) = guest
            .execute(&input, &dry.witness, &[], PROVER_ADDRESS)
            .unwrap();
        assert_eq!(report.exit_code, 0, "precompile {id}");
        let expected = borsh::to_vec(&neutrin0_runtime_abi::BlockReceiptStatement {
            output: dry.output,
            prover_address: PROVER_ADDRESS,
        })
        .unwrap();
        if public.as_slice() != expected {
            diverged.push(id);
        }
    }
    assert_eq!(
        diverged,
        Vec::<u16>::new(),
        "precompiles whose ELF output differs"
    );
}
