//! One execution-only fixture shared by every native/WASM/final-ELF parity case.
//! These inputs establish STF parity, not BFT finality or recursive acceptance.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Shared fixtures of a private test support module; `pub` would be unreachable."
)]

use alloy_consensus::{SignableTransaction, Signed, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Signature, U256, keccak256};
use neutrin0_consensus_types::{
    Body, Header, evidence::EvidenceAnchor, history_proof::ConsensusBoundary,
};
use neutrin0_primitives::{Hash, ProgramSet, blake3_256};
use neutrin0_runtime_abi::{
    RuntimeBlockInput, RuntimeBlockResult, RuntimeGenesisInput, RuntimeTransaction,
    ethereum::{EvmGenesisConfig, EvmReceipt, GenesisAccount},
};
use neutrin0_runtime_core::{
    StateBackend, WitnessState,
    host::{LiveTrie, TracingState},
};
use neutrin0_runtime_host::{
    EVM_GUEST_ELF, ProverCtx,
    package::RuntimePackage,
    wasm::{EVM_MASTER_WASM, WasmRuntime},
};
use neutrin0_trie::Trie;
use sp1_sdk::{
    HashableKey as _,
    blocking::{CpuProver, ProverClient},
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

pub(super) const CHAIN_ID: u64 = 7;
pub(super) const GAS_LIMIT: u64 = 1_000_000;
pub(super) const GENESIS_HASH: Hash = [6; 32];
pub(super) const SEED: Hash = [8; 32];

pub(super) fn sender() -> Address {
    let key = signing_key();
    let point = key.verifying_key().to_sec1_point(false);
    Address::from_slice(&keccak256(&point.as_bytes()[1..])[12..])
}

fn signing_key() -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap()
}

pub(super) fn signature(hash: B256) -> Signature {
    let (signature, recovery) = signing_key().sign_prehash_recoverable(hash.as_slice());
    let bytes = signature.to_bytes();
    Signature::from_scalars_and_parity(
        B256::from_slice(&bytes[..32]),
        B256::from_slice(&bytes[32..]),
        recovery.is_y_odd(),
    )
}

pub(super) fn signed<T>(transaction: T) -> RuntimeTransaction
where
    T: SignableTransaction<Signature>,
    TxEnvelope: From<Signed<T>>,
{
    let signature = signature(transaction.signature_hash());
    RuntimeTransaction::User(TxEnvelope::from(transaction.into_signed(signature)).encoded_2718())
}

pub(super) const fn contract(
    address: Address,
    code: Vec<u8>,
    storage: Vec<([u8; 32], [u8; 32])>,
) -> GenesisAccount {
    GenesisAccount {
        address: address.into_array(),
        balance: [0; 32],
        nonce: 1,
        code,
        storage,
    }
}

pub(super) fn funded_sender() -> GenesisAccount {
    GenesisAccount {
        address: sender().into_array(),
        balance: U256::from(1_000_000_000_000_000_000_u64).to_be_bytes(),
        nonce: 0,
        code: Vec::new(),
        storage: Vec::new(),
    }
}

pub(super) struct Harness {
    pub(super) wasm: WasmRuntime,
    /// The final Block Guest executor; `None` compares native and WASM only.
    pub(super) sp1: Option<ProverCtx<CpuProver>>,
    pub(super) programs: ProgramSet,
}

pub(super) struct Transition {
    pub(super) result: RuntimeBlockResult,
    pub(super) post: Trie,
    pub(super) native_hash: Hash,
}

impl Harness {
    pub(super) fn new() -> Self {
        let package = RuntimePackage::embedded(Vec::new()).unwrap();
        let prover = ProverClient::builder().cpu().build();
        let sp1 = ProverCtx::new_cached_for(prover, EVM_GUEST_ELF.clone()).unwrap();
        assert_eq!(sp1.vk.hash_u32(), package.programs.execution.block);
        assert_eq!(
            package.programs.runtime_code_hash,
            blake3_256(EVM_MASTER_WASM)
        );
        Self {
            wasm: WasmRuntime::new(EVM_MASTER_WASM).unwrap(),
            sp1: Some(sp1),
            programs: package.programs,
        }
    }

    /// Native and WASM execution without the SP1 executor or its key setup,
    /// for differential checks that run in ordinary CI. Native code has the
    /// Block Guest's 64-bit pointer width, WASM the producers' 32 bits. The
    /// program identities are plain data to the runtime.
    pub(super) fn execution_only() -> Self {
        Self {
            wasm: WasmRuntime::new(EVM_MASTER_WASM).unwrap(),
            sp1: None,
            programs: ProgramSet {
                runtime_code_hash: blake3_256(EVM_MASTER_WASM),
                execution: neutrin0_primitives::ExecutionPrograms {
                    fact: [1; 8],
                    evidence: [2; 8],
                    block: [3; 8],
                },
            },
        }
    }

    pub(super) fn genesis(&self, accounts: Vec<GenesisAccount>) -> (Trie, RuntimeGenesisInput) {
        let input = RuntimeGenesisInput {
            max_block_proving_input_bytes:
                neutrin0_primitives::DEFAULT_MAX_BLOCK_PROVING_INPUT_BYTES,
            chain_id: CHAIN_ID,
            timestamp: 0,
            seed: SEED,
            genesis_block_hash: GENESIS_HASH,
            chunk_size: neutrin0_primitives::DEFAULT_CHUNK_SIZE,
            programs: self.programs,
            block_gas_limit: GAS_LIMIT,
            runtime_params: neutrin0_primitives::RuntimeParams::default(),
            validators: Vec::new(),
            configuration: borsh::to_vec(&EvmGenesisConfig {
                initial_base_fee: 10,
                accounts,
            })
            .unwrap(),
        };
        (self.genesis_input(&input), input)
    }

    pub(super) fn genesis_input(&self, input: &RuntimeGenesisInput) -> Trie {
        let (wasm_output, wasm_state) = self.wasm.init_genesis(input).unwrap();
        let empty = LiveTrie::default();
        let mut tracing = TracingState::new(&empty);
        let native_output = neutrin0_evm_runtime_core::init_genesis(input, &mut tracing);
        let (native_state, _) = tracing.into_committed_and_witness().unwrap();
        assert_eq!(native_output, wasm_output, "native/WASM genesis output");
        assert_eq!(
            native_state.root(),
            wasm_state.root(),
            "native/WASM genesis state"
        );
        wasm_state
    }

    #[allow(
        clippy::unused_self,
        reason = "Keeps the harness as the single fixture entry point."
    )]
    pub(super) fn input(
        &self,
        genesis: &RuntimeGenesisInput,
        genesis_root: Hash,
        height: u64,
        parent: Hash,
        transactions: Vec<RuntimeTransaction>,
    ) -> RuntimeBlockInput {
        let vrf = [u8::try_from(height).unwrap(); 96];
        RuntimeBlockInput {
            active_validators: genesis.validators.clone(),
            participation_acks: Vec::new(),
            program_pieces: Vec::new(),
            context: neutrin0_consensus_types::runtime::ConsensusExecutionContext {
                slot: height,
                timestamp: height * 12,
                parent_block_hash: parent,
                proposer_vrf_output: neutrin0_crypto::sha256(&vrf),
                finalized: ConsensusBoundary {
                    programs: genesis.programs,
                    state_root: genesis_root,
                    block_hash: genesis.genesis_block_hash,
                    seed: genesis.seed,
                    validators_root: neutrin0_consensus_types::evidence::commitment(
                        &genesis.validators,
                    ),
                    history_root: neutrin0_consensus_types::history::empty_history_root(),
                    ..ConsensusBoundary::default()
                },
            },
            evidence_anchor: EvidenceAnchor {
                fact_guest_vk_digest: genesis.programs.execution.fact,
                evidence_guest_vk_digest: genesis.programs.execution.evidence,
                block_guest_vk_digest: genesis.programs.execution.block,
                chunk_size: genesis.chunk_size,
                unbonding_delay_blocks: genesis.runtime_params.unbonding_delay_blocks,
                history_root: neutrin0_consensus_types::history::empty_history_root(),
                ..EvidenceAnchor::default()
            },
            chain_id: genesis.chain_id,
            block_height: height,
            block_gas_limit: genesis.block_gas_limit,
            proposer_address: neutrin0_evm_runtime_core::state::consensus_address(Address::from(
                [9; 20],
            )),
            participation: None,
            proving: None,
            transactions,
        }
    }

    pub(super) fn transition(
        &self,
        name: &str,
        pre: &Trie,
        input: &RuntimeBlockInput,
    ) -> Transition {
        let dry = self
            .wasm
            .dry_run(input, pre, &[])
            .unwrap_or_else(|error| panic!("{name}: WASM {error}"));
        let live = LiveTrie::from_trie(pre.clone());
        let mut native = TracingState::new(&live);
        let result = neutrin0_evm_runtime_core::execute_block(input, &mut native);
        let (post, native_witness) = native.into_committed_and_witness().unwrap();
        assert_eq!(result.output, dry.output, "{name}: native/WASM output");
        assert_eq!(
            result.artifacts, dry.artifacts,
            "{name}: native/WASM receipts/logs/metadata"
        );
        assert_eq!(
            post.root(),
            dry.post_state.root(),
            "{name}: native/WASM state"
        );
        assert_eq!(
            result.artifacts.commitment(),
            result.output.receipts_root,
            "{name}: artifact commitment"
        );
        for witness in [&native_witness, &dry.witness] {
            let mut replay = WitnessState::new(witness).unwrap();
            assert_eq!(
                neutrin0_evm_runtime_core::execute_block(input, &mut replay),
                result,
                "{name}: guest state backend"
            );
            assert_eq!(
                replay.post_state_root(),
                post.root(),
                "{name}: witnessed post-state"
            );
        }
        let report = self.sp1.as_ref().map(|sp1| {
            let (public, report) = sp1
                .execute(input, &dry.witness, &[], PROVER_ADDRESS)
                .unwrap();
            assert_eq!(
                report.exit_code, 0,
                "{name}: final ELF must finish successfully"
            );
            assert_eq!(
                public.as_slice(),
                receipt_bytes(&result.output),
                "{name}: final ELF public values"
            );
            report
        });
        let metadata: neutrin0_runtime_abi::ethereum::EvmBlockMetadata =
            borsh::from_slice(&result.artifacts.metadata).unwrap();
        assert_eq!(
            metadata.evm_gas + metadata.system_gas,
            result.output.gas_used,
            "{name}: gas partition"
        );
        let receipts = receipts(&result);
        assert_eq!(
            receipts.iter().map(|receipt| receipt.gas_used).sum::<u64>(),
            metadata.evm_gas,
            "{name}: receipt gas"
        );
        assert_eq!(
            metadata.context, input.context,
            "{name}: authenticated context"
        );
        if let Some(report) = report {
            eprintln!(
                "EVM_PARITY name={name:?} elf={} cycles={} gas={} witness_bytes={} syscalls={:?}",
                hex::encode(blake3_256(&EVM_GUEST_ELF)),
                report.total_instruction_count(),
                result.output.gas_used,
                borsh::object_length(&dry.witness).unwrap(),
                report.syscall_counts
            );
        }
        Transition {
            native_hash: block_hash(input, &result),
            result,
            post: dry.post_state,
        }
    }
}

pub(super) fn receipts(result: &RuntimeBlockResult) -> Vec<EvmReceipt> {
    result
        .artifacts
        .receipts
        .iter()
        .filter_map(|bytes| {
            match borsh::from_slice::<neutrin0_evm_runtime_core::execution::ExecutionReceipt>(bytes)
                .unwrap()
            {
                neutrin0_evm_runtime_core::execution::ExecutionReceipt::Ethereum(receipt) => {
                    Some(receipt)
                }
                neutrin0_evm_runtime_core::execution::ExecutionReceipt::System(_) => None,
            }
        })
        .collect()
}

pub(super) fn account(
    state: &Trie,
    address: Address,
) -> neutrin0_runtime_abi::ethereum::EvmAccount {
    state
        .get(&neutrin0_evm_runtime_core::state::account_key(address))
        .unwrap()
        .map_or_else(Default::default, |bytes| borsh::from_slice(&bytes).unwrap())
}

pub(super) fn storage(state: &Trie, address: Address, slot: u64) -> U256 {
    state
        .get(&neutrin0_evm_runtime_core::state::storage_key(
            address,
            U256::from(slot),
        ))
        .unwrap()
        .map_or(U256::ZERO, |bytes| U256::from_be_slice(&bytes))
}

fn block_hash(input: &RuntimeBlockInput, result: &RuntimeBlockResult) -> Hash {
    let body = Body {
        artifacts: result.artifacts.clone(),
        transactions: input
            .transactions
            .iter()
            .map(|transaction| borsh::to_vec(transaction).unwrap())
            .collect(),
        ..Body::default()
    };
    Header {
        height: input.block_height,
        slot: input.context.slot,
        parent_hash: input.context.parent_block_hash,
        proposer_index: 0,
        vrf_proof: [u8::try_from(input.context.slot).unwrap(); 96],
        state_root: result.output.post_state_root,
        transactions_root: result.output.transactions_root,
        votes_root: neutrin0_primitives::merkle_root_of_hashes(&[]),
        da_root: neutrin0_prover_chunk::consensus::body_da_root(&body),
        runtime_extra: result.output.consensus_candidates_root,
        inputs_root: neutrin0_prover_chunk::execution::output_inputs_root(&result.output),
        receipts_root: result.output.receipts_root,
        gas_used: result.output.gas_used,
        gas_limit: input.block_gas_limit,
        timestamp: input.context.timestamp,
        signature: [0; 96],
    }
    .hash()
}
