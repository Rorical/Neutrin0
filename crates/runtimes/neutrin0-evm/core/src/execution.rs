//! One deterministic Osaka block transition for native, WASM and SP1.

mod pending;

use crate::{
    EVM_SPEC,
    currency::SystemCurrency,
    fees::{FEE_STATE_KEY, FeeState, next_base_fee},
    state::{StateDb, VerifiedBytecodeCache, ethereum_address, read_record, write_record},
    transaction::{EthereumTransaction, decode},
};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use alloy_consensus::Transaction;
use borsh::{BorshDeserialize, BorshSerialize};
pub use neutrin0_runtime_abi::ethereum::{EvmBlockMetadata, EvmLog, EvmReceipt};
use neutrin0_runtime_abi::{
    ExecutionArtifacts, RuntimeBlockInput, RuntimeBlockOutput, RuntimeBlockResult,
    RuntimeTransaction,
};
use neutrin0_runtime_core::{StateBackend, overlay::OverlayState};
pub(crate) use pending::{execute_pending, execute_pending_head};
use revm::context::BlockEnv;
use revm::context::result::ExecutionResult;
use revm::primitives::{Address, B256, U256};
use revm::{Context, ExecuteCommitEvm, MainBuilder, MainContext};

/// Runtime receipt distinguishes autonomous system work from Ethereum transactions.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub enum ExecutionReceipt {
    /// Framework accountability work.
    System(neutrin0_runtime_system::Receipt),
    /// Ethereum user operation.
    Ethereum(EvmReceipt),
}

/// Fully decoded block input. Evidence authenticity is established by the execution shell.
pub struct PreparedBlock<'a> {
    input: &'a RuntimeBlockInput,
    transactions: Vec<Option<EthereumTransaction>>,
}

/// Decode every user transaction before touching authenticated state.
///
/// The block transition is total: an undecodable payload, like a transaction
/// that does not fit the remaining gas or that the EVM refuses, is skipped
/// with no effects and no receipt, in verification and proving exactly as
/// producer selection skips it. Every signed block therefore has one correct
/// execution, and a header claiming another is contradicted by its receipt.
pub fn prepare_block(input: &RuntimeBlockInput) -> Result<PreparedBlock<'_>, String> {
    neutrin0_runtime_core::execution::check_runtime_input(input)
        .map_err(|error| String::from(error.message()))?;
    let transactions = input
        .transactions
        .iter()
        .map(|tx| match tx {
            RuntimeTransaction::User(bytes) => decode(bytes, input.chain_id).ok(),
            RuntimeTransaction::SubmitEvidence(_) => None,
        })
        .collect();
    Ok(PreparedBlock {
        input,
        transactions,
    })
}

/// Execute a block atomically, returning complete authenticated artifacts.
pub fn execute_block<B: StateBackend>(
    input: &RuntimeBlockInput,
    state: &mut B,
) -> RuntimeBlockResult {
    let prepared = prepare_block(input).expect("valid Ethereum block encoding");
    execute_prepared_block(&prepared, state).expect("valid Ethereum block execution")
}

/// Common public output for execution-only callers.
pub fn apply_block<B: StateBackend>(
    input: &RuntimeBlockInput,
    state: &mut B,
) -> RuntimeBlockOutput {
    execute_block(input, state).output
}

/// Execute previously decoded input after the shell verifies exact evidence memberships.
pub fn apply_prepared_block<B: StateBackend>(
    input: &PreparedBlock<'_>,
    state: &mut B,
) -> RuntimeBlockOutput {
    execute_prepared_block(input, state)
        .expect("valid Ethereum block execution")
        .output
}

/// Apply Osaka transactions and mandatory economics through a disposable state journal.
pub fn execute_prepared_block<B: StateBackend>(
    prepared: &PreparedBlock<'_>,
    state: &mut B,
) -> Result<RuntimeBlockResult, String> {
    run_block(prepared, state, false, true, false).map(|(result, _)| result)
}

/// Select executable candidates against evolving scratch state after mandatory work.
/// No state changes escape this operation; returned indexes preserve execution order.
pub fn select_transactions<B: StateBackend>(
    input: &RuntimeBlockInput,
    state: &mut B,
) -> Result<Vec<u32>, String> {
    let prepared = prepare_block(input)?;
    run_block(&prepared, state, true, false, false).map(|(_, selected)| selected)
}

#[allow(
    clippy::too_many_lines,
    reason = "The atomic block transition keeps mandatory work, candidate execution, commitments and journal publication in one ordered pipeline."
)]
fn run_block<B: StateBackend>(
    prepared: &PreparedBlock<'_>,
    state: &mut B,
    selecting: bool,
    retain: bool,
    pending: bool,
) -> Result<(RuntimeBlockResult, Vec<u32>), String> {
    let input = prepared.input;
    let pre_state_root = state.pre_state_root();
    let beneficiary =
        ethereum_address(&input.proposer_address).map_err(|error| error.to_string())?;
    let mut overlay = OverlayState::new(state);
    let (fees, previous) = load_block_continuity(&mut overlay, input)?;
    let system = neutrin0_runtime_system::system::begin_block(
        input,
        &mut SystemCurrency {
            state: &mut overlay,
        },
    );
    let policy = neutrin0_runtime_system::load_runtime_policy(&mut overlay);
    record_block_context(&mut overlay, input, previous.as_ref());
    let mut artifacts = ExecutionArtifacts {
        transaction_ids: Vec::new(),
        receipts: system
            .receipts
            .iter()
            .map(|receipt| {
                borsh::to_vec(&ExecutionReceipt::System(*receipt)).expect("system receipt")
            })
            .collect(),
        metadata: Vec::new(),
    };
    let mut evm_gas = 0_u64;
    // Design 08: every base fee and tip the block's transactions paid, and
    // the tips the EVM already credited to the proposer.
    let mut fee_pool = 0_u128;
    let mut tips = 0_u128;
    let mut selected = Vec::new();
    let mut applied = 0_u32;
    let mut failed = 0_u32;
    let mut code_cache = VerifiedBytecodeCache::default();
    loop {
        let mut progress = false;
        for (index, transaction) in prepared.transactions.iter().enumerate() {
            if selecting && selected.contains(&u32::try_from(index).expect("transaction index")) {
                continue;
            }
            let Some(transaction) = transaction else {
                continue;
            };
            let remaining = input.block_gas_limit - system.gas - evm_gas;
            if transaction.environment.gas_limit > remaining {
                continue;
            }
            let db = StateDb::with_code_cache(&mut overlay, input.block_height, &mut code_cache);
            let mut evm = Context::mainnet()
                .with_db(db)
                .with_chain(input)
                .modify_cfg_chained(|cfg| {
                    cfg.chain_id = input.chain_id;
                    cfg.set_spec_and_mainnet_gas_params(EVM_SPEC);
                })
                .modify_block_chained(|block| {
                    configure_block(block, input, beneficiary, fees.next_base_fee);
                })
                .build_mainnet()
                .with_precompiles(
                    crate::system::SystemPrecompiles::new(policy).with_proposer_vrf(!pending),
                );
            let result = match evm.transact_commit(transaction.environment.clone()) {
                Ok(result) => result,
                // A transaction the EVM refuses (nonce, balance, fee, gas
                // floor) commits nothing and is skipped. State faults are not
                // transaction verdicts: they abort, so withheld or corrupt
                // state can never pass for a skip.
                Err(revm::context::result::EVMError::Transaction(_)) => continue,
                Err(_) if selecting => continue,
                Err(error) => return Err(error.to_string()),
            };
            progress = true;
            let index = u32::try_from(index).map_err(|_| "transaction index overflow")?;
            selected.push(index);
            artifacts.transaction_ids.push((index, transaction.hash.0));
            evm_gas = evm_gas
                .checked_add(result.tx_gas_used())
                .ok_or("EVM gas overflow")?;
            if result.is_success() {
                applied += 1;
            } else {
                failed += 1;
            }
            let effective_gas_price = effective_gas_price(transaction, fees.next_base_fee);
            let paid_gas = u128::from(result.tx_gas_used());
            fee_pool = fee_pool.saturating_add(paid_gas.saturating_mul(effective_gas_price));
            tips = tips.saturating_add(paid_gas.saturating_mul(
                effective_gas_price.saturating_sub(u128::from(fees.next_base_fee)),
            ));
            let receipt =
                ethereum_receipt(index, transaction, &result, evm_gas, effective_gas_price);
            artifacts.receipts.push(
                borsh::to_vec(&ExecutionReceipt::Ethereum(receipt)).expect("Ethereum receipt"),
            );
        }
        if !selecting || !progress {
            break;
        }
    }
    let gas_used = system
        .gas
        .checked_add(evm_gas)
        .ok_or("block gas overflow")?;
    let candidates = settle_block_economics(
        &mut overlay,
        input,
        &fees,
        gas_used,
        fee_pool - tips,
        &policy,
    )?;
    artifacts.metadata = borsh::to_vec(&EvmBlockMetadata {
        height: input.block_height,
        base_fee: fees.next_base_fee,
        beneficiary: beneficiary.into_array(),
        system_gas: system.gas,
        evm_gas,
        context: input.context,
    })
    .expect("EVM block metadata");
    let (transactions_root, transaction_summary) =
        neutrin0_runtime_core::execution::transaction_commitments(&input.transactions);
    let receipts_root = neutrin0_runtime_core::execution::artifacts_commitment(&artifacts);
    if retain {
        overlay.flush();
    }
    let output = RuntimeBlockOutput {
        context: input.context,
        accountability: system.accountability,
        chain_id: input.chain_id,
        block_height: input.block_height,
        block_gas_limit: input.block_gas_limit,
        proposer_address: input.proposer_address,
        participation: system.participation,
        proving: system.proving,
        participation_acks: neutrin0_consensus_types::participation::acknowledgement_commitment(
            &input.participation_acks,
        ),
        program_pieces: neutrin0_consensus_types::program_pieces_commitment(&input.program_pieces),
        transactions_root,
        transaction_summary,
        pre_state_root,
        post_state_root: if selecting {
            pre_state_root
        } else {
            overlay.post_state_root()
        },
        applied,
        failed,
        consensus_candidates_root: candidates.root(),
        gas_used,
        receipts_root,
    };
    Ok((RuntimeBlockResult { output, artifacts }, selected))
}

/// Load the fee state and previous environment the block must continue.
fn load_block_continuity<B: StateBackend>(
    overlay: &mut OverlayState<'_, B>,
    input: &RuntimeBlockInput,
) -> Result<(FeeState, Option<crate::environment::BlockEnvironment>), String> {
    let fees: FeeState =
        read_record(overlay, FEE_STATE_KEY)?.ok_or("missing EVM genesis fee state")?;
    if fees.height.checked_add(1) != Some(input.block_height) {
        return Err("EVM fee-state height mismatch".into());
    }
    let previous = read_record::<crate::environment::BlockEnvironment, _>(
        overlay,
        crate::environment::ENVIRONMENT_KEY,
    )?;
    if let Some(previous) = &previous
        && (input.context.timestamp <= previous.context.timestamp
            || input.context.slot <= previous.context.slot)
    {
        return Err("non-increasing authenticated EVM timestamp or slot".into());
    }
    Ok((fees, previous))
}

/// Record the parent hash ring, the execution environment and the finalized seed ring.
fn record_block_context<B: StateBackend>(
    overlay: &mut OverlayState<'_, B>,
    input: &RuntimeBlockInput,
    previous: Option<&crate::environment::BlockEnvironment>,
) {
    if input.block_height > 0 {
        let parent = input.block_height - 1;
        write_record(
            overlay,
            &crate::state::block_hash_key(parent % 256),
            &(parent, input.context.parent_block_hash),
        );
    }
    crate::environment::store(overlay, input, previous);
    if let Some(source) = input.context.finalized.next_chunk_id.checked_sub(1) {
        write_record(
            overlay,
            &crate::randomness::seed_key(source % 8),
            &(source, input.context.finalized.seed),
        );
    }
}

/// Block environment shared by every transaction of one execution.
fn configure_block(
    block: &mut BlockEnv,
    input: &RuntimeBlockInput,
    beneficiary: Address,
    base_fee: u64,
) {
    block.number = U256::from(input.block_height);
    block.timestamp = U256::from(input.context.timestamp);
    block.beneficiary = beneficiary;
    block.gas_limit = input.block_gas_limit;
    block.basefee = base_fee;
    block.prevrandao = Some(B256::from(input.context.finalized.seed));
    block.set_blob_excess_gas_and_price(0, 5_007_716);
}

fn effective_gas_price(transaction: &EthereumTransaction, base_fee: u64) -> u128 {
    transaction.environment.gas_price.min(
        u128::from(base_fee).saturating_add(
            transaction
                .environment
                .gas_priority_fee
                .unwrap_or(transaction.environment.gas_price),
        ),
    )
}

fn ethereum_receipt(
    index: u32,
    transaction: &EthereumTransaction,
    result: &ExecutionResult,
    cumulative_gas_used: u64,
    effective_gas_price: u128,
) -> EvmReceipt {
    EvmReceipt {
        envelope_index: index,
        transaction_hash: transaction.hash.0,
        from: transaction.sender.into_array(),
        to: transaction
            .envelope
            .to()
            .map(revm::primitives::Address::into_array),
        contract_address: result
            .created_address()
            .map(revm::primitives::Address::into_array),
        transaction_type: transaction.environment.tx_type,
        success: result.is_success(),
        gas_used: result.tx_gas_used(),
        cumulative_gas_used,
        effective_gas_price,
        logs: result
            .logs()
            .iter()
            .map(|log| EvmLog {
                address: log.address.into_array(),
                topics: log.data.topics().iter().map(|topic| topic.0).collect(),
                data: log.data.data.to_vec(),
            })
            .collect(),
    }
}

/// Advance the fee state and escrow the block's burned base fees and issuance.
fn settle_block_economics<B: StateBackend>(
    overlay: &mut OverlayState<'_, B>,
    input: &RuntimeBlockInput,
    fees: &FeeState,
    gas_used: u64,
    base_fees: u128,
    policy: &neutrin0_runtime_system::RuntimePolicy,
) -> Result<neutrin0_consensus_types::runtime::ConsensusCandidates, String> {
    write_record(
        overlay,
        FEE_STATE_KEY,
        &FeeState {
            height: input.block_height,
            next_base_fee: next_base_fee(fees.next_base_fee, gas_used, input.block_gas_limit)
                .map_err(String::from)?,
        },
    );
    write_record(overlay, b"evm:last_base_fee", &fees.next_base_fee);
    // Design 08: the proposer keeps the tips revm already credited it, which
    // pay for its own block proof. The burned base fee returns through the
    // block's escrow, split between the chunk prover and the chunk's
    // participating committee, together with the issuance accrued since the
    // previous block, all fixed now under the policy in force.
    let candidates =
        neutrin0_runtime_system::prune_consensus_candidates(overlay, &input.active_validators);
    neutrin0_runtime_system::proving::record_block_fees(
        overlay,
        input.block_height,
        &input.context,
        base_fees,
        policy,
        &candidates,
    );
    Ok(candidates)
}
