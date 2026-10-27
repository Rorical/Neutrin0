//! Disposable call simulations and gas estimation against a selected state.

use super::{CallRequest, CallResult};
use crate::state::{StateDb, read_record};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_core::{StateBackend, overlay::OverlayState};
use revm::primitives::{Address, B256, TxKind, U256};
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};

/// Execute one call in a REVM journal which is discarded without committing.
pub fn simulate<B: StateBackend>(
    request: &CallRequest,
    state: &mut B,
) -> Result<CallResult, String> {
    simulate_with_availability(request, state, true)
}

pub(super) fn estimate_gas<B: StateBackend>(
    request: &CallRequest,
    state: &mut B,
    proposer_vrf_available: bool,
) -> Result<(CallResult, u64), String> {
    let result = simulate_with_availability(request, state, proposer_vrf_available)?;
    if !result.success {
        return Ok((result, 0));
    }
    let mut upper = request.gas_limit;
    let mut lower = result
        .gas_used
        .saturating_sub(1)
        .min(upper.saturating_sub(1));
    let mut trial = request.clone();
    while upper.saturating_sub(lower) > 1 {
        let allowance = lower + (upper - lower) / 2;
        trial.gas_limit = allowance;
        if simulate_with_availability(&trial, state, proposer_vrf_available)?.success {
            upper = allowance;
        } else {
            lower = allowance;
        }
    }
    Ok((result, upper))
}

pub(super) fn simulate_with_availability<B: StateBackend>(
    request: &CallRequest,
    state: &mut B,
    proposer_vrf_available: bool,
) -> Result<CallResult, String> {
    let (input, base_fee) = selected_block_context(state, request.gas_limit)?;
    let policy = neutrin0_runtime_system::load_runtime_policy(state);
    let mut scratch = OverlayState::new(state);
    let mut evm = Context::mainnet()
        .with_db(StateDb::new(&mut scratch, input.block_height))
        .with_chain(&input)
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = input.chain_id;
            cfg.set_spec_and_mainnet_gas_params(crate::EVM_SPEC);
            cfg.disable_nonce_check = true;
            cfg.disable_eip3607 = true;
            cfg.disable_base_fee = request.fee_cap.is_none();
            cfg.disable_fee_charge = request.fee_cap.is_none();
            cfg.disable_balance_check = false;
        })
        .modify_block_chained(|block| {
            block.number = U256::from(input.block_height);
            block.timestamp = U256::from(input.context.timestamp);
            block.beneficiary = crate::state::ethereum_address(&input.proposer_address)
                .expect("canonical beneficiary");
            block.gas_limit = input.block_gas_limit;
            block.basefee = base_fee;
            block.prevrandao = Some(B256::from(input.context.finalized.seed));
            block.set_blob_excess_gas_and_price(0, 5_007_716);
        })
        .build_mainnet()
        .with_precompiles(
            crate::system::SystemPrecompiles::new(policy).with_proposer_vrf(proposer_vrf_available),
        );
    let transaction_type = simulation_transaction_type(request)?;
    let tx = simulation_transaction(request, transaction_type, input.chain_id);
    let result = match evm.transact(tx) {
        Ok(result) => result.result,
        Err(revm::context::result::EVMError::Transaction(
            revm::context::result::InvalidTransaction::CallGasCostMoreThanGasLimit { .. }
            | revm::context::result::InvalidTransaction::GasFloorMoreThanGasLimit { .. },
        )) => {
            return Ok(CallResult {
                success: false,
                reverted: false,
                gas_used: request.gas_limit,
                output: Vec::new(),
            });
        }
        Err(error) => return Err(error.to_string()),
    };
    Ok(CallResult {
        success: result.is_success(),
        reverted: matches!(
            result,
            revm::context::result::ExecutionResult::Revert { .. }
        ),
        gas_used: result.tx_gas_used(),
        output: result
            .output()
            .map_or_else(Vec::new, |bytes| bytes.to_vec()),
    })
}

/// The selected block's authenticated environment and the base fee its transactions paid.
fn selected_block_context<B: StateBackend>(
    state: &mut B,
    gas_limit: u64,
) -> Result<(RuntimeBlockInput, u64), String> {
    let input = crate::environment::load(state)?
        .ok_or("selected block execution environment unavailable")?;
    if gas_limit > input.block_gas_limit {
        return Err("simulation exceeds native block gas ceiling".into());
    }
    let fees: crate::fees::FeeState =
        read_record(state, crate::fees::FEE_STATE_KEY)?.ok_or("missing fee state")?;
    let base_fee = if input.block_height == 0 {
        fees.next_base_fee
    } else {
        read_record::<u64, _>(state, b"evm:last_base_fee")?
            .ok_or("selected block base fee unavailable")?
    };
    Ok((input, base_fee))
}

fn simulation_transaction_type(request: &CallRequest) -> Result<u8, String> {
    let transaction_type = request.transaction_type.unwrap_or_else(|| {
        if !request.authorization_list.is_empty() {
            4
        } else if request.tip_cap.is_some() {
            2
        } else {
            u8::from(!request.access_list.is_empty())
        }
    });
    if ![0, 1, 2, 4].contains(&transaction_type) {
        return Err("unsupported Ethereum simulation transaction type".into());
    }
    Ok(transaction_type)
}

fn simulation_transaction(
    request: &CallRequest,
    transaction_type: u8,
    chain_id: u64,
) -> revm::context::TxEnv {
    let access_list = simulation_access_list(request);
    revm::context::TxEnv {
        tx_type: transaction_type,
        caller: Address::from(request.from),
        kind: request.to.map_or(TxKind::Create, |address| {
            TxKind::Call(Address::from(address))
        }),
        value: U256::from_be_bytes(request.value),
        data: request.data.clone().into(),
        gas_limit: request.gas_limit,
        gas_price: request.fee_cap.or(request.tip_cap).unwrap_or(0),
        gas_priority_fee: matches!(transaction_type, 2 | 4).then_some(request.tip_cap.unwrap_or(0)),
        chain_id: Some(chain_id),
        access_list,
        authorization_list: simulation_authorizations(request),
        ..Default::default()
    }
}

fn simulation_authorizations(
    request: &CallRequest,
) -> Vec<
    revm::context_interface::either::Either<
        alloy_eips::eip7702::SignedAuthorization,
        alloy_eips::eip7702::RecoveredAuthorization,
    >,
> {
    request
        .authorization_list
        .iter()
        .map(|authorization| {
            revm::context_interface::either::Either::Left(
                alloy_eips::eip7702::SignedAuthorization::new_unchecked(
                    alloy_eips::eip7702::Authorization {
                        chain_id: U256::from_be_bytes(authorization.chain_id),
                        address: Address::from(authorization.address),
                        nonce: authorization.nonce,
                    },
                    authorization.y_parity,
                    U256::from_be_bytes(authorization.r),
                    U256::from_be_bytes(authorization.s),
                ),
            )
        })
        .collect()
}

fn simulation_access_list(
    request: &CallRequest,
) -> revm::context_interface::transaction::AccessList {
    revm::context_interface::transaction::AccessList(
        request
            .access_list
            .iter()
            .map(
                |(address, keys)| revm::context_interface::transaction::AccessListItem {
                    address: Address::from(*address),
                    storage_keys: keys.iter().copied().map(B256::from).collect(),
                },
            )
            .collect(),
    )
}
