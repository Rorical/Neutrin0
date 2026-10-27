//! Disposable candidate executions behind the Ethereum `pending` tag.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Crate-visible entry points of a private module; `pub` would be unreachable."
)]

use super::{EvmBlockMetadata, RuntimeBlockResult, configure_block, prepare_block, run_block};
use crate::{
    EVM_SPEC,
    state::{StateDb, VerifiedBytecodeCache, ethereum_address, read_record},
    transaction::decode,
};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use neutrin0_runtime_abi::{RuntimeBlockInput, RuntimeTransaction};
use neutrin0_runtime_core::{StateBackend, overlay::OverlayState};
use revm::{Context, ExecuteCommitEvm, MainBuilder, MainContext};

/// Execute candidate transactions into a caller-owned disposable journal.
/// Pending proposer identity is deliberately unavailable; no speculative state is published.
pub(crate) fn execute_pending<B: StateBackend>(
    input: &RuntimeBlockInput,
    state: &mut B,
) -> Result<RuntimeBlockResult, String> {
    let prepared = prepare_block(input)?;
    run_block(&prepared, state, true, true, true).map(|(result, _)| result)
}

/// Query-only user overlay at the already authenticated head environment.
/// It performs no begin-block, evidence/FIFO, environment, fee-state, randomness
/// ring or block-artifact publication. The caller owns a disposable journal.
pub(crate) fn execute_pending_head<B: StateBackend>(
    input: &RuntimeBlockInput,
    state: &mut B,
) -> Result<(Vec<u32>, EvmBlockMetadata), String> {
    check_head_environment(input, state)?;
    let base_fee: u64 =
        read_record(state, b"evm:last_base_fee")?.ok_or("head base fee unavailable")?;
    let beneficiary =
        ethereum_address(&input.proposer_address).map_err(|error| error.to_string())?;
    let policy = neutrin0_runtime_system::load_runtime_policy(state);
    let transactions: Vec<_> = input
        .transactions
        .iter()
        .map(|transaction| match transaction {
            RuntimeTransaction::User(bytes) => decode(bytes, input.chain_id).ok(),
            RuntimeTransaction::SubmitEvidence(_) => None,
        })
        .collect();
    let mut overlay = OverlayState::new(state);
    let mut code_cache = VerifiedBytecodeCache::default();
    let mut selected = Vec::new();
    let mut gas_used = 0_u64;
    loop {
        let mut progress = false;
        for (index, transaction) in transactions.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| "pending transaction index overflow")?;
            if selected.contains(&index) {
                continue;
            }
            let Some(transaction) = transaction else {
                continue;
            };
            let remaining = input
                .block_gas_limit
                .checked_sub(gas_used)
                .ok_or("pending gas exceeds block ceiling")?;
            if transaction.environment.gas_limit > remaining {
                continue;
            }
            let mut evm = Context::mainnet()
                .with_db(StateDb::with_code_cache(
                    &mut overlay,
                    input.block_height,
                    &mut code_cache,
                ))
                .with_chain(input)
                .modify_cfg_chained(|cfg| {
                    cfg.chain_id = input.chain_id;
                    cfg.set_spec_and_mainnet_gas_params(EVM_SPEC);
                })
                .modify_block_chained(|block| configure_block(block, input, beneficiary, base_fee))
                .build_mainnet()
                .with_precompiles(crate::system::SystemPrecompiles::new(policy));
            let Ok(result) = evm.transact_commit(transaction.environment.clone()) else {
                continue;
            };
            gas_used = gas_used
                .checked_add(result.tx_gas_used())
                .ok_or("pending gas overflow")?;
            selected.push(index);
            progress = true;
        }
        if !progress {
            break;
        }
    }
    overlay.flush();
    Ok((
        selected,
        EvmBlockMetadata {
            height: input.block_height,
            base_fee,
            beneficiary: beneficiary.into_array(),
            system_gas: 0,
            evm_gas: gas_used,
            context: input.context,
        },
    ))
}

fn check_head_environment<B: StateBackend>(
    input: &RuntimeBlockInput,
    state: &mut B,
) -> Result<(), String> {
    let stored =
        crate::environment::load(state)?.ok_or("head execution environment unavailable")?;
    let mut environment = input.clone();
    environment.transactions.clear();
    environment.participation_acks.clear();
    environment.program_pieces.clear();
    if environment != stored {
        return Err("head-local simulation environment differs from selected state".into());
    }
    Ok(())
}
