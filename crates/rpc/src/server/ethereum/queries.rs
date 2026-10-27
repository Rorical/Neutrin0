//! Runtime queries behind the facade: state, pending, admission and artifact calls.
use super::codec::error;
use crate::backend::BlockId;
use crate::server::RpcContext;
use crate::server::errors::{invalid_params, runtime_err};
use borsh::BorshDeserialize;
use jsonrpsee::types::ErrorObjectOwned;
use neutrin0_runtime_abi::{
    RuntimeBlockInput,
    ethereum::{EvmArtifacts, EvmTransaction, FeeState},
};
use std::collections::BTreeSet;

pub(super) async fn query<T: BorshDeserialize>(
    ctx: &RpcContext,
    method: &str,
    args: Vec<u8>,
    at: &BlockId,
) -> Result<T, ErrorObjectOwned> {
    let response = ctx
        .backend()
        .runtime_call(method.into(), args, at)
        .await
        .map_err(|error| runtime_err(&error))?;
    if response.code != 0 {
        return Err(error(
            "selected runtime does not provide this Ethereum operation",
        ));
    }
    borsh::from_slice(&response.payload).map_err(|_| error("malformed Ethereum runtime response"))
}
pub(super) async fn pending_query<T: BorshDeserialize>(
    ctx: &RpcContext,
    method: &str,
    args: Vec<u8>,
) -> Result<T, ErrorObjectOwned> {
    let response = ctx
        .backend()
        .runtime_pending_call(method.into(), args)
        .await
        .map_err(|error| runtime_err(&error))?;
    if response.code != 0 {
        return Err(error("pending runtime simulation unavailable"));
    }
    borsh::from_slice(&response.payload).map_err(|_| error("malformed pending runtime response"))
}
pub(super) async fn state_query<T: BorshDeserialize>(
    ctx: &RpcContext,
    method: &str,
    args: Vec<u8>,
    at: &BlockId,
    pending: bool,
) -> Result<T, ErrorObjectOwned> {
    if pending {
        pending_query(ctx, method, args).await
    } else {
        query(ctx, method, args, at).await
    }
}

pub(super) async fn artifact_query<T: BorshDeserialize>(
    ctx: &RpcContext,
    method: &str,
    args: Vec<u8>,
    block: [u8; 32],
) -> Result<T, ErrorObjectOwned> {
    let response = ctx
        .backend()
        .runtime_artifact_call(method.into(), args, block)
        .await
        .map_err(|error| runtime_err(&error))?;
    if response.code != 0 {
        return Err(error("historical runtime cannot decode Ethereum artifacts"));
    }
    borsh::from_slice(&response.payload)
        .map_err(|_| error("malformed historical Ethereum response"))
}
pub(super) async fn environment(
    ctx: &RpcContext,
    at: &BlockId,
) -> Result<RuntimeBlockInput, ErrorObjectOwned> {
    query::<Option<RuntimeBlockInput>>(ctx, "evm:environment", Vec::new(), at)
        .await?
        .ok_or_else(|| error("execution context unavailable"))
}
pub(super) async fn fees(ctx: &RpcContext) -> Result<u64, ErrorObjectOwned> {
    query::<Option<FeeState>>(ctx, "evm:next_base_fee", Vec::new(), &BlockId::Latest)
        .await?
        .map(|fees| fees.next_base_fee)
        .ok_or_else(|| error("EVM fee state unavailable"))
}
pub(super) async fn artifacts(
    ctx: &RpcContext,
    block: &neutrin0_consensus_types::Block,
) -> Result<EvmArtifacts, ErrorObjectOwned> {
    if block.body.artifacts.commitment() != block.header.receipts_root {
        return Err(error("execution artifacts differ from header commitment"));
    }
    let projected: EvmArtifacts = artifact_query(
        ctx,
        "evm:artifacts",
        borsh::to_vec(&block.body.artifacts).map_err(invalid_params)?,
        block.hash(),
    )
    .await?;
    check_artifact_projection(block, &projected)?;
    Ok(projected)
}

pub(super) fn check_artifact_projection(
    block: &neutrin0_consensus_types::Block,
    projected: &EvmArtifacts,
) -> Result<(), ErrorObjectOwned> {
    if projected.metadata.height != block.header.height
        || projected.metadata.context.slot != block.header.slot
        || projected.metadata.context.timestamp != block.header.timestamp
        || projected.metadata.context.parent_block_hash != block.header.parent_hash
        || projected.metadata.context.proposer_vrf_output
            != neutrin0_crypto::sha256(&block.header.vrf_proof)
        || projected
            .metadata
            .system_gas
            .checked_add(projected.metadata.evm_gas)
            != Some(block.header.gas_used)
        || block.header.gas_used > block.header.gas_limit
        || projected.metadata.base_fee == 0
    {
        return Err(error("execution metadata differs from header"));
    }
    let identifiers = projected
        .receipts
        .iter()
        .map(|receipt| (receipt.envelope_index, receipt.transaction_hash))
        .collect::<Vec<_>>();
    if identifiers != block.body.artifacts.transaction_ids {
        return Err(error(
            "Ethereum receipts differ from the authenticated transaction index",
        ));
    }
    let mut gas = 0_u64;
    let mut previous_index = None;
    let mut transaction_hashes = BTreeSet::new();
    for receipt in &projected.receipts {
        if usize::try_from(receipt.envelope_index)
            .map_or(true, |index| index >= block.body.transactions.len())
            || previous_index.is_some_and(|index| index >= receipt.envelope_index)
            || !transaction_hashes.insert(receipt.transaction_hash)
            || receipt.logs.iter().any(|log| log.topics.len() > 4)
        {
            return Err(error("malformed Ethereum receipt ordering or event topics"));
        }
        previous_index = Some(receipt.envelope_index);
        gas = gas
            .checked_add(receipt.gas_used)
            .ok_or_else(|| error("receipt gas accounting overflow"))?;
        if gas != receipt.cumulative_gas_used {
            return Err(error("receipt cumulative gas accounting differs"));
        }
    }
    if gas != projected.metadata.evm_gas {
        return Err(error("receipt gas differs from EVM block metadata"));
    }
    Ok(())
}
pub(super) async fn decoded(
    ctx: &RpcContext,
    raw: Vec<u8>,
    block: Option<[u8; 32]>,
) -> Result<EvmTransaction, ErrorObjectOwned> {
    let args = borsh::to_vec(&(ctx.backend().chain_id(), raw)).map_err(invalid_params)?;
    if let Some(block) = block {
        artifact_query(ctx, "evm:transaction", args, block).await
    } else {
        let response = ctx
            .backend()
            .runtime_admission_call("evm:transaction".into(), args)
            .await
            .map_err(|error| runtime_err(&error))?;
        if response.code != 0 {
            return Err(error(
                "admission runtime cannot decode this Ethereum transaction",
            ));
        }
        borsh::from_slice(&response.payload)
            .map_err(|_| error("malformed Ethereum admission response"))
    }
}
