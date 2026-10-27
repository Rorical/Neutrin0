//! Account state reads and call/estimate simulation.
use super::codec::{argument, bytes, data, fixed, height, q, quantity, word, word_quantity};
use super::queries::{environment, pending_query, query, state_query};
use super::selection::selected_id;
use crate::backend::BlockId;
use crate::server::RpcContext;
use crate::server::errors::{invalid_params, query_err};
use jsonrpsee::types::ErrorObjectOwned;
use neutrin0_runtime_abi::{
    RuntimeBlockInput,
    ethereum::{CallRequest, CallResult, EvmAccount},
};
use serde_json::Value;

pub(super) async fn account_operation(
    ctx: &RpcContext,
    method: &str,
    args: &[Value],
) -> Result<Value, ErrorObjectOwned> {
    let address: [u8; 20] = fixed(argument(args, 0)?)?;
    let block_parameter = if method == "eth_getStorageAt" { 2 } else { 1 };
    let (at, pending) = selected_id(ctx, args.get(block_parameter)).await?;
    if pending && method == "eth_getTransactionCount" {
        let head = ctx
            .backend()
            .head()
            .await
            .map_err(|error| query_err(&error))?;
        let account: EvmAccount = query(
            ctx,
            "evm:account",
            address.to_vec(),
            &BlockId::Hash(head.hash),
        )
        .await?;
        let mut credential = [0; 32];
        credential[12..].copy_from_slice(&address);
        let nonce = ctx
            .backend()
            .pending_sequence(credential, account.nonce, head.hash)
            .await
            .map_err(|error| query_err(&error))?;
        return Ok(q(u128::from(nonce)));
    }
    if method == "eth_getCode" {
        return state_query::<Vec<u8>>(ctx, "evm:code", address.to_vec(), &at, pending)
            .await
            .map(|value| bytes(&value));
    }
    if method == "eth_getStorageAt" {
        let slot = word(argument(args, 1)?)?;
        return state_query::<[u8; 32]>(
            ctx,
            "evm:storage",
            borsh::to_vec(&(address, slot)).map_err(invalid_params)?,
            &at,
            pending,
        )
        .await
        .map(|value| bytes(&value));
    }
    let account: EvmAccount =
        state_query(ctx, "evm:account", address.to_vec(), &at, pending).await?;
    if method == "eth_getBalance" {
        Ok(word_quantity(&account.balance))
    } else {
        Ok(q(u128::from(account.nonce)))
    }
}

pub(super) async fn call_operation(
    ctx: &RpcContext,
    method: &str,
    args: &[Value],
) -> Result<Value, ErrorObjectOwned> {
    let (at, pending) = selected_id(ctx, args.get(1)).await?;
    let limit = if let Some(genesis) = ctx
        .backend()
        .genesis_info()
        .await
        .map_err(|error| query_err(&error))?
    {
        genesis.gas_limit
    } else if pending {
        pending_query::<RuntimeBlockInput>(ctx, "evm:environment", Vec::new())
            .await?
            .block_gas_limit
    } else {
        environment(ctx, &at).await?.block_gas_limit
    };
    let request = call_request(argument(args, 0)?, limit)?;
    let encoded = borsh::to_vec(&request).map_err(invalid_params)?;
    let (result, allowance): (CallResult, u64) = if method == "eth_estimateGas" {
        // The runtime performs all trials against one immutable journal. In a
        // pending view this also fixes the candidate set for the entire search.
        state_query(ctx, "evm:estimate_gas", encoded, &at, pending).await?
    } else {
        let result = state_query(ctx, "evm:call", encoded, &at, pending).await?;
        (result, 0)
    };
    if !result.success {
        return Err(ErrorObjectOwned::owned(
            3,
            "execution reverted or halted",
            Some(bytes(&result.output)),
        ));
    }
    if method == "eth_call" {
        return Ok(bytes(&result.output));
    }
    Ok(q(u128::from(allowance)))
}

pub(super) fn call_request(value: &Value, limit: u64) -> Result<CallRequest, ErrorObjectOwned> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_params("call object expected"))?;
    let field_quantity = |name: &str| object.get(name).map(quantity).transpose();
    if object.contains_key("gasPrice")
        && (object.contains_key("maxFeePerGas") || object.contains_key("maxPriorityFeePerGas"))
    {
        return Err(invalid_params(
            "gasPrice cannot be combined with dynamic fee fields",
        ));
    }
    if let (Some(input), Some(calldata)) = (object.get("input"), object.get("data"))
        && data(input)? != data(calldata)?
    {
        return Err(invalid_params(
            "input and data must match when both are supplied",
        ));
    }
    if let (Some(fee), Some(tip)) = (
        field_quantity("maxFeePerGas")?,
        field_quantity("maxPriorityFeePerGas")?,
    ) && tip > fee
    {
        return Err(invalid_params("priority fee exceeds fee cap"));
    }
    let access_list = object
        .get("accessList")
        .map(|list| {
            list.as_array()
                .ok_or_else(|| invalid_params("access list expected"))?
                .iter()
                .map(|entry| {
                    let address = fixed(
                        entry
                            .get("address")
                            .ok_or_else(|| invalid_params("access list address expected"))?,
                    )?;
                    let keys = entry
                        .get("storageKeys")
                        .and_then(Value::as_array)
                        .ok_or_else(|| invalid_params("storage keys expected"))?
                        .iter()
                        .map(fixed::<32>)
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok((address, keys))
                })
                .collect::<Result<Vec<_>, ErrorObjectOwned>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(CallRequest {
        from: object
            .get("from")
            .map(fixed::<20>)
            .transpose()?
            .unwrap_or([0; 20]),
        to: object
            .get("to")
            .filter(|value| !value.is_null())
            .map(fixed::<20>)
            .transpose()?,
        value: object
            .get("value")
            .map(word)
            .transpose()?
            .unwrap_or([0; 32]),
        data: object
            .get("input")
            .or_else(|| object.get("data"))
            .map(data)
            .transpose()?
            .unwrap_or_default(),
        // A call never runs with more gas than a block could hold.
        gas_limit: u64::try_from(
            field_quantity("gas")?
                .unwrap_or_else(|| u128::from(limit.min(16_777_216)))
                .min(u128::from(limit)),
        )
        .map_err(invalid_params)?,
        fee_cap: field_quantity("maxFeePerGas")?.or(field_quantity("gasPrice")?),
        tip_cap: field_quantity("maxPriorityFeePerGas")?,
        access_list,
        transaction_type: field_quantity("type")?
            .map(u8::try_from)
            .transpose()
            .map_err(invalid_params)?,
        authorization_list: call_authorizations(object.get("authorizationList"))?,
    })
}

fn call_authorizations(
    value: Option<&Value>,
) -> Result<Vec<neutrin0_runtime_abi::ethereum::EvmAuthorization>, ErrorObjectOwned> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value
        .as_array()
        .ok_or_else(|| invalid_params("authorization list expected"))?
        .iter()
        .map(|authorization| {
            let required = |field| {
                authorization
                    .get(field)
                    .ok_or_else(|| invalid_params("authorization field missing"))
            };
            Ok(neutrin0_runtime_abi::ethereum::EvmAuthorization {
                chain_id: word(required("chainId")?)?,
                address: fixed(required("address")?)?,
                nonce: height(required("nonce")?)?,
                y_parity: u8::try_from(quantity(required("yParity")?)?).map_err(invalid_params)?,
                r: word(required("r")?)?,
                s: word(required("s")?)?,
            })
        })
        .collect()
}
