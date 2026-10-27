//! EIP-1559 construction: sender, target, nonce, fees, gas simulation and local signing.

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Signature, TxKind, U256};
use k256::ecdsa::SigningKey;
use neutrin0_rpc::BytesHex;
use neutrin0_rpc::client::{NodeApiClient, NodeClient, quantity_u64};
use serde_json::{Value, json};

use super::calldata::{amount, evm_data};
use super::{Arguments, Error, credentials, decode_bytes, read_key};

pub(super) async fn prepare_evm(
    client: &NodeClient,
    group: &str,
    operation: &str,
    chain_id: u64,
    options: &Arguments,
) -> Result<(Vec<u8>, Value), Error> {
    let seed = read_key(options.required("key-file")?)?;
    let key = SigningKey::from_bytes((&*seed).into())
        .map_err(|_| Error::Local("invalid secp256k1 key".into()))?;
    let from = sender_address(&key);
    let (to, value, data) = call_target(client, group, operation, from, options).await?;
    let nonce = pending_nonce(client, from, options).await?;
    let (max_fee, tip) = evm_fees(client, options).await?;
    let call = json!({"from": format!("{from:#x}"), "to": format!("{to:#x}"), "value": format!("{value:#x}"), "data": BytesHex(data.clone()), "maxFeePerGas": format!("0x{max_fee:x}"), "maxPriorityFeePerGas": format!("0x{tip:x}"), "type": "0x2"});
    let gas = gas_allowance(client, &call, options).await?;
    // An explicit gas allowance still undergoes a simulation before signing.
    simulate(client, call, gas).await?;
    let call_data = BytesHex(data.clone());
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit: gas,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: tip,
        to: TxKind::Call(to),
        value,
        input: data.into(),
        ..Default::default()
    };
    let bytes = sign_eip1559(&key, tx);
    let maximum_fee = U256::from(gas)
        .checked_mul(U256::from(max_fee))
        .ok_or_else(|| Error::Local("fee bound overflow".into()))?;
    Ok((
        bytes,
        json!({"operation": operation, "chain_id": chain_id, "from": format!("{from:#x}"), "to": format!("{to:#x}"), "value": value.to_string(), "amount": amount(options, false)?.to_string(), "data": call_data, "validator_account": options.get("address"), "nonce": nonce, "gas_limit": gas,
        "max_fee_per_gas": max_fee.to_string(), "max_priority_fee_per_gas": tip.to_string(), "maximum_fee": maximum_fee.to_string()}),
    ))
}

fn sender_address(key: &SigningKey) -> Address {
    let public = key.verifying_key().to_sec1_point(false);
    let digest = neutrin0_crypto::keccak256(&public.as_bytes()[1..]);
    Address::from_slice(&digest[12..])
}

/// The recipient, value and calldata: a plain transfer or call for `tx`,
/// otherwise the staking (`0x…0800`) or governance (`0x…0801`) precompile.
async fn call_target(
    client: &NodeClient,
    group: &str,
    operation: &str,
    from: Address,
    options: &Arguments,
) -> Result<(Address, U256, Vec<u8>), Error> {
    if group == "tx" {
        let destination = credentials(options.required("to")?)?;
        return Ok((
            Address::from_slice(&destination[12..]),
            amount(options, operation == "transfer")?,
            decode_bytes(options.get("data").unwrap_or(""))?,
        ));
    }
    let system = if group == "governance" {
        0x0801
    } else {
        0x0800
    };
    let mut address = [0; 20];
    address[18..].copy_from_slice(
        &u16::try_from(system)
            .expect("system address fits u16")
            .to_be_bytes(),
    );
    let data = if group == "governance" && operation != "vote" {
        crate::operator::governance::calldata(client, operation, options).await?
    } else {
        let mut credential = [0; 32];
        credential[12..].copy_from_slice(from.as_slice());
        evm_data(operation, credential, options)?
    };
    Ok((Address::from(address), U256::ZERO, data))
}

async fn pending_nonce(
    client: &NodeClient,
    from: Address,
    options: &Arguments,
) -> Result<u64, Error> {
    if options.get("nonce").is_some() {
        return options.number("nonce", 0);
    }
    let nonce = client
        .rpc()
        .ethereum_nonce(format!("{from:#x}"), json!("pending"))
        .await?;
    Ok(quantity_u64(&nonce)?)
}

async fn gas_allowance(
    client: &NodeClient,
    call: &Value,
    options: &Arguments,
) -> Result<u64, Error> {
    let gas = if options.get("gas-limit").is_some() {
        options.number("gas-limit", 0)?
    } else {
        quantity_u64(
            &client
                .rpc()
                .estimate_gas(call.clone(), json!("pending"))
                .await?,
        )?
    };
    if gas == 0 {
        return Err(Error::Usage("--gas-limit must be positive".into()));
    }
    Ok(gas)
}

async fn simulate(client: &NodeClient, call: Value, gas: u64) -> Result<(), Error> {
    let mut simulation = call;
    simulation["gas"] = json!(format!("0x{gas:x}"));
    let _ = client
        .rpc()
        .ethereum_call(simulation, json!("pending"))
        .await?;
    Ok(())
}

fn sign_eip1559(key: &SigningKey, tx: TxEip1559) -> Vec<u8> {
    let (signature, recovery) = key.sign_prehash_recoverable(tx.signature_hash().as_slice());
    let signature = signature.to_bytes();
    let signature = Signature::from_scalars_and_parity(
        B256::from_slice(&signature[..32]),
        B256::from_slice(&signature[32..]),
        recovery.is_y_odd(),
    );
    TxEnvelope::from(tx.into_signed(signature)).encoded_2718()
}

async fn evm_fees(client: &NodeClient, options: &Arguments) -> Result<(u128, u128), Error> {
    let tip = if let Some(value) = options.get("max-priority-fee-per-gas") {
        value
            .parse()
            .map_err(|_| Error::Usage("--max-priority-fee-per-gas must be a decimal u128".into()))?
    } else {
        parse_quantity_u128(&client.rpc().priority_fee().await?)?
    };
    let max_fee = if let Some(value) = options.get("max-fee-per-gas") {
        value
            .parse()
            .map_err(|_| Error::Usage("--max-fee-per-gas must be a decimal u128".into()))?
    } else {
        parse_quantity_u128(&client.rpc().gas_price().await?)?
            .checked_mul(2)
            .ok_or_else(|| Error::Local("fee suggestion overflow".into()))?
            .max(tip)
    };
    if tip > max_fee {
        return Err(Error::Usage("priority fee cannot exceed max fee".into()));
    }
    Ok((max_fee, tip))
}

fn parse_quantity_u128(value: &str) -> Result<u128, Error> {
    let value = value
        .strip_prefix("0x")
        .filter(|value| !value.is_empty() && (value.len() == 1 || !value.starts_with('0')))
        .ok_or_else(|| Error::Local("invalid fee quantity".into()))?;
    u128::from_str_radix(value, 16).map_err(|_| Error::Local("fee quantity exceeds u128".into()))
}
