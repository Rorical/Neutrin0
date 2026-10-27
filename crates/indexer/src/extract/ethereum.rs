//! Ethereum projections are selected/decoded by the full node's historical runtime.
use super::tokens;
use crate::{
    Error, Result,
    model::{IndexedBlock, IndexedLog, IndexedTransaction, hex},
};
use borsh::BorshDeserialize;
use neutrin0_rpc::client::{EthereumReceiptJson, quantity_u64};
use neutrin0_runtime_abi::{ExecutionArtifacts, RuntimeTransaction};
use serde_json::Value;

pub(super) fn decode(
    block: &mut IndexedBlock,
    artifacts: &ExecutionArtifacts,
    projection: &Value,
    receipts: &[EthereumReceiptJson],
) -> Result<()> {
    let transactions = projected_transactions(block, artifacts, projection, receipts)?;
    for tx in &mut block.transactions {
        if tx.kind != "evidence" {
            tx.kind = "evm_not_executed".into();
            tx.status = "not_executed".into();
        }
    }
    for (ordinal, ((position, id), (decoded, receipt))) in artifacts
        .transaction_ids
        .iter()
        .zip(transactions.iter().zip(receipts))
        .enumerate()
    {
        let tx = block
            .transactions
            .get_mut(*position as usize)
            .ok_or_else(|| Error::Data("Ethereum envelope index outside body".into()))?;
        let RuntimeTransaction::User(payload) = RuntimeTransaction::try_from_slice(&tx.raw)
            .map_err(|_| Error::Data("malformed Ethereum common envelope".into()))?
        else {
            return Err(Error::Data("Ethereum identity names evidence".into()));
        };
        let expected = hex(id);
        check_transaction_identity(
            &block.header,
            ordinal,
            id,
            &expected,
            &payload,
            decoded,
            receipt,
        )?;
        apply_execution(tx, expected, decoded, receipt)?;
        let transaction_hash = tx.hash.clone();
        append_logs(block, *position, &transaction_hash, receipt)?;
    }
    Ok(())
}

/// The projection's full transactions, once the projection names this block
/// and the projection, receipts and authenticated identifiers agree in count.
fn projected_transactions<'a>(
    block: &IndexedBlock,
    artifacts: &ExecutionArtifacts,
    projection: &'a Value,
    receipts: &[EthereumReceiptJson],
) -> Result<&'a Vec<Value>> {
    if field(projection, "hash")? != hex(&block.header.block_hash.0)
        || quantity(field(projection, "number")?)? != block.header.height
    {
        return Err(Error::BranchChanged);
    }
    let transactions = projection
        .get("transactions")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Data("full Ethereum transactions unavailable".into()))?;
    if transactions.len() != receipts.len() || receipts.len() != artifacts.transaction_ids.len() {
        return Err(Error::Data(
            "Ethereum projection/receipt/identifier counts differ".into(),
        ));
    }
    Ok(transactions)
}

fn check_transaction_identity(
    header: &neutrin0_rpc::HeaderJson,
    ordinal: usize,
    id: &[u8; 32],
    expected: &str,
    payload: &[u8],
    decoded: &Value,
    receipt: &EthereumReceiptJson,
) -> Result<()> {
    if neutrin0_crypto::keccak256(payload) != *id
        || field(decoded, "hash")? != expected
        || receipt.transaction_hash.0 != *id
        || receipt.block_hash != header.block_hash
        || quantity(&receipt.block_number)? != header.height
        || field(decoded, "blockHash")? != hex(&header.block_hash.0)
        || quantity(field(decoded, "transactionIndex")?)? != ordinal as u64
        || quantity(
            receipt
                .details
                .get("transactionIndex")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Data("receipt index absent".into()))?,
        )? != ordinal as u64
    {
        return Err(Error::BranchChanged);
    }
    Ok(())
}

fn apply_execution(
    tx: &mut IndexedTransaction,
    expected: String,
    decoded: &Value,
    receipt: &EthereumReceiptJson,
) -> Result<()> {
    tx.hash = expected;
    tx.kind = "ethereum".into();
    tx.from = Some(address(field(decoded, "from")?)?);
    tx.to = decoded
        .get("to")
        .filter(|value| !value.is_null())
        .map(|value| address(value.as_str().unwrap_or("")))
        .transpose()?;
    tx.contract_address = receipt
        .details
        .get("contractAddress")
        .filter(|value| !value.is_null())
        .map(|value| address(value.as_str().unwrap_or("")))
        .transpose()?;
    tx.nonce = Some(quantity(field(decoded, "nonce")?)?.to_string());
    tx.value = Some(word(field(decoded, "value")?)?);
    tx.status = match receipt.status.as_str() {
        "0x1" => "success",
        "0x0" => "failed",
        _ => return Err(Error::Data("invalid execution status".into())),
    }
    .into();
    tx.gas_used = Some(
        quantity(
            receipt
                .details
                .get("gasUsed")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Data("gasUsed absent".into()))?,
        )?
        .to_string(),
    );
    let mut receipt_meta = serde_json::to_value(receipt)?;
    receipt_meta
        .as_object_mut()
        .ok_or_else(|| Error::Data("invalid receipt projection".into()))?
        .remove("logs");
    tx.receipt = Some(receipt_meta);
    let input = field(decoded, "input")?;
    tx.details = serde_json::json!({"type": decoded.get("type"), "chainId":decoded.get("chainId"),"gas":decoded.get("gas"),"gasPrice":decoded.get("gasPrice"),"maxFeePerGas":decoded.get("maxFeePerGas"),"maxPriorityFeePerGas":decoded.get("maxPriorityFeePerGas"),"inputPrefix": input.get(..514).unwrap_or(input),"inputBytes":input.len().saturating_sub(2)/2,"contractAddress":receipt.details.get("contractAddress")});
    Ok(())
}
fn append_logs(
    block: &mut IndexedBlock,
    position: u32,
    transaction_hash: &str,
    receipt: &EthereumReceiptJson,
) -> Result<()> {
    let logs = receipt
        .details
        .get("logs")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Data("receipt logs absent".into()))?;
    if receipt.status == "0x0" && !logs.is_empty() {
        return Err(Error::Data("failed execution retained logs".into()));
    }
    for raw in logs {
        let topics = raw
            .get("topics")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Data("event topics absent".into()))?
            .iter()
            .map(|value| crate::model::hash(value.as_str().unwrap_or("")))
            .collect::<Result<Vec<_>>>()?;
        if topics.len() > 4
            || field(raw, "blockHash")? != hex(&block.header.block_hash.0)
            || field(raw, "transactionHash")? != transaction_hash
            || quantity(field(raw, "logIndex")?)? != block.logs.len() as u64
            || raw.get("removed") != Some(&Value::Bool(false))
        {
            return Err(Error::Data("invalid committed event indexing".into()));
        }
        let data = field(raw, "data")?;
        let data = hex::decode(
            data.strip_prefix("0x")
                .ok_or_else(|| Error::Data("event data lacks hex prefix".into()))?,
        )
        .map_err(|_| Error::Data("event data is not hexadecimal".into()))?;
        let log = IndexedLog {
            transaction_position: position,
            transaction_hash: transaction_hash.to_owned(),
            index: u32::try_from(block.logs.len())
                .map_err(|_| Error::Data("too many logs".into()))?,
            address: address(field(raw, "address")?)?,
            topics,
            data: hex(&data),
        };
        block.transfers.extend(tokens::decode(&log)?);
        block.logs.push(log);
        if block.logs.len() > 65_536 || block.transfers.len() > 65_536 {
            return Err(Error::Data(
                "token event expansion exceeds block limit".into(),
            ));
        }
    }
    Ok(())
}
fn address(value: &str) -> Result<String> {
    if value.len() != 42 {
        return Err(Error::Data("Ethereum address must have 20 bytes".into()));
    }
    crate::model::address(value)
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Data(format!("Ethereum {name} absent")))
}
fn quantity(value: &str) -> Result<u64> {
    quantity_u64(value).map_err(|_| Error::Data("invalid Ethereum quantity".into()))
}
fn word(value: &str) -> Result<String> {
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| Error::Data("invalid Ethereum value".into()))?;
    if raw.is_empty() || raw.len() > 64 || (raw.len() > 1 && raw.starts_with('0')) {
        return Err(Error::Data("noncanonical Ethereum value".into()));
    }
    alloy_primitives::U256::from_str_radix(raw, 16)
        .map(|word| word.to_string())
        .map_err(|_| Error::Data("invalid Ethereum word".into()))
}
