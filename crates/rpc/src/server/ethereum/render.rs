//! Ethereum JSON projections of blocks, transactions and receipts.
use super::codec::{bytes, error, q, word_quantity};
use super::queries::{artifacts, decoded, query};
use crate::backend::BlockId;
use crate::server::RpcContext;
use crate::server::errors::{invalid_params, query_err};
use jsonrpsee::types::ErrorObjectOwned;
use neutrin0_runtime_abi::ethereum::{EvmTransaction, FeeState};
use serde_json::{Value, json};

pub(super) fn pending_block_json(
    block: &neutrin0_runtime_abi::ethereum::PendingBlock,
    full: bool,
) -> Value {
    let transactions = block
        .transactions
        .iter()
        .map(|tx| {
            if full {
                transaction_json(
                    tx,
                    None,
                    tx.fee_cap.min(
                        u128::from(block.metadata.base_fee)
                            .saturating_add(tx.tip_cap.unwrap_or(tx.fee_cap)),
                    ),
                )
            } else {
                bytes(&tx.hash)
            }
        })
        .collect::<Vec<_>>();
    let mode = match block.mode {
        neutrin0_runtime_abi::ethereum::PendingMode::NextBlock => "next-block",
        neutrin0_runtime_abi::ethereum::PendingMode::HeadLocal => "head-local",
    };
    json!({"number":q(u128::from(block.number)),"hash":null,"parentHash":bytes(&block.parent_hash),"nonce":null,"miner":bytes(&block.metadata.beneficiary),"difficulty":"0x0","totalDifficulty":"0x0","extraData":"0x","gasLimit":q(u128::from(block.gas_limit)),"gasUsed":q(u128::from(block.metadata.system_gas+block.metadata.evm_gas)),"timestamp":q(u128::from(block.metadata.context.timestamp)),"baseFeePerGas":q(u128::from(block.metadata.base_fee)),"transactions":transactions,"uncles":[],"stateRoot":null,"transactionsRoot":null,"receiptsRoot":null,"logsBloom":null,"mixHash":bytes(&block.metadata.context.finalized.seed),"neutrin0PendingMode":mode})
}

pub(super) async fn genesis_json(
    ctx: &RpcContext,
    hash: [u8; 32],
) -> Result<Option<Value>, ErrorObjectOwned> {
    let Some(genesis) = ctx
        .backend()
        .genesis_info()
        .await
        .map_err(|error| query_err(&error))?
        .filter(|genesis| genesis.hash == hash)
    else {
        return Ok(None);
    };
    let fee = query::<Option<FeeState>>(ctx, "evm:next_base_fee", Vec::new(), &BlockId::Hash(hash))
        .await?
        .ok_or_else(|| error("genesis fee state unavailable"))?;
    let empty = neutrin0_runtime_abi::ExecutionArtifacts::default().commitment();
    Ok(Some(
        json!({"number":"0x0","hash":bytes(&hash),"parentHash":bytes(&[0;32]),"nonce":"0x0000000000000000","sha3Uncles":bytes(&neutrin0_crypto::keccak256(&[0xc0])),"logsBloom":bytes(&[0;256]),"transactionsRoot":bytes(&neutrin0_primitives::merkle_root_of_hashes(&[])),"stateRoot":bytes(&genesis.state_root),"receiptsRoot":bytes(&empty),"miner":bytes(&[0;20]),"difficulty":"0x0","totalDifficulty":"0x0","extraData":"0x","size":"0x0","gasLimit":q(u128::from(genesis.gas_limit)),"gasUsed":"0x0","timestamp":q(u128::from(genesis.timestamp)),"baseFeePerGas":q(u128::from(fee.next_base_fee)),"transactions":[],"uncles":[],"mixHash":bytes(&genesis.seed),"neutrin0SystemGasUsed":"0x0"}),
    ))
}

pub(super) fn transaction_json(
    tx: &EvmTransaction,
    block: Option<([u8; 32], u64, usize)>,
    price: u128,
) -> Value {
    let mut result = json!({"hash": bytes(&tx.hash), "from": bytes(&tx.from), "to": tx.to.map(|address| bytes(&address)), "nonce": q(u128::from(tx.nonce)), "gas": q(u128::from(tx.gas_limit)), "gasPrice": q(price), "value": word_quantity(&tx.value), "input": bytes(&tx.input), "type": q(u128::from(tx.transaction_type)), "chainId": q(u128::from(tx.chain_id)), "v": q(if tx.transaction_type == 0 { u128::from(tx.chain_id)*2+35+u128::from(tx.y_parity) } else { u128::from(tx.y_parity) }), "r": word_quantity(&tx.r), "s": word_quantity(&tx.s), "blockHash": block.map(|(hash,_,_)| bytes(&hash)), "blockNumber": block.map(|(_,height,_)| q(u128::from(height))), "transactionIndex": block.map(|(_,_,index)| q(index as u128))});
    if tx.transaction_type != 0 {
        result["accessList"] = json!(tx.access_list.iter().map(|(address, keys)| json!({"address": bytes(address), "storageKeys": keys.iter().map(|key| bytes(key)).collect::<Vec<_>>()})).collect::<Vec<_>>());
        result["yParity"] = q(u128::from(tx.y_parity));
    }
    if let Some(tip) = tx.tip_cap {
        result["maxFeePerGas"] = q(tx.fee_cap);
        result["maxPriorityFeePerGas"] = q(tip);
    }
    if tx.transaction_type == 4 {
        result["authorizationList"] = json!(tx.authorization_list.iter().map(|auth| json!({"chainId": word_quantity(&auth.chain_id), "address": bytes(&auth.address), "nonce": q(u128::from(auth.nonce)), "yParity": q(u128::from(auth.y_parity)), "r": word_quantity(&auth.r), "s": word_quantity(&auth.s)})).collect::<Vec<_>>());
    }
    result
}
fn bloom(logs: impl Iterator<Item = neutrin0_runtime_abi::ethereum::EvmLog>) -> Vec<u8> {
    let mut result = vec![0; 256];
    for log in logs {
        for value in core::iter::once(log.address.to_vec())
            .chain(log.topics.into_iter().map(|topic| topic.to_vec()))
        {
            let hash = neutrin0_crypto::keccak256(&value);
            for offset in [0, 2, 4] {
                let bit = (usize::from(hash[offset]) * 256 + usize::from(hash[offset + 1])) & 2047;
                result[255 - bit / 8] |= 1 << (bit % 8);
            }
        }
    }
    result
}
pub(super) fn receipt_json(
    receipt: &neutrin0_runtime_abi::ethereum::EvmReceipt,
    hash: [u8; 32],
    number: u64,
    index: usize,
    log_start: usize,
) -> Value {
    let logs = receipt.logs.iter().enumerate().map(|(offset, log)| json!({"address": bytes(&log.address), "topics": log.topics.iter().map(|topic| bytes(topic)).collect::<Vec<_>>(), "data": bytes(&log.data), "blockHash": bytes(&hash), "blockNumber": q(u128::from(number)), "transactionHash": bytes(&receipt.transaction_hash), "transactionIndex": q(index as u128), "logIndex": q((log_start+offset) as u128), "removed": false})).collect::<Vec<_>>();
    json!({"transactionHash": bytes(&receipt.transaction_hash), "transactionIndex": q(index as u128), "blockHash": bytes(&hash), "blockNumber": q(u128::from(number)), "from": bytes(&receipt.from), "to": receipt.to.map(|address| bytes(&address)), "contractAddress": receipt.contract_address.map(|address| bytes(&address)), "cumulativeGasUsed": q(u128::from(receipt.cumulative_gas_used)), "gasUsed": q(u128::from(receipt.gas_used)), "effectiveGasPrice": q(receipt.effective_gas_price), "status": q(u128::from(receipt.success)), "type": q(u128::from(receipt.transaction_type)), "logs": logs, "logsBloom": bytes(&bloom(receipt.logs.iter().cloned()))})
}
pub(super) async fn block_json(
    ctx: &RpcContext,
    block: &neutrin0_consensus_types::Block,
    full: bool,
) -> Result<Value, ErrorObjectOwned> {
    let projection = artifacts(ctx, block).await?;
    let mut transactions = Vec::new();
    for (index, receipt) in projection.receipts.iter().enumerate() {
        if full {
            let raw = block
                .body
                .transactions
                .get(receipt.envelope_index as usize)
                .ok_or_else(|| error("receipt index outside block"))?
                .clone();
            transactions.push(transaction_json(
                &decoded(ctx, raw, Some(block.hash())).await?,
                Some((block.hash(), block.header.height, index)),
                receipt.effective_gas_price,
            ));
        } else {
            transactions.push(bytes(&receipt.transaction_hash));
        }
    }
    Ok(
        json!({"number": q(u128::from(block.header.height)), "hash": bytes(&block.hash()), "parentHash": bytes(&block.header.parent_hash), "nonce": "0x0000000000000000", "sha3Uncles": bytes(&neutrin0_crypto::keccak256(&[0xc0])), "logsBloom": bytes(&bloom(projection.receipts.iter().flat_map(|receipt| receipt.logs.clone()))), "transactionsRoot": bytes(&block.header.transactions_root), "stateRoot": bytes(&block.header.state_root), "receiptsRoot": bytes(&block.header.receipts_root), "miner": bytes(&projection.metadata.beneficiary), "difficulty": "0x0", "totalDifficulty": "0x0", "extraData": "0x", "size": q(borsh::object_length(block).map_err(invalid_params)? as u128), "gasLimit": q(u128::from(block.header.gas_limit)), "gasUsed": q(u128::from(block.header.gas_used)), "timestamp": q(u128::from(block.header.timestamp)), "transactions": transactions, "uncles": [], "baseFeePerGas": q(u128::from(projection.metadata.base_fee)), "mixHash": bytes(&projection.metadata.context.finalized.seed), "neutrin0SystemGasUsed": q(u128::from(projection.metadata.system_gas))}),
    )
}
