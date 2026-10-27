//! Strict standard event layouts, without claiming a contract implements a token interface.
use crate::{
    Error, Result,
    model::{IndexedLog, IndexedTransfer, hex},
};
use alloy_primitives::U256;

pub(super) fn decode(log: &IndexedLog) -> Result<Vec<IndexedTransfer>> {
    let Some(topic) = log.topics.first() else {
        return Ok(Vec::new());
    };
    let data = hex::decode(
        log.data
            .strip_prefix("0x")
            .ok_or_else(|| Error::Data("log data lacks hexadecimal prefix".into()))?,
    )
    .map_err(|_| Error::Data("invalid log data".into()))?;
    let signature = |value: &str| hex(&neutrin0_crypto::keccak256(value.as_bytes()));
    let transfer = signature("Transfer(address,address,uint256)");
    let single = signature("TransferSingle(address,address,address,uint256,uint256)");
    let batch = signature("TransferBatch(address,address,address,uint256[],uint256[])");
    let addresses = |a: usize, b: usize| -> Option<(String, String)> {
        Some((
            address_word(log.topics.get(a)?.as_str())?,
            address_word(log.topics.get(b)?.as_str())?,
        ))
    };
    let result = if topic == &transfer {
        let Some((from, to)) = addresses(1, 2) else {
            return Ok(Vec::new());
        };
        if log.topics.len() == 3 && data.len() == 32 {
            vec![row(
                log,
                "ERC20",
                from,
                to,
                U256::from_be_slice(&data).to_string(),
                None,
                0,
            )]
        } else if log.topics.len() == 4 && data.is_empty() {
            let Some(id) = log
                .topics
                .get(3)
                .and_then(|s| hex::decode(s.strip_prefix("0x")?).ok())
            else {
                return Ok(Vec::new());
            };
            if id.len() != 32 {
                return Ok(Vec::new());
            }
            vec![row(
                log,
                "ERC721",
                from,
                to,
                "1".into(),
                Some(U256::from_be_slice(&id).to_string()),
                0,
            )]
        } else {
            Vec::new()
        }
    } else if (topic == &single || topic == &batch) && log.topics.len() == 4 {
        let Some((from, to)) = addresses(2, 3) else {
            return Ok(Vec::new());
        };
        if topic == &single && data.len() == 64 {
            vec![row(
                log,
                "ERC1155",
                from,
                to,
                U256::from_be_slice(&data[32..]).to_string(),
                Some(U256::from_be_slice(&data[..32]).to_string()),
                0,
            )]
        } else if topic == &batch {
            decode_batch(log, &data, &from, &to)
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    Ok(result)
}
fn address_word(value: &str) -> Option<String> {
    let bytes = hex::decode(value.strip_prefix("0x")?).ok()?;
    (bytes.len() == 32 && bytes[..12] == [0; 12]).then(|| hex(&bytes[12..]))
}
fn row(
    log: &IndexedLog,
    standard: &str,
    from: String,
    to: String,
    amount: String,
    token_id: Option<String>,
    item_index: u32,
) -> IndexedTransfer {
    IndexedTransfer {
        transaction_position: log.transaction_position,
        transaction_hash: log.transaction_hash.clone(),
        log_index: log.index,
        item_index,
        contract: log.address.clone(),
        standard: standard.into(),
        from,
        to,
        amount,
        token_id,
    }
}
fn offset(data: &[u8], at: usize) -> Option<usize> {
    usize::try_from(U256::from_be_slice(data.get(at..at.checked_add(32)?)?)).ok()
}
fn decode_batch(log: &IndexedLog, data: &[u8], from: &str, to: &str) -> Vec<IndexedTransfer> {
    let Some(ids) = offset(data, 0) else {
        return Vec::new();
    };
    let Some(values) = offset(data, 32) else {
        return Vec::new();
    };
    let Some(count) = offset(data, ids) else {
        return Vec::new();
    };
    if ids != 64
        || count > 1024
        || values != ids + 32 + count * 32
        || offset(data, values) != Some(count)
        || values + 32 + count * 32 != data.len()
    {
        return Vec::new();
    }
    (0..count)
        .map(|i| {
            row(
                log,
                "ERC1155",
                from.into(),
                to.into(),
                U256::from_be_slice(&data[values + 32 + i * 32..values + 64 + i * 32]).to_string(),
                Some(U256::from_be_slice(&data[ids + 32 + i * 32..ids + 64 + i * 32]).to_string()),
                u32::try_from(i).expect("bounded batch"),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests;
