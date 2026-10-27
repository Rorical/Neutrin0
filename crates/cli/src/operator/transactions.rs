//! Local transaction construction and explicit broadcast.

use alloy_consensus::{Transaction, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use neutrin0_rpc::client::{NodeApiClient, NodeClient};
use neutrin0_rpc::{BlockId, BlockIdJson, BytesHex, HashHex};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
};
use zeroize::Zeroizing;

use super::Error;
use super::arguments::{Arguments, credentials, decode_bytes};
use super::state::check_runtime;

mod calldata;
mod signing;
#[cfg(test)]
mod tests;

const MAX_TRANSACTION_BYTES: u64 = 10 * 1024 * 1024;

fn read_key(path: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    crate::secret::read_seed(path).map_err(Error::Local)
}

pub(super) fn write_new(path: &str, bytes: &[u8]) -> Result<(), Error> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| Error::Local(format!("create output file: {error}")))?;
    let result = file.write_all(bytes).and_then(|()| file.sync_all());
    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(Error::Local(format!("write output file: {error}")));
    }
    Ok(())
}

fn read_transaction(path: &str) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![];
    File::open(path)
        .map_err(|error| Error::Local(format!("open transaction file: {error}")))?
        .take(MAX_TRANSACTION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Error::Local(format!("read transaction file: {error}")))?;
    if bytes.is_empty()
        || bytes.len() > usize::try_from(MAX_TRANSACTION_BYTES).expect("bounded transaction size")
    {
        return Err(Error::Usage(
            "transaction must contain between 1 byte and 10 MiB".into(),
        ));
    }
    Ok(bytes)
}

fn validate_wait(options: &Arguments) -> Result<(), Error> {
    if let Some(wait) = options.get("wait")
        && !["included", "finalized"].contains(&wait)
    {
        return Err(Error::Usage("--wait must be included or finalized".into()));
    }
    let _ = options.duration("wait-timeout-secs", 1800)?;
    let _ = options.duration("poll-secs", 1)?;
    Ok(())
}

pub(super) async fn submit(client: &NodeClient, options: &Arguments) -> Result<Value, Error> {
    validate_wait(options)?;
    let bytes = match (options.get("bytes"), options.get("file")) {
        (Some(bytes), None) => decode_bytes(bytes)?,
        (None, Some(path)) => read_transaction(path)?,
        _ => {
            return Err(Error::Usage(
                "provide exactly one of --bytes or --file".into(),
            ));
        }
    };
    if bytes.is_empty()
        || bytes.len() > usize::try_from(MAX_TRANSACTION_BYTES).expect("bounded transaction size")
    {
        return Err(Error::Usage(
            "transaction must contain between 1 byte and 10 MiB".into(),
        ));
    }
    let head = client.pin(BlockIdJson(BlockId::Latest)).await?;
    check_runtime(client, head).await?;
    let mut input = bytes.as_slice();
    let tx = TxEnvelope::decode_2718(&mut input)
        .map_err(|_| Error::Usage("invalid Ethereum transaction".into()))?;
    if !input.is_empty() || tx.chain_id() != Some(client.rpc().chain_id().await?) {
        return Err(Error::Usage(
            "transaction must be exact bytes signed for the connected chain ID".into(),
        ));
    }
    broadcast(client, bytes, options).await
}

pub(super) async fn prepare(
    client: &NodeClient,
    group: &str,
    operation: &str,
    options: &Arguments,
) -> Result<Value, Error> {
    validate_wait(options)?;
    if options.get("wait").is_some() && !options.flag("submit") {
        return Err(Error::Usage(
            "--wait requires --submit when preparing a transaction".into(),
        ));
    }
    let head = client.pin(BlockIdJson(BlockId::Latest)).await?;
    check_runtime(client, head).await?;
    let chain_id = client.rpc().chain_id().await?;
    if options.get("chain-id").is_some() && options.number("chain-id", chain_id)? != chain_id {
        return Err(Error::Usage(
            "--chain-id does not match the connected node".into(),
        ));
    }
    let (bytes, mut description) =
        signing::prepare_evm(client, group, operation, chain_id, options).await?;
    description["hash"] = json!(HashHex(neutrin0_crypto::keccak256(&bytes)));
    description["context"] = json!(head);
    if let Some(path) = options.get("out") {
        write_new(path, &bytes)?;
        description["path"] = json!(path);
    }
    if options.flag("submit") {
        let result = broadcast(client, bytes, options).await?;
        description["submitted"] = json!(true);
        description["confirmation"] = result["confirmation"].clone();
    } else {
        description["submitted"] = json!(false);
        description["signed_bytes"] = json!(BytesHex(bytes));
    }
    Ok(description)
}

async fn broadcast(
    client: &NodeClient,
    bytes: Vec<u8>,
    options: &Arguments,
) -> Result<Value, Error> {
    let expected = neutrin0_crypto::keccak256(&bytes);
    eprintln!(
        "{}",
        json!({"submission_attempt": true, "hash": HashHex(expected)})
    );
    let hash = client.rpc().send_raw_transaction(BytesHex(bytes)).await?;
    if hash.0 != expected {
        return Err(Error::Local(format!(
            "provider returned a mismatched transaction identifier; expected 0x{}; do not resubmit automatically",
            hex::encode(expected)
        )));
    }
    if options.get("wait").is_some() {
        // Retain the identifier even if confirmation is interrupted or times out.
        eprintln!("{}", json!({"submitted": true, "hash": hash}));
        let confirmation = wait(client, hash, options, true).await?;
        Ok(json!({"hash": hash, "submitted": true, "confirmation": confirmation}))
    } else {
        Ok(json!({"hash": hash, "submitted": true}))
    }
}

pub(super) async fn wait(
    client: &NodeClient,
    hash: HashHex,
    options: &Arguments,
    default_finalized: bool,
) -> Result<neutrin0_rpc::client::TransactionConfirmation, Error> {
    let finalized = match options.get("wait").unwrap_or(if default_finalized {
        "finalized"
    } else {
        "included"
    }) {
        "finalized" => true,
        "included" => false,
        _ => return Err(Error::Usage("--wait must be included or finalized".into())),
    };
    let timeout = options.duration("wait-timeout-secs", 1800)?;
    let poll = options.duration("poll-secs", 1)?;
    let confirmation = async { Ok(client.wait_ethereum(hash, finalized, timeout, poll).await?) };
    tokio::select! {
        result = confirmation => result,
        result = tokio::signal::ctrl_c() => { result.map_err(|error| Error::Local(error.to_string()))?; Err(Error::Local(format!("confirmation interrupted for transaction 0x{}; check its status before retrying", hex::encode(hash.0)))) }
    }
}
