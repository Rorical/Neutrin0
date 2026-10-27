//! Pure indexing decoders, never state transition execution.
mod ethereum;
mod tokens;
use crate::{
    Error, Result,
    config::Config,
    model::{IndexedBlock, IndexedTransaction, hex},
    source::Source,
};
use borsh::BorshDeserialize;
use neutrin0_rpc::types::{BlockArtifactsJson, BlockJson};
use neutrin0_runtime_abi::{ExecutionArtifacts, RuntimeTransaction};

/// Fetch and validate one block's bound data before publishing any derived rows.
pub async fn block(source: &dyn Source, config: &Config, block: BlockJson) -> Result<IndexedBlock> {
    let raw = source
        .artifacts(block.header.block_hash)
        .await?
        .ok_or_else(|| {
            Error::Data("execution artifacts unavailable; archive/full source required".into())
        })?;
    validate(&block, &raw)?;
    let artifacts: ExecutionArtifacts = borsh::from_slice(&raw.artifacts.0)
        .map_err(|_| Error::Data("malformed execution artifacts".into()))?;
    let mut result = IndexedBlock {
        header: block.header,
        runtime_hash: hex(&raw.runtime_code_hash.0),
        decoding: config.runtime.clone(),
        artifacts: raw.artifacts.0,
        transactions: block
            .body
            .transactions
            .into_iter()
            .enumerate()
            .map(|(position, raw)| transaction(position, raw.0))
            .collect::<Result<_>>()?,
        logs: Vec::new(),
        transfers: Vec::new(),
    };
    match config.runtime.as_str() {
        "evm" => {
            let (projection, receipts) = source.ethereum(result.header.block_hash).await?;
            ethereum::decode(&mut result, &artifacts, &projection, &receipts)?;
        }
        "opaque" => {}
        _ => return Err(Error::Config("unknown decoder".into())),
    }
    Ok(result)
}
fn validate(block: &BlockJson, raw: &BlockArtifactsJson) -> Result<()> {
    if raw.block_hash != block.header.block_hash
        || raw.artifacts.0.len() > 32 * 1024 * 1024
        || block.body.transactions.len() > 65_536
        || neutrin0_primitives::transactions_root_of_blobs(
            &block
                .body
                .transactions
                .iter()
                .map(|value| value.0.clone())
                .collect::<Vec<_>>(),
        ) != block.header.transactions_root.0
    {
        return Err(Error::Data(
            "block hash/transaction commitment or size mismatch".into(),
        ));
    }
    let artifacts: ExecutionArtifacts = borsh::from_slice(&raw.artifacts.0)
        .map_err(|_| Error::Data("malformed execution artifacts".into()))?;
    if artifacts.commitment() != block.header.receipts_root.0
        || artifacts
            .transaction_ids
            .windows(2)
            .any(|pair| pair[0].0 >= pair[1].0)
        || artifacts
            .transaction_ids
            .iter()
            .any(|(index, _)| *index as usize >= block.body.transactions.len())
    {
        return Err(Error::Data(
            "execution artifacts differ from committed header/body".into(),
        ));
    }
    Ok(())
}
fn transaction(position: usize, raw: Vec<u8>) -> Result<IndexedTransaction> {
    let envelope = RuntimeTransaction::try_from_slice(&raw)
        .map_err(|_| Error::Data("malformed common transaction envelope".into()))?;
    let hash = hex(&neutrin0_primitives::blake3_256(&raw));
    Ok(IndexedTransaction {
        hash: hash.clone(),
        envelope_hash: hash,
        position: u32::try_from(position).map_err(|_| Error::Data("too many envelopes".into()))?,
        kind: if matches!(envelope, RuntimeTransaction::SubmitEvidence(_)) {
            "evidence"
        } else {
            "opaque"
        }
        .into(),
        contract_address: None,
        from: None,
        to: None,
        nonce: None,
        value: None,
        status: "unknown".into(),
        gas_used: None,
        receipt: None,
        details: serde_json::Value::Null,
        raw,
    })
}
