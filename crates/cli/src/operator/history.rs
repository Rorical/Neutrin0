//! History proof export: `history latest` bytes and the `history checkpoint` anchor.

use neutrin0_rpc::client::{NodeApiClient, NodeClient};
use neutrin0_rpc::{BlockId, BlockIdJson, BytesHex, HashHex};
use serde_json::{Value, json};

use super::{Arguments, Error, to_value, transactions};

/// Write the endpoint of the queried node's latest History proof as a trusted
/// `Checkpoint` for `[bootstrap]` or `[light_client]`, trusted from the time
/// its block was produced. The anchor is only as trustworthy as the queried
/// node; the bootstrapping node still verifies a History proof from the
/// specification's start that contains it.
pub(super) async fn checkpoint(client: &NodeClient, options: &Arguments) -> Result<Value, Error> {
    let out = options.required("out")?;
    let (bytes, diagnostics) =
        tokio::try_join!(client.rpc().history_latest(), client.rpc().diagnostics())?;
    let proof: neutrin0_consensus_types::history_proof::HistoryProof = borsh::from_slice(&bytes.0)
        .map_err(|error| Error::Local(format!("invalid History proof: {error}")))?;
    if proof.chain().chain_spec_hash != diagnostics.chain_spec_hash.0 {
        return Err(Error::Local(
            "History proof names another chain specification than the node reports".into(),
        ));
    }
    let checkpoint = proof.end_checkpoint();
    // Weak subjectivity counts from when the boundary was produced, not from
    // when it was fetched: a stale provider's old endpoint must not look fresh.
    let header = client
        .rpc()
        .header(BlockIdJson(BlockId::Hash(checkpoint.boundary.block_hash)))
        .await?
        .ok_or_else(|| Error::Local("the endpoint block header is not retained".into()))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| Error::Local(error.to_string()))?
        .as_secs();
    let trusted_at = header.timestamp.min(now);
    let encoded = borsh::to_vec(&checkpoint).map_err(|error| Error::Local(error.to_string()))?;
    transactions::write_new(out, &encoded)?;
    Ok(
        json!({"path": out, "trusted_at": trusted_at, "age_secs": now - trusted_at,
        "chain_spec_hash": diagnostics.chain_spec_hash,
        "finalized_chunks": checkpoint.boundary.next_chunk_id, "height": checkpoint.boundary.height,
        "block_hash": HashHex(checkpoint.boundary.block_hash),
        "node_config": format!("--trusted-checkpoint {out} --trusted-at {trusted_at}")}),
    )
}

pub(super) fn proof_output(bytes: BytesHex, options: &Arguments) -> Result<Value, Error> {
    if let Some(path) = options.get("out") {
        transactions::write_new(path, &bytes.0)?;
        Ok(json!({"path": path, "bytes": bytes.0.len()}))
    } else {
        to_value(bytes)
    }
}
