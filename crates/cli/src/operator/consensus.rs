//! Finalized consensus inspection and durable event replay over the typed client.

use super::{Arguments, Error, to_value, transactions};
use neutrin0_rpc::{
    client::{NodeApiClient, NodeClient},
    types::{ArtifactIdJson, ChainCursorJson},
};
use serde_json::Value;

pub(super) fn allowed(group: &str, operation: &str) -> Option<Vec<&'static str>> {
    match (group, operation) {
        ("chunk", "get" | "certificate") => Some(vec!["id"]),
        ("chunk", "proof") => Some(vec!["id", "out"]),
        ("proof", "get") => Some(vec!["kind", "hash", "id", "out"]),
        ("chain", "events") => Some(vec!["after-stream", "after-sequence", "limit"]),
        ("chain", "watch-events") => Some(vec![
            "after-stream",
            "after-sequence",
            "interval-secs",
            "count",
        ]),
        _ => None,
    }
}
fn after(options: &Arguments) -> Result<Option<ChainCursorJson>, Error> {
    match (options.get("after-stream"), options.get("after-sequence")) {
        (None, None) => Ok(None),
        (Some(_), Some(sequence)) => Ok(Some(ChainCursorJson {
            stream_id: options.hash("after-stream")?,
            sequence: sequence.to_owned(),
        })),
        _ => Err(Error::Usage(
            "--after-stream and --after-sequence must be supplied together".into(),
        )),
    }
}
async fn chunk_id(client: &NodeClient, options: &Arguments) -> Result<Option<u64>, Error> {
    if options.get("id").is_some() {
        Ok(Some(options.number("id", 0)?))
    } else {
        Ok(client.rpc().finalized().await?.chunk_id)
    }
}
pub(super) async fn query(
    client: &NodeClient,
    group: &str,
    operation: &str,
    options: &Arguments,
) -> Result<Value, Error> {
    if group == "chain" {
        let limit = u32::try_from(options.number("limit", 128)?)
            .map_err(|_| Error::Usage("--limit exceeds u32".into()))?;
        return to_value(client.rpc().chain_events(after(options)?, limit).await?);
    }
    if group == "chunk" {
        let id = chunk_id(client, options).await?;
        if operation == "get" {
            return to_value(client.rpc().chunk(id).await?);
        }
        let Some(id) = id else {
            return Ok(Value::Null);
        };
        if operation == "certificate" {
            return to_value(client.rpc().certificate(id).await?);
        }
        return download(client, ArtifactIdJson::ChunkProof { chunk: id }, options).await;
    }
    let id =
        match options.required("kind")? {
            "block" if options.get("id").is_none() => ArtifactIdJson::BlockProof {
                block: options.hash("hash")?,
            },
            "chunk" | "certificate" if options.get("hash").is_none() => {
                options.required("id")?;
                let chunk = options.number("id", 0)?;
                if options.get("kind") == Some("chunk") {
                    ArtifactIdJson::ChunkProof { chunk }
                } else {
                    ArtifactIdJson::Certificate { chunk }
                }
            }
            _ => return Err(Error::Usage(
                "proof get requires --kind block --hash HEX, or --kind chunk|certificate --id N"
                    .into(),
            )),
        };
    download(client, id, options).await
}
async fn download(
    client: &NodeClient,
    id: ArtifactIdJson,
    options: &Arguments,
) -> Result<Value, Error> {
    if let Some(path) = options.get("out") {
        let (metadata, bytes) = client.download_artifact(id).await?;
        transactions::write_new(path, &bytes)?;
        to_value(metadata)
    } else {
        to_value(client.rpc().artifact(id).await?)
    }
}

pub(super) async fn watch(client: &NodeClient, options: &Arguments) -> Result<u8, Error> {
    let mut cursor = after(options)?;
    let interval = options.duration("interval-secs", 1)?;
    let count = options.number("count", 0)?;
    let mut emitted = 0;
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        let page = tokio::select! {
            result = client.rpc().chain_events(cursor.clone(), 128) => result?,
            _ = &mut shutdown => return Ok(0),
        };
        if cursor.is_none() {
            options.output(
                &serde_json::json!({"type": "snapshot", "status": page.status}),
                true,
            )?;
        }
        for event in &page.events {
            options.output(&to_value(event)?, true)?;
            emitted += 1;
            if count > 0 && emitted >= count {
                return Ok(0);
            }
        }
        cursor = Some(page.next);
        if !page.has_more {
            tokio::select! {
                () = tokio::time::sleep(interval) => {},
                _ = &mut shutdown => return Ok(0),
            }
        }
    }
}
