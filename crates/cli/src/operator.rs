//! Commands for querying and operating a running node.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Entry points are private binary implementation, not exported library APIs."
)]

use neutrin0_rpc::client::{ClientError, NodeApiClient, NodeClient};
use neutrin0_rpc::{BlockId, BlockIdJson, BytesHex};
use serde_json::{Value, json};
use std::process::ExitCode;

mod arguments;
mod consensus;
mod governance;
mod help;
mod history;
mod management;
mod node;
mod state;
#[cfg(test)]
mod tests;
mod transactions;

use arguments::{Arguments, decode_bytes};
pub(super) use help::print_usage;

pub(super) fn is_command(command: &str) -> bool {
    matches!(
        command,
        "chunk"
            | "proof"
            | "node"
            | "chain"
            | "block"
            | "account"
            | "validator"
            | "tx"
            | "governance"
            | "programs"
            | "proving"
            | "history"
            | "runtime"
    )
}

#[derive(Debug)]
enum Error {
    Usage(String),
    Client(ClientError),
    Local(String),
}

impl From<ClientError> for Error {
    fn from(error: ClientError) -> Self {
        Self::Client(error)
    }
}
impl From<jsonrpsee::core::client::Error> for Error {
    fn from(error: jsonrpsee::core::client::Error) -> Self {
        Self::Client(error.into())
    }
}

impl Error {
    fn value(&self) -> Value {
        let (kind, message) = match self {
            Self::Usage(message) => ("invalid_arguments", message.clone()),
            Self::Local(message) => ("local", message.clone()),
            Self::Client(error) => ("rpc_or_runtime", error.to_string()),
        };
        let mut value = json!({"error": {"kind": kind, "message": message}});
        if let Self::Client(ClientError::Rpc(jsonrpsee::core::client::Error::Call(error))) = self {
            value["error"]["code"] = json!(error.code());
            if let Some(data) = error.data() {
                value["error"]["data"] = serde_json::from_str(data.get()).unwrap_or(Value::Null);
            }
        }
        if let Self::Client(ClientError::Runtime {
            method,
            code,
            payload,
        }) = self
        {
            value["error"]["method"] = json!(method);
            value["error"]["runtime_code"] = json!(code);
            value["error"]["payload"] = json!(payload);
        }
        value
    }
}

pub(super) async fn execute(args: &[String]) -> ExitCode {
    let json_output = args.iter().any(|arg| arg == "--json");
    if args.iter().any(|arg| arg == "--help") {
        println!("{}", help::HELP);
        return ExitCode::SUCCESS;
    }
    match run(args).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let value = error.value();
            if json_output {
                eprintln!("{value}");
            } else {
                eprintln!(
                    "error: {}",
                    value["error"]["message"]
                        .as_str()
                        .unwrap_or("command failed")
                );
            }
            ExitCode::from(if matches!(error, Error::Usage(_)) {
                2
            } else {
                1
            })
        }
    }
}

const SIGN_OPTIONS: &[&str] = &[
    "key-file",
    "nonce",
    "chain-id",
    "gas-limit",
    "max-fee-per-gas",
    "max-priority-fee-per-gas",
    "submit",
    "out",
    "wait",
    "wait-timeout-secs",
    "poll-secs",
];

fn allowed(group: &str, operation: &str) -> Result<Vec<&'static str>, Error> {
    if let Some(request) = management::request(group, operation) {
        let mut flags = vec!["management-socket"];
        flags.extend_from_slice(management::flags(&request));
        return Ok(flags);
    }
    if let Some(flags) = consensus::allowed(group, operation) {
        return Ok(flags);
    }
    let flags: &[&str] = match (group, operation) {
        ("node", "status" | "doctor")
        | ("chain", "head" | "finalized" | "genesis" | "validators")
        | ("validator", "list")
        | ("programs" | "proving", "status")
        | ("history", "retention") => &[],
        ("node", "watch") => &["interval-secs", "count"],
        ("block", "get" | "header") | ("governance", "status" | "policy") => &["at"],
        ("account", "get") | ("validator", "status") => &["address", "at"],
        ("runtime", "call") => &["method", "args", "at"],
        ("tx", "get" | "receipt") => &["hash"],
        ("tx", "wait") => &["hash", "wait", "wait-timeout-secs", "poll-secs"],
        ("tx", "submit") => &["bytes", "file", "wait", "wait-timeout-secs", "poll-secs"],
        ("tx", "transfer" | "send")
        | ("validator", "register" | "rotate-key" | "stake" | "unstake" | "exit" | "withdraw")
        | (
            "governance",
            "vote" | "propose-upgrade" | "cancel-upgrade" | "propose-policy" | "propose-fork"
            | "cancel-fork",
        ) => {
            let mut flags = SIGN_OPTIONS.to_vec();
            flags.extend_from_slice(match operation {
                "transfer" => &["to", "amount"],
                "send" => &["to", "amount", "data"],
                "register" => &["amount", "ikm-path"],
                "rotate-key" => &["ikm-path", "keystore", "password-file"],
                "stake" | "unstake" => &["amount"],
                "vote" => &["proposal-id"],
                "propose-upgrade" => &["package", "activate-at-chunk"],
                "propose-fork" => &["fork-chunk", "successor"],
                "propose-policy" => governance::POLICY_FLAGS,
                _ => &[],
            });
            return Ok(flags);
        }
        ("history", "latest" | "checkpoint") => &["out"],
        _ => {
            return Err(Error::Usage(format!(
                "unknown RPC command `{group} {operation}`; use --help"
            )));
        }
    };
    Ok(flags.to_vec())
}

async fn run(args: &[String]) -> Result<u8, Error> {
    let group = args
        .first()
        .ok_or_else(|| Error::Usage("missing command".into()))?;
    let operation = args
        .get(1)
        .ok_or_else(|| Error::Usage(format!("missing {group} operation; use --help")))?;
    let options = Arguments::parse(&args[2..], &allowed(group, operation)?)?;
    if let Some(request) = management::request(group, operation) {
        return management::run(request, &options).await;
    }
    let endpoint = options
        .get("rpc")
        .map(str::to_owned)
        .or_else(|| std::env::var("NEUTRIN0_RPC_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:9933".into());
    let client = NodeClient::connect(&endpoint, options.duration("timeout-secs", 10)?)?;
    if group == "chain" && operation == "watch-events" {
        return consensus::watch(&client, &options).await;
    }
    if group == "node" && operation == "watch" {
        return node::watch(&client, &options).await;
    }
    let value = dispatch(&client, group, operation, &options).await?;
    options.output(&value, false)?;
    if (group == "node" && operation == "doctor" && value["checks_passed"] == false)
        || value.pointer("/confirmation/execution_success") == Some(&Value::Bool(false))
    {
        Ok(3)
    } else {
        Ok(0)
    }
}

async fn dispatch(
    client: &NodeClient,
    group: &str,
    operation: &str,
    options: &Arguments,
) -> Result<Value, Error> {
    if consensus::allowed(group, operation).is_some() {
        return consensus::query(client, group, operation, options).await;
    }
    let rpc = client.rpc();
    match (group, operation) {
        ("node", "status") => to_value(client.status().await?),
        ("node", "doctor") => {
            let (status, programs) =
                tokio::try_join!(client.status(), async { Ok(rpc.programs().await?) })?;
            Ok(node::diagnose(&status, &programs))
        }
        ("chain", "head") => to_value(rpc.head().await?),
        ("chain", "finalized") => to_value(rpc.finalized().await?),
        ("chain", "genesis") => to_value(rpc.genesis().await?),
        ("chain", "validators") | ("validator", "list") => to_value(rpc.validators().await?),
        ("block", "get") => to_value(rpc.block(options.at()?).await?),
        ("block", "header") => to_value(rpc.header(options.at()?).await?),
        ("account", "get") => state::account(client, options).await,
        ("validator", "status") => state::validator(client, options).await,
        ("programs", "status") => to_value(rpc.programs().await?),
        ("proving", "status") => to_value(rpc.proving().await?),
        ("history", "retention") => to_value(rpc.retention().await?),
        ("history", "latest") => history::proof_output(rpc.history_latest().await?, options),
        ("history", "checkpoint") => history::checkpoint(client, options).await,
        ("runtime", "call") => {
            let at = client.pin(options.at()?).await?;
            let result = rpc
                .runtime_call(
                    options.required("method")?.into(),
                    BytesHex(decode_bytes(options.get("args").unwrap_or(""))?),
                    BlockIdJson(BlockId::Hash(at.hash.0)),
                )
                .await?;
            if result.code != 0 {
                return Err(ClientError::Runtime {
                    method: options.required("method")?.into(),
                    code: result.code,
                    payload: result.payload,
                }
                .into());
            }
            Ok(json!({"at": at, "result": result}))
        }
        ("governance", "policy") => governance::policy(client, options).await,
        ("governance", "status") => governance::status(client, options).await,
        ("tx", "get" | "receipt") => {
            if operation == "get" {
                to_value(rpc.ethereum_transaction(options.hash("hash")?).await?)
            } else {
                to_value(rpc.receipt(options.hash("hash")?).await?)
            }
        }
        ("tx", "wait") => {
            let hash = options.hash("hash")?;
            Ok(json!({"confirmation": transactions::wait(client, hash, options, true).await?}))
        }
        ("tx", "submit") => transactions::submit(client, options).await,
        ("tx", "transfer" | "send") | ("validator" | "governance", _) => {
            transactions::prepare(client, group, operation, options).await
        }
        _ => Err(Error::Usage("unsupported command".into())),
    }
}

fn to_value(value: impl serde::Serialize) -> Result<Value, Error> {
    serde_json::to_value(value).map_err(|error| Error::Local(error.to_string()))
}
