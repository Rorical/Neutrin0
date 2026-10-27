//! `node doctor` diagnostics and the `node watch` status stream.

use neutrin0_rpc::client::{NodeClient, NodeStatusJson};
use serde_json::{Value, json};

use super::{Arguments, Error, to_value};

pub(super) fn diagnose(
    status: &NodeStatusJson,
    programs: &neutrin0_rpc::ProgramsStatusJson,
) -> Value {
    let diagnostics = &status.diagnostics;
    let mut issues: Vec<String> = vec![];
    if diagnostics.storage_pressure {
        issues.push(
            "data filesystem below its free-space quota; production and new candidates paused"
                .into(),
        );
    }
    if let Some(missing) = programs
        .scheduled_missing
        .as_ref()
        .filter(|missing| !missing.is_empty())
    {
        issues.push(format!(
            "scheduled program switch not installed locally: {}",
            missing.join(", ")
        ));
    }
    if diagnostics.bootstrap_pending {
        issues.push("authenticated bootstrap pending".into());
    }
    if diagnostics.trust_anchor_expired {
        issues.push("trust anchor expired".into());
    }
    if diagnostics.history_conflict {
        issues.push("conflicting History proofs halted the light client; configure a new trusted checkpoint".into());
    }
    if diagnostics.sync.as_ref().is_some_and(|sync| sync.syncing) {
        issues.push("synchronization incomplete".into());
    }
    if !diagnostics.proof_only && !status.health.runtime_available {
        issues.push("runtime unavailable".into());
    }
    json!({"checks_passed": issues.is_empty(), "issues": issues, "status": status,
        "scope": "local RPC observations; HTTP readiness also checks configured peer policy and finality-stall timeout"})
}

pub(super) async fn watch(client: &NodeClient, options: &Arguments) -> Result<u8, Error> {
    let interval = options.duration("interval-secs", 2)?;
    let count = options.number("count", u64::MAX)?;
    if count == 0 {
        return Err(Error::Usage("--count must be positive".into()));
    }
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    for sample in 0..count {
        let status = tokio::select! {
            result = &mut interrupt => { result.map_err(|error| Error::Local(error.to_string()))?; return Ok(0); }
            status = client.status() => status?,
        };
        options.output(&to_value(status)?, true)?;
        if sample + 1 < count {
            tokio::select! {
                result = &mut interrupt => { result.map_err(|error| Error::Local(error.to_string()))?; return Ok(0); }
                () = tokio::time::sleep(interval) => {}
            }
        }
    }
    Ok(0)
}
