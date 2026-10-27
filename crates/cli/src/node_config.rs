//! Pure rendering of node configuration templates from operator options.

use super::Options;
use neutrin0_node::ChainSpecFile;
use std::fmt::Write as _;
use std::path::Path;

/// Render a node configuration after the parent command has loaded its spec.
#[allow(clippy::redundant_pub_crate)] // Keep this entry point limited to the parent command.
pub(super) fn render(
    opts: &Options,
    spec_path: &Path,
    file: &ChainSpecFile,
) -> Result<String, String> {
    let role = opts.get("role").unwrap_or("validator");
    if !matches!(
        role,
        "validator" | "full" | "archive" | "light-client" | "reporter"
    ) {
        return Err(format!("unknown --role `{role}`"));
    }
    let proving = opts.get("proving").unwrap_or("cpu");
    if !matches!(proving, "cpu" | "cuda") {
        return Err(format!("unknown --proving `{proving}`"));
    }
    let mut text = String::new();
    let _ = writeln!(text, "chain_id = {}", file.chain_id);
    let _ = writeln!(text, "role = \"{role}\"");
    let _ = writeln!(text, "chain_spec_path = \"{}\"", spec_path.display());
    if let Some(dir) = opts.get("data-dir") {
        let _ = writeln!(text, "data_dir = \"{dir}\"");
    }
    let listen = opts.all("listen");
    if !listen.is_empty() {
        let _ = writeln!(text, "listen = {}", toml_string_array(&listen));
    }
    let bootnodes = opts.all("bootnode");
    if !bootnodes.is_empty() {
        let _ = writeln!(text, "bootnodes = {}", toml_string_array(&bootnodes));
    }
    if let Some(path) = opts.get("network-key-path") {
        let _ = writeln!(text, "network_key_path = \"{path}\"");
    }
    if role == "validator" {
        match opts.get("ikm-path") {
            Some(path) => {
                let _ = writeln!(text, "proposer_ikm_path = \"{path}\"");
            }
            None => {
                let _ = writeln!(
                    text,
                    "# proposer_ikm_path = \"validator.ikm\"   # or export {}",
                    neutrin0_node::PROPOSER_IKM_ENV
                );
            }
        }
        let index = opts.get("proposer-index").unwrap_or("0");
        index
            .parse::<u32>()
            .map_err(|_| format!("--proposer-index must be an integer, got `{index}`"))?;
        let _ = writeln!(text, "proposer_index = {index}");
    }
    append_reporter_config(&mut text, role, opts)?;
    append_bootstrap_config(&mut text, role, opts)?;
    text.push_str("\n[proving]\n");
    let _ = writeln!(text, "backend = \"{proving}\"");
    text.push_str("concurrency = 2\ncapacity = 16\n");
    if let Some(address) = opts.get("prover-address") {
        let address = neutrin0_node::config::HexAddress::try_from(address.to_owned())
            .map_err(|error| error.to_string())?;
        let _ = writeln!(text, "prover_address = \"{}\"", hex::encode(address.0));
    }
    // The free-space quota is always on; these are its defaults.
    text.push_str("\n[storage]\nmin_free_bytes = 10737418240\nhalt_free_bytes = 2147483648\n");
    if let Some(rpc) = opts.get("rpc") {
        text.push_str("\n[rpc]\n");
        let _ = writeln!(text, "listen = \"{rpc}\"");
        text.push_str("max_connections = 200\nmax_concurrent_requests = 64\n");
        text.push_str("requests_per_second_per_client = 50\n");
        text.push_str("max_batch_requests = 16\nruntime_call_timeout_ms = 2000\n");
    }
    if let Some(metrics) = opts.get("metrics") {
        text.push_str("\n[metrics]\n");
        let _ = writeln!(text, "listen = \"{metrics}\"");
    }
    if let Some(socket) = opts.get("management-socket") {
        if !Path::new(socket).is_absolute() {
            return Err("--management-socket must be an absolute path".into());
        }
        text.push_str("\n[management]\n");
        let quoted = serde_json::to_string(socket).map_err(|error| error.to_string())?;
        let _ = writeln!(text, "socket = {quoted}");
    }
    text.push_str("\n[execution]\n");
    // Make the role's default head-state mode visible: validators, full and
    // reporter nodes follow verified receipts and state diffs; archives execute.
    if role != "light-client" {
        let mode = match role {
            "archive" => "execute",
            _ => "proof_follow",
        };
        let _ = writeln!(text, "mode = \"{mode}\"");
    }
    // The rendered fuel budgets are the runtime host's own defaults.
    let limits = neutrin0_runtime_host::wasm::WasmLimits::default();
    let _ = writeln!(text, "query_fuel = {}", limits.query_fuel);
    let _ = writeln!(text, "validate_tx_fuel = {}", limits.validate_tx_fuel);
    Ok(text)
}

fn append_reporter_config(text: &mut String, role: &str, opts: &Options) -> Result<(), String> {
    let address = opts.get("reporter-reward-address");
    if role != "reporter" {
        if address.is_some() {
            return Err("--reporter-reward-address requires --role reporter".into());
        }
        return Ok(());
    }
    let address =
        address.ok_or("--role reporter requires --reporter-reward-address <32-byte hex>")?;
    let config = neutrin0_node::NodeConfig {
        role: neutrin0_node::NodeRole::Reporter,
        reporter: Some(neutrin0_node::ReporterConfig {
            reward_address_hex: address.to_owned(),
        }),
        ..neutrin0_node::NodeConfig::default()
    };
    let recipient = config
        .reporter_reward_address()?
        .ok_or("reporter reward address missing")?;
    text.push_str("\n[reporter]\n");
    let _ = writeln!(text, "reward_address_hex = \"{}\"", hex::encode(recipient));
    Ok(())
}

/// A trusted checkpoint (`history checkpoint --out`) lets a full node or
/// validator bootstrap past the weak-subjectivity window of genesis.
fn append_bootstrap_config(text: &mut String, role: &str, opts: &Options) -> Result<(), String> {
    let (Some(path), Some(at)) = (opts.get("trusted-checkpoint"), opts.get("trusted-at")) else {
        if opts.has("trusted-checkpoint") || opts.has("trusted-at") {
            return Err("--trusted-checkpoint and --trusted-at must be given together".into());
        }
        return Ok(());
    };
    at.parse::<u64>()
        .map_err(|_| format!("--trusted-at must be Unix seconds, got `{at}`"))?;
    let section = match role {
        "light-client" => "light_client",
        "archive" => return Err("archive nodes replay from genesis and take no checkpoint".into()),
        _ => "bootstrap",
    };
    let _ = writeln!(text, "\n[{section}]");
    let _ = writeln!(text, "trusted_checkpoint_path = \"{path}\"");
    let _ = writeln!(text, "trusted_at = {at}");
    Ok(())
}

fn toml_string_array(items: &[&str]) -> String {
    let quoted: Vec<String> = items.iter().map(|item| format!("\"{item}\"")).collect();
    format!("[{}]", quoted.join(", "))
}

#[cfg(test)]
mod tests;
