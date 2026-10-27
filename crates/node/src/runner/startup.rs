//! Inputs resolved before any worker exists: the hard-fork handoff, the
//! chain specification with its authenticated genesis programs and the
//! configured network endpoints.

use std::net::SocketAddr;

use neutrin0_network::Multiaddr;
use neutrin0_primitives::ChainSpec;

use super::NodeError;
use crate::chain_spec::{ChainSpecError, ChainSpecFile, GenesisPrograms};
use crate::config::{NodeConfig, NodeRole};
use crate::fork::Handoff;

/// A hard fork's successor derives its specification from the
/// predecessor's endpoint bundle and this binary's programs (design 20);
/// every other node requires a `chain_spec_path`. Misconfigured
/// deployments must fail loudly instead of silently running an
/// unreachable chain.
pub(super) async fn prepare_fork_handoff(
    config: &NodeConfig,
) -> Result<Option<Handoff>, NodeError> {
    match (&config.bootstrap.fork_from, &config.data_dir) {
        (None, _) => Ok(None),
        (Some(_), None) => Err(NodeError::Engine(
            "[bootstrap] fork_from needs a data_dir for the successor".into(),
        )),
        (Some(_), Some(_))
            if config.chain_spec_path.is_some()
                || config.bootstrap.snapshot_path.is_some()
                || config.role == NodeRole::LightClient =>
        {
            Err(NodeError::Engine(
                "[bootstrap] fork_from derives the specification and the snapshot; \
                 leave chain_spec_path and snapshot_path unset, and use it on a non-light node"
                    .into(),
            ))
        }
        (Some(from), Some(data_dir)) => {
            let (from, data_dir) = (from.clone(), data_dir.clone());
            Ok(Some(
                tokio::task::spawn_blocking(move || Handoff::prepare(&from, &data_dir))
                    .await
                    .map_err(|error| {
                        NodeError::Engine(format!("fork handoff task failed: {error}"))
                    })?
                    .map_err(NodeError::Engine)?,
            ))
        }
    }
}

/// The specification text, its parsed file, the canonical chain spec and the
/// genesis programs it pins, checked against the node configuration.
pub(super) async fn load_genesis_spec(
    config: &NodeConfig,
    handoff: Option<&Handoff>,
) -> Result<(String, ChainSpecFile, ChainSpec, GenesisPrograms), NodeError> {
    let Some(chain_spec_path) = handoff
        .map(|handoff| handoff.spec_path.display().to_string())
        .or_else(|| config.chain_spec_path.clone())
    else {
        return Err(NodeError::ChainSpec(ChainSpecError::Validation(
            "chain_spec_path is required".to_owned(),
        )));
    };
    // The text a fork's endpoint bundle derives the successor's file from.
    let raw_spec = std::fs::read_to_string(&chain_spec_path).map_err(|source| {
        NodeError::ChainSpec(ChainSpecError::Io {
            path: chain_spec_path.clone(),
            source,
        })
    })?;
    // Verifying-key and fact-receipt caches belong to this node's data
    // directory, where the storage quota sees them, not to the build tree.
    if let Some(dir) = &config.data_dir {
        neutrin0_runtime_host::set_cache_dir(dir.join("sp1-cache"));
    }
    // Package authentication derives SP1 keys through the SDK's blocking
    // runtime. Pinned programs the binary does not embed come from the node's program
    // store, where they are kept under their content hashes.
    let package_dir = config.data_dir.as_ref().map(|dir| dir.join("programs"));
    let (spec_file, chain_spec, genesis_programs) = tokio::task::spawn_blocking(move || {
        let spec_file = ChainSpecFile::load_from_path(&chain_spec_path)?;
        let programs = spec_file.genesis_programs(package_dir.as_deref())?;
        let chain_spec = spec_file.to_chain_spec_with(&programs)?;
        Ok::<_, ChainSpecError>((spec_file, chain_spec, programs))
    })
    .await
    .map_err(|error| NodeError::ProofSystem(format!("genesis setup task failed: {error}")))??;
    if chain_spec.chain_id != config.chain_id {
        return Err(NodeError::ChainSpec(ChainSpecError::Validation(format!(
            "chain spec chain_id {} does not match node config chain_id {}",
            chain_spec.chain_id, config.chain_id
        ))));
    }
    let expected_programs = neutrin0_primitives::ProgramSet {
        runtime_code_hash: chain_spec.runtime_code_hash,
        execution: chain_spec.genesis_execution,
    };
    if genesis_programs.package.programs != expected_programs
        || genesis_programs.chunk != chain_spec.genesis_chunk
    {
        return Err(NodeError::ChainSpec(ChainSpecError::Validation(
            "runtime package changed after genesis identities were derived".to_owned(),
        )));
    }
    Ok((raw_spec, spec_file, chain_spec, genesis_programs))
}

/// Listen and bootnode multiaddrs, validated before any worker starts.
pub(super) fn parse_peer_addresses(
    config: &NodeConfig,
) -> Result<(Vec<Multiaddr>, Vec<Multiaddr>), NodeError> {
    let listen_addrs = parse_multiaddrs(&config.effective_listen())?;
    let bootnodes = parse_multiaddrs(&config.bootnodes)?;
    Ok((listen_addrs, bootnodes))
}

/// The RPC runtime configuration and the metrics socket address.
pub(super) fn parse_service_endpoints(
    config: &NodeConfig,
) -> Result<(Option<neutrin0_rpc::RpcConfig>, Option<SocketAddr>), NodeError> {
    let rpc_config = config
        .rpc
        .as_ref()
        .map(|rpc| {
            rpc.to_runtime_config()
                .map_err(|source| NodeError::RpcListen {
                    addr: rpc.listen.clone(),
                    source,
                })
        })
        .transpose()?;
    let metrics_addr = config
        .metrics
        .as_ref()
        .map(|metrics| {
            metrics
                .listen
                .parse::<SocketAddr>()
                .map_err(|error| NodeError::MetricsListen {
                    addr: metrics.listen.clone(),
                    reason: error.to_string(),
                })
        })
        .transpose()?;
    Ok((rpc_config, metrics_addr))
}

fn parse_multiaddrs(addresses: &[String]) -> Result<Vec<Multiaddr>, NodeError> {
    addresses
        .iter()
        .map(|addr| {
            addr.parse().map_err(|source| NodeError::InvalidMultiaddr {
                addr: addr.clone(),
                source,
            })
        })
        .collect()
}
