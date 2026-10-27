//! Backend initialisation after the engine opened: the light client's trust
//! anchor, or a full node's executor, program store, bootstrap sources,
//! local snapshot and hard-fork endpoint watcher.

use std::sync::Arc;
use std::time::Duration;

use neutrin0_runtime_host::{ProgramProver, WasmExecutor};
use tracing::info;

use super::engine::load_trusted_checkpoint;
use super::{NodeBackend, NodeError};
use crate::config::{NodeConfig, NodeRole};
use crate::fork::Handoff;
use crate::supervision::TaskSupervisor;

pub(super) fn initialize_light_client<P: ProgramProver + Send + Sync + 'static>(
    backend: &NodeBackend<P>,
    config: &NodeConfig,
) -> Result<(), NodeError> {
    let (spec, domain) = backend.history_profile().map_err(NodeError::ProofSystem)?;
    let (anchor, trusted_at) = match (
        &config.light_client.trusted_checkpoint_path,
        config.light_client.trusted_at,
    ) {
        (Some(path), Some(trusted_at)) => (load_trusted_checkpoint(path)?, trusted_at),
        (None, None) => (
            neutrin0_consensus_types::history_proof::Checkpoint {
                chain: domain.chain,
                boundary: domain.genesis_boundary(&spec),
            },
            spec.genesis_time,
        ),
        _ => {
            return Err(NodeError::ProofSystem(
                "trusted_checkpoint_path and trusted_at must be configured together".into(),
            ));
        }
    };
    backend
        .initialize_light(
            anchor,
            trusted_at,
            config.light_client.max_future_drift_secs,
        )
        .map_err(NodeError::ProofSystem)
}

/// Retention, History domain and the WASM block executor of a full node.
pub(super) fn initialize_execution<P: ProgramProver + Send + Sync + 'static>(
    backend: &NodeBackend<P>,
    config: &NodeConfig,
    selected_wasm: &[u8],
) -> Result<(), NodeError> {
    backend
        .set_retention_policy(config.role.retention_policy())
        .map_err(NodeError::ProofSystem)?;
    backend
        .initialize_history()
        .map_err(NodeError::ProofSystem)?;
    // Use the same authenticated package as SP1 setup. Re-reading a
    // mutable package path here could install a different runtime.
    let runtime = neutrin0_runtime_host::wasm::WasmRuntime::new(selected_wasm)
        .and_then(|runtime| runtime.with_limits(config.execution.to_wasm_limits()))
        .map_err(|error| NodeError::ProofSystem(error.to_string()))?;
    let block_executor = WasmExecutor::new(runtime);
    backend.set_block_executor(block_executor);
    if config.execution.effective_mode(config.role) == crate::config::ExecutionMode::ProofFollow {
        backend.enable_proof_follow().map_err(NodeError::Engine)?;
    }
    if config.proving.prove_foreign_blocks {
        // Foreign candidates are proven from locally retained
        // witnesses, which only the executing mode records.
        if config.execution.effective_mode(config.role) != crate::config::ExecutionMode::Execute {
            return Err(NodeError::Engine(
                "proving.prove_foreign_blocks requires execution.mode = \"execute\"".to_owned(),
            ));
        }
        backend.set_prove_foreign_blocks(true);
    }
    backend.set_rescue_proofs(
        config
            .proving
            .rescue_unproven_blocks
            .unwrap_or(config.proving.backend == crate::config::ProvingBackend::Cuda),
    );
    Ok(())
}

/// On-chain program artifacts (design 20): accepted artifacts persist
/// under the data directory and are reinstalled on every start.
pub(super) fn attach_program_store<P: ProgramProver + Send + Sync + 'static>(
    backend: &NodeBackend<P>,
    config: &NodeConfig,
) -> Result<(), NodeError> {
    if let Some(data_dir) = &config.data_dir {
        let programs_dir = data_dir.join("programs");
        let store = crate::programs::ProgramStore::open(&programs_dir).map_err(|source| {
            NodeError::DataDir {
                path: programs_dir.display().to_string(),
                source,
            }
        })?;
        backend.set_program_store(store);
    }
    Ok(())
}

/// Bootstrap state, persisted programs and the reporter role.
pub(super) fn initialize_sources<P: ProgramProver + Send + Sync + 'static>(
    backend: &NodeBackend<P>,
    config: &NodeConfig,
    reporter: Option<[u8; 32]>,
) -> Result<(), NodeError> {
    if config.role == NodeRole::Archive {
        backend
            .discard_bootstrap_download()
            .map_err(NodeError::ProofSystem)?;
    } else {
        backend
            .initialize_bootstrap(&config.bootstrap)
            .map_err(NodeError::ProofSystem)?;
    }
    // Authenticate saved snapshot requirements before any source
    // pruning; its endpoint programs may differ from the live head.
    if config.data_dir.is_some() {
        backend.restore_programs();
    }
    if let Some(address) = reporter {
        backend
            .initialize_reporter(address)
            .map_err(NodeError::Engine)?;
    }
    Ok(())
}

/// An operator-supplied snapshot, or a hard fork's endpoint
/// bundle, installs before any peer is contacted, so no
/// network download competes with it. An archive takes only
/// a hard fork's start from one.
pub(super) async fn install_local_snapshot<P: ProgramProver + Send + Sync + 'static>(
    backend: &NodeBackend<P>,
    config: &NodeConfig,
    handoff: Option<&Handoff>,
    forked: bool,
) -> Result<(), NodeError> {
    if let Some(handoff) = handoff {
        backend
            .complete_fork_handoff(handoff)
            .await
            .map_err(NodeError::ProofSystem)?;
    } else if (config.role != NodeRole::Archive || forked)
        && config.bootstrap.enabled
        && let Some(path) = &config.bootstrap.snapshot_path
    {
        let installed = backend
            .import_snapshot(path)
            .await
            .map_err(NodeError::ProofSystem)?;
        info!(path = %path.display(), installed, "snapshot file");
    }
    Ok(())
}

/// The chain Guest ends this chain at a fork governance
/// scheduled: once finalized up to it, write the endpoint
/// bundle and stop. The watcher is a job that ends once it
/// asked for shutdown; a failed export stops the node.
pub(super) fn spawn_fork_endpoint_watcher<P: ProgramProver + Send + Sync + 'static>(
    backend: &Arc<NodeBackend<P>>,
    tasks: &TaskSupervisor,
    data_dir: std::path::PathBuf,
    fork_endpoint: &Arc<std::sync::Mutex<Option<(u64, std::path::PathBuf)>>>,
    management_shutdown: &Arc<tokio::sync::Notify>,
    raw_spec: &str,
    slot_duration_secs: u64,
) {
    let worker = Arc::clone(backend);
    let reached = Arc::clone(fork_endpoint);
    let shutdown = Arc::clone(management_shutdown);
    let raw_spec = raw_spec.to_owned();
    let slot = Duration::from_secs(slot_duration_secs.max(1));
    let _ = tasks.spawner().spawn_job("fork-endpoint", async move {
        let mut ticks = tokio::time::interval(slot);
        loop {
            ticks.tick().await;
            let Some(fork) = worker.reached_fork() else {
                continue;
            };
            let exporter = Arc::clone(&worker);
            let (raw_spec, data_dir) = (raw_spec.clone(), data_dir.clone());
            let bundle = tokio::task::spawn_blocking(move || {
                exporter.export_fork_endpoint(&raw_spec, &data_dir)
            })
            .await
            .map_err(|error| error.to_string())??;
            info!(count = fork.count, bundle = %bundle.display(), "hard fork endpoint bundle written");
            *reached.lock().expect("fork endpoint flag poisoned") = Some((fork.count, bundle));
            shutdown.notify_one();
            return Ok(());
        }
    });
}
