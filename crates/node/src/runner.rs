//! High-level node lifecycle.
//!
//! Builds a libp2p [`NetworkService`](neutrin0_network::service::NetworkService), spawns the [`SyncDriver`](neutrin0_sync::SyncDriver),
//! attaches a [`SyncBackend`](neutrin0_sync::SyncBackend), and waits for `SIGINT`/`SIGTERM` before
//! shutting down. The chain specification comes from
//! [`NodeConfig::chain_spec_path`] or a hard fork's endpoint bundle.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use neutrin0_network::service::NetworkError;
use neutrin0_rpc::RpcBackend;
use neutrin0_rpc::RpcStartError;
use neutrin0_runtime_host::{ProgramProver, Sp1HostError, Sp1ProofSystem};
use thiserror::Error;
use tracing::info;

use crate::chain_backend::ChainBackend;
use crate::chain_spec::ChainSpecError;
use crate::config::{NodeConfig, NodeRole, ProvingBackend};
use crate::db::{NodeDb, NodeDbError};
use crate::supervision::{TaskFailure, TaskSupervisor};

mod engine;
mod node_init;
mod proposer;
mod startup;
mod workers;

/// The backend every node role runs: the engine over the node database with
/// the SP1 proof system of prover `P`.
type NodeBackend<P> = ChainBackend<NodeDb, Sp1ProofSystem<P>>;

/// Errors returned by [`run`].
#[derive(Debug, Error)]
pub enum NodeError {
    /// Multiaddr parsing failed for a listen / bootnode entry.
    #[error("invalid multiaddr `{addr}`: {source}")]
    InvalidMultiaddr {
        /// Offending multiaddr string.
        addr: String,
        /// Underlying error.
        #[source]
        source: neutrin0_network::libp2p::multiaddr::Error,
    },
    /// Network service construction failed.
    #[error("network service error: {0}")]
    Network(#[from] NetworkError),
    /// The persisted P2P identity could not be loaded or created.
    #[error("network identity error: {0}")]
    NetworkIdentity(String),
    /// A worker required for the node lifetime stopped unexpectedly.
    #[error("critical task `{task}` stopped: {reason}")]
    CriticalTask {
        /// Name registered by the runner or backend.
        task: &'static str,
        /// Failure or unexpected completion.
        reason: String,
    },
    /// Chain spec loading or validation failed.
    #[error("chain spec error: {0}")]
    ChainSpec(#[from] ChainSpecError),
    /// Engine initialisation failed.
    #[error("engine error: {0}")]
    Engine(String),
    /// Proposer key derivation failed.
    #[error("proposer key error: {0}")]
    ProposerKey(String),
    /// Database backend failed to open or operate on its data directory.
    #[error("storage error: {0}")]
    Storage(#[from] NodeDbError),
    /// `data_dir` could not be created on disk.
    #[error("failed to create data directory `{path}`: {source}")]
    DataDir {
        /// Configured data directory.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Generic I/O surface (signal hookup, config read, ...).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The configured metrics listen address could not be parsed or bound.
    #[error("metrics listen address `{addr}` is invalid or unavailable: {reason}")]
    MetricsListen {
        /// Configured `host:port` string.
        addr: String,
        /// Parse or bind failure.
        reason: String,
    },
    /// The configured RPC listen address could not be parsed.
    #[error("rpc listen address `{addr}` is invalid: {source}")]
    RpcListen {
        /// Configured `host:port` string.
        addr: String,
        /// Parse error.
        #[source]
        source: std::net::AddrParseError,
    },
    /// Failed to start the JSON-RPC server.
    #[error("rpc server failed to start: {0}")]
    Rpc(#[from] RpcStartError),
    /// Failed to initialise the SP1 proof system (vk setup or disk cache I/O).
    #[error("proof system error: {0}")]
    ProofSystem(String),
    /// This chain ended at a hard fork and the node wrote its endpoint
    /// bundle; the successor's binary continues from it (design 20).
    #[error(
        "this chain ended at the hard fork at chunk {count}; its endpoint bundle is in {}. \
         Start the successor's binary with a new data_dir and [bootstrap] fork_from naming this one",
        bundle.display()
    )]
    ForkEndpoint {
        /// The fork's count.
        count: u64,
        /// The endpoint bundle directory.
        bundle: std::path::PathBuf,
    },
}

/// Run the node until `SIGINT` or `SIGTERM` arrive.
///
/// # Errors
///
/// Surfaces any of the variants of [`NodeError`].
pub async fn run(config: NodeConfig) -> Result<(), NodeError> {
    config
        .proving
        .validate()
        .map_err(|error| NodeError::ProofSystem(error.into()))?;
    config.health.validate().map_err(NodeError::Engine)?;
    config.storage.validate().map_err(NodeError::Engine)?;
    config.light_client.validate().map_err(NodeError::Engine)?;
    config
        .execution
        .validate(config.role)
        .map_err(NodeError::Engine)?;
    let reporter = config
        .reporter_reward_address()
        .map_err(NodeError::Engine)?;
    if !config.proving.generates_proofs(config.role) {
        return Box::pin(run_with_prover(config, reporter, || {
            Ok(sp1_sdk::blocking::ProverClient::builder().light().build())
        }))
        .await;
    }
    match config.proving.backend {
        ProvingBackend::Cpu => {
            Box::pin(run_with_prover(config, reporter, || {
                Ok(sp1_sdk::blocking::ProverClient::builder().cpu().build())
            }))
            .await
        }
        ProvingBackend::Cuda => {
            #[cfg(feature = "cuda")]
            {
                let device = config.proving.cuda_device.unwrap_or(0);
                Box::pin(run_with_prover(config, reporter, move || {
                    neutrin0_runtime_host::backend::cuda_prover(device)
                }))
                .await
            }
            #[cfg(not(feature = "cuda"))]
            Err(NodeError::ProofSystem(
                "CUDA requires --features cuda".into(),
            ))
        }
    }
}

/// `reporter` is the reward address [`run`] already decoded from `config`.
#[allow(clippy::too_many_lines)]
async fn run_with_prover<P: ProgramProver + Send + Sync + 'static>(
    config: NodeConfig,
    reporter: Option<[u8; 32]>,
    build_prover: impl FnOnce() -> Result<P, Sp1HostError> + Send + 'static,
) -> Result<(), NodeError> {
    let handoff = startup::prepare_fork_handoff(&config).await?;
    let (raw_spec, spec_file, chain_spec, genesis_programs) =
        startup::load_genesis_spec(&config, handoff.as_ref()).await?;
    let selected_wasm = genesis_programs.package.wasm.clone();
    let genesis_package = genesis_programs.package.clone();

    let production_config = proposer::build_block_producer_config(&config, &chain_spec)?;
    let slot_schedule = (
        chain_spec.genesis_time,
        chain_spec.consensus.slot_duration_secs,
    );
    // Validate addresses before starting any worker, including backend workers.
    let (listen_addrs, bootnodes) = startup::parse_peer_addresses(&config)?;
    let (rpc_config, metrics_addr) = startup::parse_service_endpoints(&config)?;
    let local_key = crate::identity::load_network_identity(&config)
        .map_err(|error| NodeError::NetworkIdentity(error.to_string()))?;
    let health = Arc::new(crate::health::NodeHealth::new(
        &config.health,
        chain_spec.consensus.slot_duration_secs,
        chain_spec.consensus.chunk_size,
    ));
    let tasks = TaskSupervisor::new();
    let mut rpc_handle = None;
    #[cfg(not(unix))]
    if config.management.is_some() {
        return Err(NodeError::Io(std::io::Error::other(
            "management requires Unix sockets",
        )));
    }
    let management_shutdown = Arc::new(tokio::sync::Notify::new());
    let fork_endpoint: Arc<std::sync::Mutex<Option<(u64, std::path::PathBuf)>>> =
        Arc::new(std::sync::Mutex::new(None));
    let shutdown = async {
        tokio::select! {
            result = wait_for_shutdown() => result,
            () = management_shutdown.notified() => Ok(()),
        }
    };
    tokio::pin!(shutdown);

    // Startup and steady-state share one owner. An early error or signal also
    // stops workers created while restoring programs or BFT sessions.
    let outcome = supervise_lifecycle(
        &tasks,
        &mut shutdown,
        async {
            let mut db = engine::open_node_db(&config)?;
            // A successor signs nothing before its predecessor's protection
            // is in place.
            if let Some(handoff) = &handoff {
                handoff
                    .import_signing(&mut db, &chain_spec)
                    .map_err(NodeError::Engine)?;
            }
            // Create the configured data directory before binding a socket inside it,
            // but reject an unsafe management endpoint before configuring any signer.
            #[cfg(unix)]
            let management_listener = config
                .management
                .as_ref()
                .map(|management| crate::management::bind(&management.socket))
                .transpose()?;
            let forked = chain_spec.fork.is_some();
            let engine = engine::open_engine(db, chain_spec, spec_file, genesis_package).await?;
            let proof_system = engine::build_proof_system(genesis_programs, build_prover).await?;
            if config.proving.generates_proofs(config.role) {
                info!(backend = ?config.proving.backend, cuda_device = ?config.proving.cuda_device,
                        concurrency = config.proving.concurrency, "SP1 proving backend initialized");
            } else {
                info!("SP1 verification-only backend initialized");
            }
            info!(
                chain_id = config.chain_id,
                head_height = engine.head_height(),
                "consensus engine opened"
            );
            let concrete_backend = Arc::new(ChainBackend::new(engine, proof_system));
            if config.role != NodeRole::LightClient {
                concrete_backend
                    .initialize_chain_events()
                    .map_err(NodeError::Engine)?;
            }
            concrete_backend.set_task_spawner(tasks.spawner());
            concrete_backend.set_proving_concurrency(config.proving.concurrency);
            concrete_backend.set_proving_policy(config.proving.scheduling_policy());
            if let Some(address) = config.proving.prover_address {
                concrete_backend.set_prover_address(address.0);
            }
            if config.role == NodeRole::LightClient {
                node_init::initialize_light_client(&concrete_backend, &config)?;
            } else {
                node_init::initialize_execution(&concrete_backend, &config, &selected_wasm)?;
                node_init::attach_program_store(&concrete_backend, &config)?;
                node_init::initialize_sources(&concrete_backend, &config, reporter)?;
                node_init::install_local_snapshot(
                    &concrete_backend,
                    &config,
                    handoff.as_ref(),
                    forked,
                )
                .await?;
                if let Some(data_dir) = config.data_dir.clone() {
                    node_init::spawn_fork_endpoint_watcher(
                        &concrete_backend,
                        &tasks,
                        data_dir,
                        &fork_endpoint,
                        &management_shutdown,
                        &raw_spec,
                        slot_schedule.1,
                    );
                }
            }
            let (cmd_tx, event_rx) = workers::start_network(
                &concrete_backend,
                &config,
                &tasks,
                local_key,
                listen_addrs,
                bootnodes,
            )
            .await?;
            workers::subscribe_topics(&cmd_tx, &config).await?;
            concrete_backend.set_network_publisher(cmd_tx.clone());
            workers::configure_local_voter(&concrete_backend, &config, production_config.as_ref());
            workers::spawn_consensus_workers(&concrete_backend, &tasks).await?;
            let source = Arc::clone(&concrete_backend) as Arc<dyn crate::metrics::MetricsSource>;
            workers::spawn_health_monitor(&tasks, &health, &source);
            if let Some(addr) = metrics_addr {
                workers::start_metrics_endpoint(addr, &tasks, &health, source).await?;
            }
            workers::start_sync_driver(
                &concrete_backend,
                &config,
                &tasks,
                cmd_tx.clone(),
                event_rx,
            )
            .await?;
            workers::spawn_production(
                &concrete_backend,
                &config,
                &tasks,
                production_config,
                cmd_tx,
                slot_schedule,
            );
            #[cfg(unix)]
            workers::start_management(
                &concrete_backend,
                &tasks,
                &management_shutdown,
                management_listener,
            );
            if let Some(runtime_cfg) = rpc_config {
                let listen = runtime_cfg.listen;
                let rpc_backend = Arc::clone(&concrete_backend) as Arc<dyn RpcBackend>;
                let handle = neutrin0_rpc::serve_with_metrics(
                    rpc_backend,
                    runtime_cfg,
                    concrete_backend.rpc_metrics(),
                )
                .await?;
                let stop_handle = handle.clone();
                tasks.on_shutdown(move || {
                    let _ = stop_handle.stop();
                });
                let monitor_handle = handle.clone();
                let _ = tasks.spawner().spawn_critical("rpc", async move {
                    monitor_handle.stopped().await;
                    Ok(())
                });
                rpc_handle = Some(handle);
                info!(%listen, "rpc server listening");
            } else {
                info!("rpc disabled (no [rpc] section in node config)");
            }
            Ok::<(), NodeError>(())
        },
        || health.mark_running(),
    )
    .await;
    if outcome.is_ok() {
        health.mark_stopping();
        info!("shutdown signal received");
    } else {
        health.mark_failed();
    }
    tasks.close();
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        tasks.shutdown().await;
        if let Some(handle) = rpc_handle {
            handle.stopped().await;
        }
    })
    .await;
    info!("node stopped");
    let reached = fork_endpoint
        .lock()
        .expect("fork endpoint flag poisoned")
        .take();
    match (outcome, reached) {
        (Ok(()), Some((count, bundle))) => Err(NodeError::ForkEndpoint { count, bundle }),
        (outcome, _) => outcome,
    }
}

async fn supervise_lifecycle(
    tasks: &TaskSupervisor,
    shutdown: impl Future<Output = Result<(), std::io::Error>>,
    startup: impl Future<Output = Result<(), NodeError>>,
    on_started: impl FnOnce(),
) -> Result<(), NodeError> {
    tokio::pin!(shutdown);
    tokio::select! {
        biased;
        failure = tasks.next_failure() => return Err(task_error(failure)),
        result = &mut shutdown => return result.map_err(NodeError::Io),
        result = startup => result?,
    }
    on_started();
    tokio::select! {
        biased;
        failure = tasks.next_failure() => Err(task_error(failure)),
        result = &mut shutdown => result.map_err(NodeError::Io),
    }
}

fn task_error(failure: TaskFailure) -> NodeError {
    NodeError::CriticalTask {
        task: failure.name,
        reason: failure.reason,
    }
}
async fn wait_for_shutdown() -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = sigint.recv() => Ok(()),
            _ = sigterm.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod lifecycle_tests;
