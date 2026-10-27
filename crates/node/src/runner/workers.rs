//! The network service and the supervised workers the node runs once its
//! backend is initialised, spawned in the order the lifecycle fixes.

use std::net::SocketAddr;
use std::sync::Arc;

use neutrin0_network::service::{NetworkCommand, NetworkError, NetworkEvent, NetworkService};
use neutrin0_network::{Multiaddr, Topic};
use neutrin0_runtime_host::ProgramProver;
use neutrin0_sync::{SyncBackend, SyncDriver, SyncDriverConfig};
use tokio::sync::mpsc;
use tracing::{info, warn};

use super::{NodeBackend, NodeError};
use crate::config::{NodeConfig, NodeRole};
use crate::producer::{BlockProducerConfig, run_block_producer, run_chain_timers};
use crate::supervision::TaskSupervisor;

/// Build the network service, bind its listeners, start the storage guard
/// and the network worker; returns the command sender and the event stream.
pub(super) async fn start_network<P: ProgramProver + Send + Sync + 'static>(
    backend: &Arc<NodeBackend<P>>,
    config: &NodeConfig,
    tasks: &TaskSupervisor,
    local_key: neutrin0_network::libp2p::identity::Keypair,
    listen_addrs: Vec<Multiaddr>,
    bootnodes: Vec<Multiaddr>,
) -> Result<(mpsc::Sender<NetworkCommand>, mpsc::Receiver<NetworkEvent>), NodeError> {
    let local_peer_id = neutrin0_network::PeerId::from(local_key.public());
    info!(%local_peer_id, role = ?config.role, chain_id = config.chain_id, "starting node");
    let (cmd_tx, cmd_rx) = mpsc::channel::<NetworkCommand>(256);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(256);
    let mut svc = NetworkService::new(local_key, cmd_rx, event_tx)?;
    let chain_status = SyncBackend::local_status(backend.as_ref())
        .await
        .map_err(|error| NodeError::Engine(error.to_string()))?;
    svc.require_chain(chain_status);
    for addr in listen_addrs {
        let id = svc.listen_on(addr.clone()).map_err(NetworkError::from)?;
        info!(%addr, ?id, "listening");
    }
    svc.configure_bootnodes(bootnodes)?;
    backend.set_network_metrics(svc.metrics());
    backend.set_local_peer_id(local_peer_id.to_string());
    if let Some(path) = &config.data_dir {
        backend.set_metrics_data_path(path.clone());
        let path = path.clone();
        let storage = config.storage;
        let pressure = backend.storage_pressure_flag();
        let _ = tasks.spawner().spawn_critical("storage-guard", async move {
            crate::storage_guard::run(path, storage, pressure).await
        });
    }
    let _ = tasks.spawner().spawn_critical("network", async move {
        Box::pin(svc.run()).await.map_err(|error| error.to_string())
    });
    Ok((cmd_tx, event_rx))
}

/// Subscribe to the configured gossip topics, or the role's default set.
pub(super) async fn subscribe_topics(
    cmd_tx: &mpsc::Sender<NetworkCommand>,
    config: &NodeConfig,
) -> Result<(), NodeError> {
    let topics_to_subscribe: Vec<Topic> = config.subscribe_topics.as_ref().map_or_else(
        || {
            if config.role == NodeRole::LightClient {
                vec![Topic::Checkpoints]
            } else {
                Topic::all_default().collect()
            }
        },
        |names| {
            names
                .iter()
                .filter_map(|name| {
                    topic_from_name(name).or_else(|| {
                        warn!(topic = %name, "unknown topic name; ignoring");
                        None
                    })
                })
                .collect()
        },
    );
    for topic in topics_to_subscribe {
        cmd_tx
            .send(NetworkCommand::Subscribe(topic))
            .await
            .map_err(|_| NodeError::CriticalTask {
                task: "network",
                reason: "command channel closed during startup".into(),
            })?;
    }
    Ok(())
}

pub(super) fn topic_from_name(name: &str) -> Option<Topic> {
    Topic::all_default().find(|t| t.protocol_string() == name)
}

/// Hand the validator's keys and doppelganger policy to the engine.
pub(super) fn configure_local_voter<P: ProgramProver + Send + Sync + 'static>(
    backend: &NodeBackend<P>,
    config: &NodeConfig,
    production_config: Option<&BlockProducerConfig>,
) {
    if let Some(production) = production_config
        && let Some(proposer) = production.proposer.clone()
    {
        backend.set_local_voter(proposer);
        if let Some(standby) = production.standby.clone() {
            backend.set_standby_voter(standby);
        }
        let quiet = config.doppelganger.quiet_chunks;
        backend.set_doppelganger_quiet_chunks(quiet);
        if quiet == 0 {
            // Meant for development networks: a second process signing
            // with this key goes unseen until it conflicts.
            warn!("doppelganger quiet period disabled; signing starts at once");
        } else {
            info!(
                quiet_chunks = quiet,
                "signing waits out the doppelganger quiet period"
            );
        }
    }
}

/// Resume saved BFT sessions, then run proof notifications and, for a
/// voter, the round clock.
pub(super) async fn spawn_consensus_workers<P: ProgramProver + Send + Sync + 'static>(
    backend: &Arc<NodeBackend<P>>,
    tasks: &TaskSupervisor,
) -> Result<(), NodeError> {
    backend
        .resume_bft_sessions()
        .await
        .map_err(NodeError::Engine)?;
    let worker = Arc::clone(backend);
    let _ = tasks
        .spawner()
        .spawn_critical("consensus-notifications", async move {
            Box::pin(worker.run_consensus_proof_notifications()).await;
            Ok(())
        });
    if backend.local_voter().is_some() {
        let worker = Arc::clone(backend);
        let _ = tasks.spawner().spawn_critical("bft-clock", async move {
            worker.run_bft_round_timeouts().await;
            Ok(())
        });
    }
    Ok(())
}

pub(super) fn spawn_health_monitor(
    tasks: &TaskSupervisor,
    health: &Arc<crate::health::NodeHealth>,
    source: &Arc<dyn crate::metrics::MetricsSource>,
) {
    let monitor_health = Arc::clone(health);
    let monitor_source = Arc::clone(source);
    let _ = tasks
        .spawner()
        .spawn_critical("health-monitor", async move {
            monitor_health.monitor(monitor_source).await;
            Ok(())
        });
}

pub(super) async fn start_metrics_endpoint(
    addr: SocketAddr,
    tasks: &TaskSupervisor,
    health: &Arc<crate::health::NodeHealth>,
    source: Arc<dyn crate::metrics::MetricsSource>,
) -> Result<(), NodeError> {
    let listener = crate::metrics::bind(addr)
        .await
        .map_err(|error| NodeError::MetricsListen {
            addr: addr.to_string(),
            reason: error.to_string(),
        })?;
    let metrics_health = Arc::clone(health);
    let _ = tasks.spawner().spawn_critical("metrics", async move {
        crate::metrics::serve(listener, source, metrics_health)
            .await
            .map_err(|error| error.to_string())
    });
    info!(listen = %addr, "metrics endpoint listening");
    Ok(())
}

pub(super) async fn start_sync_driver<P: ProgramProver + Send + Sync + 'static>(
    backend: &Arc<NodeBackend<P>>,
    config: &NodeConfig,
    tasks: &TaskSupervisor,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    event_rx: mpsc::Receiver<NetworkEvent>,
) -> Result<(), NodeError> {
    let sync_backend = Arc::clone(backend) as Arc<dyn SyncBackend>;
    let local_progress = sync_backend
        .local_progress()
        .await
        .map_err(|error| NodeError::Engine(error.to_string()))?;
    let driver_cfg = SyncDriverConfig {
        mode: config.role.sync_mode(),
        light_sampling: config.light_client.sampling(),
        ..SyncDriverConfig::default()
    };
    let driver = SyncDriver::new(driver_cfg, sync_backend, local_progress, cmd_tx, event_rx);
    backend.set_sync_status(driver.status());
    let _ = tasks.spawner().spawn_critical("sync", async move {
        driver.run().await;
        Ok(())
    });
    Ok(())
}

/// The producer, or the chain timers every other non-light node runs.
pub(super) fn spawn_production<P: ProgramProver + Send + Sync + 'static>(
    backend: &Arc<NodeBackend<P>>,
    config: &NodeConfig,
    tasks: &TaskSupervisor,
    production_config: Option<BlockProducerConfig>,
    cmd_tx: mpsc::Sender<NetworkCommand>,
    slot_schedule: (u64, u64),
) {
    if let Some(production) = production_config {
        let worker = Arc::clone(backend);
        let _ = tasks.spawner().spawn_critical("producer", async move {
            run_block_producer(worker, cmd_tx, production).await;
            Ok(())
        });
    } else if config.role != NodeRole::LightClient {
        // The producer applies the time-driven chain rules itself;
        // every other non-light node runs them on its own timer.
        let worker = Arc::clone(backend);
        let (genesis_time_secs, slot_duration_secs) = slot_schedule;
        let _ = tasks.spawner().spawn_critical("chain-timers", async move {
            run_chain_timers(worker, genesis_time_secs, slot_duration_secs).await;
            Ok(())
        });
    }
}

#[cfg(unix)]
pub(super) fn start_management<P: ProgramProver + Send + Sync + 'static>(
    backend: &Arc<NodeBackend<P>>,
    tasks: &TaskSupervisor,
    management_shutdown: &Arc<tokio::sync::Notify>,
    listener: Option<crate::management::ManagementListener>,
) {
    if let Some(listener) = listener {
        let worker = Arc::clone(backend);
        let shutdown = Arc::clone(management_shutdown);
        let _ = tasks.spawner().spawn_critical("management", async move {
            crate::management::serve(listener, worker, shutdown)
                .await
                .map_err(|error| error.to_string())
        });
        info!("local management endpoint listening");
    }
}
