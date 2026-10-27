use super::*;

fn health() -> NodeHealth {
    NodeHealth::new(
        &HealthConfig {
            min_peers: 1,
            finality_stall_timeout_secs: Some(60),
        },
        4,
        128,
    )
}

fn connected() -> MetricsSnapshot {
    MetricsSnapshot {
        peers: 1,
        ..MetricsSnapshot::default()
    }
}

#[test]
fn readiness_tracks_startup_peers_sync_bootstrap_and_shutdown() {
    let health = health();
    assert_eq!(health.status().reason.label(), "starting");
    health.mark_running();
    assert_eq!(health.status().reason.label(), "health_sample_pending");
    health.sample_at(MetricsSnapshot::default(), Instant::now());
    assert_eq!(health.status().reason.label(), "insufficient_peers");
    assert!(health.status().live);
    health.sample_at(
        MetricsSnapshot {
            syncing: true,
            ..connected()
        },
        Instant::now(),
    );
    assert_eq!(health.status().reason.label(), "syncing");
    health.sample_at(
        MetricsSnapshot {
            bootstrap_pending: true,
            ..connected()
        },
        Instant::now(),
    );
    assert_eq!(health.status().reason.label(), "bootstrap_pending");
    health.sample_at(
        MetricsSnapshot {
            trust_anchor_expired: true,
            ..connected()
        },
        Instant::now(),
    );
    assert_eq!(health.status().reason.label(), "trust_anchor_expired");
    health.sample_at(
        MetricsSnapshot {
            history_conflict: true,
            ..connected()
        },
        Instant::now(),
    );
    assert_eq!(health.status().reason.label(), "history_conflict");
    health.sample_at(connected(), Instant::now());
    assert!(health.status().ready);
    health.mark_stopping();
    assert_eq!(health.status().reason.label(), "stopping");
    assert!(!health.status().live);
    health.mark_failed();
    assert_eq!(health.status().reason.label(), "critical_task_failed");
}

#[test]
fn only_new_finality_resets_the_stall_clock_and_sampling_must_continue() {
    let health = health();
    health.mark_running();
    let start = Instant::now();
    health.sample_at(connected(), start);
    let later = start + Duration::from_secs(60);
    health.sample_at(
        MetricsSnapshot {
            head_height: 100,
            ..connected()
        },
        later,
    );
    assert_eq!(health.status_at(later).reason.label(), "finality_stalled");
    assert!(health.status_at(later).live);
    health.sample_at(
        MetricsSnapshot {
            finalized_chunks: 1,
            ..connected()
        },
        later,
    );
    assert!(health.status_at(later).ready);
    let stale = health.status_at(later + SAMPLE_TIMEOUT + Duration::from_secs(1));
    assert_eq!(stale.reason.label(), "health_sample_stale");
    assert!(!stale.live);
}

#[test]
fn isolated_nodes_can_opt_out_of_peer_requirement_and_timeout_is_derived_safely() {
    let health = NodeHealth::new(
        &HealthConfig {
            min_peers: 0,
            finality_stall_timeout_secs: None,
        },
        10,
        128,
    );
    assert_eq!(health.stall_timeout, Duration::from_mins(64));
    health.mark_running();
    health.sample_at(
        MetricsSnapshot {
            syncing: true,
            sync_awaiting_peer: true,
            ..MetricsSnapshot::default()
        },
        Instant::now(),
    );
    assert!(health.status().ready);
    health.sample_at(
        MetricsSnapshot {
            syncing: true,
            sync_awaiting_peer: false,
            ..MetricsSnapshot::default()
        },
        Instant::now(),
    );
    assert_eq!(health.status().reason.label(), "syncing");
    assert_eq!(
        NodeHealth::new(&HealthConfig::default(), u64::MAX, u64::MAX).stall_timeout,
        Duration::from_secs(u64::MAX)
    );
}
