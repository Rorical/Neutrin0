use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::http::Scraper;
use super::*;
use crate::config::HealthConfig;
use crate::health::NodeHealth;

struct Stub(NodeMetrics, MetricsSnapshot, AtomicU64);

impl Stub {
    fn new(snapshot: MetricsSnapshot) -> Self {
        Self(NodeMetrics::default(), snapshot, AtomicU64::new(0))
    }
}

impl MetricsSource for Stub {
    fn metrics(&self) -> &NodeMetrics {
        &self.0
    }
    fn snapshot(&self) -> MetricsSnapshot {
        self.2.fetch_add(1, Ordering::Relaxed);
        self.1.clone()
    }
}

fn health(snapshot: MetricsSnapshot) -> Arc<NodeHealth> {
    let health = Arc::new(NodeHealth::new(&HealthConfig::default(), 4, 128));
    health.mark_running();
    health.sample_for_test(snapshot);
    health
}

#[test]
fn scrapes_inside_the_interval_reuse_one_snapshot() {
    let stub = Arc::new(Stub::new(MetricsSnapshot::default()));
    let scraper = Scraper {
        source: Arc::clone(&stub) as Arc<dyn MetricsSource>,
        health: health(MetricsSnapshot::default()),
        cached: Mutex::new(None),
    };
    let first = scraper.exposition();
    let second = scraper.exposition();
    assert!(Arc::ptr_eq(&first, &second));
    assert_eq!(stub.2.load(Ordering::Relaxed), 0);
    // Expire the cache and render the monitor's latest sample.
    scraper.health.sample_for_test(MetricsSnapshot {
        head_height: 7,
        ..MetricsSnapshot::default()
    });
    scraper.cached.lock().unwrap().as_mut().unwrap().0 -= SNAPSHOT_INTERVAL * 2;
    let third = scraper.exposition();
    assert!(!Arc::ptr_eq(&first, &third));
    assert!(third.contains("neutrin0_head_height 7"));
    assert_eq!(stub.2.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn idle_connections_beyond_the_cap_are_closed_unanswered() {
    let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let source: Arc<dyn MetricsSource> = Arc::new(Stub::new(MetricsSnapshot::default()));
    tokio::spawn(serve(listener, source, health(MetricsSnapshot::default())));
    // Fill every slot with connections that never send a request.
    let mut idle = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        idle.push(TcpStream::connect(addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The next connection is accepted and closed without a response.
    let mut extra = TcpStream::connect(addr).await.unwrap();
    let _ = extra
        .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n")
        .await;
    let mut response = String::new();
    let read = tokio::time::timeout(Duration::from_secs(2), extra.read_to_string(&mut response))
        .await
        .expect("connection must be closed promptly");
    assert!(read.is_ok() || read.is_err());
    assert!(response.is_empty(), "{response}");
    drop(idle);
}

#[test]
fn histogram_buckets_are_cumulative_and_outcomes_are_split() {
    let stage = StageMetrics::default();
    stage.observe(Duration::from_millis(500), true);
    stage.observe(Duration::from_secs(45), true);
    stage.observe(Duration::from_secs(5000), false);
    let mut out = String::new();
    stage.render(&mut out, "neutrin0_block_proof", "Block proof");
    assert!(out.contains("neutrin0_block_proof_total{outcome=\"ok\"} 2"));
    assert!(out.contains("neutrin0_block_proof_total{outcome=\"failed\"} 1"));
    assert!(out.contains("neutrin0_block_proof_seconds_bucket{le=\"1\"} 1"));
    assert!(out.contains("neutrin0_block_proof_seconds_bucket{le=\"30\"} 1"));
    assert!(out.contains("neutrin0_block_proof_seconds_bucket{le=\"60\"} 2"));
    assert!(out.contains("neutrin0_block_proof_seconds_bucket{le=\"1800\"} 2"));
    assert!(out.contains("neutrin0_block_proof_seconds_bucket{le=\"+Inf\"} 3"));
    assert!(out.contains("neutrin0_block_proof_seconds_count 3"));
    assert!(out.contains("neutrin0_block_proof_max_seconds 5000"));
}

#[test]
fn render_includes_snapshot_gauges_and_sessions() {
    let metrics = NodeMetrics::default();
    metrics.blocks_produced.store(7, Ordering::Relaxed);
    let snapshot = MetricsSnapshot {
        head_height: 42,
        finalized_chunks: 5,
        peers: 2,
        syncing: true,
        bft_sessions: vec![BftSessionGauge {
            chunk_id: 5,
            local_prevoted: true,
            ..BftSessionGauge::default()
        }],
        ..MetricsSnapshot::default()
    };
    let out = render(&metrics, &snapshot);
    assert!(out.contains("neutrin0_head_height 42"));
    assert!(out.contains("neutrin0_finalized_chunks 5"));
    assert!(out.contains("neutrin0_syncing 1"));
    assert!(out.contains("neutrin0_blocks_produced_total 7"));
    assert!(out.contains("neutrin0_bft_session{slot=\"0\",flag=\"local_prevoted\"} 1"));
    assert!(out.contains("neutrin0_bft_session{slot=\"0\",flag=\"precommit_quorum\"} 0"));
}

#[tokio::test]
async fn http_endpoint_serves_metrics_and_rejects_other_paths() {
    let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let snapshot = MetricsSnapshot {
        head_height: 9,
        ..MetricsSnapshot::default()
    };
    let source: Arc<dyn MetricsSource> = Arc::new(Stub::new(snapshot.clone()));
    let health = health(snapshot);
    tokio::spawn(serve(listener, source, Arc::clone(&health)));
    for (path, expect_status, expect_body) in [
        ("/metrics", "200 OK", "neutrin0_head_height 9"),
        ("/health", "503 Service Unavailable", "insufficient_peers"),
        ("/ready", "503 Service Unavailable", "insufficient_peers"),
        ("/live", "200 OK", "ok"),
        ("/nope", "404 Not Found", "not found"),
    ] {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(
            response.starts_with(&format!("HTTP/1.1 {expect_status}")),
            "{response}"
        );
        assert!(response.contains(expect_body), "{response}");
    }
    health.sample_for_test(MetricsSnapshot {
        peers: 1,
        ..MetricsSnapshot::default()
    });
    for path in ["/health", "/ready"] {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        assert!(response.ends_with("ok\n"));
    }
}

#[tokio::test]
async fn health_monitor_samples_without_any_http_scrapes() {
    let stub = Arc::new(Stub::new(MetricsSnapshot {
        peers: 1,
        finalized_chunks: 3,
        ..MetricsSnapshot::default()
    }));
    let health = Arc::new(NodeHealth::new(&HealthConfig::default(), 4, 128));
    health.mark_running();
    let monitor =
        tokio::spawn(Arc::clone(&health).monitor(Arc::clone(&stub) as Arc<dyn MetricsSource>));
    tokio::time::timeout(Duration::from_secs(2), async {
        while !health.status().ready {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(health.snapshot().finalized_chunks, 3);
    assert_eq!(stub.2.load(Ordering::Relaxed), 1);
    monitor.abort();
    let _ = monitor.await;
}
#[test]
fn chunk_identity_changes_never_create_label_values() {
    let metrics = NodeMetrics::default();
    let mut snapshot = MetricsSnapshot {
        bft_sessions: vec![BftSessionGauge {
            chunk_id: 1,
            ..BftSessionGauge::default()
        }],
        ..MetricsSnapshot::default()
    };
    let first = render(&metrics, &snapshot);
    snapshot.bft_sessions[0].chunk_id = u64::MAX;
    let later = render(&metrics, &snapshot);
    let labels = |body: &str| {
        body.lines()
            .filter(|line| !line.starts_with('#'))
            .map(|line| line.split_once(' ').unwrap().0.to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(labels(&first), labels(&later));
    assert!(!later.contains("chunk_id="));
    assert!(later.contains("# TYPE neutrin0_blocks_produced_total counter"));
    assert!(!later.contains("neutrin0_chunk_fact_checks_total"));
}

#[test]
fn complete_exposition_fixture_has_unique_samples_and_coherent_coverage() {
    let metrics = NodeMetrics::default();
    metrics
        .block_proofs
        .observe(Duration::from_millis(500), true);
    metrics.proof_pipeline.set_fact_coverage(3, 7);
    metrics.reporter.set_inventory(
        [1; 32],
        &neutrin0_consensus_engine::store::ReporterStorageStats::default(),
        crate::reporter_metrics::ReportPoolMetrics::default(),
        crate::reporter_metrics::ReporterRecovery {
            gap_chunks: 3,
            dormant_paths: 1,
        },
    );
    metrics.reporter.set_economics(
        [1; 32],
        128,
        &neutrin0_runtime_abi::operational::SettlementSnapshot::default(),
    );
    let mut extra = String::new();
    crate::supervision::TaskSupervisor::new()
        .spawner()
        .render_metrics(&mut extra);
    neutrin0_network::metrics::NetworkMetrics::default().render(&mut extra);
    neutrin0_sync::metrics::SyncMetrics::default().render(&mut extra);
    neutrin0_rpc::metrics::RpcMetrics::default().render(&mut extra);
    let mut process = crate::process_metrics::ProcessSampler::default();
    process.set_path(std::env::current_dir().unwrap());
    process.sample(&mut extra);
    let mut body = render(
        &metrics,
        &MetricsSnapshot {
            validator_set_available: true,
            bft_sessions: vec![BftSessionGauge::default()],
            ..MetricsSnapshot::default()
        },
    );
    body.push_str(&extra);
    let mut seen = std::collections::BTreeSet::new();
    for line in body
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
    {
        let (key, value) = line.split_once(' ').expect("sample has a value");
        assert!(seen.insert(key), "duplicate sample {key}");
        assert!(value.parse::<f64>().expect("numeric sample").is_finite());
    }
    assert!(body.contains("neutrin0_last_chunk_fact_checks_covered 3"));
    assert!(body.contains("neutrin0_last_chunk_fact_checks 7"));
    if let Some(path) = std::env::var_os("NEUTRIN0_METRICS_FIXTURE") {
        std::fs::write(path, body).expect("write requested promtool fixture");
    }
}

#[test]
fn unknown_validator_lists_do_not_report_genesis_counts() {
    let metrics = NodeMetrics::default();
    let mut snapshot = MetricsSnapshot {
        active_validators: 4,
        validator_seats: 5,
        ..MetricsSnapshot::default()
    };
    let unknown = render(&metrics, &snapshot);
    assert!(unknown.contains("neutrin0_validator_set_available 0"));
    assert!(!unknown.contains("neutrin0_active_validators "));
    snapshot.validator_set_available = true;
    let known = render(&metrics, &snapshot);
    assert!(known.contains("neutrin0_active_validators 4"));
    assert!(known.contains("neutrin0_validator_seats 5"));
}

#[test]
fn stage_timer_records_early_return_once() {
    let metrics = StageMetrics::default();
    drop(metrics.timer());
    metrics.timer().finish(true);
    let mut body = String::new();
    metrics.render(&mut body, "attempt", "Attempt");
    assert!(body.contains("attempt_total{outcome=\"ok\"} 1"));
    assert!(body.contains("attempt_total{outcome=\"failed\"} 1"));
    assert!(body.contains("attempt_seconds_count 2"));
}
