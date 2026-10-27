//! The minimal HTTP/1.1 responder serving `GET /metrics` and the health
//! paths, sampling state at most once per [`SNAPSHOT_INTERVAL`].

#![allow(clippy::redundant_pub_crate)] // Crate-internal helpers re-exported by the parent module.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::{MetricsSource, gauge, labeled, render};
use crate::health::NodeHealth;

/// Bind the metrics listener.
///
/// # Errors
/// Returns the bind error.
pub async fn bind(listen: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(listen).await
}

/// Connections served at once; further connections are closed unanswered.
pub const MAX_CONNECTIONS: usize = 16;

/// Minimum interval between two state samples. Scrapes inside the window
/// reuse the previous exposition so a flood cannot hammer the engine lock.
pub const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(1);

/// Shared scrape state: the source plus the last rendered exposition.
pub(super) struct Scraper {
    pub(super) source: Arc<dyn MetricsSource>,
    pub(super) health: Arc<NodeHealth>,
    pub(super) cached: Mutex<Option<(Instant, Arc<String>)>>,
}

impl Scraper {
    pub(super) fn exposition(&self) -> Arc<String> {
        let mut cached = self.cached.lock().expect("metrics cache poisoned");
        if let Some((at, body)) = cached.as_ref()
            && at.elapsed() < SNAPSHOT_INTERVAL
        {
            return Arc::clone(body);
        }
        let snapshot = self.health.snapshot();
        let mut body = render(self.source.metrics(), &snapshot);
        self.source.render_subsystems(&mut body);
        let health = self.health.status();
        gauge(
            &mut body,
            "neutrin0_live",
            "Critical workers and health sampler are live.",
            u8::from(health.live),
        );
        gauge(
            &mut body,
            "neutrin0_ready",
            "Node satisfies configured readiness requirements.",
            u8::from(health.ready),
        );
        gauge(
            &mut body,
            "neutrin0_finality_progress_age_seconds",
            "Seconds since the last locally observed finality progress.",
            health.finality_age.as_secs(),
        );
        gauge(
            &mut body,
            "neutrin0_finality_stall_timeout_seconds",
            "Configured finality progress timeout.",
            health.stall_timeout.as_secs(),
        );
        gauge(
            &mut body,
            "neutrin0_bootstrap_pending",
            "Authenticated snapshot installation is pending.",
            u8::from(snapshot.bootstrap_pending),
        );
        gauge(
            &mut body,
            "neutrin0_trust_anchor_expired",
            "Proof-only weak-subjectivity anchor has expired.",
            u8::from(snapshot.trust_anchor_expired),
        );
        gauge(
            &mut body,
            "neutrin0_light_history_conflict",
            "Two verified History proofs disagree; the light client is halted.",
            u8::from(snapshot.history_conflict),
        );
        gauge(
            &mut body,
            "neutrin0_sync_awaiting_peer",
            "Sync FSM is waiting for its first peer handshake.",
            u8::from(snapshot.sync_awaiting_peer),
        );
        gauge(
            &mut body,
            "neutrin0_health_sample_age_seconds",
            "Age of the last health sample; -1 before the first sample.",
            health
                .sample_age
                .map_or_else(|| "-1".to_owned(), |age| age.as_secs().to_string()),
        );
        labeled(
            &mut body,
            "neutrin0_readiness_reason",
            "Current finite readiness reason.",
            "gauge",
            "reason",
            crate::health::ReadinessReason::ALL
                .map(|reason| (reason.label(), u8::from(health.reason == reason))),
        );
        let body = Arc::new(body);
        *cached = Some((Instant::now(), Arc::clone(&body)));
        body
    }
}

/// Serve `GET /metrics` until the listener fails.
///
/// Each connection handles one request and is closed; a 5 second deadline
/// bounds slow or idle clients, at most [`MAX_CONNECTIONS`] are served at
/// once, and state is sampled at most once per [`SNAPSHOT_INTERVAL`]. Bodies
/// and other paths are ignored.
///
/// # Errors
/// Returns a listener accept error so supervision can terminate the node.
pub(crate) async fn serve(
    listener: TcpListener,
    source: Arc<dyn MetricsSource>,
    health: Arc<NodeHealth>,
) -> std::io::Result<()> {
    let scraper = Arc::new(Scraper {
        source,
        health,
        cached: Mutex::new(None),
    });
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            // Over capacity: close immediately rather than queue work.
            drop(stream);
            continue;
        };
        let scraper = Arc::clone(&scraper);
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(Duration::from_secs(5), respond(stream, scraper)).await;
        });
    }
}

async fn respond(mut stream: TcpStream, scraper: Arc<Scraper>) -> std::io::Result<()> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0_u8; 512];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") || buffer.len() > 8192 {
            break;
        }
    }
    let request_line = buffer
        .split(|byte| *byte == b'\n')
        .next()
        .map(|line| String::from_utf8_lossy(line).trim().to_owned())
        .unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let (status, body): (&str, Arc<String>) =
        if method == "GET" && (path == "/metrics" || path == "/") {
            let scraper = Arc::clone(&scraper);
            let body = tokio::task::spawn_blocking(move || scraper.exposition())
                .await
                .map_err(std::io::Error::other)?;
            ("200 OK", body)
        } else if method == "GET" && matches!(path, "/health" | "/ready" | "/live") {
            let health = scraper.health.status();
            let healthy = if path == "/live" {
                health.live
            } else {
                health.ready
            };
            let reason = if healthy { "ok" } else { health.reason.label() };
            (
                if healthy {
                    "200 OK"
                } else {
                    "503 Service Unavailable"
                },
                Arc::new(format!("{reason}\n")),
            )
        } else {
            ("404 Not Found", Arc::new("not found\n".to_owned()))
        };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}
