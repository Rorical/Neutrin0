//! Prometheus text exposition of [`NetworkMetrics`].

use super::{
    BOOTNODE_STATES, BUCKETS_MILLIS, DIAL_FAILURES, Direction, GOSSIP_PUBLISH, GOSSIP_VALIDATION,
    GUARD_ACTIONS, Histogram, NetworkMetrics, OUTCOMES, protocol_index, protocol_label,
};
use crate::rpc::RpcProtocol;
use std::{fmt::Write as _, sync::atomic::Ordering};

impl Histogram {
    fn render(&self, out: &mut String, name: &str, labels: &str) {
        let separator = if labels.is_empty() { "" } else { "," };
        let mut count = 0;
        for (bound, bucket) in BUCKETS_MILLIS.iter().zip(&self.buckets) {
            count += bucket.load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{name}_bucket{{{labels}{separator}le=\"{}\"}} {count}",
                seconds(bound * 1_000)
            );
        }
        count += self.overflow.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "{name}_bucket{{{labels}{separator}le=\"+Inf\"}} {count}"
        );
        let suffix = if labels.is_empty() {
            String::new()
        } else {
            format!("{{{labels}}}")
        };
        let _ = writeln!(
            out,
            "{name}_sum{suffix} {}",
            seconds(self.sum_micros.load(Ordering::Relaxed))
        );
        let _ = writeln!(out, "{name}_count{suffix} {count}");
    }
}

impl NetworkMetrics {
    /// Append Prometheus text exposition. Counters describe observed events for
    /// this process lifetime. RPC latency covers decoded request to wire
    /// completion (inbound), or service dispatch to response/failure (outbound).
    /// Undecodable inbound failures have no invented latency or request count.
    #[allow(clippy::too_many_lines)]
    pub fn render(&self, out: &mut String) {
        scalar(
            out,
            "neutrin0_bootnode_dial_attempts_total",
            "counter",
            self.bootnode_attempts.load(Ordering::Relaxed),
        );
        family(out, "neutrin0_bootnode_dial_failures_total", "counter");
        for (reason, value) in DIAL_FAILURES.iter().zip(&self.bootnode_failures) {
            let _ = writeln!(
                out,
                "neutrin0_bootnode_dial_failures_total{{reason=\"{reason}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        family(out, "neutrin0_bootnodes", "gauge");
        for (state, value) in BOOTNODE_STATES.iter().zip(&self.bootnode_states) {
            let _ = writeln!(
                out,
                "neutrin0_bootnodes{{state=\"{state}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        // Every close follows its open; loading closes first keeps the
        // derived open gauges non-negative under concurrent updates.
        let closed = self
            .closed
            .each_ref()
            .map(|value| value.load(Ordering::Relaxed));
        let opened = self
            .opened
            .each_ref()
            .map(|value| value.load(Ordering::Relaxed));
        let connections = [0, 1].map(|index| opened[index].saturating_sub(closed[index]));
        for (name, values, kind) in [
            ("neutrin0_network_connections", connections, "gauge"),
            (
                "neutrin0_network_connections_opened_total",
                opened,
                "counter",
            ),
            (
                "neutrin0_network_connections_closed_total",
                closed,
                "counter",
            ),
        ] {
            family(out, name, kind);
            for direction in [Direction::Inbound, Direction::Outbound] {
                let _ = writeln!(
                    out,
                    "{name}{{direction=\"{}\"}} {}",
                    direction.label(),
                    values[direction.index()]
                );
            }
        }
        let peer_disconnects = self.peer_disconnects.load(Ordering::Relaxed);
        let peer_connections = self.peer_connections.load(Ordering::Relaxed);
        scalar(
            out,
            "neutrin0_network_connected_peers",
            "gauge",
            peer_connections.saturating_sub(peer_disconnects),
        );
        scalar(
            out,
            "neutrin0_network_peer_connections_total",
            "counter",
            peer_connections,
        );
        scalar(
            out,
            "neutrin0_network_peer_disconnects_total",
            "counter",
            peer_disconnects,
        );
        family(out, "neutrin0_network_ping_total", "counter");
        let _ = writeln!(
            out,
            "neutrin0_network_ping_total{{outcome=\"ok\"}} {}",
            self.ping_ok.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "neutrin0_network_ping_total{{outcome=\"failed\"}} {}",
            self.ping_failed.load(Ordering::Relaxed)
        );
        family(out, "neutrin0_network_ping_seconds", "histogram");
        self.ping_latency
            .render(out, "neutrin0_network_ping_seconds", "");
        for (name, kind) in [
            ("neutrin0_network_rpc_started_total", "counter"),
            ("neutrin0_network_rpc_inflight", "gauge"),
            ("neutrin0_network_rpc_completed_total", "counter"),
            ("neutrin0_network_rpc_transport_failures_total", "counter"),
            ("neutrin0_network_rpc_seconds", "histogram"),
        ] {
            family(out, name, kind);
        }
        for protocol in RpcProtocol::ALL {
            for direction in [Direction::Inbound, Direction::Outbound] {
                let labels = format!(
                    "protocol=\"{}\",direction=\"{}\"",
                    protocol_label(protocol),
                    direction.label()
                );
                let value = &self.rpc[protocol_index(protocol)][direction.index()];
                let _ = writeln!(
                    out,
                    "neutrin0_network_rpc_started_total{{{labels}}} {}",
                    value.started.load(Ordering::Relaxed)
                );
                let _ = writeln!(
                    out,
                    "neutrin0_network_rpc_inflight{{{labels}}} {}",
                    value.inflight()
                );
                for (index, outcome) in OUTCOMES.iter().enumerate() {
                    let _ = writeln!(
                        out,
                        "neutrin0_network_rpc_completed_total{{{labels},outcome=\"{outcome}\"}} {}",
                        value.completed[index].load(Ordering::Relaxed)
                    );
                    let _ = writeln!(
                        out,
                        "neutrin0_network_rpc_transport_failures_total{{{labels},reason=\"{outcome}\"}} {}",
                        value.transport_failures[index].load(Ordering::Relaxed)
                    );
                }
                value
                    .latency
                    .render(out, "neutrin0_network_rpc_seconds", &labels);
            }
        }
        scalar(
            out,
            "neutrin0_network_gossip_received_total",
            "counter",
            self.gossip_received.load(Ordering::Relaxed),
        );
        scalar(
            out,
            "neutrin0_network_gossip_received_bytes_total",
            "counter",
            self.gossip_received_bytes.load(Ordering::Relaxed),
        );
        family(out, "neutrin0_network_gossip_publish_total", "counter");
        for (outcome, value) in GOSSIP_PUBLISH.iter().zip(&self.gossip_publish) {
            let _ = writeln!(
                out,
                "neutrin0_network_gossip_publish_total{{outcome=\"{outcome}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        family(out, "neutrin0_network_guard_actions_total", "counter");
        for (reason, value) in GUARD_ACTIONS.iter().zip(&self.guard_actions) {
            let _ = writeln!(
                out,
                "neutrin0_network_guard_actions_total{{reason=\"{reason}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        family(out, "neutrin0_network_gossip_validation_total", "counter");
        for (outcome, value) in GOSSIP_VALIDATION.iter().zip(&self.gossip_validation) {
            let _ = writeln!(
                out,
                "neutrin0_network_gossip_validation_total{{outcome=\"{outcome}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        scalar(
            out,
            "neutrin0_network_listener_failures_total",
            "counter",
            self.listener_failures.load(Ordering::Relaxed),
        );
    }
}

fn seconds(micros: u64) -> String {
    format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000)
}

fn family(out: &mut String, name: &str, kind: &str) {
    let _ = writeln!(out, "# HELP {name} Process-lifetime network measurements.");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

fn scalar(out: &mut String, name: &str, kind: &str, value: u64) {
    family(out, name, kind);
    let _ = writeln!(out, "{name} {value}");
}
