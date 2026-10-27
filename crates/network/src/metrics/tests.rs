use super::*;

#[test]
fn observations_finish_exactly_once_and_drop_cancels_inflight() {
    let metrics = Arc::new(NetworkMetrics::default());
    let mut observation = metrics.rpc_start(RpcProtocol::Status, Direction::Outbound);
    observation.complete(RpcOutcome::Ok);
    observation.complete(RpcOutcome::Timeout);
    drop(observation);
    drop(metrics.rpc_start(RpcProtocol::Status, Direction::Outbound));
    let value = &metrics.rpc[0][1];
    assert_eq!(value.started.load(Ordering::Relaxed), 2);
    assert_eq!(value.inflight(), 0);
    assert_eq!(value.completed[0].load(Ordering::Relaxed), 1);
    assert_eq!(value.completed[2].load(Ordering::Relaxed), 0);
    assert_eq!(value.completed[8].load(Ordering::Relaxed), 1);
}

#[test]
fn failures_before_decoding_do_not_invent_requests_or_latency() {
    let metrics = NetworkMetrics::default();
    metrics.inbound_failure(RpcProtocol::Status, &InboundFailure::Timeout);
    let value = &metrics.rpc[0][0];
    assert_eq!(value.started.load(Ordering::Relaxed), 0);
    assert_eq!(value.inflight(), 0);
    assert_eq!(value.transport_failures[2].load(Ordering::Relaxed), 1);
    assert_eq!(value.latency.sum_micros.load(Ordering::Relaxed), 0);
}

#[test]
fn connection_metrics_distinguish_connections_and_peers() {
    let metrics = NetworkMetrics::default();
    metrics.connected(true, true);
    metrics.connected(false, false);
    metrics.disconnected(true, false);
    let peers = |metrics: &NetworkMetrics| {
        metrics.peer_connections.load(Ordering::Relaxed)
            - metrics.peer_disconnects.load(Ordering::Relaxed)
    };
    assert_eq!(peers(&metrics), 1);
    metrics.disconnected(false, true);
    assert_eq!(peers(&metrics), 0);
    assert_eq!(metrics.peer_disconnects.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.opened[0].load(Ordering::Relaxed), 1);
    assert_eq!(metrics.opened[1].load(Ordering::Relaxed), 1);
}

#[test]
fn bootnode_state_discriminants_index_their_labels() {
    for (state, label) in [
        (BootnodeState::Connected, "connected"),
        (BootnodeState::Pending, "pending"),
        (BootnodeState::Backoff, "backoff"),
        (BootnodeState::Ready, "ready"),
        (BootnodeState::Disabled, "disabled"),
        (BootnodeState::Blocked, "blocked"),
    ] {
        assert_eq!(BOOTNODE_STATES[state as usize], label);
    }
}

#[test]
fn protocol_and_outcome_labels_are_fixed_and_all_protocols_are_distinct() {
    let mut labels = std::collections::HashSet::new();
    for (index, protocol) in RpcProtocol::ALL.into_iter().enumerate() {
        assert_eq!(protocol_index(protocol), index);
        assert!(labels.insert(protocol_label(protocol)));
    }
    let mut body = String::new();
    NetworkMetrics::default().render(&mut body);
    assert!(body.contains("protocol=\"bft_round_by_chunk\",direction=\"inbound\""));
    assert!(!body.contains("peer_id"));
    assert!(!body.contains("address="));
    assert!(!body.contains("chunk_id="));
    assert!(body.contains("# TYPE neutrin0_network_rpc_completed_total counter"));
}
