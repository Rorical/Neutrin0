use super::*;

fn address(port: u16, peer: Option<PeerId>) -> Multiaddr {
    let mut result: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
    if let Some(peer) = peer {
        result.push(Protocol::P2p(peer));
    }
    result
}

#[test]
fn fake_time_retries_back_off_with_bounded_jitter_and_ignore_stale_failures() {
    let now = Instant::now();
    let mut state = Bootnodes::configured(PeerId::random(), vec![address(1, None)], now).unwrap();
    assert_eq!(state.next_due(now), Some(0));
    for attempt in 0..100 {
        let at = state.next_deadline().unwrap();
        let connection = ConnectionId::new_unchecked(attempt);
        assert!(state.start(0, connection));
        assert_eq!(state.next_deadline(), None);
        assert!(!state.start(0, ConnectionId::new_unchecked(1000)));
        state.failed(ConnectionId::new_unchecked(1000), at, false);
        assert_eq!(state.next_deadline(), None);
        state.failed(connection, at, false);
        let next = state.next_deadline().unwrap();
        let nominal = (1000_u64 << attempt.min(6)).min(MAX_BACKOFF_MILLIS);
        let delay = next.duration_since(at);
        assert!(delay >= Duration::from_millis((nominal / 2).max(1000)));
        assert!(delay <= Duration::from_millis(nominal));
        assert_eq!(state.next_due(next - Duration::from_nanos(1)), None);
        assert_eq!(state.next_due(next), Some(0));
    }
}

#[test]
fn same_peer_addresses_share_pending_and_connected_state_until_last_connection_closes() {
    let now = Instant::now();
    let peer = PeerId::random();
    let addresses = vec![address(1, Some(peer)), address(2, Some(peer))];
    let mut state = Bootnodes::configured(PeerId::random(), addresses.clone(), now).unwrap();
    let first = ConnectionId::new_unchecked(1);
    assert!(state.start(0, first));
    assert_eq!(state.next_deadline(), None);
    state.failed(first, now, false);
    assert_eq!(state.next_due(now), Some(1));
    let second = ConnectionId::new_unchecked(2);
    assert!(state.start(1, second));
    state.connected(peer, second, &addresses[1]);
    assert_eq!(state.next_deadline(), None);
    state.disconnected(peer, 1, now);
    assert_eq!(state.next_deadline(), None);
    state.disconnected(peer, 0, now);
    assert!(state.next_deadline().unwrap() > now);
    assert!(state.next_deadline().unwrap() <= now + Duration::from_secs(1));
}

#[test]
fn bare_address_can_reconnect_to_a_restarted_peer_with_a_new_identity() {
    let now = Instant::now();
    let address = address(1, None);
    let mut state = Bootnodes::configured(PeerId::random(), vec![address.clone()], now).unwrap();
    let first_peer = PeerId::random();
    let first = ConnectionId::new_unchecked(1);
    assert!(state.start(0, first));
    state.connected(first_peer, first, &address);
    assert_eq!(state.next_deadline(), None);
    state.disconnected(first_peer, 0, now);
    let second_peer = PeerId::random();
    let second = ConnectionId::new_unchecked(2);
    assert!(state.start(0, second));
    state.connected(second_peer, second, &address);
    state.failed(first, now, false);
    assert_eq!(state.entries[0].connected_peer, Some(second_peer));
    assert_eq!(state.entries[0].failures, 0);
}

#[test]
fn only_configured_addresses_are_tracked_and_self_dials_are_disabled() {
    let now = Instant::now();
    let address = address(1, None);
    let mut state = Bootnodes::configured(PeerId::random(), vec![address.clone()], now).unwrap();
    state.connected(
        PeerId::random(),
        ConnectionId::new_unchecked(9),
        &super::tests::address(2, None),
    );
    assert_eq!(state.next_due(now), Some(0));
    let pending = ConnectionId::new_unchecked(1);
    assert!(state.start(0, pending));
    state.failed(pending, now, true);
    assert_eq!(state.next_deadline(), None);
    let mut local = Bootnodes::configured(PeerId::random(), vec![address.clone()], now).unwrap();
    local.local_address(&address);
    assert_eq!(local.next_deadline(), None);
}

#[test]
fn configuration_is_bounded_deduplicated_and_rejects_local_identity() {
    let now = Instant::now();
    let local = PeerId::random();
    let address = address(1, None);
    let state = Bootnodes::configured(local, vec![address.clone(), address.clone()], now).unwrap();
    assert_eq!(state.entries.len(), 1);
    assert!(Bootnodes::configured(local, vec![address; MAX_BOOTNODES + 1], now).is_err());
    assert!(Bootnodes::configured(local, vec![self::address(1, Some(local))], now).is_err());
    assert!(Bootnodes::configured(local, vec![Multiaddr::empty()], now).is_err());
    let only_peer: Multiaddr = format!("/p2p/{}", PeerId::random()).parse().unwrap();
    assert!(Bootnodes::configured(local, vec![only_peer], now).is_err());
}
