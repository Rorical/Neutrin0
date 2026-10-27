use super::*;
fn peer() -> PeerId {
    PeerId::random()
}
fn address(value: &str) -> Multiaddr {
    value.parse().unwrap()
}

#[test]
fn rotating_identities_cannot_fill_one_ip_or_prefix() {
    let mut guard = Guard::default();
    let now = Instant::now();
    for _ in 0..4 {
        assert!(guard.connect(peer(), &address("/ip4/8.8.8.1/tcp/1"), false, now));
    }
    assert!(!guard.connect(peer(), &address("/ip4/8.8.8.1/tcp/2"), false, now));
    for index in 2..6 {
        assert!(guard.connect(
            peer(),
            &address(&format!("/ip4/8.8.8.{index}/tcp/1")),
            false,
            now
        ));
    }
    assert!(!guard.connect(peer(), &address("/ip4/8.8.8.6/tcp/1"), false, now));
    assert!(guard.connect(peer(), &address("/ip4/8.8.9.1/tcp/1"), false, now));
    assert!(guard.connect(peer(), &address("/ip4/8.8.8.1/tcp/1"), true, now));
}

#[test]
fn reconnecting_with_new_keys_cannot_reset_the_prefix_request_budget() {
    let mut guard = Guard::default();
    let now = Instant::now();
    for _ in 0..4 {
        let source = peer();
        assert!(guard.connect(source, &address("/ip4/8.8.8.1/tcp/1"), false, now));
        for _ in 0..16 {
            assert!(guard.admit(source, true, 1, now));
        }
        guard.disconnect(&source);
    }
    let source = peer();
    assert!(guard.connect(source, &address("/ip6/::ffff:8.8.8.2/tcp/1"), false, now));
    assert!(!guard.admit(source, true, 1, now));
    assert!(guard.admit(source, true, 1, now + WINDOW));
    assert_eq!(guard.groups.len(), 1);
}

#[test]
fn handshake_timeout_shared_rate_and_quarantine_are_bounded() {
    let mut guard = Guard {
        chain: Some((7, [3; 32])),
        ..Guard::default()
    };
    let now = Instant::now();
    let source = peer();
    assert!(guard.connect(source, &address("/ip4/127.0.0.1/tcp/1"), false, now));
    assert!(!guard.ready(&source));
    assert!(!guard.status(source, (7, [4; 32])));
    assert_eq!(guard.expired(now + Duration::from_secs(31)), vec![source]);
    assert!(guard.status(source, (7, [3; 32])));
    assert_eq!(
        guard.expired(now + Duration::from_secs(31)),
        Vec::<PeerId>::new()
    );
    for _ in 0..16 {
        assert!(guard.admit(source, true, 1, now));
    }
    assert!(!guard.admit(source, true, 1, now));
    assert!(guard.admit(source, true, 1, now + WINDOW));
    assert!(!guard.invalid(source, now));
    assert!(!guard.invalid(source, now));
    assert!(guard.invalid(source, now));
    guard.disconnect(&source);
    assert!(!guard.connect(source, &address("/ip4/127.0.0.1/tcp/1"), false, now));
    assert!(guard.connect(
        source,
        &address("/ip4/127.0.0.1/tcp/1"),
        false,
        now + QUARANTINE
    ));
}

#[test]
fn response_bytes_spend_the_requesters_budget() {
    let mut guard = Guard::default();
    let now = Instant::now();
    let source = peer();
    assert!(guard.connect(source, &address("/ip4/8.8.8.1/tcp/1"), false, now));
    assert!(guard.admit(source, true, 1024 * 1024, now));
    guard.charge(source, 32 * 1024 * 1024, now);
    assert!(!guard.admit(source, true, 1024 * 1024, now));
    assert!(guard.admit(source, true, 1024 * 1024, now + WINDOW));
    assert_eq!(
        host_group(&address("/ip4/8.8.8.1/tcp/1")),
        Some([0, 0, 0, 8, 8, 8])
    );
    assert_eq!(host_group(&address("/ip4/127.0.0.1/tcp/1")), None);
}

#[test]
fn fresh_identities_from_one_address_cannot_reset_its_strikes() {
    let mut guard = Guard::default();
    let now = Instant::now();
    for _ in 0..2 {
        let source = peer();
        assert!(guard.connect(source, &address("/ip4/8.8.8.1/tcp/1"), false, now));
        assert!(!guard.invalid(source, now));
        assert!(!guard.invalid(source, now));
        guard.disconnect(&source);
    }
    // The sixth strike from the address quarantines it whatever identity
    // carries it, and the address may not connect again for a while.
    let source = peer();
    assert!(guard.connect(source, &address("/ip4/8.8.8.1/tcp/1"), false, now));
    assert!(!guard.invalid(source, now));
    assert!(guard.invalid(source, now));
    assert!(!guard.connect(peer(), &address("/ip4/8.8.8.1/tcp/1"), false, now));
    assert!(guard.connect(peer(), &address("/ip4/8.8.8.2/tcp/1"), false, now));
    assert!(guard.connect(
        peer(),
        &address("/ip4/8.8.8.1/tcp/1"),
        false,
        now + QUARANTINE
    ));
}
