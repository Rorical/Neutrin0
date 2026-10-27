use super::*;

fn address(value: &str) -> Multiaddr {
    value.parse().unwrap()
}

/// A book for a private test network, where local targets are dialable.
fn private_network() -> Discovery {
    let mut discovery = Discovery::default();
    discovery.allow_local(true);
    discovery
}

#[test]
fn one_prefix_cannot_fill_the_book_or_a_dial_round() {
    let local = PeerId::random();
    let now = Instant::now();
    let mut discovery = private_network();
    for host in 1..=10 {
        discovery.learn(
            &local,
            PeerId::random(),
            [address(&format!("/ip4/10.0.0.{host}/tcp/30303"))],
            now,
        );
    }
    assert_eq!(discovery.len(), MAX_LEARNED_PER_PREFIX);
    let other = PeerId::random();
    discovery.learn(&local, other, [address("/ip4/10.0.1.1/tcp/30303")], now);
    // Two prefixes yield at most one dial each per round.
    let due = discovery.due(|_| false, DIALS_PER_WALK, now);
    assert_eq!(due.len(), 2);
    assert!(due.iter().any(|(target, _)| target.peer() == other));
    // Dialed peers wait before another attempt; others remain due.
    let next = discovery.due(|_| false, DIALS_PER_WALK, now);
    assert_eq!(next.len(), 1);
    assert!(
        next.iter()
            .all(|(target, _)| due.iter().all(|(dialed, _)| dialed != target))
    );
    assert!(
        discovery
            .due(|_| false, DIALS_PER_WALK, now + REDIAL_AFTER)
            .len()
            >= 2
    );
}

#[test]
fn replies_cannot_name_other_identities_or_undialable_targets() {
    let local = PeerId::random();
    let now = Instant::now();
    let mut discovery = private_network();
    let peer = PeerId::random();
    for bad in [
        format!("/ip4/10.0.0.1/tcp/1/p2p/{}", PeerId::random()),
        "/ip4/0.0.0.0/tcp/1".to_owned(),
        "/ip4/224.0.0.1/tcp/1".to_owned(),
        "/ip4/255.255.255.255/tcp/1".to_owned(),
        "/ip4/10.0.0.1".to_owned(),
        "/dns4/example.org/tcp/1".to_owned(),
    ] {
        discovery.learn(&local, peer, [address(&bad)], now);
    }
    discovery.learn(&local, local, [address("/ip4/10.0.0.1/tcp/1")], now);
    assert_eq!(discovery.len(), 0);
    discovery.learn(
        &local,
        peer,
        [address(&format!("/ip4/10.0.0.1/tcp/1/p2p/{peer}"))],
        now,
    );
    assert_eq!(discovery.due(|_| false, 1, now).len(), 1);
    assert_eq!(
        discovery
            .due(|candidate| *candidate == peer, 1, now + REDIAL_AFTER)
            .len(),
        0
    );
}

#[test]
fn a_public_node_never_dials_local_targets_a_reply_names() {
    let local = PeerId::random();
    let now = Instant::now();
    let mut discovery = Discovery::default();
    for target in [
        "/ip4/127.0.0.1/tcp/1",
        "/ip4/10.1.2.3/tcp/1",
        "/ip4/192.168.1.1/tcp/1",
        "/ip4/169.254.0.1/tcp/1",
        "/ip4/100.64.0.1/tcp/1",
        "/ip6/::1/tcp/1",
        "/ip6/fd00::1/tcp/1",
        "/ip6/fe80::1/tcp/1",
    ] {
        discovery.learn(&local, PeerId::random(), [address(target)], now);
    }
    assert_eq!(discovery.len(), 0);
    discovery.learn(
        &local,
        PeerId::random(),
        [address("/ip4/198.51.100.1/tcp/1")],
        now,
    );
    assert_eq!(discovery.len(), 1);
}

#[test]
fn replies_add_entries_but_never_replace_them_and_a_failed_dial_forgets_one() {
    let local = PeerId::random();
    let now = Instant::now();
    let mut discovery = private_network();
    let peer = PeerId::random();
    discovery.learn(
        &local,
        peer,
        [
            address("/ip4/10.0.0.1/tcp/1"),
            address("/ip4/10.9.9.9/tcp/1"),
        ],
        now,
    );
    // Only addresses inside the first one's prefix join that entry; a
    // later reply naming another prefix adds a second entry instead of
    // moving or replacing the first.
    discovery.learn(&local, peer, [address("/ip4/10.7.7.7/tcp/1")], now);
    assert_eq!(discovery.len(), 2);
    // One entry per peer is dialed in a round.
    let due = discovery.due(|_| false, DIALS_PER_WALK, now);
    assert_eq!(due.len(), 1);
    let (target, addresses) = due[0].clone();
    assert_eq!(target.peer(), peer);
    // A failed dial forgets that entry only.
    let connection = ConnectionId::new_unchecked(7);
    discovery.dialing(connection, target);
    discovery.dial_ended(connection, true);
    assert_eq!(discovery.len(), 1);
    let remaining = discovery.due(|_| false, DIALS_PER_WALK, now);
    assert_eq!(remaining.len(), 1);
    assert_ne!(remaining[0].1, addresses);
}
