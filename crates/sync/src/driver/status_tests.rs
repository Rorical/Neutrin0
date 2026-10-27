use super::*;

fn peer() -> neutrin0_network::PeerId {
    neutrin0_network::PeerId::from(
        neutrin0_network::libp2p::identity::Keypair::generate_ed25519().public(),
    )
}

#[test]
fn ahead_hints_are_debounced_per_provider_and_bounded_across_providers() {
    let mut hints = AheadHints::default();
    let start = tokio::time::Instant::now();
    let source = peer();
    assert!(hints.allow(source, start));
    assert!(!hints.allow(source, start + Duration::from_secs(1)));
    for _ in 0..3 {
        assert!(hints.allow(peer(), start));
    }
    assert!(!hints.allow(peer(), start + Duration::from_secs(4)));
    assert_eq!(hints.peers.len(), 4);
    assert!(hints.allow(source, start + RETRY_INTERVAL));
    assert_eq!(hints.peers.len(), 1);
    assert_eq!(hints.count, 1);
}

#[test]
fn ahead_hint_identity_cache_never_grows_past_its_bound() {
    let start = tokio::time::Instant::now();
    let mut hints = AheadHints::default();
    for _ in 0..256 {
        hints.peers.insert(peer(), start);
    }
    assert!(!hints.allow(peer(), start));
    assert_eq!(hints.peers.len(), 256);
    assert!(hints.allow(peer(), start + RETRY_INTERVAL));
    assert_eq!(hints.peers.len(), 1);
}

#[test]
fn default_status_reports_no_peers_and_syncing() {
    let status = SyncStatus::default();
    assert_eq!(status.peer_count(), 0);
    assert!(status.is_syncing());
    assert!(status.awaiting_first_peer());
}

#[test]
fn publish_shares_state_across_clones() {
    let status = SyncStatus::default();
    let observer = status.clone();
    status.publish(3, &SyncState::Following);
    assert_eq!(observer.peer_count(), 3);
    assert!(!observer.is_syncing());
    assert!(!observer.awaiting_first_peer());

    status.publish(0, &SyncState::Init);
    assert_eq!(observer.peer_count(), 0);
    assert!(observer.is_syncing());
    assert!(observer.awaiting_first_peer());
}

#[test]
fn known_backfill_or_stalled_state_is_not_awaiting_first_peer() {
    let status = SyncStatus::default();
    for state in [
        SyncState::HistoryFetch {
            local_finalized_index: 0,
            target_index: 9,
            in_flight: false,
        },
        SyncState::Stalled {
            reason: neutrin0_network::sync::SyncStallReason::HistoryConflict,
        },
    ] {
        status.publish(0, &state);
        assert!(status.is_syncing());
        assert!(!status.awaiting_first_peer());
    }
}
