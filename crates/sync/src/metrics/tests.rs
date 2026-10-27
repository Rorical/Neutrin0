use super::*;

#[test]
fn phases_expose_targets_and_reset_without_dynamic_labels() {
    let metrics = SyncMetrics::default();
    metrics.publish_phase(metrics.publish_fsm(&SyncState::HistoryFetch {
        local_finalized_index: 10,
        target_index: 20,
        in_flight: true,
    }));
    let operator = metrics.operator_progress();
    assert_eq!(operator.phase, "history_fetch");
    assert_eq!(operator.full_chunk_target_height, None);
    let mut body = String::new();
    metrics.render(&mut body);
    assert!(body.contains("neutrin0_sync_phase{phase=\"history_fetch\"} 1"));
    assert!(body.contains("neutrin0_sync_fsm_cursor{unit=\"chunks\"} 10"));
    assert!(body.contains("neutrin0_sync_fsm_remaining{unit=\"chunks\"} 10"));
    metrics.publish_phase(metrics.publish_fsm(&SyncState::Following));
    let operator = metrics.operator_progress();
    assert_eq!(operator.phase, "following");
    assert_eq!(operator.target_height, 0);
    body.clear();
    metrics.render(&mut body);
    assert!(body.contains("neutrin0_sync_fsm_target{unit=\"height\"} 0"));
    assert!(!body.contains("height="));
    assert!(!body.contains("peer="));
    assert!(!body.contains("hash="));
}

#[test]
fn bootstrap_failures_and_installs_count_only_observed_events() {
    let metrics = SyncMetrics::default();
    metrics.bootstrap_request(BootstrapKind::History);
    metrics.bootstrap_result::<()>(
        BootstrapKind::History,
        &Err(SyncBackendError::Rejected(
            "peer controlled text".to_owned(),
        )),
    );
    metrics.bootstrap_request(BootstrapKind::State);
    metrics.bootstrap_result(BootstrapKind::State, &Ok(()));
    metrics.bootstrap_pending(3);
    metrics.bootstrap_state_entries(2);
    metrics.bootstrap_installed();
    let mut body = String::new();
    metrics.render(&mut body);
    assert!(body.contains(
        "neutrin0_sync_bootstrap_results_total{kind=\"history\",outcome=\"rejected\"} 1"
    ));
    assert!(
        body.contains("neutrin0_sync_bootstrap_results_total{kind=\"state\",outcome=\"ok\"} 1")
    );
    assert!(body.contains("neutrin0_sync_bootstrap_pending_items 0"));
    assert!(body.contains("neutrin0_sync_bootstrap_state_entries_accepted_total 2"));
    assert!(body.contains("neutrin0_sync_bootstrap_installs_total 1"));
    assert!(!body.contains("peer controlled text"));
    body.clear();
    metrics.render(&mut body);
    assert!(body.contains("neutrin0_sync_bootstrap_installs_total 1"));
}

#[test]
fn bootstrap_phase_takes_priority_and_full_chunk_cursor_is_bounded() {
    let metrics = SyncMetrics::default();
    let fsm = metrics.publish_fsm(&SyncState::Following);
    metrics.publish_full_chunk(true, true, [10, 2], 64);
    metrics.publish_bootstrap(true, true);
    metrics.publish_phase(Phase::select(
        fsm,
        Some(BootstrapKind::State),
        true,
        Some(true),
    ));
    let mut body = String::new();
    metrics.render(&mut body);
    assert!(body.contains("neutrin0_sync_phase{phase=\"bootstrap_state\"} 1"));
    assert!(body.contains("neutrin0_sync_phase{phase=\"full_chunk\"} 0"));
    assert!(body.contains("neutrin0_sync_full_chunk_cursor{kind=\"next_block\"} 10"));
    assert!(body.contains("neutrin0_sync_full_chunk_cursor{kind=\"chunk_id\"} 2"));
}
#[test]
fn progress_and_targets_have_explicit_availability_in_all_modes() {
    let metrics = SyncMetrics::default();
    let progress = LocalProgress {
        head_height: 9,
        ..LocalProgress::default()
    };
    metrics.publish_non_full_progress(&progress);
    let mut body = String::new();
    metrics.render(&mut body);
    assert!(body.contains("neutrin0_sync_progress_available 1"));
    assert!(body.contains("neutrin0_sync_full_chunk_target_available 0"));
    assert!(body.contains("neutrin0_sync_fsm_progress{kind=\"head_height\"} 9"));
    assert!(!body.contains("neutrin0_sync_full_chunk_consensus_target{"));

    let target = ConsensusSyncTarget {
        chunk_id: 1,
        start_height: 3,
        end_height: 4,
    };
    metrics.publish_full_availability(true, Some(&target));
    body.clear();
    metrics.render(&mut body);
    assert!(body.contains("neutrin0_sync_full_chunk_target_available 1"));
    assert!(body.contains("neutrin0_sync_full_chunk_consensus_target{field=\"end_height\"} 4"));

    // Ok(None) is unknown without inventing a query failure.
    metrics.publish_full_availability(true, None);
    body.clear();
    metrics.render(&mut body);
    assert!(body.contains("neutrin0_sync_progress_available 1"));
    assert!(body.contains("neutrin0_sync_full_chunk_target_available 0"));
    assert!(
        body.contains("neutrin0_sync_observation_failures_total{operation=\"consensus_target\"} 0")
    );
    assert!(!body.contains("neutrin0_sync_full_chunk_target_height "));

    // A failed progress query never publishes the old progress as current.
    metrics.observation_error(Observation::LocalProgress);
    metrics.publish_full_availability(false, Some(&target));
    body.clear();
    metrics.render(&mut body);
    assert!(body.contains("neutrin0_sync_progress_available 0"));
    assert!(body.contains("neutrin0_sync_full_chunk_target_available 1"));
    assert!(!body.contains("neutrin0_sync_fsm_progress{"));
    metrics.publish_non_full_progress(&progress);
    body.clear();
    metrics.render(&mut body);
    assert!(body.contains("neutrin0_sync_progress_available 1"));
    assert!(body.contains("neutrin0_sync_full_chunk_target_available 0"));
}
