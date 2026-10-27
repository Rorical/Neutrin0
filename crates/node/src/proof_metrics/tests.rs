use super::{ProofMetrics, ProofStage};
use std::sync::atomic::Ordering;

#[test]
fn backlog_guards_release_on_drop_and_unwind() {
    let metrics = ProofMetrics::default();
    let first = metrics.fact_backlog.track(64);
    let second = metrics.fact_backlog.track(7);
    assert_eq!(metrics.fact_backlog.0.jobs.load(Ordering::Relaxed), 2);
    assert_eq!(metrics.fact_backlog.0.items.load(Ordering::Relaxed), 71);
    drop(first);
    assert_eq!(metrics.fact_backlog.0.items.load(Ordering::Relaxed), 7);
    let result = std::panic::catch_unwind(|| {
        let _owned = second;
        panic!("queue consumer panic");
    });
    assert!(result.is_err());
    assert_eq!(metrics.fact_backlog.0.jobs.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.fact_backlog.0.items.load(Ordering::Relaxed), 0);
}

#[test]
fn coverage_distinguishes_no_success_from_success_without_checks() {
    let metrics = ProofMetrics::default();
    assert_eq!(metrics.fact_coverage(), None);
    metrics.set_fact_coverage(0, 0);
    assert_eq!(metrics.fact_coverage(), Some((0, 0)));
}

#[test]
fn exposition_has_all_fixed_stage_and_outcome_labels() {
    let metrics = ProofMetrics::default();
    metrics.evidence_outcome(neutrin0_sync::EvidenceProofAcceptance::Rejected);
    metrics.local_evidence_outcome(neutrin0_sync::EvidenceProofAcceptance::Accepted, true);
    let mut rendered = String::new();
    metrics.render(&mut rendered);
    for stage in ProofStage::ALL {
        assert!(rendered.contains(&format!(
            "neutrin0_proving_inflight{{stage=\"{}\",priority=\"{}\"}} 0",
            stage.label(),
            stage.priority_label()
        )));
    }
    assert!(rendered.contains("neutrin0_evidence_report_import_total{outcome=\"rejected\"} 1"));
    assert!(rendered.contains("neutrin0_evidence_local_install_total{outcome=\"inserted\"} 1"));
}
