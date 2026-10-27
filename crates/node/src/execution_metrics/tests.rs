use std::sync::Arc;

use neutrin0_proof_system::ErasedBlockExecutor;
use neutrin0_trie::{Poseidon2Hasher, Trie};

use super::*;
use crate::metrics::NodeMetrics;
#[test]
fn repeated_finality_notifications_do_not_duplicate_latency() {
    let metrics = ExecutionMetrics::default();
    metrics.opened(4, None);
    metrics.opened(4, None);
    metrics.finalized(4);
    metrics.finalized(4);
    let mut out = String::new();
    metrics.render(&mut out);
    assert!(out.contains("neutrin0_bft_finalization_seconds_count 1"));
    assert!(out.contains("neutrin0_chunk_finality_lag_seconds_count 0"));
}
#[test]
fn certificate_lag_is_recorded_once_against_the_tail_slot() {
    let metrics = ExecutionMetrics::default();
    // A slot that ended long ago: the certificate counts as stalled.
    metrics.opened(7, Some((0, 1)));
    let lag = metrics.certified(7).expect("first certificate");
    assert!(
        lag.stall
            .is_some_and(|stall| stall > Duration::from_secs(1))
    );
    assert!(metrics.certified(7).is_none());
    assert!(metrics.certified(8).is_none());
    metrics.finalized(7);
    let mut out = String::new();
    metrics.render(&mut out);
    assert!(out.contains("neutrin0_chunk_tail_ready_seconds_count 1"));
    assert!(out.contains("neutrin0_bft_certificate_seconds_count 1"));
    assert!(out.contains("neutrin0_chunk_certificate_lag_seconds_count 1"));
    assert!(out.contains("neutrin0_chunk_certificate_stall_total{outcome=\"failed\"} 1"));
    assert!(out.contains("neutrin0_chunk_finality_lag_seconds_count 1"));
}
#[test]
fn runtime_traps_are_observed_and_still_propagate() {
    let metrics = Arc::new(NodeMetrics::default());
    let executor = MeteredExecutor::new(
        neutrin0_proof_system::UnsupportedExecutor,
        Arc::clone(&metrics),
    );
    let result = executor.validate_tx(&[], 1, 100, [0; 32], &Trie::<Poseidon2Hasher>::new());
    assert!(result.is_err());
    let mut out = String::new();
    metrics.execution.render(&mut out);
    assert!(out.contains("neutrin0_transaction_validation_total{outcome=\"failed\"} 1"));
}
