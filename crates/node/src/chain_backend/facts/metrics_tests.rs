use super::{FactJob, enqueue_fact_groups};
use crate::metrics::NodeMetrics;
use neutrin0_prover_chunk::facts::{FactRequest, MAX_FACTS};
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;

fn request(message: Vec<u8>) -> FactRequest {
    FactRequest::Signature {
        key: [1; 48],
        message,
        signature: [2; 96],
        possession: false,
    }
}

fn pending(metrics: &NodeMetrics) -> (u64, u64) {
    let mut rendered = String::new();
    metrics.proof_pipeline.render(&mut rendered);
    let read = |name: &str| {
        rendered
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    };
    (
        read("neutrin0_fact_queue_pending "),
        read("neutrin0_fact_queue_items_pending "),
    )
}

#[test]
fn full_queue_counts_all_discarded_groups_and_receiver_drop_releases_occupancy() {
    let metrics = NodeMetrics::default();
    let (sender, receiver) = mpsc::channel::<FactJob>(8);
    let requests = vec![request(vec![3]); MAX_FACTS * 11];
    enqueue_fact_groups(&sender, [1; 8], &requests, &metrics);
    assert_eq!(
        metrics
            .proof_pipeline
            .fact_dropped_full
            .load(Ordering::Relaxed),
        3
    );
    assert_eq!(pending(&metrics), (8, 512));
    drop(receiver);
    assert_eq!(pending(&metrics), (0, 0));
    enqueue_fact_groups(&sender, [1; 8], &requests, &metrics);
    assert_eq!(
        metrics
            .proof_pipeline
            .fact_dropped_closed
            .load(Ordering::Relaxed),
        11
    );
    assert_eq!(pending(&metrics), (0, 0));
}

#[test]
fn oversize_fact_group_is_discarded_without_leaving_a_backlog() {
    let metrics = NodeMetrics::default();
    let (sender, mut receiver) = mpsc::channel::<FactJob>(8);
    enqueue_fact_groups(
        &sender,
        [1; 8],
        &[request(vec![0; 2 * 1024 * 1024])],
        &metrics,
    );
    assert_eq!(
        metrics
            .proof_pipeline
            .fact_dropped_oversize
            .load(Ordering::Relaxed),
        1
    );
    assert!(receiver.try_recv().is_err());
    assert_eq!(pending(&metrics), (0, 0));
}
