use super::{FactJob, enqueue_fact_groups, run_fact_worker};
use crate::metrics::NodeMetrics;
use crate::proving_budget::ProvingBudget;
use neutrin0_consensus_types::{BlockProofPublicInputs, history_proof::VkDigest};
use neutrin0_primitives::Hash;
use neutrin0_proof_system::{ProofError, ProofSystem};
use neutrin0_prover_chunk::facts::{FactRequest, MAX_FACTS};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::mpsc;

struct FactProbe {
    calls: mpsc::UnboundedSender<(VkDigest, Vec<FactRequest>)>,
}

impl ProofSystem for FactProbe {
    type BlockProof = Vec<u8>;
    type ChunkProof = Vec<u8>;

    fn prove_block(
        &self,
        _witness: &[u8],
        _inputs: &BlockProofPublicInputs,
        _prover: Hash,
    ) -> Result<Self::BlockProof, ProofError> {
        unreachable!("this fixture observes optional fact scheduling only")
    }

    fn verify_block(
        &self,
        _proof: &Self::BlockProof,
        _inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError> {
        unreachable!("this fixture does not verify block proofs")
    }

    fn preprove_facts(
        &self,
        program: &VkDigest,
        requests: &[FactRequest],
    ) -> Result<(), ProofError> {
        self.calls.send((*program, requests.to_vec())).unwrap();
        Ok(())
    }
}

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

#[tokio::test]
async fn fact_worker_waits_between_block_jobs_and_coalesces_without_mixing_programs() {
    let metrics = Arc::new(NodeMetrics::default());
    let budget = Arc::new(ProvingBudget::with_metrics(1, Arc::clone(&metrics)));
    let (sender, receiver) = mpsc::channel(8);
    let (calls, mut observed_calls) = mpsc::unbounded_channel();
    let first = request(vec![1]);
    let second = request(vec![2]);
    let other = request(vec![3]);
    // No native call holds a permit, but two producer jobs still need it.
    budget.set_block_backlog(2);
    enqueue_fact_groups(&sender, [1; 8], std::slice::from_ref(&first), &metrics);
    let worker = tokio::spawn(run_fact_worker(
        receiver,
        Arc::new(FactProbe { calls }),
        Arc::clone(&budget),
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), observed_calls.recv())
            .await
            .is_err()
    );
    enqueue_fact_groups(&sender, [1; 8], std::slice::from_ref(&second), &metrics);
    enqueue_fact_groups(&sender, [2; 8], std::slice::from_ref(&other), &metrics);
    // Finishing one job cannot admit facts ahead of the remaining block.
    budget.set_block_backlog(1);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), observed_calls.recv())
            .await
            .is_err()
    );
    budget.set_block_backlog(0);
    let timeout = Duration::from_secs(5);
    assert_eq!(
        tokio::time::timeout(timeout, observed_calls.recv())
            .await
            .unwrap(),
        Some(([1; 8], vec![first, second]))
    );
    assert_eq!(
        tokio::time::timeout(timeout, observed_calls.recv())
            .await
            .unwrap(),
        Some(([2; 8], vec![other]))
    );
    drop(sender);
    tokio::time::timeout(timeout, worker)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending(&metrics), (0, 0));
}
