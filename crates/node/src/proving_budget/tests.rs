use std::{
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

use super::{ProofStage, ProvingBudget, ProvingPriority};

const fn stage(priority: ProvingPriority) -> ProofStage {
    match priority {
        ProvingPriority::Critical => ProofStage::Block,
        ProvingPriority::Normal => ProofStage::Fact,
    }
}

const TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn device_budget_serializes_actual_resource_and_orders_critical_work_first() {
    let metrics = Arc::new(crate::metrics::NodeMetrics::default());
    let budget = Arc::new(ProvingBudget::with_device(
        8,
        Arc::clone(&metrics),
        Some(43),
    ));
    budget.set_capacity(64);
    assert_eq!(budget.state.lock().unwrap().capacity, 1);
    let active = budget.acquire(ProofStage::Evidence);
    let evidence = budget.request(ProofStage::Evidence);
    let setup = budget.request(ProofStage::ProgramSetup);
    let block = budget.request(ProofStage::Block);
    let cancelled = budget.request(ProofStage::Chunk);
    drop(cancelled);
    let (entered, arrivals) = mpsc::channel();
    thread::scope(|scope| {
        for (id, request) in [(0, evidence), (1, setup), (2, block)] {
            let entered = entered.clone();
            scope.spawn(move || {
                let permit = request.wait();
                permit.run(|| entered.send(id).unwrap());
            });
        }
        drop(active);
        for expected in [2, 0, 1] {
            assert_eq!(arrivals.recv_timeout(TIMEOUT).unwrap(), expected);
        }
    });
    assert_eq!(
        metrics
            .proof_pipeline
            .budget
            .inflight(ProofStage::ProgramSetup),
        0
    );
    assert_eq!(metrics.proof_pipeline.budget.inflight(ProofStage::Block), 0);
}

#[test]
fn stale_block_or_chunk_wait_cancels_before_the_active_prover_returns() {
    use std::sync::atomic::{AtomicBool, Ordering};
    for device in [None, Some(44)] {
        let metrics = Arc::new(crate::metrics::NodeMetrics::default());
        let budget = Arc::new(ProvingBudget::with_device(1, Arc::clone(&metrics), device));
        let active = budget.acquire(ProofStage::Evidence);
        let stale = budget.request(ProofStage::Chunk);
        let needed = Arc::new(AtomicBool::new(true));
        let worker_needed = Arc::clone(&needed);
        let worker_budget = Arc::clone(&budget);
        let (checked, checks) = mpsc::channel();
        let (done, completion) = mpsc::channel();
        let worker = thread::spawn(move || {
            let permit = stale.wait_if(|| {
                assert!(worker_budget.state.try_lock().is_ok());
                let _ = checked.send(());
                worker_needed.load(Ordering::Acquire)
            });
            done.send(permit.is_none()).unwrap();
        });
        checks.recv_timeout(TIMEOUT).unwrap();
        needed.store(false, Ordering::Release);
        assert!(completion.recv_timeout(TIMEOUT).unwrap());
        worker.join().unwrap();
        assert_eq!(
            metrics.proof_pipeline.budget.inflight(ProofStage::Evidence),
            1
        );
        assert_eq!(metrics.proof_pipeline.budget.inflight(ProofStage::Chunk), 0);
        drop(active);
        let _fresh = budget.acquire(ProofStage::Block);
    }
}

#[test]
fn normal_native_observer_accounts_stage_waiters_and_calls_without_outer_permit() {
    use neutrin0_runtime_host::backend::SubmissionObserver;
    let metrics = Arc::new(crate::metrics::NodeMetrics::default());
    let observer = super::NativeStageObserver {
        metrics: Arc::clone(&metrics),
        stage: ProofStage::Fact,
    };
    observer.queued();
    let mut rendered = String::new();
    metrics.proof_pipeline.render(&mut rendered);
    assert!(rendered.contains("neutrin0_proving_waiters{stage=\"fact\",priority=\"normal\"} 1"));
    observer.admitted(Duration::from_millis(1));
    assert_eq!(metrics.proof_pipeline.budget.inflight(ProofStage::Fact), 1);
    observer.released();
    assert_eq!(metrics.proof_pipeline.budget.inflight(ProofStage::Fact), 0);
    observer.queued();
    observer.cancelled(Duration::from_millis(1));
    rendered.clear();
    metrics.proof_pipeline.render(&mut rendered);
    assert!(rendered.contains("neutrin0_proving_waiters{stage=\"fact\",priority=\"normal\"} 0"));
}

#[test]
fn cpu_normal_composite_releases_between_native_calls_for_critical_work() {
    use neutrin0_runtime_host::{ProgramProver, backend::SubmissionPriority};
    let metrics = Arc::new(crate::metrics::NodeMetrics::default());
    let budget = Arc::new(ProvingBudget::with_backend(
        1,
        Arc::clone(&metrics),
        None,
        true,
    ));
    let prover = sp1_sdk::blocking::ProverClient::builder().mock().build();
    let (order, received) = mpsc::channel();
    let mut workers = Vec::new();
    budget
        .prove(ProofStage::Fact, || {
            prover.submit(SubmissionPriority::Normal, || {
                assert_eq!(metrics.proof_pipeline.budget.inflight(ProofStage::Fact), 1);
                order.send(1).unwrap();
                let critical = budget.request(ProofStage::Block);
                let order = order.clone();
                workers.push(thread::spawn(move || {
                    let permit = critical.wait();
                    permit.run(|| order.send(2).unwrap());
                }));
                // Reentrant wrappers use this same capacity-one native lease.
                prover.submit(SubmissionPriority::Normal, || {});
            });
            prover.submit(SubmissionPriority::Normal, || order.send(3).unwrap());
            Ok::<_, ()>(())
        })
        .unwrap();
    for expected in [1, 2, 3] {
        assert_eq!(received.recv_timeout(TIMEOUT).unwrap(), expected);
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(metrics.proof_pipeline.budget.inflight(ProofStage::Fact), 0);
}

#[test]
fn cpu_setup_accounts_native_leaf_only_and_custom_backends_keep_outer_budget() {
    use neutrin0_runtime_host::{ProgramProver, backend::SubmissionPriority};
    let metrics = Arc::new(crate::metrics::NodeMetrics::default());
    let budget = Arc::new(ProvingBudget::with_backend(
        1,
        Arc::clone(&metrics),
        None,
        true,
    ));
    let prover = sp1_sdk::blocking::ProverClient::builder().mock().build();
    budget
        .setup(|| {
            assert_eq!(
                metrics
                    .proof_pipeline
                    .budget
                    .inflight(ProofStage::ProgramSetup),
                0
            );
            prover.submit(SubmissionPriority::Normal, || {
                assert_eq!(
                    metrics
                        .proof_pipeline
                        .budget
                        .inflight(ProofStage::ProgramSetup),
                    1
                );
            });
            Ok::<_, ()>(())
        })
        .unwrap();
    assert_eq!(
        metrics
            .proof_pipeline
            .budget
            .inflight(ProofStage::ProgramSetup),
        0
    );
    let custom = Arc::new(ProvingBudget::with_backend(
        1,
        Arc::clone(&metrics),
        None,
        false,
    ));
    custom
        .prove(ProofStage::Evidence, || {
            assert_eq!(
                metrics.proof_pipeline.budget.inflight(ProofStage::Evidence),
                1
            );
            Ok::<_, ()>(())
        })
        .unwrap();
    assert_eq!(
        metrics.proof_pipeline.budget.inflight(ProofStage::Evidence),
        0
    );
}

fn wait_for_queue(budget: &ProvingBudget, expected: [usize; 2]) {
    let deadline = Instant::now() + TIMEOUT;
    let mut state = budget.state.lock().unwrap();
    while core::array::from_fn(|index| state.waiting[index].len()) != expected {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "waiter did not enter proving queue");
        let (next, timed) = budget.changed.wait_timeout(state, remaining).unwrap();
        state = next;
        assert!(!timed.timed_out(), "waiter did not enter proving queue");
    }
    drop(state);
}

#[test]
fn queued_work_respects_priority_and_fifo() {
    let budget = Arc::new(ProvingBudget::new(1));
    let held = budget.acquire(ProofStage::Evidence);
    let (entered, arrival) = mpsc::channel();
    let mut workers = Vec::new();
    let submissions = [
        (ProvingPriority::Normal, [0, 1]),
        (ProvingPriority::Normal, [0, 2]),
        (ProvingPriority::Critical, [1, 2]),
        (ProvingPriority::Critical, [2, 2]),
    ];
    for (id, (priority, queued)) in submissions.into_iter().enumerate() {
        let worker_budget = Arc::clone(&budget);
        let entered = entered.clone();
        workers.push(thread::spawn(move || {
            let _permit = worker_budget.acquire(stage(priority));
            entered.send(id).unwrap();
        }));
        wait_for_queue(&budget, queued);
    }
    drop(held);
    for expected in [2, 3, 0, 1] {
        assert_eq!(arrival.recv_timeout(TIMEOUT).unwrap(), expected);
    }
    for worker in workers {
        worker.join().unwrap();
    }
}

#[test]
fn resizing_wakes_waiters_without_revoking_running_work() {
    let budget = Arc::new(ProvingBudget::new(1));
    let held = budget.acquire(ProofStage::Block);
    let (entered, arrival) = mpsc::channel();
    let worker_budget = Arc::clone(&budget);
    let worker = thread::spawn(move || {
        let permit = worker_budget.acquire(ProofStage::Fact);
        entered.send(permit).unwrap();
    });
    wait_for_queue(&budget, [0, 1]);
    budget.set_capacity(2);
    let second = arrival.recv_timeout(TIMEOUT).unwrap();
    budget.set_capacity(0);
    assert_eq!(budget.state.lock().unwrap().active, 2);
    assert_eq!(budget.state.lock().unwrap().capacity, 1);
    drop(second);
    drop(held);
    worker.join().unwrap();
    budget.set_capacity(usize::MAX);
    assert_eq!(budget.state.lock().unwrap().capacity, 64);
}

#[test]
fn unwinding_releases_the_slot() {
    let budget = Arc::new(ProvingBudget::new(1));
    let worker_budget = Arc::clone(&budget);
    assert!(
        thread::spawn(move || {
            let _permit = worker_budget.acquire(ProofStage::Block);
            panic!("failed proof");
        })
        .join()
        .is_err()
    );
    let _next = budget.acquire(ProofStage::Fact);
}

#[test]
fn cancelled_reservation_updates_wait_metrics_and_does_not_block_fifo() {
    use crate::metrics::NodeMetrics;
    let metrics = Arc::new(NodeMetrics::default());
    let budget = Arc::new(ProvingBudget::with_metrics(1, Arc::clone(&metrics)));
    let held = budget.acquire(ProofStage::Evidence);
    let cancelled = budget.request(ProofStage::Block);
    let next = budget.request(ProofStage::Chunk);
    let mut rendered = String::new();
    metrics.proof_pipeline.render(&mut rendered);
    assert!(rendered.contains("neutrin0_proving_waiters{stage=\"block\",priority=\"critical\"} 1"));
    assert_eq!(metrics.proof_pipeline.budget.inflight(ProofStage::Block), 0);
    drop(cancelled);
    drop(held);
    let permit = next.wait();
    rendered.clear();
    metrics.proof_pipeline.render(&mut rendered);
    assert!(rendered.contains(
        "neutrin0_proving_wait_total{stage=\"block\",priority=\"critical\",outcome=\"cancelled\"} 1"
    ));
    assert!(
        rendered.contains("neutrin0_proving_inflight{stage=\"chunk\",priority=\"critical\"} 1")
    );
    assert!(rendered.contains("neutrin0_proving_waiters{stage=\"block\",priority=\"critical\"} 0"));
    drop(permit);
    assert_eq!(budget.state.lock().unwrap().active, 0);
}

#[test]
fn panicking_native_call_releases_actual_running_and_stage_gauges() {
    use crate::metrics::NodeMetrics;
    let metrics = Arc::new(NodeMetrics::default());
    let budget = Arc::new(ProvingBudget::with_metrics(2, Arc::clone(&metrics)));
    assert!(
        std::panic::catch_unwind(|| {
            let _permit = budget.acquire(ProofStage::Block);
            assert_eq!(metrics.proof_pipeline.budget.inflight(ProofStage::Block), 1);
            panic!("native proving panic");
        })
        .is_err()
    );
    assert_eq!(metrics.proof_pipeline.budget.inflight(ProofStage::Block), 0);
    let mut rendered = String::new();
    metrics.proof_pipeline.render(&mut rendered);
    assert!(
        rendered.contains("neutrin0_proving_inflight{stage=\"block\",priority=\"critical\"} 0")
    );
    assert!(rendered.contains(
        "neutrin0_proving_wait_total{stage=\"block\",priority=\"critical\",outcome=\"admitted\"} 1"
    ));
    assert!(
        rendered.contains(
            "neutrin0_proving_wait_seconds_count{stage=\"block\",priority=\"critical\"} 1"
        )
    );
}
