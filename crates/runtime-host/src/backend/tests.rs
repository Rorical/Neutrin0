#[cfg(feature = "cuda")]
use super::cuda::CudaGates;
use super::*;
use sp1_sdk::{HashableKey, ProvingKey, blocking::ProverClient};
use std::collections::VecDeque;

#[cfg(feature = "cuda")]
#[test]
fn cuda_setup_attempt_budget_never_refunds_failed_attempts() {
    let mut gates = CudaGates::default();
    for _ in 0..MAX_CUDA_SETUP_ATTEMPTS {
        gates.reserve_setup(0).unwrap();
        // No successful key is required, and dropping one cannot refund an
        // attempted remote setup whose asynchronous cleanup is unconfirmed.
    }
    assert!(gates.reserve_setup(0).is_err());
    assert_eq!(gates.setup_attempts[&0], MAX_CUDA_SETUP_ATTEMPTS);
    assert!(gates.reserve_setup(1).is_ok());
}

#[test]
fn native_gate_prioritizes_critical_over_setup_fifo() {
    let gate = Arc::new(SubmissionGate::default());
    let active = gate.acquire(SubmissionPriority::Normal);
    let requests = [
        SubmissionPriority::Normal,
        SubmissionPriority::Normal,
        SubmissionPriority::Critical,
        SubmissionPriority::Critical,
    ]
    .map(|priority| gate.request(priority));
    let cancelled = gate.request(SubmissionPriority::Critical);
    drop(cancelled);
    let (sent, received) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        for (index, request) in requests.into_iter().enumerate() {
            let sent = sent.clone();
            scope.spawn(move || {
                let guard = request.wait();
                guard.run(|| sent.send((index, submission_priority())).unwrap());
            });
        }
        drop(active);
        for (index, priority) in [
            (2, SubmissionPriority::Critical),
            (3, SubmissionPriority::Critical),
            (0, SubmissionPriority::Normal),
            (1, SubmissionPriority::Normal),
        ] {
            assert_eq!(
                received
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap(),
                (index, priority)
            );
        }
    });
    assert!(!gate.state.lock().unwrap().active);
}

#[test]
fn native_reservations_reenter_only_the_same_device_and_restore_on_panic() {
    let first = cuda_submission_gate(41).unwrap();
    let second = cuda_submission_gate(42).unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    let guard = first.acquire(SubmissionPriority::Critical);
    let other = second.acquire(SubmissionPriority::Normal);
    guard.run(|| {
        // This would deadlock if the node's reservation were reacquired.
        submit_serial(41, SubmissionPriority::Normal, || {
            assert_eq!(submission_priority(), SubmissionPriority::Critical);
        });
        let reserved = RESERVED.with(Cell::get);
        other.run(|| {
            assert_ne!(RESERVED.with(Cell::get), reserved);
            assert_eq!(submission_priority(), SubmissionPriority::Normal);
        });
        assert_eq!(RESERVED.with(Cell::get), reserved);
    });
    assert_eq!(RESERVED.with(Cell::get), None);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            guard.run(|| panic!("native submission failure"));
        }))
        .is_err()
    );
    assert_eq!(RESERVED.with(Cell::get), None);
    drop(guard);
    drop(other);
    let _next = first.acquire(SubmissionPriority::Normal);
}

#[test]
fn stale_queued_submission_cancels_while_the_running_call_keeps_its_gate() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let gate = Arc::new(SubmissionGate::default());
    let active = gate.acquire(SubmissionPriority::Critical);
    let request = gate.request(SubmissionPriority::Critical);
    let needed = Arc::new(AtomicBool::new(true));
    let (checked, checks) = std::sync::mpsc::channel();
    let (completed, completion) = std::sync::mpsc::channel();
    let worker_gate = Arc::clone(&gate);
    let worker_needed = Arc::clone(&needed);
    let worker = std::thread::spawn(move || {
        let result = request.wait_if(|| {
            assert!(
                worker_gate.state.try_lock().is_ok(),
                "readiness ran under gate lock"
            );
            let _ = checked.send(());
            worker_needed.load(Ordering::Acquire)
        });
        completed.send(result.is_none()).unwrap();
    });
    checks
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    needed.store(false, Ordering::Release);
    assert!(
        completion
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
    );
    worker.join().unwrap();
    let state = gate.state.lock().unwrap();
    assert!(state.active, "cancellation revoked admitted work");
    assert!(state.waiting.iter().all(VecDeque::is_empty));
    drop(state);
    drop(active);
    let _next = gate.acquire(SubmissionPriority::Normal);
}

#[test]
fn reservation_on_one_device_does_not_bypass_another_devices_active_call() {
    let first = cuda_submission_gate(45).unwrap();
    let second = cuda_submission_gate(46).unwrap();
    let first_active = first.acquire(SubmissionPriority::Critical);
    let second_active = second.acquire(SubmissionPriority::Normal);
    let (completed, completion) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        first_active.run(|| {
            submit_serial(46, SubmissionPriority::Critical, || {
                completed.send(()).unwrap();
            });
        });
    });
    let mut state = second.state.lock().unwrap();
    while state.waiting[SubmissionPriority::Critical.index()].is_empty() {
        let (next, timed) = second
            .changed
            .wait_timeout(state, std::time::Duration::from_secs(5))
            .unwrap();
        state = next;
        assert!(
            !timed.timed_out(),
            "second-device admission bypassed its gate"
        );
    }
    assert!(completion.try_recv().is_err());
    drop(state);
    drop(second_active);
    completion
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    worker.join().unwrap();
}

#[test]
fn composite_metrics_count_each_native_call_once_and_release_after_panic() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[derive(Default)]
    struct Observer {
        queued: AtomicUsize,
        admitted: AtomicUsize,
        released: AtomicUsize,
    }
    impl SubmissionObserver for Observer {
        fn queued(&self) {
            self.queued.fetch_add(1, Ordering::Relaxed);
        }
        fn admitted(&self, _: Duration) {
            self.admitted.fetch_add(1, Ordering::Relaxed);
        }
        fn released(&self) {
            self.released.fetch_add(1, Ordering::Relaxed);
        }
        fn cancelled(&self, _: Duration) {
            panic!("unexpected queue cancellation");
        }
    }
    let observer = Arc::new(Observer::default());
    with_submission_observer(observer.clone(), || {
        submit_serial(47, SubmissionPriority::Normal, || {
            submit_serial(47, SubmissionPriority::Normal, || {});
        });
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                submit_serial(47, SubmissionPriority::Normal, || panic!("native failure"));
            }))
            .is_err()
        );
    });
    assert_eq!(observer.queued.load(Ordering::Relaxed), 2);
    assert_eq!(observer.admitted.load(Ordering::Relaxed), 2);
    assert_eq!(observer.released.load(Ordering::Relaxed), 2);
    assert!(OBSERVER.with(|value| value.borrow().is_none()));
}

#[test]
fn cached_program_keys_match_local_verification_for_all_stages() {
    let prover = ProverClient::builder().mock().build();
    let verifier = ProverClient::builder().light().build();
    let mut digests = std::collections::BTreeSet::new();
    for elf in [
        crate::EVM_GUEST_ELF,
        crate::EVIDENCE_GUEST_ELF,
        crate::FACT_GUEST_ELF,
        crate::CONSENSUS_CHUNK_GUEST_ELF,
    ] {
        let key = prover.setup_program(elf.clone()).unwrap();
        let verifier_key = verifier.setup(elf.clone()).unwrap();
        assert_eq!(&**key.elf(), &*elf);
        assert_eq!(
            key.verifying_key().hash_u32(),
            verifier_key.verifying_key().hash_u32()
        );
        assert!(
            digests.insert(key.verifying_key().hash_u32()),
            "program identities must be distinct"
        );
    }
}

#[cfg(all(
    feature = "cuda",
    not(all(target_os = "linux", target_arch = "x86_64"))
))]
#[test]
fn cuda_factory_rejects_unsupported_platform_before_sdk_startup() {
    let Err(error) = cuda_prover(0) else {
        panic!("CUDA initialized on unsupported host");
    };
    assert!(error.to_string().contains("Linux x86-64"));
}

#[cfg(all(feature = "cuda", target_os = "linux", target_arch = "x86_64"))]
#[test]
fn cuda_factory_requires_runtime_before_sdk_startup() {
    let Err(error) = cuda_prover(0) else {
        panic!("CUDA initialized without Tokio runtime");
    };
    assert!(error.to_string().contains("Tokio runtime"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let _guard = runtime.enter();
    let Err(error) = cuda_prover(0) else {
        panic!("CUDA initialized with current-thread runtime");
    };
    assert!(error.to_string().contains("multithreaded Tokio runtime"));
}
