use super::*;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicUsize, Ordering},
};

#[tokio::test]
async fn peer_receipt_removes_waiting_jobs_without_aborting_active_work() {
    let mut queue = ProofQueue::new(1, 2);
    queue.push([1; 32], 1);
    queue.push([2; 32], 2);
    let (started, starts) = std::sync::mpsc::channel();
    let (release, releases) = std::sync::mpsc::channel();
    let releases = Arc::new(std::sync::Mutex::new(releases));
    queue.start(move |job| {
        started.send(job).unwrap();
        releases.lock().unwrap().recv().unwrap();
        job
    });
    tokio::task::spawn_blocking(move || {
        starts
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
    })
    .await
    .unwrap();
    queue.retain_pending(|_| false);
    assert_eq!(queue.pending(), 0);
    assert_eq!(queue.running(), 1);
    assert!(queue.contains(&[1; 32]));
    assert!(!queue.contains(&[2; 32]));
    release.send(()).unwrap();
    let (hash, result) = queue.completed().await;
    assert_eq!(hash, [1; 32]);
    assert_eq!(result.unwrap(), 1);
}

#[tokio::test]
async fn bounds_concurrency_deduplicates_and_releases_after_panic() {
    let barrier = Arc::new(Barrier::new(3));
    let count = Arc::new(AtomicUsize::new(0));
    let mut queue = ProofQueue::new(2, 3);
    assert!(queue.push([1; 32], 1));
    assert!(!queue.push([1; 32], 1));
    assert!(queue.push([2; 32], 2));
    assert!(queue.push([3; 32], 3));
    assert!(!queue.push([4; 32], 4));
    let work = {
        let barrier = barrier.clone();
        let count = count.clone();
        move |job| {
            count.fetch_add(1, Ordering::SeqCst);
            if job < 3 {
                barrier.wait();
            }
            assert!(job != 2, "simulated prover panic");
            job
        }
    };
    queue.start(work.clone());
    tokio::task::spawn_blocking(move || barrier.wait())
        .await
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
    let first = queue.completed().await;
    let second = queue.completed().await;
    assert_eq!(
        usize::from(first.1.is_err()) + usize::from(second.1.is_err()),
        1
    );
    assert_eq!(queue.available(), 2);
    assert!(queue.push([2; 32], 4));
    queue.start(work);
    assert!(queue.completed().await.1.is_ok());
    assert!(queue.completed().await.1.is_ok());
    assert_eq!(queue.available(), 3);
    assert!(queue.push([5; 32], 5));
    assert!(queue.push([6; 32], 6));
    queue.retain_pending(|hash| *hash == [6; 32]);
    assert!(!queue.contains(&[5; 32]));
    assert!(queue.contains(&[6; 32]));
    assert_eq!(queue.available(), 2);
    queue.start(|job| job);
    assert_eq!(queue.completed().await.0, [6; 32]);
    assert_eq!(queue.available(), 3);
}
