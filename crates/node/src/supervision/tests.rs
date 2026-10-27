use super::*;
use tokio::sync::oneshot;

struct DropNotice(Option<oneshot::Sender<()>>);

impl Drop for DropNotice {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

#[tokio::test]
async fn critical_normal_return_is_an_error_with_the_task_name() {
    let tasks = TaskSupervisor::new();
    let _ = tasks.spawner().spawn_critical("network", async { Ok(()) });
    assert_eq!(
        tasks.next_failure().await,
        TaskFailure {
            name: "network",
            reason: "returned unexpectedly".into(),
        }
    );
}

#[tokio::test]
async fn critical_error_and_panic_are_observed() {
    let tasks = TaskSupervisor::new();
    let _ = tasks
        .spawner()
        .spawn_critical("sync", async { Err("backend unavailable".into()) });
    let failure = tasks.next_failure().await;
    assert_eq!(failure.name, "sync");
    assert_eq!(failure.reason, "backend unavailable");
    let _ = tasks.spawner().spawn_critical("history", async {
        panic!("test history worker panic");
    });
    let failure = tasks.next_failure().await;
    assert_eq!(failure.name, "history");
    assert!(failure.reason.contains("test history worker panic"));
}

#[tokio::test]
async fn finite_completion_is_allowed_but_finite_panic_is_observed() {
    let tasks = TaskSupervisor::new();
    let _ = tasks.spawner().spawn_job("evidence", async { Ok(()) });
    let _ = tasks.spawner().spawn_job("program-install", async {
        panic!("test program setup panic");
    });
    let failure = tasks.next_failure().await;
    assert_eq!(failure.name, "program-install");
    assert!(failure.reason.contains("test program setup panic"));
}

#[tokio::test]
async fn backend_registration_wakes_an_empty_supervisor() {
    let tasks = TaskSupervisor::new();
    let spawner = tasks.spawner();
    let registration = async move {
        tokio::task::yield_now().await;
        let _ = spawner.spawn_critical("facts", async { Ok(()) });
    };
    let (failure, ()) = tokio::join!(tasks.next_failure(), registration);
    assert_eq!(failure.name, "facts");
}

#[tokio::test]
async fn owner_drop_aborts_workers_even_when_backend_keeps_a_spawner() {
    let tasks = TaskSupervisor::new();
    let spawner = tasks.spawner();
    let (sender, dropped) = oneshot::channel();
    let notice = DropNotice(Some(sender));
    let _ = spawner.spawn_critical("history", async move {
        let _notice = notice;
        core::future::pending().await
    });
    drop(tasks);
    dropped.await.unwrap();
    assert!(
        spawner
            .spawn_job("late-program", async { Ok(()) })
            .is_none()
    );
}

#[tokio::test]
async fn shutdown_cancels_all_tasks_and_runs_service_cleanup_once() {
    let tasks = TaskSupervisor::new();
    let (sender, dropped) = oneshot::channel();
    let notice = DropNotice(Some(sender));
    let _ = tasks.spawner().spawn_critical("producer", async move {
        let _notice = notice;
        core::future::pending().await
    });
    let (stopped, cleaned) = oneshot::channel();
    tasks.on_shutdown(move || {
        let _ = stopped.send(());
    });
    tasks.shutdown().await;
    dropped.await.unwrap();
    cleaned.await.unwrap();
    tasks.shutdown().await;
}
