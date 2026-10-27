//! Local CLI controls send typed requests without connecting to public RPC.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use neutrin0_rpc::management::{ManagementRequest, read_frame, write_frame};
use tokio::net::UnixListener;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let path = root.join(format!("neutrin0-cli-management-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_commands_dispatch_over_the_private_socket() {
    let directory = Directory::new();
    let socket = directory.0.join("node.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let commands = [
        (["node", "control-status"], ManagementRequest::Status),
        (
            ["validator", "pause-signing"],
            ManagementRequest::PauseSigning,
        ),
        (
            ["validator", "resume-signing"],
            ManagementRequest::ResumeSigning,
        ),
        (
            ["validator", "pause-production"],
            ManagementRequest::PauseProduction,
        ),
        (
            ["validator", "resume-production"],
            ManagementRequest::ResumeProduction,
        ),
        (["node", "shutdown"], ManagementRequest::Shutdown),
    ];
    for (command, expected) in commands {
        let path = socket.clone();
        let mut process = tokio::task::spawn_blocking(move || {
            std::process::Command::new(env!("CARGO_BIN_EXE_neutrin0-cli"))
                .args(command)
                .arg("--management-socket")
                .arg(path)
                .arg("--json")
                .env("NEUTRIN0_RPC_URL", "not-a-public-rpc-url")
                .output()
                .unwrap()
        });
        // Starting a freshly linked binary can take several seconds on macOS.
        // This is a process startup deadline; the client's I/O timeout stays ten seconds.
        let (mut stream, _) = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(30), listener.accept()) => {
                result.expect("CLI did not connect within its startup deadline").unwrap()
            }
            result = &mut process => {
                let output = result.unwrap();
                panic!("CLI exited before connecting: status={} stderr={}", output.status, String::from_utf8_lossy(&output.stderr));
            }
        };
        let request = read_frame(&mut stream, 4096).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<ManagementRequest>(&request).unwrap(),
            expected
        );
        let response = serde_json::json!({
            "result": "ok", "status": {
                "chain_id": 7, "chain_spec_hash": format!("0x{}", "01".repeat(32)),
                "validator_public_key": null, "validator_index": null, "membership": "no_key",
                "local_peer_id": null, "local_votes": [], "publish_queue": [],
                "signing_paused": expected == ManagementRequest::PauseSigning,
                "production_paused": expected == ManagementRequest::PauseProduction,
                "persistence_fault": false, "stopping": expected == ManagementRequest::Shutdown,
                "bootstrap_pending": false, "validator_active": false,
                "signing_quiet_until_slot": 0, "doppelganger": null, "head_height": 0,
            }
        });
        write_frame(&mut stream, &serde_json::to_vec(&response).unwrap())
            .await
            .unwrap();
        let output = process.await.unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["chain_id"], 7);
        assert_eq!(result["stopping"], expected == ManagementRequest::Shutdown);
    }
}

#[test]
fn local_controls_reject_public_rpc_and_missing_socket() {
    for args in [
        vec![
            "validator",
            "pause-signing",
            "--rpc",
            "http://localhost:9933",
            "--json",
        ],
        vec!["node", "shutdown", "--json"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_neutrin0-cli"))
            .args(args)
            .env_remove("NEUTRIN0_MANAGEMENT_SOCKET")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let result: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(result["error"]["kind"], "invalid_arguments");
    }
}
