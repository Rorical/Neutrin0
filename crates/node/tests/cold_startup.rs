//! A fresh node process authenticates built-in programs before opening RPC.

#![cfg(unix)]

use std::{
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime},
};

struct Process {
    child: Child,
    directory: PathBuf,
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.directory);
    }
}

#[test]
fn cold_evm_light_node_reaches_rpc_and_shuts_down() {
    let unique = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "neutrin0-cold-node-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&directory).unwrap();
    let proposer = neutrin0_consensus_engine::ProposerKey::from_ikm(&[8; 32], 0).unwrap();
    let spec = directory.join("chain.toml");
    let text = format!(
        "name = \"cold-start\"\nchain_id = 734211\n\
             genesis_time = {timestamp}\ngenesis_gas_limit = 1000000\n\
             [[validators]]\npubkey_hex = \"{key}\"\neffective_stake = \"32000000000000000000\"\n\
             withdrawal_credentials_hex = \"{owner}\"\npop_hex = \"{pop}\"\n\
             [[accounts]]\naddress_hex = \"{owner}\"\nbalance = 1000000000000000000\n",
        timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        key = hex::encode(proposer.public_key_bytes()),
        owner = hex::encode([8; 20]),
        pop = hex::encode(
            proposer
                .prove_registration(&neutrin0_primitives::runtime_account([8; 20]))
                .to_bytes()
        ),
    );
    // `neutrin0-cli genesis --write` pins the programs; this binary's are the
    // ones the spec names.
    let mut file = neutrin0_node::ChainSpecFile::from_toml_str(&text).unwrap();
    file.pin_embedded_programs().unwrap();
    fs::write(&spec, format!("{text}{}", file.programs_toml().unwrap())).unwrap();
    let config = directory.join("node.toml");
    fs::write(
        &config,
        format!(
            "chain_id = 734211\nrole = \"light-client\"\n\
             chain_spec_path = {spec:?}\ndata_dir = {data:?}\n\
             listen = [\"/ip4/127.0.0.1/tcp/0\"]\n\
             [rpc]\nlisten = \"127.0.0.1:0\"\n",
            data = directory.join("db"),
        ),
    )
    .unwrap();
    let log = directory.join("node.log");
    let stream = fs::File::create(&log).unwrap();
    let mut process = Process {
        child: Command::new(env!("CARGO_BIN_EXE_neutrin0-node"))
            .arg("--config")
            .arg(config)
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(stream.try_clone().unwrap()))
            .stderr(Stdio::from(stream))
            .spawn()
            .unwrap(),
        directory,
    };
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let text = fs::read_to_string(&log).unwrap();
        assert!(process.child.try_wait().unwrap().is_none(), "{text}");
        if text.contains("rpc server listening") {
            break;
        }
        assert!(Instant::now() < deadline, "startup timed out: {text}");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        Command::new("kill")
            .args(["-TERM", &process.child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = process.child.try_wait().unwrap() {
            assert!(status.success(), "{}", fs::read_to_string(&log).unwrap());
            break;
        }
        assert!(Instant::now() < deadline, "shutdown timed out");
        std::thread::sleep(Duration::from_millis(20));
    }
}
