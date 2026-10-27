//! Cold command-line genesis initialization must not nest Tokio runtimes,
//! and the binary names the programs it pins as a hard fork's successor.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::SystemTime,
};

struct Directory(PathBuf);

impl Directory {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = Self(
            std::env::temp_dir().join(format!("neutrin0-{name}-{}-{unique}", std::process::id())),
        );
        fs::create_dir(&directory.0).unwrap();
        directory
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Write a one-validator specification into `directory` and pin it with
/// `genesis --write`.
fn written_spec(directory: &Path) -> PathBuf {
    let proposer = neutrin0_consensus_engine::ProposerKey::from_ikm(&[7; 32], 0).unwrap();
    let spec = directory.join("chain.toml");
    fs::write(
        &spec,
        format!(
            "name = \"genesis-cli\"\nchain_id = 734210\n\
             genesis_time = 0\ngenesis_gas_limit = 1000000\n\
             [[validators]]\npubkey_hex = \"{}\"\neffective_stake = \"32000000000000000000\"\n\
             withdrawal_credentials_hex = \"{owner}\"\npop_hex = \"{pop}\"\n\
             [[accounts]]\naddress_hex = \"{owner}\"\nbalance = 1000000000000000000\n",
            hex::encode(proposer.public_key_bytes()),
            owner = hex::encode([7; 20]),
            pop = hex::encode(
                proposer
                    .prove_registration(&neutrin0_primitives::runtime_account([7; 20]))
                    .to_bytes()
            ),
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_neutrin0-cli"))
        .args(["genesis", "--spec"])
        .arg(&spec)
        .arg("--write")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    spec
}

#[test]
fn evm_genesis_command_authenticates_programs_and_pins_root() {
    let directory = Directory::new("genesis-cli");
    let spec = written_spec(&directory.0);
    let file = neutrin0_node::ChainSpecFile::load_from_path(&spec).unwrap();
    let chain = file.to_chain_spec().unwrap();
    assert_eq!(
        file.genesis_state_root_hex.as_deref(),
        Some(hex::encode(chain.genesis_state_root).as_str())
    );
    assert!(chain.genesis_execution.is_complete());
}

/// `fork programs` prints the commitment of the programs this binary pins as
/// a hard fork's successor, which a fork proposal names.
#[test]
fn fork_programs_command_prints_the_successor_commitment() {
    let directory = Directory::new("fork-cli");
    let spec = written_spec(&directory.0);
    let pinned = neutrin0_node::ChainSpecFile::load_from_path(&spec)
        .unwrap()
        .to_chain_spec()
        .unwrap()
        .pinned_programs();
    let output = Command::new(env!("CARGO_BIN_EXE_neutrin0-cli"))
        .args(["fork", "programs", "--spec"])
        .arg(&spec)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(printed["successor"], hex::encode(pinned.commitment()));
    assert!(
        printed["programs"]
            .as_str()
            .unwrap()
            .starts_with("[programs]")
    );
}
