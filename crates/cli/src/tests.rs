//! Option parser and node-config command checks.

use super::*;
use std::fs;
use std::path::Path;

#[test]
fn options_parse_flags_values_and_repeats() {
    let args: Vec<String> = ["--out", "dir", "--write", "--listen", "a", "--listen", "b"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let opts = Options::parse(&args).unwrap();
    assert_eq!(opts.get("out"), Some("dir"));
    assert!(opts.has("write"));
    assert_eq!(opts.all("listen"), vec!["a", "b"]);
    assert!(Options::parse(&["stray".to_owned()]).is_err());
}

#[test]
fn generated_node_config_parses() {
    let dir = env::temp_dir().join(format!("neutrin0-cli-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let spec = dir.join("chain-spec.toml");
    fs::write(
        &spec,
        "name = \"t\"\nchain_id = 9\ngenesis_time = 0\ngenesis_gas_limit = 1\n[[validators]]\npubkey_hex = \"00\"\npop_hex = \"00\"\neffective_stake = 1\n",
    )
    .unwrap();
    let out = dir.join("config.toml");
    let args: Vec<String> = [
        "--spec",
        spec.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--rpc",
        "127.0.0.1:9933",
        "--ikm-path",
        "validator.ikm",
        "--listen",
        "/ip4/0.0.0.0/tcp/30303",
        "--metrics",
        "127.0.0.1:9615",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    node_config(&Options::parse(&args).unwrap()).unwrap();
    let cfg: neutrin0_node::NodeConfig =
        toml::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(cfg.chain_id, 9);
    assert_eq!(
        cfg.proposer_ikm_path.as_deref(),
        Some(Path::new("validator.ikm"))
    );
    assert!(cfg.rpc.is_some());
    assert_eq!(cfg.metrics.unwrap().listen, "127.0.0.1:9615");
    let _ = fs::remove_dir_all(&dir);
}
