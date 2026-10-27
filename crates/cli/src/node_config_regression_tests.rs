//! Node-config validation failures leave the output file untouched.

use super::*;
use crate::node_config_test_cases::FAILURE_CASES;
use std::fs;
use std::path::Path;

fn fixture_paths(name: &str) -> (PathBuf, PathBuf) {
    let dir = env::temp_dir().join(format!(
        "neutrin0-cli-node-config-{name}-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    let spec = dir.join("chain-spec.toml");
    fs::write(
        &spec,
        include_str!("../tests/fixtures/node_config/chain-spec.toml"),
    )
    .unwrap();
    (dir, spec)
}

fn command_options(spec: &Path, out: &Path, flags: &[&str]) -> Options {
    let mut args = vec![
        "--spec".to_owned(),
        spec.to_str().unwrap().to_owned(),
        "--out".to_owned(),
        out.to_str().unwrap().to_owned(),
    ];
    args.extend(flags.iter().map(|flag| (*flag).to_owned()));
    Options::parse(&args).unwrap()
}

#[test]
fn node_config_validation_failures_leave_output_untouched() {
    let (dir, spec) = fixture_paths("errors");
    for case in FAILURE_CASES {
        let out = dir.join(format!("{}.toml", case.name));
        let options = command_options(&spec, &out, case.flags);
        assert_eq!(
            node_config(&options),
            Err(case.error.to_owned()),
            "case {} with no output",
            case.name,
        );
        assert!(!out.exists(), "case {} created output", case.name);

        fs::write(&out, "sentinel\n").unwrap();
        assert_eq!(
            node_config(&options),
            Err(case.error.to_owned()),
            "case {} with existing output",
            case.name,
        );
        assert_eq!(
            fs::read(&out).unwrap(),
            b"sentinel\n",
            "case {} changed existing output",
            case.name,
        );
    }
    fs::remove_dir_all(dir).unwrap();
}
