//! Golden output and validation contracts for the pure renderer.

use super::*;
use crate::node_config_test_cases::{FAILURE_CASES, SUCCESS_CASES};

fn chain_spec() -> ChainSpecFile {
    toml::from_str(include_str!(
        "../../tests/fixtures/node_config/chain-spec.toml"
    ))
    .unwrap()
}

#[test]
fn management_template_encodes_an_absolute_socket_path() {
    let socket = "/tmp/node \"operator\"/control.sock";
    let opts = options(&["--management-socket", socket]);
    let text = render(&opts, Path::new("chain-spec.toml"), &chain_spec()).unwrap();
    let config: neutrin0_node::NodeConfig = toml::from_str(&text).unwrap();
    assert_eq!(config.management.unwrap().socket, Path::new(socket));
    let opts = options(&["--management-socket", "relative.sock"]);
    assert!(render(&opts, Path::new("chain-spec.toml"), &chain_spec()).is_err());
}

fn options(flags: &[&str]) -> Options {
    let args: Vec<String> = flags.iter().map(|flag| (*flag).to_owned()).collect();
    Options::parse(&args).unwrap()
}

#[test]
fn recorded_templates_match_renderer_output() {
    let file = chain_spec();
    for case in SUCCESS_CASES {
        let actual = render(&options(case.flags), Path::new("chain-spec.toml"), &file).unwrap();
        assert_eq!(actual, case.expected, "case {}", case.name);
    }
}

#[test]
fn recorded_validation_errors_keep_precedence() {
    let file = chain_spec();
    for case in FAILURE_CASES {
        assert_eq!(
            render(&options(case.flags), Path::new("chain-spec.toml"), &file),
            Err(case.error.to_owned()),
            "case {}",
            case.name,
        );
    }
}

#[test]
fn reporter_template_binds_recipient_without_validator_key() {
    let args = vec![
        "--reporter-reward-address".into(),
        format!("{}{}", "00".repeat(12), "ab".repeat(20)),
    ];
    let options = Options::parse(&args).unwrap();
    let mut text = "chain_id = 1\nrole = 'reporter'\n".to_owned();
    append_reporter_config(&mut text, "reporter", &options).unwrap();
    let config: neutrin0_node::NodeConfig = toml::from_str(&text).unwrap();
    let mut expected = [0xab; 32];
    expected[..12].fill(0);
    assert_eq!(config.reporter_reward_address().unwrap(), Some(expected));
    assert!(config.proposer_ikm_path.is_none());
    assert!(append_reporter_config(&mut String::new(), "full", &options).is_err());
    let missing = Options::parse(&[]).unwrap();
    assert!(append_reporter_config(&mut String::new(), "reporter", &missing).is_err());
    let zero = Options::parse(&["--reporter-reward-address".into(), "00".repeat(32)]).unwrap();
    assert!(append_reporter_config(&mut String::new(), "reporter", &zero).is_err());
    // The runtime could never pay a value outside its account space.
    let unpayable = Options::parse(&["--reporter-reward-address".into(), "ab".repeat(32)]).unwrap();
    assert!(append_reporter_config(&mut String::new(), "reporter", &unpayable).is_err());
}
