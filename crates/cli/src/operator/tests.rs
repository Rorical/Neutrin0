//! Parser and local signing contract checks.

use super::arguments::credentials;
use super::*;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

#[test]
fn operator_arguments_reject_unknown_duplicate_and_missing_values() {
    for values in [
        &["--typo", "x"][..],
        &["--rpc", "a", "--rpc", "b"],
        &["--rpc"],
        &["--at", "--json"],
        &["stray"],
    ] {
        assert!(Arguments::parse(&args(values), &["at"]).is_err());
    }
    let options = Arguments::parse(&args(&["--at", "0x10", "--json"]), &["at"]).expect("parse");
    assert_eq!(
        options.at().expect("selector"),
        BlockIdJson(BlockId::Height(16))
    );
    assert!(options.flag("json"));
    assert!(
        Arguments::parse(&args(&["--timeout-secs", "0"]), &[])
            .expect("parse")
            .duration("timeout-secs", 10)
            .is_err()
    );
}

#[test]
fn ethereum_addresses_cannot_alias_noncanonical_credentials() {
    let value = "11".repeat(20);
    let padded = credentials(&value).expect("Ethereum");
    assert_eq!(&padded[..12], &[0; 12]);
    assert_eq!(&padded[12..], &[0x11; 20]);
    assert!(credentials(&"11".repeat(32)).is_err());
    assert_eq!(credentials(&hex::encode(padded)).expect("padded"), padded);
}

#[test]
fn structured_rpc_errors_preserve_retention_horizon() {
    let error = Error::from(jsonrpsee::core::client::Error::Call(
        jsonrpsee::types::ErrorObjectOwned::owned(
            -32024,
            "pruned",
            Some(json!({"retained_from_height": 100})),
        ),
    ));
    let value = error.value();
    assert_eq!(value["error"]["code"], -32024);
    assert_eq!(value["error"]["data"]["retained_from_height"], 100);
}
