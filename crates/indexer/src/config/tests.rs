use super::*;
fn config() -> Config {
    toml::from_str(&format!(
        "rpc_url='http://127.0.0.1:9944'\nchain_spec_hash='{}'",
        crate::model::hex(&[1; 32])
    ))
    .unwrap()
}
#[test]
fn schema_is_isolated_and_cannot_inject_identifiers() {
    for name in [
        "public",
        "pg_catalog",
        "a;DROP TABLE blocks",
        "a\"b",
        "1index",
        "",
    ] {
        assert!(validate_schema(name).is_err());
    }
    for name in ["neutrin0_indexer", "test_42", "_index"] {
        assert!(validate_schema(name).is_ok());
    }
}
#[test]
fn unknown_profiles_are_refused_and_limits_are_bounded() {
    let mut config = config();
    assert!(config.validate().is_ok());
    config.runtime = "native".into();
    assert!(config.validate().is_err());
    config.runtime = "opaque".into();
    assert!(config.validate().is_ok());
    config.batch_blocks = 1025;
    assert!(config.validate().is_err());
}
#[test]
fn tuning_preserves_decoder_semantics() {
    let mut config = config();
    let before = config.decoder_hash().unwrap();
    config.batch_blocks = 32;
    config.poll_seconds = 10;
    assert_eq!(config.decoder_hash().unwrap(), before);
    config.runtime = "opaque".into();
    assert_ne!(config.decoder_hash().unwrap(), before);
}
