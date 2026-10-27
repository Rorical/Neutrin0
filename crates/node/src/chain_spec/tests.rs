use super::*;

/// Parse `raw` and pin this binary's programs, as `neutrin0-cli genesis
/// --write` does for a new specification.
fn pinned_toml(raw: &str) -> Result<ChainSpecFile, ChainSpecError> {
    let mut file = ChainSpecFile::from_toml_str(raw)?;
    file.pin_embedded_programs()?;
    Ok(file)
}

#[test]
fn pin_genesis_root_replaces_or_inserts_before_first_table() {
    let raw = "name = \"x\"\nchain_id = 1\n[[validators]]\npubkey_hex = \"00\"\n";
    let pinned = pin_genesis_root(raw, "ab");
    assert_eq!(
        pinned,
        "name = \"x\"\nchain_id = 1\ngenesis_state_root_hex = \"ab\"\n[[validators]]\npubkey_hex = \"00\"\n"
    );
    let again = pin_genesis_root(&pinned, "cd");
    assert!(again.contains("genesis_state_root_hex = \"cd\""));
    assert_eq!(again.matches("genesis_state_root_hex").count(), 1);
}

#[test]
fn a_spec_without_program_pins_derives_no_chain() {
    let file = ChainSpecFile::from_toml_str(&minimal_spec_toml()).unwrap();
    let error = file.to_chain_spec().unwrap_err().to_string();
    assert!(error.contains("[programs]"), "{error}");
    assert!(file.runtime_package().is_err());
}

fn minimal_spec_toml() -> String {
    format!(
        r#"
name = "neutrin0-m6-test"
chain_id = 7
genesis_time = 1700000000
genesis_gas_limit = 30000000
genesis_block_hash_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[validators]]
{}effective_stake = "32000000000000000000"
"#,
        test_validator_fields(1, [0xab; 20])
    )
}

#[test]
fn genesis_keys_must_prove_possession_for_their_credentials() {
    let other = test_validator_fields(2, [0xab; 20]);
    let other_pop = other.lines().nth(2).unwrap();
    let own = test_validator_fields(1, [0xab; 20]);
    let own_pop = own.lines().nth(2).unwrap();
    // Another key's proof, or this key's proof for other credentials,
    // does not seat the key.
    let elsewhere = test_validator_fields(1, [0xcd; 20]);
    for pop in [other_pop, elsewhere.lines().nth(2).unwrap()] {
        let raw = minimal_spec_toml().replace(own_pop, pop);
        let error = pinned_toml(&raw).unwrap().to_chain_spec().unwrap_err();
        assert!(
            error.to_string().contains("does not prove possession"),
            "{error}"
        );
    }
    // A 48-byte string that is not a subgroup point is refused before any
    // proof is checked.
    let own_key = own.lines().next().unwrap();
    let raw =
        minimal_spec_toml().replace(own_key, &format!("pubkey_hex = \"{}\"", "01".repeat(48)));
    let error = pinned_toml(&raw).unwrap().to_chain_spec().unwrap_err();
    assert!(
        error.to_string().contains("prime-order subgroup"),
        "{error}"
    );
}

/// Pinned identities decide the chain; bytes are accepted only when they
/// reproduce them, whether embedded or read from the package directory.
#[test]
fn pinned_programs_must_be_reproduced_by_embedded_or_packaged_bytes() {
    let file = pinned_toml(&minimal_spec_toml()).unwrap();
    let embedded = file.genesis_programs(None).unwrap();
    let programs = embedded.package.programs;
    let artifacts = embedded.artifacts;
    let pins = |chunk: [u32; 8]| ProgramPins {
        runtime_code_hash: hex::encode(programs.runtime_code_hash),
        fact_vk: vk_hex(&programs.execution.fact),
        evidence_vk: vk_hex(&programs.execution.evidence),
        block_vk: vk_hex(&programs.execution.block),
        chunk_vk: vk_hex(&chunk),
        runtime_artifact: Some(hex::encode(artifacts.runtime)),
        fact_artifact: Some(hex::encode(artifacts.fact)),
        evidence_artifact: Some(hex::encode(artifacts.evidence)),
        block_artifact: Some(hex::encode(artifacts.block)),
        chunk_artifact: Some(hex::encode(artifacts.chunk)),
    };
    let mut pinned = file.clone();
    pinned.programs = Some(pins(embedded.chunk));
    let spec = pinned.to_chain_spec().unwrap();
    assert_eq!(spec, file.to_chain_spec().unwrap());
    assert_eq!(spec.genesis_chunk, embedded.chunk);
    assert_eq!(spec.genesis_artifacts, artifacts);

    // A chunk Guest this binary does not embed must come from the
    // package directory under its pinned content hash.
    pinned.programs = Some(pins([9; 8]));
    let error = pinned.genesis_programs(None).unwrap_err().to_string();
    assert!(error.contains("is not embedded"), "{error}");
    let dir = std::env::temp_dir().join(format!("neutrin0-pins-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join(format!("{}.bin", hex::encode(artifacts.chunk))),
        neutrin0_runtime_host::CONSENSUS_CHUNK_GUEST_ELF.to_vec(),
    )
    .unwrap();
    // Those bytes derive another key, so they are refused.
    let error = pinned.genesis_programs(Some(&dir)).unwrap_err().to_string();
    assert!(error.contains("do not reproduce"), "{error}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn parses_minimal_chain_spec() {
    let file = pinned_toml(&minimal_spec_toml()).expect("parse");
    assert_eq!(file.chain_id, 7);
    assert_eq!(file.validators.len(), 1);
}

#[test]
fn amounts_are_wei_integers_or_decimal_strings() {
    let file = pinned_toml(&minimal_spec_toml()).unwrap();
    assert_eq!(
        file.validators[0].effective_stake,
        32 * neutrin0_primitives::WEI_PER_TOKEN
    );
    let integer = minimal_spec_toml().replace("\"32000000000000000000\"", "5");
    let file = pinned_toml(&integer).unwrap();
    assert_eq!(file.validators[0].effective_stake, 5);
    for bad in [
        "\"32.5\"",
        "\"\"",
        "-1",
        "\"1e18\"",
        "\"340282366920938463463374607431768211456\"",
    ] {
        let raw = minimal_spec_toml().replace("\"32000000000000000000\"", bad);
        assert!(pinned_toml(&raw).is_err(), "{bad}");
    }
}

#[test]
fn embedded_evm_validator_address_is_canonically_padded() {
    let file = pinned_toml(&minimal_spec_toml()).unwrap();
    let validators = file.genesis_validators().unwrap();
    assert_eq!(validators[0].withdrawal_credentials[..12], [0; 12]);
    assert_eq!(validators[0].withdrawal_credentials[12..], [0xab; 20]);
}

#[test]
fn rejects_unknown_chain_spec_fields_at_every_level() {
    let account = format!(
        "\n[[accounts]]\naddress_hex = \"{}\"\nbalance = 100\n",
        "11".repeat(32)
    );
    for raw in [
        format!("runtime_version = 1\n{}", minimal_spec_toml()),
        format!("{}\nruntime_version = 1\n", minimal_spec_toml()),
        format!("{}{account}runtime_version = 1\n", minimal_spec_toml()),
    ] {
        let error = pinned_toml(&raw).unwrap_err();
        assert!(matches!(error, ChainSpecError::Toml(_)));
        assert!(
            error
                .to_string()
                .contains("unknown field `runtime_version`")
        );
    }
    // The same nested entries parse without the unknown field.
    let file = pinned_toml(&format!("{}{account}", minimal_spec_toml())).expect("canonical fields");
    assert_eq!(file.accounts.len(), 1);
}

#[test]
fn materialises_canonical_chain_spec() {
    let file = pinned_toml(&minimal_spec_toml()).expect("parse");
    let spec = file.to_chain_spec().expect("to_chain_spec");
    assert_eq!(spec.chain_id, 7);
    assert_eq!(spec.genesis_block_hash, [0xAA; 32]);
    assert!(spec.initial_validators[0].effective_stake > 0);
}

#[test]
fn identical_spec_files_hash_identically() {
    let a = pinned_toml(&minimal_spec_toml())
        .unwrap()
        .to_chain_spec()
        .unwrap();
    let b = pinned_toml(&minimal_spec_toml())
        .unwrap()
        .to_chain_spec()
        .unwrap();
    assert_eq!(a.hash(), b.hash());
}

#[test]
fn changing_chain_id_changes_hash() {
    let a = pinned_toml(&minimal_spec_toml())
        .unwrap()
        .to_chain_spec()
        .unwrap();
    let modified = minimal_spec_toml().replace("chain_id = 7", "chain_id = 8");
    let b = pinned_toml(&modified).unwrap().to_chain_spec().unwrap();
    assert_ne!(a.hash(), b.hash());
}

#[test]
fn rejects_short_pubkey() {
    let bad = r#"
name = "x"
chain_id = 1
genesis_time = 0
genesis_gas_limit = 1

[[validators]]
pubkey_hex = "0102"
pop_hex = "00"
effective_stake = 1
"#;
    let file = pinned_toml(bad).expect("parse");
    match file.to_chain_spec() {
        Err(ChainSpecError::Hex { field, .. }) => {
            assert!(field.starts_with("validators[0]"));
        }
        other => panic!("expected Hex error, got {other:?}"),
    }
}

#[test]
fn rejects_oversized_name() {
    let mut long_name = String::with_capacity(128);
    for _ in 0..128 {
        long_name.push('a');
    }
    let raw = format!(
        r#"
name = "{long_name}"
chain_id = 1
genesis_time = 0
genesis_gas_limit = 1

[[validators]]
{}effective_stake = 1
"#,
        test_validator_fields(1, [0; 20])
    );
    let file = pinned_toml(&raw).expect("parse");
    assert!(matches!(
        file.to_chain_spec(),
        Err(ChainSpecError::NameTooLong { .. })
    ));
}
