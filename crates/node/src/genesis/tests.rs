use super::*;
use neutrin0_consensus_types::runtime::{CONSENSUS_CANDIDATES_KEY, ConsensusCandidates};
use neutrin0_runtime_core::host::LiveTrie;
use neutrin0_runtime_system::{Validator as RuntimeValidator, validator_key};

/// Zero-padded system address of the Ethereum account `[byte; 20]`.
fn padded(byte: u8) -> [u8; 32] {
    let mut address = [0; 32];
    address[12..].copy_from_slice(&[byte; 20]);
    address
}

/// Parse `raw` with this binary's programs pinned.
fn pinned(raw: &str) -> Result<ChainSpecFile, ChainSpecError> {
    let mut file = ChainSpecFile::from_toml_str(raw)?;
    file.pin_embedded_programs()?;
    Ok(file)
}

fn spec(extra: &str) -> ChainSpecFile {
    pinned(&format!(
        r#"
name = "genesis-test"
chain_id = 7
genesis_time = 1700000000
genesis_gas_limit = 30000000
{extra}
[[validators]]
{fields}effective_stake = 500
"#,
        fields = crate::chain_spec::test_validator_fields(1, [0x11; 20])
    ))
    .unwrap()
}

#[test]
fn empty_allocation_still_seeds_the_runtime_records() {
    let file = spec("");
    let state = build_genesis_state(&file).unwrap();
    // No accounts, yet the fee environment, the system accounts and the
    // governable policy are always present, so the root is never zero.
    assert_ne!(state.root, ZERO_HASH);
    assert_eq!(state.accounts, 0);
    assert_eq!(state.staked_validators, 1);
    let live = LiveTrie::from_trie(state.trie);
    assert!(
        live.get(neutrin0_runtime_system::RUNTIME_POLICY_KEY)
            .unwrap()
            .is_some()
    );
}

#[test]
fn a_validator_without_an_accountable_account_is_rejected() {
    let file = pinned(&format!(
        r#"
name = "x"
chain_id = 7
genesis_time = 0
genesis_gas_limit = 30000000
[[validators]]
{}effective_stake = 1
"#,
        crate::chain_spec::test_validator_fields(1, [0; 20])
    ))
    .unwrap();
    assert!(matches!(
        build_genesis_state(&file),
        Err(ChainSpecError::Validation(_))
    ));
}

#[test]
fn accounts_and_validators_are_seeded_deterministically() {
    let extra = format!(
        "[[accounts]]\naddress_hex = \"{}\"\nbalance = 1000\n",
        "22".repeat(20)
    );
    let a = build_genesis_state(&spec(&extra)).unwrap();
    let b = build_genesis_state(&spec(&extra)).unwrap();
    assert_eq!(a.root, b.root);
    assert_ne!(a.root, ZERO_HASH);
    assert_eq!(a.accounts, 1);
    assert_eq!(a.staked_validators, 1);
    let live = LiveTrie::from_trie(a.trie.clone());
    let mut state = neutrin0_runtime_core::host::TracingState::new(&live);
    let account = neutrin0_evm_runtime_core::state::load_account(
        &mut state,
        alloy_primitives::Address::from([0x22; 20]),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        alloy_primitives::U256::from_be_bytes(account.balance),
        alloy_primitives::U256::from(1000)
    );
    let validator: RuntimeValidator =
        borsh::from_slice(&a.trie.get(&validator_key(&padded(0x11))).unwrap().unwrap()).unwrap();
    assert_eq!(validator.stake, 500);
    let candidates: ConsensusCandidates =
        borsh::from_slice(&a.trie.get(CONSENSUS_CANDIDATES_KEY).unwrap().unwrap()).unwrap();
    assert_eq!(candidates.entries.len(), 1);
    assert_eq!(candidates.entries[0].stake, 500);
    // The spec derives the same root and binds it into the chain spec.
    let chain_spec = spec(&extra).to_chain_spec().unwrap();
    assert_eq!(chain_spec.genesis_state_root, a.root);
}

#[test]
fn declared_root_must_match_allocation() {
    let extra = format!(
        "genesis_state_root_hex = \"{}\"\n[[accounts]]\naddress_hex = \"{}\"\nbalance = 1\n",
        "ff".repeat(32),
        "22".repeat(20)
    );
    assert!(matches!(
        spec(&extra).to_chain_spec(),
        Err(ChainSpecError::Validation(_))
    ));
}

#[test]
fn duplicate_account_is_rejected() {
    let extra = format!(
        "[[accounts]]\naddress_hex = \"{a}\"\nbalance = 1\n[[accounts]]\naddress_hex = \"{a}\"\nbalance = 2\n",
        a = "22".repeat(20)
    );
    assert!(build_genesis_state(&spec(&extra)).is_err());
}

#[test]
fn genesis_candidate_validation_rejects_missing_stake_and_invalid_standby_identity() {
    use neutrin0_consensus_types::runtime::{BlsIdentity, ConsensusCandidate, ConsensusCandidates};
    let validators = spec("").genesis_validators().unwrap();
    let mut candidates = ConsensusCandidates::default();
    assert!(validate_genesis_candidates(&candidates, &validators).is_err());
    candidates.upsert(ConsensusCandidate {
        address: padded(0x11),
        stake: 499,
        identity: None,
    });
    assert!(validate_genesis_candidates(&candidates, &validators).is_err());
    candidates.upsert(ConsensusCandidate {
        address: padded(0x11),
        stake: 500,
        identity: None,
    });
    assert!(validate_genesis_candidates(&candidates, &validators).is_ok());
    candidates.upsert(ConsensusCandidate {
        address: padded(0x22),
        stake: 0,
        identity: Some(BlsIdentity {
            pubkey: [0; 48],
            pop_signature: [0; 96],
        }),
    });
    assert!(validate_genesis_candidates(&candidates, &validators).is_err());
}
