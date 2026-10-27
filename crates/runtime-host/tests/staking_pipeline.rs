//! End-to-end staking pipeline: stake and unstake system calls flow through
//! dry-run → SP1 mock-prove → verify exactly like transfers, and the
//! committed `consensus_candidates_root` changes deterministically as stakes
//! move.
#[path = "../../prover-chunk/tests/support/mod.rs"]
pub mod support;

use std::sync::OnceLock;

use alloy_primitives::U256;
use neutrin0_evm_runtime_core::{addresses, state::consensus_address};
use neutrin0_primitives::RuntimeParams;
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_core::host::LiveTrie;
use neutrin0_runtime_host::{ProverCtx, dry_run};
use sp1_sdk::blocking::{MockProver, ProverClient};

/// Attribution every receipt in this test names (design 08).
const PROVER_ADDRESS: [u8; 32] = [0x50; 32];

static MOCK_CTX: OnceLock<ProverCtx<MockProver>> = OnceLock::new();

fn mock_ctx() -> &'static ProverCtx<MockProver> {
    MOCK_CTX.get_or_init(|| {
        let prover = ProverClient::builder().mock().build();
        ProverCtx::new(prover).expect("mock setup")
    })
}

/// Genesis in which the funded development account is also the committee's
/// accountable validator, under a policy whose stake floor admits the
/// tests' small stakes. Stake only adds to an existing record, which genesis
/// or a registration creates.
fn staking_genesis() -> (LiveTrie, RuntimeBlockInput) {
    let (_, input, _) = support::fixture([1; 8], [4; 32]);
    let (mut validators, _) = support::fixture_committee();
    validators[0].withdrawal_credentials = consensus_address(support::sender());
    let params = RuntimeParams {
        min_validator_stake: 1,
        ..RuntimeParams::default()
    };
    let live = support::evm_genesis_live(&support::evm_genesis_input(
        support::programs([1; 8], [4; 32]),
        30_000_000,
        0,
        &validators,
        1,
        params,
    ));
    let mut input = input;
    // The executed committee must open against the authenticated boundary.
    input.context.finalized.validators_root =
        neutrin0_consensus_types::evidence::commitment(&validators);
    input.active_validators = validators;
    input.proposer_address = consensus_address(support::sender());
    input.transactions.clear();
    (live, input)
}

fn amount(value: u64) -> [u8; 32] {
    U256::from(value).to_be_bytes()
}

/// Header commitment of a candidate record holding `entries` without BLS identities.
fn candidates_root(entries: &[([u8; 32], u128)]) -> neutrin0_primitives::Hash {
    let mut candidates = neutrin0_consensus_types::runtime::ConsensusCandidates::default();
    for (address, stake) in entries {
        candidates.upsert(neutrin0_consensus_types::runtime::ConsensusCandidate {
            address: *address,
            stake: *stake,
            identity: None,
        });
    }
    candidates.root()
}

#[test]
fn stake_pipeline_prove_verify_mock() {
    let ctx = mock_ctx();
    let (live, mut input) = staking_genesis();
    let validator = consensus_address(support::sender());
    input.transactions = vec![support::call(
        0,
        addresses::STAKING,
        support::system_call(b"stake(uint256)", &[amount(60)]),
        300_000,
    )];
    let dry = dry_run(&input, &live, &[]).expect("native dry run");
    assert_eq!(dry.output.applied, 1);
    assert_eq!(dry.output.failed, 0);
    // Genesis collateral plus the staked amount.
    assert_eq!(
        dry.output.consensus_candidates_root,
        candidates_root(&[(validator, 160)])
    );
    let post = LiveTrie::from_trie(dry.post_state.clone());
    assert!(
        support::balance_of(&post, support::sender())
            < support::balance_of(&live, support::sender()) - U256::from(60)
    );

    let proof = ctx
        .prove(&input, dry.witness.clone(), &[], PROVER_ADDRESS)
        .unwrap();
    ctx.verify(&proof.proof, &dry.output)
        .expect("verify accepts proof");
}

#[test]
fn stake_then_unstake_round_trip() {
    let ctx = mock_ctx();
    let (live, mut input) = staking_genesis();
    let validator = consensus_address(support::sender());
    input.transactions = vec![
        support::call(
            0,
            addresses::STAKING,
            support::system_call(b"stake(uint256)", &[amount(40)]),
            300_000,
        ),
        support::call(
            1,
            addresses::STAKING,
            support::system_call(b"unstake(uint256)", &[amount(40)]),
            300_000,
        ),
    ];
    let dry = dry_run(&input, &live, &[]).expect("native dry run");
    assert_eq!(dry.output.applied, 2);
    assert_eq!(dry.output.failed, 0);
    // Net effect: the added stake is queued for withdrawal and the seated
    // validator keeps its genesis collateral. The sole active seat cannot
    // unstake to zero: a full exit needs another seated validator to hand
    // off to.
    assert_eq!(
        dry.output.consensus_candidates_root,
        candidates_root(&[(validator, 100)])
    );

    let proof = ctx
        .prove(&input, dry.witness.clone(), &[], PROVER_ADDRESS)
        .unwrap();
    ctx.verify(&proof.proof, &dry.output)
        .expect("verify accepts proof");
}
