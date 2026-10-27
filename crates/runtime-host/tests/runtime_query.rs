//! Read-only query path: `WasmRuntime::query` runs the master cdylib's
//! `_neutrin0_query` entrypoint against a pre-populated [`LiveTrie`] and
//! returns runtime-defined `QueryResponse` payloads.
//!
//! The system methods exercised here (`validator_get`, `validator_set`,
//! `runtime_info`, reporter status and settlement metrics) are the ones the
//! EVM runtime forwards to `neutrin0_runtime_system::query`. Unknown methods
//! surface as [`QueryStatus::UnknownMethod`], malformed args as
//! [`QueryStatus::InvalidArguments`].

use borsh::BorshSerialize;
use neutrin0_consensus_types::runtime::{
    CONSENSUS_CANDIDATES_KEY, ConsensusCandidate, ConsensusCandidates, Sanction,
};
use neutrin0_primitives::RuntimeInfo;
use neutrin0_runtime_abi::{QueryRequest, QueryResponse, QueryStatus};
use neutrin0_runtime_core::{StateBackend, host::LiveTrie};
use neutrin0_runtime_host::wasm::WasmRuntime;
use neutrin0_runtime_system::{
    Address, QUERY_METHOD_RUNTIME_INFO, QUERY_METHOD_VALIDATOR_GET, QUERY_METHOD_VALIDATOR_SET,
    Validator, ValidatorSet, encode_validator, validator_key,
};

const ADDR_A: Address = [0xA1; 32];
const ADDR_B: Address = [0xB2; 32];

fn empty_runtime_and_trie() -> (WasmRuntime, LiveTrie) {
    let runtime = WasmRuntime::embedded().expect("compile master.wasm");
    let live = LiveTrie::default();
    (runtime, live)
}

fn live_with(entries: &[(Vec<u8>, Vec<u8>)]) -> LiveTrie {
    let mut live = LiveTrie::default();
    for (key, value) in entries {
        live.insert(key, value.clone());
    }
    live
}

fn request(method: &str, args: Vec<u8>) -> QueryRequest {
    QueryRequest {
        method: method.to_string(),
        args,
    }
}

fn run(runtime: &WasmRuntime, live: &LiveTrie, req: &QueryRequest) -> QueryResponse {
    runtime
        .query(req, live.trie())
        .expect("wasmtime query should not trap")
}

fn assert_ok(response: &QueryResponse) {
    assert!(
        response.is_ok(),
        "expected ok response, got code={} payload={:?}",
        response.code,
        response.payload
    );
}

#[test]
fn validator_get_returns_existing_validator() {
    let runtime = WasmRuntime::embedded().expect("compile master.wasm");
    let validator = Validator { stake: 5_000 };
    let live = live_with(&[(validator_key(&ADDR_A), encode_validator(&validator))]);

    let req = request(QUERY_METHOD_VALIDATOR_GET, ADDR_A.to_vec());
    let response = run(&runtime, &live, &req);

    assert_ok(&response);
    let decoded: Option<Validator> = borsh::from_slice(&response.payload).expect("decode payload");
    assert_eq!(decoded, Some(validator));
}

#[test]
fn validator_get_for_unknown_validator_returns_none() {
    let (runtime, live) = empty_runtime_and_trie();

    let req = request(QUERY_METHOD_VALIDATOR_GET, ADDR_A.to_vec());
    let response = run(&runtime, &live, &req);

    assert_ok(&response);
    let decoded: Option<Validator> = borsh::from_slice(&response.payload).expect("decode payload");
    assert_eq!(decoded, None);
}

#[test]
fn validator_get_rejects_malformed_args() {
    let (runtime, live) = empty_runtime_and_trie();

    // Address must be 32 bytes; passing 4 bytes triggers
    // `QueryStatus::InvalidArguments`.
    let req = request(QUERY_METHOD_VALIDATOR_GET, vec![0xAA; 4]);
    let response = run(&runtime, &live, &req);

    assert_eq!(response.code, QueryStatus::InvalidArguments.as_u32());
}

#[test]
fn validator_set_returns_canonical_set() {
    let runtime = WasmRuntime::embedded().expect("compile master.wasm");
    let mut set = ValidatorSet::default();
    set.upsert(ADDR_A, 100);
    set.upsert(ADDR_B, 200);
    // The set is a view of the stakes the consensus candidates mirror;
    // a candidate without stake is not a member.
    let mut candidates = ConsensusCandidates::default();
    for (address, stake) in [(ADDR_A, 100), (ADDR_B, 200), ([0xC3; 32], 0)] {
        candidates.upsert(ConsensusCandidate {
            address,
            stake,
            identity: None,
        });
    }
    let live = live_with(&[(
        CONSENSUS_CANDIDATES_KEY.to_vec(),
        borsh::to_vec(&candidates).expect("borsh encode candidates"),
    )]);

    let req = request(QUERY_METHOD_VALIDATOR_SET, Vec::new());
    let response = run(&runtime, &live, &req);

    assert_ok(&response);
    let decoded: ValidatorSet = borsh::from_slice(&response.payload).expect("decode payload");
    assert_eq!(decoded, set);
}

#[test]
fn validator_set_returns_empty_set_when_state_is_unpopulated() {
    let (runtime, live) = empty_runtime_and_trie();

    let req = request(QUERY_METHOD_VALIDATOR_SET, Vec::new());
    let response = run(&runtime, &live, &req);

    assert_ok(&response);
    let decoded: ValidatorSet = borsh::from_slice(&response.payload).expect("decode payload");
    assert_eq!(decoded, ValidatorSet::default());
}

#[test]
fn runtime_info_advertises_evm_metadata() {
    let (runtime, live) = empty_runtime_and_trie();

    let req = request(QUERY_METHOD_RUNTIME_INFO, Vec::new());
    let response = run(&runtime, &live, &req);

    assert_ok(&response);
    let decoded: RuntimeInfo = borsh::from_slice(&response.payload).expect("decode payload");
    // The embedded runtime names itself; a change to its metadata surfaces here.
    assert_eq!(decoded.spec_name, *b"NEUTRIN0_EVM\0\0\0\0");
    assert_ne!(decoded, RuntimeInfo::default());
}

#[test]
fn unknown_method_returns_unknown_method_status() {
    let (runtime, live) = empty_runtime_and_trie();

    let req = request("nonexistent_method", Vec::new());
    let response = run(&runtime, &live, &req);

    assert_eq!(response.code, QueryStatus::UnknownMethod.as_u32());
    assert_eq!(response.payload, b"nonexistent_method");
}

#[test]
fn settlement_query_is_bounded_read_only_and_preserves_overflow_flags() {
    use neutrin0_runtime_core::host::TracingState;
    use neutrin0_runtime_system::{
        QUERY_METHOD_ACCOUNTABILITY_METRICS,
        accountability::settlement::{
            SETTLEMENT_TOTALS_KEY, SettlementCounter, SettlementSnapshot, SettlementTotals,
        },
    };
    let runtime = WasmRuntime::embedded().unwrap();
    let mut totals = SettlementTotals::default();
    totals.slash.deducted = SettlementCounter {
        value: u128::MAX,
        overflowed: true,
    };
    totals.slash.rewarded.value = 17;
    let live = live_with(&[(
        SETTLEMENT_TOTALS_KEY.to_vec(),
        borsh::to_vec(&totals).unwrap(),
    )]);
    let root = live.state_root();
    let req = request(QUERY_METHOD_ACCOUNTABILITY_METRICS, Vec::new());
    let response = run(&runtime, &live, &req);
    let mut native = TracingState::new(&live);
    assert_eq!(
        response,
        neutrin0_evm_runtime_core::query(&req, &mut native)
    );
    assert_eq!(native.post_state_root(), root);
    let decoded: SettlementSnapshot = borsh::from_slice(&response.payload).unwrap();
    assert_eq!(decoded.totals, totals);
    assert_eq!(decoded.pending_slash, 0);
    assert_eq!(
        run(
            &runtime,
            &live,
            &request(QUERY_METHOD_ACCOUNTABILITY_METRICS, vec![1])
        )
        .code,
        QueryStatus::InvalidArguments.as_u32()
    );
    let empty = run(&runtime, &LiveTrie::default(), &req);
    assert_eq!(
        borsh::from_slice::<SettlementSnapshot>(&empty.payload).unwrap(),
        SettlementSnapshot::default()
    );
}

#[test]
fn malformed_request_bytes_yield_invalid_arguments() {
    // A request with garbage args for a method that does decode args
    // surfaces `InvalidArguments` through the dispatch path; the in-crate
    // `runtime-abi` tests cover borsh round-trips of the envelope itself.
    let (runtime, live) = empty_runtime_and_trie();
    let req = request(QUERY_METHOD_VALIDATOR_GET, vec![]); // empty bytes != 32-byte address
    let response = run(&runtime, &live, &req);
    assert_eq!(response.code, QueryStatus::InvalidArguments.as_u32());
}

#[test]
fn validator_get_against_finalized_view_matches_latest() {
    // The same query against the same state produces the same result
    // twice: the runtime carries no hidden cross-call mutable state.
    let runtime = WasmRuntime::embedded().expect("compile master.wasm");
    let validator = Validator { stake: 9 };
    let live = live_with(&[(validator_key(&ADDR_A), encode_validator(&validator))]);
    let req = request(QUERY_METHOD_VALIDATOR_GET, ADDR_A.to_vec());

    let first = run(&runtime, &live, &req);
    let second = run(&runtime, &live, &req);
    assert_eq!(first.code, second.code);
    assert_eq!(first.payload, second.payload);
}

#[test]
fn query_does_not_mutate_live_state() {
    // Even if the runtime attempted to write, the host's `state_write` and
    // `state_delete` imports drop the write and flag the attempt. The
    // runtime's `query` only reads; the snapshot's root stays unchanged.
    let runtime = WasmRuntime::embedded().expect("compile master.wasm");
    let validator = Validator { stake: 100 };
    let live = live_with(&[(validator_key(&ADDR_A), encode_validator(&validator))]);
    let pre_root = live.state_root();

    let req = request(QUERY_METHOD_VALIDATOR_GET, ADDR_A.to_vec());
    let _ = run(&runtime, &live, &req);

    assert_eq!(live.state_root(), pre_root);
}

#[test]
fn args_serialised_as_borsh_address_also_works() {
    // The raw-bytes encoding matches `borsh([u8; 32])` exactly, so either
    // argument shape decodes correctly. This pins that property so a future
    // borsh upgrade that adds a length prefix to fixed-size arrays would
    // surface here.
    let runtime = WasmRuntime::embedded().expect("compile master.wasm");
    let validator = Validator { stake: 7 };
    let live = live_with(&[(validator_key(&ADDR_A), encode_validator(&validator))]);

    let mut borsh_bytes = Vec::new();
    BorshSerialize::serialize(&ADDR_A, &mut borsh_bytes).expect("borsh encode address");
    assert_eq!(borsh_bytes, ADDR_A.to_vec());

    let req = request(QUERY_METHOD_VALIDATOR_GET, borsh_bytes);
    let response = run(&runtime, &live, &req);
    assert_ok(&response);
    let decoded: Option<Validator> = borsh::from_slice(&response.payload).expect("decode payload");
    assert_eq!(decoded, Some(validator));
}

#[test]
#[allow(clippy::too_many_lines)] // Explicit shared-account and FIFO state fixtures test both query engines.
fn reporter_status_matches_native_and_tracks_shared_accounts_and_pending_slashes() {
    use neutrin0_runtime_core::host::TracingState;
    use neutrin0_runtime_system::{
        QUERY_METHOD_REPORTER_STATUS, ReporterIdentity, ReporterStatus, ReporterStatusRequest,
        Withdrawal, WithdrawalQueue,
        accountability::{PendingSanction, QUEUE_KEY, slashed_key},
        withdrawal_key,
    };

    let runtime = WasmRuntime::embedded().unwrap();
    let identities = vec![
        ReporterIdentity {
            pubkey: [1; 48],
            withdrawal_credentials: ADDR_A,
        },
        ReporterIdentity {
            pubkey: [2; 48],
            withdrawal_credentials: ADDR_A,
        },
        ReporterIdentity {
            pubkey: [3; 48],
            withdrawal_credentials: ADDR_B,
        },
    ];
    let obligation = PendingSanction {
        sanction: Sanction {
            offence_id: [9; 32],
            offender: neutrin0_primitives::Validator {
                pubkey: identities[1].pubkey,
                withdrawal_credentials: ADDR_A,
                effective_stake: 100,
                activation_epoch: 0,
                exit_epoch: u64::MAX,
            },
            kind: neutrin0_consensus_types::evidence::SanctionKind::Slash,
        },
        amount: 20,
        reporter: None,
        reporter_reward_bps: 1_000,
    };
    let live = live_with(&[
        (
            validator_key(&ADDR_A),
            encode_validator(&Validator { stake: 40 }),
        ),
        (
            withdrawal_key(&ADDR_A),
            borsh::to_vec(&WithdrawalQueue {
                entries: vec![
                    Withdrawal {
                        amount: 60,
                        mature_at_height: 1,
                    },
                    Withdrawal {
                        amount: 20,
                        mature_at_height: 100,
                    },
                ],
            })
            .unwrap(),
        ),
        (slashed_key(&identities[1].pubkey), vec![0]),
        (
            QUEUE_KEY.to_vec(),
            borsh::to_vec(&vec![obligation]).unwrap(),
        ),
    ]);
    let req = request(
        QUERY_METHOD_REPORTER_STATUS,
        borsh::to_vec(&ReporterStatusRequest {
            identities: identities.clone(),
        })
        .unwrap(),
    );
    let root = live.state_root();
    let response = run(&runtime, &live, &req);
    assert_ok(&response);
    let mut native = TracingState::new(&live);
    assert_eq!(
        response,
        neutrin0_evm_runtime_core::query(&req, &mut native)
    );
    assert_eq!(native.post_state_root(), root);
    assert_eq!(live.state_root(), root);
    let statuses: Vec<ReporterStatus> = borsh::from_slice(&response.payload).unwrap();
    assert_eq!(
        statuses,
        vec![
            ReporterStatus {
                identity: identities[0],
                slashable_balance: 120,
                tombstoned: false,
                pending: false
            },
            ReporterStatus {
                identity: identities[1],
                slashable_balance: 120,
                tombstoned: true,
                pending: true
            },
            ReporterStatus {
                identity: identities[2],
                slashable_balance: 0,
                tombstoned: false,
                pending: false
            },
        ]
    );
    // Funds outside runtime staking carry no liability: once stake and
    // withdrawals have left, historical signatures may be cleaned even if the
    // account still holds tokens.
    let exited = live_with(&[(b"unrelated".to_vec(), vec![1])]);
    let response = run(&runtime, &exited, &req);
    let statuses: Vec<ReporterStatus> = borsh::from_slice(&response.payload).unwrap();
    assert!(statuses.iter().all(|status| status.slashable_balance == 0));
}

#[test]
fn reporter_status_rejects_unbounded_or_malformed_identity_batches() {
    use neutrin0_runtime_system::{
        MAX_REPORTER_STATUS_IDENTITIES, QUERY_METHOD_REPORTER_STATUS, ReporterIdentity,
        ReporterStatusRequest,
    };
    let (runtime, live) = empty_runtime_and_trie();
    let request_args = borsh::to_vec(&ReporterStatusRequest {
        identities: vec![
            ReporterIdentity {
                pubkey: [1; 48],
                withdrawal_credentials: ADDR_A
            };
            MAX_REPORTER_STATUS_IDENTITIES + 1
        ],
    })
    .unwrap();
    for args in [
        vec![],
        vec![1, 0, 0, 0],
        u32::MAX.to_le_bytes().to_vec(),
        request_args,
    ] {
        let response = run(
            &runtime,
            &live,
            &request(QUERY_METHOD_REPORTER_STATUS, args),
        );
        assert_eq!(response.code, QueryStatus::InvalidArguments.as_u32());
    }
}
