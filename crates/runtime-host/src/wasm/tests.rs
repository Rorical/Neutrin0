use super::host_state::MAX_STATE_KEY_BYTES;
use super::*;
use neutrin0_runtime_abi::{
    HOST_IMPORT_MODULE, QueryRequest, RuntimeBlockInput, RuntimeBlockOutput,
};
use neutrin0_trie::{Poseidon2Hasher, Trie};

/// Host imports in function-index order with their wasm type indices.
const IMPORTS: [(&str, u8); 6] = [
    ("state_read_len", 0),
    ("state_read_into", 1),
    ("state_write", 2),
    ("state_delete", 3),
    ("pre_state_root", 1),
    ("post_state_root", 1),
];

/// Encoded function types: `(i32, i32) -> i32`, `(i32) -> ()`,
/// `(i32, i32, i32, i32) -> ()` and `(i32, i32) -> ()` for the imports,
/// then `(i32) -> i32` for `neutrin0_allocate` and `(i32, i32) -> i64`
/// for the entrypoints.
const TYPES: [&[u8]; 6] = [
    b"\x60\x02\x7f\x7f\x01\x7f",
    b"\x60\x01\x7f\x00",
    b"\x60\x04\x7f\x7f\x7f\x7f\x00",
    b"\x60\x02\x7f\x7f\x00",
    b"\x60\x01\x7f\x01\x7f",
    b"\x60\x02\x7f\x7f\x01\x7e",
];

const EXPORTS: [(&str, u8, u8); 6] = [
    (MEMORY_EXPORT, 0x02, 0),
    (ALLOCATE_ENTRYPOINT, 0x00, 6),
    (DEALLOCATE_ENTRYPOINT, 0x00, 8),
    (QUERY_ENTRYPOINT, 0x00, 7),
    (VALIDATE_TX_ENTRYPOINT, 0x00, 7),
    (APPLY_BLOCK_ENTRYPOINT, 0x00, 7),
];

// Entrypoint bodies. Each leaves `i64.const 0` unless it trapped; `-16`
// and 65 520 leave the single memory page once 32 bytes are added.

/// `state_read_into(0)` without any read.
const READ_INTO_UNREAD: &[u8] = b"\x41\x00\x10\x01\x42\x00";
/// `state_read_len(0, 2)` of absent key `[0, 0]`, then `state_read_into(0)`.
const READ_INTO_ABSENT: &[u8] = b"\x41\x00\x41\x02\x10\x00\x1a\x41\x00\x10\x01\x42\x00";
/// `state_read_len(-16, 32)`.
const READ_LEN_OUTSIDE: &[u8] = b"\x41\x70\x41\x20\x10\x00\x1a\x42\x00";
/// `state_write(-16, 32, 0, 0)`.
const WRITE_KEY_OUTSIDE: &[u8] = b"\x41\x70\x41\x20\x41\x00\x41\x00\x10\x02\x42\x00";
/// `state_write(0, 1, -16, 32)`.
const WRITE_VALUE_OUTSIDE: &[u8] = b"\x41\x00\x41\x01\x41\x70\x41\x20\x10\x02\x42\x00";
/// `state_delete(-16, 32)`.
const DELETE_OUTSIDE: &[u8] = b"\x41\x70\x41\x20\x10\x03\x42\x00";
/// `state_read_len(0, 1)` of present key `[0]`, then `state_read_into(-16)`.
const READ_INTO_OUTSIDE: &[u8] = b"\x41\x00\x41\x01\x10\x00\x1a\x41\x70\x10\x01\x42\x00";
/// `pre_state_root(65_520)`.
const PRE_ROOT_OUTSIDE: &[u8] = b"\x41\xf0\xff\x03\x10\x04\x42\x00";
/// `post_state_root(65_520)`.
const POST_ROOT_OUTSIDE: &[u8] = b"\x41\xf0\xff\x03\x10\x05\x42\x00";
/// Packed output at address 0 with length `u32::MAX`.
const HUGE_OUTPUT: &[u8] = b"\x42\xff\xff\xff\xff\x0f";

/// Append `value` as unsigned LEB128.
fn push_leb(out: &mut Vec<u8>, mut value: usize) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Append `name` as a length-prefixed wasm name.
fn push_name(out: &mut Vec<u8>, name: &str) {
    push_leb(out, name.len());
    out.extend_from_slice(name.as_bytes());
}

/// A runtime whose query, admission and block entrypoints all run `body`,
/// raw instructions leaving the packed `i64` output. Host import `i` of
/// [`IMPORTS`] is function `i`; `neutrin0_allocate` returns address 32768,
/// above any data segment a stub returns from offset 0.
fn runtime_running(body: &[u8]) -> WasmRuntime {
    runtime_running_with_data(body, &[])
}

fn runtime_running_with_data(body: &[u8], data: &[u8]) -> WasmRuntime {
    WasmRuntime::new(&runtime_module(body, data, &EXPORTS, &[])).expect("valid test runtime")
}

fn runtime_module(
    body: &[u8],
    data: &[u8],
    exported: &[(&str, u8, u8)],
    deallocate_body: &[u8],
) -> Vec<u8> {
    let mut types = vec![6];
    for ty in TYPES {
        types.extend_from_slice(ty);
    }
    let mut imports = vec![6];
    for (field, ty) in IMPORTS {
        push_name(&mut imports, HOST_IMPORT_MODULE);
        push_name(&mut imports, field);
        imports.extend_from_slice(&[0x00, ty]);
    }
    let mut exports = Vec::new();
    push_leb(&mut exports, exported.len());
    for &(field, kind, index) in exported {
        push_name(&mut exports, field);
        exports.extend_from_slice(&[kind, index]);
    }
    // Allocator, entrypoint and no-op deallocator bodies without locals.
    let mut code = vec![3, 6, 0x00, 0x41, 0x80, 0x80, 0x02, 0x0b];
    push_leb(&mut code, body.len() + 2);
    code.push(0x00);
    code.extend_from_slice(body);
    code.push(0x0b);
    push_leb(&mut code, deallocate_body.len() + 2);
    code.push(0);
    code.extend_from_slice(deallocate_body);
    code.push(0x0b);
    let mut module = b"\0asm\x01\0\0\0".to_vec();
    for (id, section) in [
        (1, types),
        (2, imports),
        (3, vec![3, 4, 5, 3]),
        (5, vec![1, 0x00, 1]),
        (7, exports),
        (10, code),
    ] {
        module.push(id);
        push_leb(&mut module, section.len());
        module.extend_from_slice(&section);
    }
    if !data.is_empty() {
        let mut section = vec![1, 0, 0x41, 0, 0x0b];
        push_leb(&mut section, data.len());
        section.extend_from_slice(data);
        module.push(11);
        push_leb(&mut module, section.len());
        module.extend_from_slice(&section);
    }
    module
}

#[test]
fn runtime_installation_requires_the_complete_abi() {
    for (index, &(name, _, _)) in EXPORTS.iter().enumerate() {
        let mut exported = EXPORTS.to_vec();
        exported.remove(index);
        let error = WasmRuntime::new(&runtime_module(b"\x42\x00", &[], &exported, &[]))
            .err()
            .expect("missing ABI export must reject installation");
        assert!(error.to_string().contains(name));

        let mut exported = EXPORTS;
        // Point the export at a function with the wrong kind or signature.
        exported[index] = (name, 0, if name == DEALLOCATE_ENTRYPOINT { 6 } else { 8 });
        let error = WasmRuntime::new(&runtime_module(b"\x42\x00", &[], &exported, &[]))
            .err()
            .expect("wrong ABI signature must reject installation");
        assert!(error.to_string().contains(name));
    }
}

#[test]
fn runtime_calls_propagate_deallocation_traps() {
    let runtime = WasmRuntime::new(&runtime_module(b"\x42\x00", &[], &EXPORTS, b"\x00"))
        .expect("complete ABI with trapping deallocator");
    let state = Trie::<Poseidon2Hasher>::default();
    let host = HostState::new(&state, true, runtime.limits.query_memory_bytes);
    assert!(matches!(
        runtime.invoke(QUERY_ENTRYPOINT, &[], host, runtime.limits.query_fuel),
        Err(WasmError::ResourceLimit(_))
    ));
}

fn runtime_returning(output: &RuntimeBlockOutput) -> WasmRuntime {
    let bytes = borsh::to_vec(&neutrin0_runtime_abi::RuntimeCallOutput::Block(
        neutrin0_runtime_abi::RuntimeBlockResult {
            output: output.clone(),
            artifacts: neutrin0_runtime_abi::ExecutionArtifacts::default(),
        }
        .into(),
    ))
    .unwrap();
    let mut body = vec![0x42]; // i64.const packed pointer 0 and length
    push_leb(&mut body, bytes.len());
    runtime_running_with_data(&body, &bytes)
}

#[test]
fn non_default_runtime_accepts_opaque_user_payloads() {
    use neutrin0_runtime_abi::RuntimeTransaction;
    let state = Trie::<Poseidon2Hasher>::default();
    let input = RuntimeBlockInput {
        active_validators: Vec::new(),
        participation_acks: Vec::new(),
        program_pieces: Vec::new(),

        context: neutrin0_consensus_types::runtime::ConsensusExecutionContext::default(),
        evidence_anchor: neutrin0_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: 17,
        block_height: 1,
        block_gas_limit: 100,
        proposer_address: [4; 32],
        participation: None,
        proving: None,
        transactions: vec![RuntimeTransaction::User(b"muri:create-order".to_vec())],
    };
    let (transactions_root, transaction_summary) =
        neutrin0_runtime_core::execution::transaction_commitments(&input.transactions);
    let output = RuntimeBlockOutput {
        context: neutrin0_consensus_types::runtime::ConsensusExecutionContext::default(),
        accountability: neutrin0_runtime_abi::AccountabilityOutput {
            anchor: input.evidence_anchor,
            ..Default::default()
        },
        chain_id: input.chain_id,
        block_height: input.block_height,
        block_gas_limit: input.block_gas_limit,
        proposer_address: input.proposer_address,
        pre_state_root: state.root(),
        post_state_root: state.root(),
        transactions_root,
        transaction_summary,
        receipts_root: neutrin0_runtime_abi::ExecutionArtifacts::default().commitment(),
        applied: 1,
        gas_used: 1,
        ..Default::default()
    };
    let dry = runtime_returning(&output)
        .dry_run(&input, &state, &[])
        .unwrap();
    assert_eq!(dry.output, output);
    assert_eq!(dry.post_state.root(), state.root());

    // A different runtime cannot return declarations for different inputs
    // or roots while the host commits the actual scratch state.
    for forged in [
        RuntimeBlockOutput {
            context: neutrin0_consensus_types::runtime::ConsensusExecutionContext::default(),
            chain_id: 18,
            ..output.clone()
        },
        RuntimeBlockOutput {
            transactions_root: [9; 32],
            ..output.clone()
        },
        RuntimeBlockOutput {
            post_state_root: [9; 32],
            ..output.clone()
        },
        RuntimeBlockOutput {
            gas_used: 101,
            ..output
        },
    ] {
        assert!(
            runtime_returning(&forged)
                .dry_run(&input, &state, &[])
                .is_err()
        );
    }
}

/// Query and admission errors of a runtime running `body` over state
/// holding key `[0]`.
fn errors_of(body: &[u8]) -> [WasmError; 2] {
    let runtime = runtime_running(body);
    let mut live = Trie::<Poseidon2Hasher>::default();
    live.insert(&[0], b"v".to_vec()).expect("test state");
    let request = QueryRequest {
        method: "any".to_owned(),
        args: Vec::new(),
    };
    let query = runtime.query(&request, &live);
    let admission = runtime.validate_tx(&[], 1, 1, &live);
    [
        query.expect_err("query traps"),
        admission.expect_err("admission traps"),
    ]
}

#[test]
fn reading_nothing_pending_traps_instead_of_panicking() {
    for body in [READ_INTO_UNREAD, READ_INTO_ABSENT] {
        for err in errors_of(body) {
            assert!(matches!(err, WasmError::Wasmtime(_)), "{err}");
        }
    }
}

#[test]
fn import_ranges_outside_memory_trap_as_memory_faults() {
    for body in [
        READ_LEN_OUTSIDE,
        WRITE_KEY_OUTSIDE,
        WRITE_VALUE_OUTSIDE,
        DELETE_OUTSIDE,
        READ_INTO_OUTSIDE,
        PRE_ROOT_OUTSIDE,
        POST_ROOT_OUTSIDE,
    ] {
        for err in errors_of(body) {
            assert!(matches!(err, WasmError::ResourceLimit(_)), "{err}");
        }
    }
}

#[test]
fn a_block_entrypoint_that_never_returns_exhausts_its_fuel() {
    // `loop br 0 end`, then the unreachable packed output.
    let runtime = runtime_running(b"\x03\x40\x0c\x00\x0b\x42\x00")
        .with_limits(WasmLimits {
            block_fuel: 1_000_000,
            ..WasmLimits::default()
        })
        .expect("valid limits");
    let input = RuntimeBlockInput {
        active_validators: Vec::new(),
        participation_acks: Vec::new(),
        program_pieces: Vec::new(),

        context: neutrin0_consensus_types::runtime::ConsensusExecutionContext::default(),
        evidence_anchor: neutrin0_consensus_types::evidence::EvidenceAnchor::default(),
        chain_id: 1,
        block_height: 1,
        block_gas_limit: 1,
        proposer_address: [0; 32],
        participation: None,
        proving: None,
        transactions: Vec::new(),
    };
    let Err(err) = runtime.dry_run(&input, &Trie::<Poseidon2Hasher>::default(), &[]) else {
        panic!("a spinning block traps");
    };
    assert!(matches!(err, WasmError::ResourceLimit(_)), "{err}");
}

#[test]
fn output_ranges_outside_memory_are_rejected_before_copying() {
    for err in errors_of(HUGE_OUTPUT) {
        assert!(matches!(err, WasmError::Wasmtime(_)), "{err}");
    }
}

#[test]
fn guest_ranges_and_state_keys_are_bounded() {
    let memory = [0_u8; 8];
    assert_eq!(guest_slice(&memory, 8, 0), Some(&[][..]));
    assert_eq!(guest_slice(&memory, 4, 4), Some(&memory[4..]));
    assert_eq!(guest_slice(&memory, 4, 5), None);
    assert_eq!(guest_slice(&memory, 9, 0), None);
    assert_eq!(guest_slice(&memory, u32::MAX, u32::MAX), None);
    // The trie prefixes a four-byte length and counts the bits in a u32.
    let bits = |key_len: usize| u32::try_from((key_len + 4) * 8);
    assert!(bits(MAX_STATE_KEY_BYTES).is_ok());
    assert!(bits(MAX_STATE_KEY_BYTES + 1).is_err());
}
