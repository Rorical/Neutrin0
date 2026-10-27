//! Native preflight of a governed EVM program switch over waiting chunks.
#[path = "support/evm_acceptance.rs"]
pub mod evm_acceptance;
use evm_acceptance::*;
pub use evm_acceptance::{acceptance, support};

use neutrin0_primitives::blake3_256;
use neutrin0_prover_chunk::consensus::validate_consensus_with_context;
use neutrin0_runtime_core::host::{LiveTrie, TracingState};
use neutrin0_runtime_host::wasm::{EVM_MASTER_WASM, WasmRuntime};

#[test]
fn governed_upgrade_native_preflight_checks_waiting_chunks() {
    let programs = support::programs([6; 8], blake3_256(EVM_MASTER_WASM));
    let wasm = upgrade_wasm();
    let mut upgraded = programs;
    upgraded.runtime_code_hash = blake3_256(&wasm);
    upgraded.execution.block = [9; 8];
    let genesis = upgrade_genesis_input(programs, 0, true);
    let (mut witness, mut input, _, live) = upgrade_fixture(
        programs,
        support::chunk_program(),
        &genesis,
        vec![
            transaction(
                0,
                neutrin0_evm_runtime_core::addresses::GOVERNANCE,
                upgrade_call(
                    upgraded,
                    &wasm,
                    b"preflight-only-artifact",
                    UPGRADE_ACTIVATION_CHUNK,
                ),
            ),
            transaction_with_key(
                8,
                0,
                neutrin0_evm_runtime_core::addresses::GOVERNANCE,
                upgrade_vote_call(
                    upgraded,
                    &wasm,
                    b"preflight-only-artifact",
                    UPGRADE_ACTIVATION_CHUNK,
                ),
                200_000,
            ),
        ],
    );
    let dry = WasmRuntime::new(EVM_MASTER_WASM)
        .unwrap()
        .dry_run(&input, live.trie(), &[])
        .unwrap();
    let mut post = LiveTrie::from_trie(dry.post_state);
    // The chunks after the governance block publish both changed programs.
    let mut batches =
        publication_batches(&[wasm.as_slice(), b"preflight-only-artifact"]).into_iter();
    for id in 0..UPGRADE_ACTIVATION_CHUNK {
        let schedule =
            neutrin0_runtime_system::governance::load_scheduled(&mut TracingState::new(&post))
                .unwrap();
        assert_eq!(schedule.activate_at_chunk, UPGRADE_ACTIVATION_CHUNK);
        let output = validate_consensus_with_context(&witness).unwrap();
        assert_eq!(
            output.statement.end.programs,
            if id + 1 == UPGRADE_ACTIVATION_CHUNK {
                upgraded
            } else {
                programs
            }
        );
        if id + 1 < UPGRADE_ACTIVATION_CHUNK {
            input.transactions.clear();
            let (next, next_input, _, next_post) = successor_publishing(
                &witness,
                input,
                &post,
                vec![],
                EVM_MASTER_WASM,
                batches.next().unwrap_or_default(),
            );
            witness = next;
            input = next_input;
            post = next_post;
        }
    }
}
