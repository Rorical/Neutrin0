//! Programs `build.rs` compiled into this binary and their identities.

use sp1_sdk::{Elf, include_elf};

/// Embedded Osaka EVM SP1 block Guest compiled by `build.rs`. The
/// production verifier pins this program's verifying key.
pub const EVM_GUEST_ELF: Elf = include_elf!("neutrin0-evm-runtime-guest");

/// Guest that verifies execution bindings, BLS finality, VRF, rotation and
/// the previous chunk's receipt. Evidence is the Evidence Guest's.
pub const CONSENSUS_CHUNK_GUEST_ELF: Elf = include_elf!("neutrin0-consensus-chunk-guest");

/// Independent objective-evidence guest, with the same pinned SP1 toolchain.
pub const EVIDENCE_GUEST_ELF: Elf = include_elf!("neutrin0-evidence-guest");

/// Program for early reusable cryptographic facts.
pub const FACT_GUEST_ELF: Elf = include_elf!("neutrin0-fact-guest");

/// BLAKE3 hash of the embedded runtime master WASM cdylib.
///
/// This is the value a chain spec's `runtime_code_hash` must match
/// for a node compiled with this binary to accept the spec. The hash
/// covers the WASM cdylib (the runtime the WASM full-node path
/// executes), not the SP1 Guest ELF — the two come from the same
/// source tree but go through different toolchains, and the chain's
/// identity is the value users see at RPC time.
///
/// Use [`expect_runtime_code_hash`] for the matching consistency
/// check at node startup.
#[must_use]
pub fn embedded_runtime_code_hash() -> [u8; 32] {
    neutrin0_primitives::blake3_256(crate::wasm::EVM_MASTER_WASM)
}

/// Validate that the chain specification names the embedded WASM runtime.
///
/// # Errors
/// Returns the declared and actual hashes when they differ.
pub fn expect_runtime_code_hash(chain_spec_hash: [u8; 32]) -> Result<(), ([u8; 32], [u8; 32])> {
    let actual = embedded_runtime_code_hash();
    if chain_spec_hash == actual {
        Ok(())
    } else {
        Err((chain_spec_hash, actual))
    }
}
