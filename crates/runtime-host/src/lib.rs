#![deny(unsafe_code)]

//! SP1 prover/verifier and WASM dynamic runtime host for Neutrin0.
//!
//! Exposes execution and proof orchestration entry points:
//!
//! - [`dry_run`] — native dry-run against a [`LiveTrie`] using a
//!   [`TracingState`]; returns the recorded [`StateWitness`] plus the
//!   candidate [`RuntimeBlockOutput`]. Convenient for tests.
//! - [`wasm::WasmRuntime::dry_run`] — the production dry-run path:
//!   loads the master cdylib in wasmtime, runs `apply_block` against
//!   live state through host imports, and captures the witness the
//!   SP1 Guest will replay.
//! - [`prove_with`] / [`prove`] — borsh-encode `(RuntimeBlockInput, StateWitness)`
//!   into the SP1 stdin, run the guest, and return the proof bundle.
//! - [`verify_with`] / [`verify`] — verify a proof, decode the committed
//!   [`RuntimeBlockOutput`], and check it equals the caller's expected
//!   output, so a tampered `post_state_root` is rejected.
//!
//! [`LiveTrie`]: neutrin0_runtime_core::host::LiveTrie
//! [`TracingState`]: neutrin0_runtime_core::host::TracingState
//! [`StateWitness`]: neutrin0_runtime_abi::StateWitness
//! [`RuntimeBlockOutput`]: neutrin0_runtime_abi::RuntimeBlockOutput

#[cfg(panic = "abort")]
compile_error!(
    "runtime-host requires panic=unwind to contain adversarial receipt verifier failures"
);

pub mod backend;
mod block_proving;
mod bounded_cache;
mod dry_run;
mod embedded;
mod error;
pub mod evidence;
mod evidence_prover;
pub mod executor;
mod fact_cache;
mod history;
mod native_bls;
pub mod package;
pub mod programs;
pub mod proof_system;
mod prover_ctx;
mod sp1_calls;
mod vk_cache;
pub mod wasm;

pub use backend::ProgramProver;
pub use block_proving::{BlockProof, prove, prove_with, verify, verify_with, vk_fingerprint};
pub use dry_run::{DryRun, dry_run};
pub use embedded::{
    CONSENSUS_CHUNK_GUEST_ELF, EVIDENCE_GUEST_ELF, EVM_GUEST_ELF, FACT_GUEST_ELF,
    embedded_runtime_code_hash, expect_runtime_code_hash,
};
pub use error::Sp1HostError;
pub use executor::{
    BlockWitness, ExecutorError, WasmExecutor, decode_witness_bundle, encode_witness_bundle,
};
pub use proof_system::{Sp1BlockProof, Sp1ProofSystem};
pub use prover_ctx::{ProverCtx, default_ctx};
pub use vk_cache::set_cache_dir;

pub(crate) use block_proving::block_stdin;
pub(crate) use dry_run::state_writes;
pub(crate) use error::sdk_err;
pub(crate) use sp1_calls::{guarded, prove_compressed, push_receipt};
pub(crate) use vk_cache::{cache_dir, cached_proving_key, load_cached_vk_for, write_atomic};

#[cfg(test)]
mod tests;
