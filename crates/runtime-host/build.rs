//! Builds five artefacts:
//! - the `neutrin0-evm-runtime-guest` ELF (block prover) via `sp1-build`,
//!   consumed by `lib.rs` through `include_elf!`,
//! - the `neutrin0-consensus-chunk-guest` ELF (full consensus),
//! - the `neutrin0-evidence-guest` ELF (batched objective offences),
//! - the `neutrin0-fact-guest` ELF (reusable cryptographic verdicts),
//! - the `neutrin0-evm-runtime-master` `wasm32-unknown-unknown` cdylib via
//!   a sub-cargo invocation; the resulting `.wasm` path is exposed to
//!   `lib.rs` via `NEUTRIN0_EVM_MASTER_WASM`.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    rerun_if_changed_runtime_sources();

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir
        .join("..")
        .join("..")
        .canonicalize()
        .expect("canonicalize workspace root");
    let remap = path_remapping(&workspace_root);

    // ----- SP1 Guest ELFs -----
    let guest_args = sp1_build::BuildArgs {
        locked: true,
        rustflags: remap.clone(),
        ..Default::default()
    };
    sp1_build::build_program_with_args("../runtimes/neutrin0-evm/guest", guest_args.clone());
    sp1_build::build_program_with_args("../prover-chunk/guest", guest_args);

    // ----- WASM master cdylib -----

    // Run cargo from the workspace root so it discovers the workspace
    // unambiguously. We isolate the wasm32 build into its own target
    // dir so it does not contend with the parent build's lock file.
    let wasm_target_dir = workspace_root.join("target").join("master-wasm");

    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(&cargo)
        .args([
            "build",
            "--target",
            "wasm32-unknown-unknown",
            "--profile",
            "runtime-artifact",
            "-p",
            "neutrin0-evm-runtime-master",
            "--locked",
        ])
        .current_dir(&workspace_root)
        .env("CARGO_TARGET_DIR", &wasm_target_dir)
        // Make sure we are NOT inheriting any host-rustflags that would
        // confuse the wasm build; only the path remapping applies.
        .env_remove("RUSTFLAGS")
        .env("CARGO_ENCODED_RUSTFLAGS", remap.join("\x1f"))
        .env_remove("CARGO_BUILD_RUSTFLAGS")
        // Clippy's workspace wrapper changes Cargo's crate metadata and
        // therefore the embedded runtime's code hash. Build the same master
        // artifact during ordinary builds and host lint checks.
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("CLIPPY_ARGS")
        .status()
        .expect("spawn cargo for wasm32 build");

    assert!(
        status.success(),
        "failed to build the runtime master for wasm32-unknown-unknown"
    );

    let evm_path = wasm_target_dir
        .join("wasm32-unknown-unknown")
        .join("runtime-artifact")
        .join("neutrin0_evm_runtime_master.wasm");
    assert!(evm_path.exists(), "EVM WASM build artifact missing");
    println!(
        "cargo:rustc-env=NEUTRIN0_EVM_MASTER_WASM={}",
        evm_path.display()
    );
}

/// Compiler flags mapping the checkout and the Cargo home to fixed prefixes.
///
/// Panic locations embed source paths, so without them an artifact's content
/// hash, which chain specifications pin, would depend on where the tree and
/// its dependencies were built rather than on the code alone.
fn path_remapping(workspace_root: &Path) -> Vec<String> {
    let cargo_home = env::var_os("CARGO_HOME").map_or_else(
        || PathBuf::from(env::var_os("HOME").expect("HOME or CARGO_HOME is set")).join(".cargo"),
        PathBuf::from,
    );
    let cargo_home = cargo_home.canonicalize().unwrap_or(cargo_home);
    vec![
        format!("--remap-path-prefix={}=/neutrin0", workspace_root.display()),
        format!("--remap-path-prefix={}=/cargo", cargo_home.display()),
    ]
}

fn rerun_if_changed_runtime_sources() {
    println!("cargo:rerun-if-env-changed=CARGO_HOME");
    for path in [
        "../runtime-system/src",
        "../runtime-system/Cargo.toml",
        "../runtimes/neutrin0-evm/core/src",
        "../runtimes/neutrin0-evm/core/Cargo.toml",
        "../runtimes/neutrin0-evm/master/Cargo.toml",
        "../runtimes/neutrin0-evm/guest/src",
        "../runtimes/neutrin0-evm/guest/Cargo.toml",
        "../runtimes/neutrin0-evm/guest/Cargo.lock",
        "../../Cargo.lock",
        "../../Cargo.toml",
        "../runtimes/neutrin0-evm/master/src",
        "../prover-chunk/guest/src",
        "../prover-chunk/guest/Cargo.toml",
        "../prover-chunk/guest/Cargo.lock",
        "../runtime-core/src",
        "../runtime-core/Cargo.toml",
        "../runtime-abi/src",
        "../runtime-abi/Cargo.toml",
        "../prover-chunk/src",
        "../prover-chunk/Cargo.toml",
        "../consensus-types/src",
        "../primitives/src",
        "../vrf/src",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
}
