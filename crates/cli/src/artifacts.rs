//! Upgrade artifact commands: `program-hash` and `runtime-package`.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Entry points are private binary implementation, not exported library APIs."
)]

use std::fs;
use std::io::Write as _;

use crate::Options;

/// Content hash an upgrade proposal names for a runtime or Guest artifact.
pub(super) fn program_hash(opts: &Options) -> Result<(), String> {
    let path = opts
        .get("file")
        .ok_or_else(|| "program-hash requires --file <path>".to_owned())?;
    let bytes = fs::read(path).map_err(|error| format!("read {path}: {error}"))?;
    let kind = match neutrin0_node::programs::ArtifactKind::of(&bytes) {
        neutrin0_node::programs::ArtifactKind::Wasm => "wasm",
        neutrin0_node::programs::ArtifactKind::Elf => "elf",
        neutrin0_node::programs::ArtifactKind::Unknown => "unknown",
    };
    let hash = neutrin0_node::programs::content_hash(&bytes)
        .ok_or_else(|| "artifact is empty or exceeds the 16 MiB protocol bound".to_owned())?;
    println!(
        "{} {kind} {} bytes",
        neutrin0_node::programs::hex_hash(&hash),
        bytes.len()
    );
    Ok(())
}

pub(super) fn runtime_package(opts: &Options) -> Result<(), String> {
    let path = opts.require("out")?;
    let read = |flag| -> Result<Vec<u8>, String> {
        use std::io::Read as _;
        let path = opts.require(flag)?;
        let limit = if flag == "genesis" {
            neutrin0_runtime_host::package::MAX_RUNTIME_PACKAGE_BYTES
        } else {
            neutrin0_runtime_host::package::MAX_RUNTIME_ARTIFACT_BYTES
        };
        let mut bytes = Vec::new();
        fs::File::open(path)
            .and_then(|file| file.take(limit as u64 + 1).read_to_end(&mut bytes))
            .map_err(|error| format!("read {path}: {error}"))?;
        if bytes.len() > limit {
            return Err(format!("{flag} file exceeds its {limit}-byte limit"));
        }
        Ok(bytes)
    };
    let fact = if opts.has("fact") {
        read("fact")?
    } else {
        neutrin0_runtime_host::FACT_GUEST_ELF.to_vec()
    };
    let evidence = if opts.has("evidence") {
        read("evidence")?
    } else {
        neutrin0_runtime_host::EVIDENCE_GUEST_ELF.to_vec()
    };
    let package = neutrin0_runtime_host::package::RuntimePackage::from_artifacts(
        read("wasm")?,
        fact,
        evidence,
        read("block")?,
        read("genesis")?,
    )
    .map_err(|error| error.to_string())?;
    let encoded = package.encode().map_err(|error| error.to_string())?;
    let distribution = package
        .distribution_artifacts()
        .map_err(|error| error.to_string())?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create {path}: {error}"))?;
    file.write_all(&encoded)
        .map_err(|error| error.to_string())?;
    println!(
        "runtime_code_hash = {}",
        hex::encode(package.programs.runtime_code_hash)
    );
    // Little-endian VK bytes: the spec file's and the proposal interface's form.
    let vk = neutrin0_node::chain_spec::vk_hex;
    println!("fact_guest_vk = {}", vk(&package.programs.execution.fact));
    println!(
        "evidence_guest_vk = {}",
        vk(&package.programs.execution.evidence)
    );
    println!("block_guest_vk = {}", vk(&package.programs.execution.block));
    println!("# Governance program-lane content hashes (distinct from raw BLAKE3 checksums)");
    println!(
        "runtime_artifact_hash = {}",
        hex::encode(distribution.runtime)
    );
    println!("fact_artifact_hash = {}", hex::encode(distribution.fact));
    println!(
        "evidence_artifact_hash = {}",
        hex::encode(distribution.evidence)
    );
    println!("block_artifact_hash = {}", hex::encode(distribution.block));
    println!("wrote {path} ({} bytes)", encoded.len());
    Ok(())
}
