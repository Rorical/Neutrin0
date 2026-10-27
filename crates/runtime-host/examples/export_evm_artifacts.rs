#![deny(unsafe_code)]
//! Export the exact final programs embedded in the locked host build.
//! This performs no key setup, execution or proving.

use neutrin0_runtime_host::{
    CONSENSUS_CHUNK_GUEST_ELF, EVIDENCE_GUEST_ELF, EVM_GUEST_ELF, FACT_GUEST_ELF,
    wasm::EVM_MASTER_WASM,
};
use std::{
    error::Error,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

fn save(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension("export.tmp");
    let mut file = fs::File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temporary, path)
}

fn main() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("usage: export_evm_artifacts <artifact-directory>")?,
    );
    fs::create_dir_all(&directory)?;
    let artifacts: [(&str, &[u8]); 5] = [
        ("evm-optimized.elf", &EVM_GUEST_ELF),
        ("evm.wasm", EVM_MASTER_WASM),
        ("fact.elf", &FACT_GUEST_ELF),
        ("evidence.elf", &EVIDENCE_GUEST_ELF),
        ("chunk.elf", &CONSENSUS_CHUNK_GUEST_ELF),
    ];
    let mut manifest = Vec::new();
    for (name, bytes) in artifacts {
        save(&directory.join(name), bytes)?;
        manifest.push(serde_json::json!({
            "file": name, "bytes": bytes.len(),
            "raw_blake3": hex::encode(neutrin0_primitives::blake3_256(bytes)),
        }));
    }
    let manifest = serde_json::json!({
        "sp1_circuit": sp1_sdk::SP1_CIRCUIT_VERSION,
        "artifacts": manifest,
    });
    save(
        &directory.join("embedded-programs.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}
