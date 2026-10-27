//! The `genesis` command: derive and optionally pin a chain specification's genesis root.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Entry points are private binary implementation, not exported library APIs."
)]

use std::fs;
use std::path::PathBuf;

use neutrin0_node::{ChainSpecFile, build_genesis_state};

use crate::Options;

pub(super) fn genesis(opts: &Options) -> Result<(), String> {
    let spec_path = PathBuf::from(opts.require("spec")?);
    let mut file = ChainSpecFile::load_from_path(&spec_path).map_err(|err| err.to_string())?;
    // A new specification pins the programs this binary embeds; an existing
    // pin is kept and must be reproduced.
    if file.programs.is_none() {
        file.pin_embedded_programs()
            .map_err(|err| err.to_string())?;
    }
    let state = build_genesis_state(&file).map_err(|err| err.to_string())?;
    let root_hex = hex::encode(state.root);
    let mut pinned = file;
    pinned.genesis_state_root_hex = Some(root_hex.clone());
    let spec = pinned.to_chain_spec().map_err(|err| err.to_string())?;

    println!("genesis_state_root_hex     = \"{root_hex}\"");
    println!(
        "genesis_validator_set_root = {}",
        hex::encode(spec.genesis_validator_set_root)
    );
    println!("chain_spec_hash            = {}", hex::encode(spec.hash()));
    println!(
        "runtime_code_hash          = {}",
        hex::encode(spec.runtime_code_hash)
    );
    println!("accounts                   = {}", state.accounts);
    println!("staked_validators          = {}", state.staked_validators);
    println!(
        "initial_validators         = {}",
        spec.initial_validators.len()
    );
    // The pins a production spec carries, so a later binary embedding other
    // programs still derives this chain (and fetches these by content hash).
    let programs = pinned
        .programs_toml()
        .ok_or_else(|| "chain spec has no [programs] table".to_owned())?;
    println!("# chain-spec.toml program pins\n{programs}");

    if opts.has("write") {
        let raw = fs::read_to_string(&spec_path)
            .map_err(|err| format!("read {}: {err}", spec_path.display()))?;
        let mut updated = neutrin0_node::chain_spec::pin_genesis_root(&raw, &root_hex);
        if !raw.lines().any(|line| line.trim() == "[programs]") {
            updated = format!("{}\n{programs}", updated.trim_end());
        }
        crate::files::replace_file(&spec_path, updated.as_bytes())?;
        println!("pinned genesis_state_root_hex into {}", spec_path.display());
    }
    Ok(())
}
