//! The programs a hard fork's successor pins (design 20).
#![allow(
    clippy::redundant_pub_crate,
    reason = "Entry points are private binary implementation, not exported library APIs."
)]

use neutrin0_node::ChainSpecFile;
use serde_json::json;

use crate::Options;

/// Print the programs this binary pins as a hard fork's successor.
///
/// It prints the `[programs]` table and its commitment, which a fork
/// proposal names and voters reproduce from their own build. `--spec` names
/// any specification file of the chain, whose pins are replaced by this
/// binary's.
pub(super) fn programs(opts: &Options) -> Result<(), String> {
    let path = opts.require("spec")?;
    let mut file = ChainSpecFile::load_from_path(path).map_err(|err| err.to_string())?;
    file.pin_embedded_programs()
        .map_err(|err| err.to_string())?;
    let pinned = file
        .pinned_programs()
        .map_err(|err| format!("{path}: {err}"))?;
    crate::keys::print_json(&json!({
        "successor": hex::encode(pinned.commitment()),
        "programs": file.programs_toml(),
    }))
}
