//! Hard-fork handoff between a predecessor's data directory and its
//! successor's (design 20).
//!
//! Governance schedules a fork by its count and the commitment of the
//! successor's pinned programs; the chain Guest ends the chain there. Once
//! the chunk before the count finalizes, the predecessor's node writes the
//! endpoint bundle into `<data_dir>/fork-endpoint` and stops: the successor's
//! specification without its programs, the endpoint snapshot, what the
//! directory retained beyond the endpoint (the carry) and the signing
//! protection. The successor's binary, started with a new `data_dir` and
//! `[bootstrap] fork_from` naming the predecessor's, completes the
//! specification with its own programs, which must be the ones governance
//! scheduled, writes it to `<data_dir>/chain-spec.toml`, and starts from the
//! bundle: the signing protection before anything is signed, the snapshot as
//! its start, the carry once. No database is rewritten in place.

use std::fmt::Write as _;
use std::fs;
use std::io::{BufWriter, Read as _, Write as _};
use std::path::{Path, PathBuf};

use neutrin0_consensus_engine::signing_transfer::SigningTransfer;
use neutrin0_consensus_types::history_proof::HistoryProof;
use neutrin0_primitives::{ChainSpec, PriorDomain};
use neutrin0_storage::Database;

use crate::chain_spec::{ChainSpecError, ChainSpecFile, pin_genesis_root};

/// Directory of the endpoint bundle inside the predecessor's data directory.
pub const ENDPOINT_DIR: &str = "fork-endpoint";
/// The successor's specification inside its data directory.
pub const SPEC_FILE: &str = "chain-spec.toml";
/// Exit status of a node whose chain ended at a hard fork's endpoint after it
/// wrote the bundle; process supervisors should not restart it.
pub const EXIT_FORK_ENDPOINT: u8 = 10;

/// The successor's specification without its `[programs]` table.
const TEMPLATE: &str = "successor.toml";
/// The endpoint snapshot file.
const SNAPSHOT: &str = "snapshot.bin";
/// The carry of what the predecessor retained beyond the endpoint.
const CARRY: &str = "carry.bin";
/// The predecessor's signing protection.
const SIGNING: &str = "signing.bin";
/// Bound on a signing transfer, as on the operator's own transfer files.
const MAX_SIGNING_BYTES: u64 = 256 * 1024 * 1024;

/// The successor's specification without its programs.
///
/// A predecessor's node writes it at the endpoint `proof` ends at: the
/// predecessor's file `raw` with its genesis state root pinned, since the
/// successor's programs would derive another, without its programs and with
/// the `[fork]` table.
///
/// # Errors
/// Refuses a proof of another specification or one that does not end at a
/// scheduled fork's count.
pub(crate) fn successor_template(
    raw: &str,
    spec: &ChainSpec,
    proof: &HistoryProof,
) -> Result<String, String> {
    let end = proof.end();
    if proof.statement.statement.chain.chain_spec_hash != spec.hash()
        || end.fork.is_none_or(|fork| fork.count != end.next_chunk_id)
    {
        return Err("the History proof does not end at this chain's fork".into());
    }
    let mut prior_domains = spec
        .fork
        .as_ref()
        .map(|fork| fork.prior_domains.clone())
        .unwrap_or_default();
    prior_domains.push(PriorDomain {
        chain_spec_hash: spec.hash(),
        end_chunk: end.next_chunk_id,
        end_height: end.height,
    });
    if prior_domains.len() > neutrin0_primitives::MAX_PRIOR_DOMAINS {
        return Err(format!(
            "a successor would carry {} predecessor domains; a specification holds at most {}",
            prior_domains.len(),
            neutrin0_primitives::MAX_PRIOR_DOMAINS
        ));
    }
    let kept = strip_tables(raw, &["programs", "fork", "fork.prior_domains"]);
    let kept = pin_genesis_root(&kept, &hex::encode(spec.genesis_state_root));
    let mut text = format!(
        "{}\n\n[fork]\npredecessor_hex = \"{}\"\nendpoint_hex = \"{}\"\nendpoint_prover_hex = \"{}\"\n",
        kept.trim_end(),
        hex::encode(spec.hash()),
        hex::encode(borsh::to_vec(end).map_err(|error| error.to_string())?),
        hex::encode(proof.statement.chunk_prover_address),
    );
    for prior in &prior_domains {
        let _ = write!(
            text,
            "\n[[fork.prior_domains]]\nchain_spec_hash_hex = \"{}\"\nend_chunk = {}\nend_height = {}\n",
            hex::encode(prior.chain_spec_hash),
            prior.end_chunk,
            prior.end_height,
        );
    }
    Ok(text)
}

/// `template` completed with this binary's embedded programs, and the
/// specification it derives. Derivation refuses programs other than the
/// ones the predecessor's endpoint schedules.
///
/// # Errors
/// Returns a template or programs that derive no specification.
pub fn complete_successor(template: &str) -> Result<(String, ChainSpec), ChainSpecError> {
    let mut file = ChainSpecFile::from_toml_str(template)?;
    file.pin_embedded_programs()?;
    let programs = file.programs_toml().ok_or_else(|| {
        ChainSpecError::Validation("the successor has no [programs] table".into())
    })?;
    let text = format!("{}\n\n{programs}", template.trim_end());
    let spec = ChainSpecFile::from_toml_str(&text)?.to_chain_spec()?;
    Ok((text, spec))
}

/// The bundle a successor starts from: the predecessor's endpoint files.
#[derive(Clone, Debug)]
pub struct Handoff {
    /// The predecessor's endpoint bundle directory.
    pub bundle: PathBuf,
    /// The successor's specification in its own data directory.
    pub spec_path: PathBuf,
}

impl Handoff {
    /// Locate the endpoint bundle of the predecessor at `fork_from` and make
    /// sure `data_dir` holds the successor's specification.
    ///
    /// The first start derives it from the bundle and this binary's
    /// programs. Later starts read the written specification and need the
    /// bundle only until the handoff completes.
    ///
    /// # Errors
    /// Returns a missing bundle before the first derivation, and every
    /// derivation and write failure.
    pub fn prepare(fork_from: &Path, data_dir: &Path) -> Result<Self, String> {
        let bundle = fork_from.join(ENDPOINT_DIR);
        let spec_path = data_dir.join(SPEC_FILE);
        if !spec_path.is_file() {
            let template = fs::read_to_string(bundle.join(TEMPLATE)).map_err(|error| {
                format!(
                    "{} holds no fork endpoint bundle ({error}); run the predecessor's node until it stops at the fork",
                    fork_from.display()
                )
            })?;
            let (text, spec) = complete_successor(&template).map_err(|error| error.to_string())?;
            fs::create_dir_all(data_dir).map_err(|error| error.to_string())?;
            write_atomically(&spec_path, text.as_bytes())?;
            tracing::info!(
                chain_spec_hash = %hex::encode(spec.hash()),
                fork_count = spec.first_chunk(),
                path = %spec_path.display(),
                "hard fork successor specification derived"
            );
        }
        Ok(Self { bundle, spec_path })
    }

    /// The endpoint snapshot file.
    #[must_use]
    pub fn snapshot(&self) -> PathBuf {
        self.bundle.join(SNAPSHOT)
    }

    /// The carry file.
    #[must_use]
    pub fn carry(&self) -> PathBuf {
        self.bundle.join(CARRY)
    }

    /// Move the predecessor's signing protection into `db`, the successor's
    /// database, before its engine starts: only the proposer slot watermarks,
    /// rebound to `spec`. A database that already records a chain, from an
    /// earlier start or this import, is left alone.
    ///
    /// # Errors
    /// Returns an unreadable transfer and every transfer `spec` refuses.
    pub fn import_signing<DB: Database>(&self, db: &mut DB, spec: &ChainSpec) -> Result<(), String>
    where
        DB::Error: core::fmt::Display,
    {
        if SigningTransfer::recorded_chain(db)?.is_some() {
            return Ok(());
        }
        let path = self.bundle.join(SIGNING);
        let mut bytes = Vec::new();
        fs::File::open(&path)
            .and_then(|file| file.take(MAX_SIGNING_BYTES + 1).read_to_end(&mut bytes))
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if bytes.len() as u64 > MAX_SIGNING_BYTES {
            return Err(format!(
                "{} exceeds the transfer size limit",
                path.display()
            ));
        }
        let transfer: SigningTransfer = borsh::from_slice(&bytes)
            .map_err(|error| format!("invalid transfer {}: {error}", path.display()))?;
        transfer.for_successor(spec)?.import(db)
    }
}

/// Write the endpoint bundle into `<data_dir>/fork-endpoint`.
///
/// It is staged in a sibling directory and renamed into place once every
/// file is durable, so a bundle that exists is complete. `write_snapshot`,
/// `write_carry` and the signing `transfer` supply the node's own data.
///
/// # Errors
/// Returns every write failure; the staged directory is replaced next time.
pub(crate) fn write_bundle(
    data_dir: &Path,
    template: &str,
    transfer: &SigningTransfer,
    write_snapshot: impl FnOnce(&Path) -> Result<(), String>,
    write_carry: impl FnOnce(&mut BufWriter<fs::File>) -> Result<(), String>,
) -> Result<PathBuf, String> {
    let bundle = data_dir.join(ENDPOINT_DIR);
    let staged = data_dir.join(format!("{ENDPOINT_DIR}.partial"));
    if staged.exists() {
        fs::remove_dir_all(&staged).map_err(|error| error.to_string())?;
    }
    fs::create_dir_all(&staged).map_err(|error| error.to_string())?;
    write_new(&staged.join(TEMPLATE), template.as_bytes())?;
    write_new(
        &staged.join(SIGNING),
        &borsh::to_vec(transfer).map_err(|error| error.to_string())?,
    )?;
    write_snapshot(&staged.join(SNAPSHOT))?;
    let carry = new_file(&staged.join(CARRY))?;
    let mut writer = BufWriter::new(carry);
    write_carry(&mut writer)?;
    writer
        .into_inner()
        .map_err(|error| error.to_string())?
        .sync_all()
        .map_err(|error| error.to_string())?;
    fs::rename(&staged, &bundle).map_err(|error| error.to_string())?;
    sync_dir(data_dir)?;
    Ok(bundle)
}

/// `raw` without the TOML tables named `names`: each header line through the
/// line before the next header.
fn strip_tables(raw: &str, names: &[&str]) -> String {
    let mut kept = Vec::new();
    let mut skipping = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            let name = trimmed.trim_matches(|c| c == '[' || c == ']').trim();
            skipping = names.contains(&name);
        }
        if !skipping {
            kept.push(line);
        }
    }
    let mut text = kept.join("\n");
    text.push('\n');
    text
}

/// A new owner-only file at `path`.
fn new_file(path: &Path) -> Result<fs::File, String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = new_file(path)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write {}: {error}", path.display()))
}

/// Replace `path` with `bytes` through a durable temporary sibling.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let staged = path.with_extension("partial");
    if staged.exists() {
        fs::remove_file(&staged).map_err(|error| error.to_string())?;
    }
    write_new(&staged, bytes)?;
    fs::rename(&staged, path).map_err(|error| error.to_string())?;
    sync_dir(path.parent().unwrap_or_else(|| Path::new(".")))
}

fn sync_dir(dir: &Path) -> Result<(), String> {
    fs::File::open(dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|error| format!("sync {}: {error}", dir.display()))
}

#[cfg(test)]
mod tests;
