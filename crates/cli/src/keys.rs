//! Local key inspection and validator signing-protection transfer.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Entry points are private binary implementation, not exported library APIs."
)]

use std::fs;
use std::io::Read as _;
use std::path::Path;

use neutrin0_consensus_engine::ProposerKey;
use neutrin0_consensus_engine::signing_transfer::SigningTransfer;
use neutrin0_node::NodeDb;
use serde_json::{Value, json};

use crate::Options;

/// Largest transfer file read back; journals are pruned below finality.
const MAX_TRANSFER_BYTES: u64 = 256 * 1024 * 1024;

/// Public identities behind the given key files; secrets are never printed.
pub(super) fn inspect(opts: &Options) -> Result<(), String> {
    let mut report = serde_json::Map::new();
    if let Some(path) = opts.get("ikm-path") {
        let seed = crate::secret::read_seed(path)?;
        let proposer = ProposerKey::from_ikm(seed.as_ref(), 0).map_err(|err| err.to_string())?;
        report.insert(
            "bls_public_key".into(),
            json!(format!("0x{}", hex::encode(proposer.public_key_bytes()))),
        );
    }
    if let Some(path) = opts.get("keystore") {
        let keystore = neutrin0_keystore::Keystore::from_file(Path::new(path))?;
        report.insert(
            "keystore_public_key".into(),
            json!(format!(
                "0x{}",
                hex::encode(keystore.public_key().map_err(|err| err.to_string())?)
            )),
        );
    }
    if let Some(path) = opts.get("key-file") {
        let seed = crate::secret::read_seed(path)?;
        let account = neutrin0_crypto::secp256k1::SecretKey::from_bytes(&seed)
            .map_err(|_| "invalid secp256k1 key".to_owned())?;
        let address = account.public_key().ethereum_address();
        let mut credentials = [0; 32];
        credentials[12..].copy_from_slice(&address);
        report.insert(
            "address".into(),
            json!(format!("0x{}", hex::encode(address))),
        );
        report.insert(
            "withdrawal_credentials".into(),
            json!(format!("0x{}", hex::encode(credentials))),
        );
    }
    if let Some(path) = opts.get("network-key") {
        let peer_id = neutrin0_node::identity::read_peer_id(Path::new(path))
            .map_err(|err| err.to_string())?
            .ok_or_else(|| format!("{path} does not exist"))?;
        report.insert("peer_id".into(), json!(peer_id));
    }
    if report.is_empty() {
        return Err(
            "keys inspect needs --ikm-path, --keystore, --key-file or --network-key".into(),
        );
    }
    print_json(&Value::Object(report))
}

/// Write the BLS key of the IKM file `--ikm-path` as an EIP-2335 keystore at
/// `--out`, encrypted under the password in `--password-file`.
pub(super) fn encrypt(opts: &Options) -> Result<(), String> {
    let seed = crate::secret::read_seed(opts.require("ikm-path")?)?;
    let secret = neutrin0_crypto::bls::SecretKey::key_gen(seed.as_ref(), &[])
        .map_err(|err| err.to_string())?;
    let out = Path::new(opts.require("out")?);
    let name = out
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("validator");
    write_keystore(
        out,
        &secret,
        Path::new(opts.require("password-file")?),
        name,
    )?;
    print_json(&json!({
        "out": out.display().to_string(),
        "bls_public_key": format!("0x{}", hex::encode(secret.public_key().to_bytes())),
    }))
}

/// Encrypt `secret` under the password in `password_file` into the new
/// owner-only keystore file `path`, described as `description`.
pub(super) fn write_keystore(
    path: &Path,
    secret: &neutrin0_crypto::bls::SecretKey,
    password_file: &Path,
    description: &str,
) -> Result<(), String> {
    let password = neutrin0_keystore::read_password_file(password_file)?;
    if password.is_empty() {
        return Err(format!(
            "{} holds an empty password",
            password_file.display()
        ));
    }
    let keystore = neutrin0_keystore::Keystore::encrypt(secret, &password, description)
        .map_err(|err| err.to_string())?;
    crate::secret::write_new_file(
        path,
        keystore
            .to_json()
            .map_err(|err| err.to_string())?
            .as_bytes(),
    )
}

/// Copy a stopped validator's signing protection out of its data directory.
pub(super) fn export(opts: &Options) -> Result<(), String> {
    let data_dir = opts.require("data-dir")?;
    // Opening would otherwise create an empty database at a mistyped path.
    if !Path::new(data_dir).join("CURRENT").is_file() {
        return Err(format!("{data_dir} holds no node database"));
    }
    let db = open(data_dir)?;
    let transfer = SigningTransfer::export(&db)?;
    let out = opts.require("out")?;
    let bytes = borsh::to_vec(&transfer).map_err(|err| err.to_string())?;
    crate::secret::write_new_file(Path::new(out), &bytes)?;
    print_json(&summary(&transfer, out))
}

/// Install exported signing protection into a data directory before the
/// validator first starts there.
pub(super) fn import(opts: &Options) -> Result<(), String> {
    let path = opts.require("file")?;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(MAX_TRANSFER_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|err| format!("read {path}: {err}"))?;
    if bytes.len() as u64 > MAX_TRANSFER_BYTES {
        return Err(format!("{path} exceeds the transfer size limit"));
    }
    let transfer: SigningTransfer =
        borsh::from_slice(&bytes).map_err(|err| format!("invalid transfer {path}: {err}"))?;
    let data_dir = opts.require("data-dir")?;
    fs::create_dir_all(data_dir).map_err(|err| format!("create {data_dir}: {err}"))?;
    let mut db = open(data_dir)?;
    transfer.import(&mut db)?;
    print_json(&summary(&transfer, data_dir))
}

/// RocksDB holds an exclusive lock, so this fails while the node runs.
pub(super) fn open(data_dir: &str) -> Result<NodeDb, String> {
    NodeDb::open_rocks(data_dir).map_err(|err| {
        format!("open {data_dir}: {err}; stop the node that uses this data directory first")
    })
}

fn summary(transfer: &SigningTransfer, location: &str) -> Value {
    json!({"location": location, "chain_spec_hash": format!("0x{}", hex::encode(transfer.chain_spec_hash)),
        "journal_entries": transfer.journal.len(), "bft_sessions": transfer.sessions.len(),
        "policy": transfer.policy.is_some()})
}

pub(super) fn print_json(value: &Value) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|err| err.to_string())?
    );
    Ok(())
}
