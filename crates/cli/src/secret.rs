//! Owner-only key files: reading one 32-byte hex seed and creating new files.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Shared by the binary's command modules, not an exported library API."
)]

use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::path::Path;
use zeroize::Zeroizing;

/// Read bounded owner-only key material without printing or retaining its textual seed.
///
/// # Errors
/// Refuses symlinks, special files, modes other than 600 on Unix, oversized
/// files and anything but exactly 32 hex-encoded bytes.
pub(super) fn read_seed(path: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "cannot read key file".to_owned())?;
    if !metadata.is_file() {
        return Err("key path must be a regular file, not a symlink".into());
    }
    let file = File::open(path).map_err(|_| "cannot open key file".to_owned())?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect key file".to_owned())?;
    if !metadata.is_file() {
        return Err("key must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o7777 != 0o600 {
            return Err("key file must have mode 600".into());
        }
    }
    let mut text = Zeroizing::new(String::new());
    file.take(4097)
        .read_to_string(&mut text)
        .map_err(|_| "cannot read key material".to_owned())?;
    if text.len() > 4096 {
        return Err("key file exceeds size limit".into());
    }
    let text = text.trim();
    let value = text.strip_prefix("0x").unwrap_or(text);
    let mut seed = Zeroizing::new([0; 32]);
    hex::decode_to_slice(value, seed.as_mut())
        .map_err(|_| "key file must contain exactly 32 bytes encoded as hex".to_owned())?;
    Ok(seed)
}

/// Write `bytes` to a new owner-only file and sync it, refusing to overwrite.
pub(super) fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|err| format!("create {}: {err}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|err| format!("write {}: {err}", path.display()))
}

/// Write `contents` to a new owner-only file, refusing to overwrite.
pub(super) fn write_secret(path: &Path, contents: &str) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|err| format!("create {}: {err}", path.display()))?;
    writeln!(file, "{contents}").map_err(|err| format!("write {}: {err}", path.display()))
}
