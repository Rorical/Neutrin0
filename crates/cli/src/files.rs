//! Replacing operator files without a window in which they are partial.
#![allow(
    clippy::redundant_pub_crate,
    reason = "Binary-internal helpers shared by sibling command modules."
)]

use std::fs;
use std::io::Write;
use std::path::Path;

/// Replace `path` with `bytes` through a synced sibling renamed over it, so
/// a crash or full disk leaves the old file or the new one, never a
/// truncated mix. An existing file keeps its permissions.
pub(super) fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let describe = |error: std::io::Error| format!("write {}: {error}", path.display());
    let staged = path.with_extension("partial");
    let mut file = fs::File::create(&staged).map_err(describe)?;
    if let Ok(existing) = fs::metadata(path) {
        file.set_permissions(existing.permissions())
            .map_err(describe)?;
    }
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&staged, path))
        .map_err(|error| {
            let _ = fs::remove_file(&staged);
            describe(error)
        })?;
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(describe)
}

#[cfg(test)]
mod tests;
