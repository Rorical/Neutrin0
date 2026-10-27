//! Streaming locally published files into produced blocks, and the
//! operator-facing store status.

use std::fs;
use std::path::{Path, PathBuf};

use neutrin0_consensus_types::ProgramPiece;

use super::{ProgramStore, ProgramStoreStatus, Publishing, split_into_pieces};

impl ProgramStore {
    /// Next pieces for a produced block, at most `max_pieces`, drawn from the
    /// publish directory.
    #[must_use]
    pub fn next_pieces(&self, max_pieces: usize) -> Vec<ProgramPiece> {
        let Some(dir) = &self.dir else {
            return Vec::new();
        };
        let mut publishing = self
            .publishing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut pieces = Vec::new();
        while pieces.len() < max_pieces {
            if publishing.is_none() {
                *publishing = Self::next_publish_file(dir);
            }
            let Some(current) = publishing.as_mut() else {
                break;
            };
            pieces.push(current.pieces[current.next].clone());
            current.next += 1;
            if current.next >= current.pieces.len() {
                let done = publishing.take().expect("current publication");
                let target = dir.join("published").join(
                    done.path
                        .file_name()
                        .map_or_else(|| "artifact".into(), std::ffi::OsStr::to_os_string),
                );
                let _ = fs::rename(&done.path, target);
            }
        }
        drop(publishing);
        pieces
    }

    fn next_publish_file(dir: &Path) -> Option<Publishing> {
        let mut files: Vec<PathBuf> = fs::read_dir(dir.join("publish"))
            .ok()?
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_file())
            .collect();
        files.sort();
        for path in files {
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let Some(pieces) = split_into_pieces(&bytes) else {
                let _ = fs::remove_file(&path);
                continue;
            };
            return Some(Publishing {
                content_hash: pieces[0].content_hash(),
                path,
                pieces,
                next: 0,
            });
        }
        None
    }

    /// Operator-facing snapshot.
    #[must_use]
    pub fn status(&self) -> ProgramStoreStatus {
        let assembling = self
            .partial
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(hash, entry)| {
                (
                    *hash,
                    u32::try_from(entry.bytes).unwrap_or(u32::MAX),
                    entry.total_len,
                )
            })
            .collect();
        let complete = self
            .complete
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .artifacts
            .keys()
            .copied()
            .collect();
        let persisted = self.persisted_summary();
        let publishing = self
            .publishing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|current| {
                (
                    current.content_hash,
                    u32::try_from(current.next).unwrap_or(u32::MAX),
                    u32::try_from(current.pieces.len()).unwrap_or(u32::MAX),
                )
            });
        let publish_queue = self
            .dir
            .as_ref()
            .and_then(|dir| fs::read_dir(dir.join("publish")).ok())
            .map(|entries| {
                let mut names: Vec<String> = entries
                    .flatten()
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .collect();
                names.sort();
                names
            })
            .unwrap_or_default();
        ProgramStoreStatus {
            assembling,
            complete,
            persisted,
            publishing,
            publish_queue,
        }
    }
}
