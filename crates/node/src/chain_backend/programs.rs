//! Installing on-chain program artifacts into the executor and proof backend.

mod fetch;
mod install;
mod restore;
mod retention;
#[cfg(test)]
mod tests;
mod wanted;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use neutrin0_consensus_types::{
    ProgramPiece,
    history_proof::{ProgramArtifacts, ProgramSet},
};
use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofSystem;
use neutrin0_proof_system::artifacts::ArtifactIdentity;
use neutrin0_storage::Database;

use super::ChainBackend;
use crate::programs::ArtifactKind;

/// The identity governance declared for a named artifact. An installed
/// artifact must produce exactly this identity or it is discarded.
pub(super) type ExpectedIdentity = ArtifactIdentity;

/// A program artifact being downloaded from peers fragment by fragment.
#[derive(Clone, Debug)]
pub(super) struct ProgramFetch {
    /// Identity the assembled bytes must reproduce.
    identity: ExpectedIdentity,
    /// Content hash the chain pins for the artifact, when it pins one: bytes
    /// with another are refused before any key derivation.
    content: Option<Hash>,
    /// Length every fragment declared, fixed by the first.
    total_len: Option<u64>,
    /// Bytes received so far, in order.
    bytes: Vec<u8>,
    /// When the last fragment arrived; indexing then runs in the background.
    assembled: Option<std::time::Instant>,
    /// Set when the assembled bytes do not reproduce `identity`, so the
    /// artifact is fetched again at once, from other providers.
    rejected: Arc<std::sync::atomic::AtomicBool>,
}

impl ProgramFetch {
    fn request(&self) -> neutrin0_consensus_types::bootstrap::StateItem {
        use neutrin0_consensus_types::bootstrap::StateItem;
        let item = match self.identity {
            ExpectedIdentity::Runtime(code_hash) => StateItem::runtime(code_hash),
            ExpectedIdentity::Guest(digest) => StateItem::guest(digest),
        };
        StateItem {
            offset: self.bytes.len() as u64,
            ..item
        }
    }
}

/// How long an assembled artifact may take to install before it is fetched again.
const PROGRAM_INSTALL_GRACE: std::time::Duration = std::time::Duration::from_secs(600);

/// Content hash to expected identity for every artifact the declarations
/// name; `None` when two declarations bind one hash to different identities.
fn named_artifacts(
    declarations: &[neutrin0_runtime_abi::operational::ProgramDistribution],
) -> Option<BTreeMap<Hash, ExpectedIdentity>> {
    let mut wanted = BTreeMap::new();
    for declaration in declarations {
        for (hash, identity) in expectations(&declaration.programs, &declaration.artifacts) {
            if wanted
                .insert(hash, identity)
                .is_some_and(|old| old != identity)
            {
                return None;
            }
        }
    }
    Some(wanted)
}

fn expectations(
    programs: &ProgramSet,
    artifacts: &ProgramArtifacts,
) -> impl Iterator<Item = (Hash, ExpectedIdentity)> {
    [
        (
            artifacts.runtime,
            ExpectedIdentity::Runtime(programs.runtime_code_hash),
        ),
        (
            artifacts.fact,
            ExpectedIdentity::Guest(programs.execution.fact),
        ),
        (
            artifacts.evidence,
            ExpectedIdentity::Guest(programs.execution.evidence),
        ),
        (
            artifacts.block,
            ExpectedIdentity::Guest(programs.execution.block),
        ),
    ]
    .into_iter()
    .filter(|(hash, _)| *hash != [0; 32])
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Feed an imported block's program lane to the store and install
    /// anything it completed. Only artifacts governance names are assembled.
    pub(super) fn absorb_programs(&self, pieces: &[ProgramPiece]) {
        if pieces.is_empty() {
            return;
        }
        let wanted = self.wanted_artifacts();
        let names: BTreeSet<Hash> = wanted.keys().copied().collect();
        if !self.program_store().absorb(pieces, &names).is_empty() {
            self.install_wanted(&wanted);
        }
    }

    /// Operator-facing program state for `programs_status`.
    pub fn programs_status(&self) -> neutrin0_rpc::ProgramsStatusJson {
        use neutrin0_rpc::{
            ArtifactProgressJson, HashHex, InstalledGuestJson, PersistedArtifactJson,
        };
        let status = self.program_store().status();
        let progress = |(hash, bytes, total): (Hash, u32, u32)| ArtifactProgressJson {
            content_hash: HashHex(hash),
            bytes,
            total,
        };
        neutrin0_rpc::ProgramsStatusJson {
            installed_guests: self
                .proof_system
                .installed_guests()
                .into_iter()
                .map(|(digest, elf_hash)| InstalledGuestJson {
                    digest,
                    elf_hash: HashHex(elf_hash),
                })
                .collect(),
            runtimes: self
                .block_executor_snapshot()
                .map(|executor| executor.installed_runtimes())
                .unwrap_or_default()
                .into_iter()
                .map(HashHex)
                .collect(),
            wanted: self
                .wanted_programs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .copied()
                .map(HashHex)
                .collect(),
            assembling: status.assembling.into_iter().map(progress).collect(),
            complete: status.complete.into_iter().map(HashHex).collect(),
            persisted: status
                .persisted
                .into_iter()
                .map(|(hash, kind)| PersistedArtifactJson {
                    content_hash: HashHex(hash),
                    kind: match kind {
                        ArtifactKind::Wasm => "wasm",
                        ArtifactKind::Elf => "elf",
                        ArtifactKind::Unknown => "unknown",
                    }
                    .to_owned(),
                })
                .collect(),
            publishing: status.publishing.map(progress),
            queued_publications: u64::try_from(status.publish_queue.len()).unwrap_or(u64::MAX),
            scheduled_missing: self
                .scheduled_missing_programs()
                .map(|missing| missing.into_iter().map(str::to_owned).collect()),
        }
    }
}
