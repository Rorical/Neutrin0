//! Program-lane piece tracking: the artifacts an open program proposal or an
//! unavailable schedule names, and the point at which a schedule becomes
//! available (design 20, "Artifact availability").

#![allow(
    clippy::redundant_pub_crate,
    reason = "Block-start hooks stay explicitly crate-scoped inside this private module."
)]

use alloc::vec::Vec;

use neutrin0_consensus_types::history_proof::{ProgramArtifacts, ProgramSet};
use neutrin0_runtime_core::StateBackend;

use super::{
    ArtifactPieces, ProposalAction, UPGRADE_PIECES_KEY, load_proposals, load_scheduled,
    store_scheduled,
};
use crate::state::{read_record, write_record};

/// Load the program-lane pieces seen so far.
pub fn load_pieces<B: StateBackend>(state: &mut B) -> Vec<ArtifactPieces> {
    read_record(state, UPGRADE_PIECES_KEY).unwrap_or_default()
}

/// Artifacts whose pieces are being collected: those a stored program
/// proposal or an unavailable schedule names.
fn collected_artifacts<B: StateBackend>(state: &mut B) -> Vec<[u8; 32]> {
    let mut artifacts: Vec<[u8; 32]> = Vec::new();
    for proposal in load_proposals(state) {
        if let ProposalAction::Programs {
            artifacts: named, ..
        } = proposal.action
        {
            artifacts.extend(named.named());
        }
    }
    if let Some(scheduled) = load_scheduled(state).filter(|scheduled| !scheduled.available) {
        artifacts.extend(scheduled.artifacts.named());
    }
    artifacts.sort_unstable();
    artifacts.dedup();
    artifacts
}

/// The artifacts of the programs a switch from `current` to `next` changes;
/// an unchanged program's artifact is distributed only if named, never
/// required.
pub(super) fn changed_artifacts(
    current: &ProgramSet,
    next: &ProgramSet,
    artifacts: &ProgramArtifacts,
) -> impl Iterator<Item = [u8; 32]> {
    [
        (
            current.runtime_code_hash != next.runtime_code_hash,
            artifacts.runtime,
        ),
        (
            current.execution.evidence != next.execution.evidence,
            artifacts.evidence,
        ),
        (
            current.execution.block != next.execution.block,
            artifacts.block,
        ),
    ]
    .into_iter()
    .filter_map(|(changed, artifact)| changed.then_some(artifact))
}

/// Delete the piece record once nothing names an artifact being collected.
/// A missing record is left alone, so a block's write set never carries a
/// delete that changes nothing, and the proposals are read only behind one.
pub(super) fn forget_uncollected_pieces<B: StateBackend>(state: &mut B) {
    if state.read(UPGRADE_PIECES_KEY).is_some() && collected_artifacts(state).is_empty() {
        state.delete(UPGRADE_PIECES_KEY);
    }
}

/// Whether every artifact the switch from `current` to `next` changes was
/// completely published.
pub(super) fn published(
    pieces: &[ArtifactPieces],
    current: &ProgramSet,
    next: &ProgramSet,
    artifacts: &ProgramArtifacts,
) -> bool {
    changed_artifacts(current, next, artifacts).all(|artifact| {
        pieces
            .iter()
            .any(|entry| entry.artifact == artifact && entry.complete())
    })
}

/// Record a block's authenticated program-lane pieces of the artifacts being
/// collected, and mark a schedule available once every artifact of a program
/// it changes from `current` was seen in full. Runs at block start, before
/// transactions. A block without pieces changes nothing and reads nothing.
pub(crate) fn record_program_pieces<B: StateBackend>(
    state: &mut B,
    pieces: &[neutrin0_consensus_types::ProgramPieceRef],
    current: &ProgramSet,
) {
    if pieces.is_empty() {
        return;
    }
    let collected = collected_artifacts(state);
    let mut tracked = load_pieces(state);
    let before = tracked.clone();
    tracked.retain(|entry| collected.binary_search(&entry.artifact).is_ok());
    for piece in pieces {
        if collected.binary_search(&piece.artifact).is_err()
            || piece.count == 0
            || piece.count > 64
            || piece.index >= piece.count
        {
            continue;
        }
        let entry = if let Some(at) = tracked
            .iter()
            .position(|entry| entry.artifact == piece.artifact)
        {
            &mut tracked[at]
        } else {
            tracked.push(ArtifactPieces {
                artifact: piece.artifact,
                count: piece.count,
                received: 0,
            });
            tracked.last_mut().expect("just pushed")
        };
        if entry.count == piece.count {
            entry.received |= 1 << piece.index;
        }
    }
    if tracked != before {
        if tracked.is_empty() {
            state.delete(UPGRADE_PIECES_KEY);
        } else {
            write_record(state, UPGRADE_PIECES_KEY, &tracked);
        }
    }
    if let Some(mut scheduled) = load_scheduled(state).filter(|scheduled| !scheduled.available)
        && published(&tracked, current, &scheduled.programs, &scheduled.artifacts)
    {
        scheduled.available = true;
        store_scheduled(state, &scheduled);
        forget_uncollected_pieces(state);
    }
}
