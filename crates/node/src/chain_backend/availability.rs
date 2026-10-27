//! Original signed source availability and delayed offence detection.

mod accountability;
mod pending_rejections;
mod sources;
mod verdicts;

pub(super) use pending_rejections::PendingRejections;
pub(super) use verdicts::{ProofVerdict, VerdictCache};

use super::{ChainBackend, reporter_retention, storage_error};
use neutrin0_consensus_types::signed_artifacts::{
    SignedArtifact, SignedArtifactKind, SignedArtifactRef,
};
use neutrin0_consensus_types::{BlockProof, FinalityVote};
use neutrin0_network::rpc::{SignedArtifactByIdResponse, SignedArtifactInventoryByChunkResponse};
use neutrin0_primitives::{ChunkId, Hash};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;

type Rejection = neutrin0_consensus_types::ProofRejectionReason;

/// Source identity of a block proof, equal to its `SignedArtifact::BlockProof`
/// id and its proof-manifest leaf: the envelope's tagged commitment.
pub(super) fn block_proof_source_id(proof: &BlockProof) -> Hash {
    neutrin0_consensus_types::evidence::commitment(proof)
}

fn deduplicate_source_votes(votes: &mut Vec<FinalityVote>) {
    let mut seen = std::collections::BTreeSet::new();
    votes.retain(|vote| seen.insert(SignedArtifact::Vote(vote.clone()).id()));
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Source inventories never extend local history or move its pruning boundary.
    pub(super) fn availability_source_known(&self, chunk_id: ChunkId) -> bool {
        self.with_engine(|engine| {
            let next = engine.finalized_next_chunk_id();
            if chunk_id == next {
                return true;
            }
            let retained = reporter_retention(engine)
                || neutrin0_consensus_types::history::is_recent_history_index(chunk_id, next);
            retained
                && engine
                    .store()
                    .historical_chunk(chunk_id)
                    .ok()
                    .flatten()
                    .is_some()
        })
    }

    /// Read one durable exact source, including bytes of rejected alternative proofs.
    pub(super) fn query_signed_artifact(
        &self,
        id: Hash,
    ) -> Result<SignedArtifactByIdResponse, SyncBackendError> {
        self.with_engine(|engine| {
            engine
                .store()
                .signed_artifact(&id)
                .map_err(storage_error)?
                .map(|(_, artifact)| SignedArtifactByIdResponse { artifact })
                .ok_or_else(|| SyncBackendError::NotAvailable("signed source unavailable".into()))
        })
    }

    /// Stable bounded inventory; archive providers can also serve older source rows.
    pub(super) fn query_signed_inventory(
        &self,
        chunk_id: ChunkId,
        after: Option<Hash>,
    ) -> Result<SignedArtifactInventoryByChunkResponse, SyncBackendError> {
        self.with_engine(|engine| {
            engine
                .store()
                .signed_artifact_inventory(chunk_id, after)
                .map_err(storage_error)
        })
    }

    /// Exact missing proof identities from authenticated declarations, bounded before
    /// driver admission. Earlier vote/lock sources are discovered by chunk inventory.
    pub(super) fn missing_signed_artifacts(&self, vote: &FinalityVote) -> Vec<SignedArtifactRef> {
        if !self.with_engine(|engine| {
            engine.validate_signed_artifact(&SignedArtifact::Vote(vote.clone()))
        }) {
            return Vec::new();
        }
        let Some(manifests) =
            neutrin0_consensus_types::ProofManifestIndex::new(&vote.proof_manifests)
        else {
            return Vec::new();
        };
        if !manifests.covers_exact(&vote.attestations) {
            return Vec::new();
        }
        let mut missing = Vec::new();
        for commitment in manifests.commitments() {
            let Some(manifest) = manifests.get(&commitment) else {
                continue;
            };
            for id in &manifest.proof_hashes {
                if missing.len() >= 128 {
                    return missing;
                }
                if !missing
                    .iter()
                    .any(|reference: &SignedArtifactRef| reference.id == *id)
                    && self
                        .with_engine(|engine| engine.store().signed_artifact_metadata_by_id(id))
                        .ok()
                        .flatten()
                        .is_none()
                {
                    missing.push(SignedArtifactRef {
                        id: *id,
                        kind: SignedArtifactKind::BlockProof,
                    });
                }
            }
        }
        missing
    }
}
