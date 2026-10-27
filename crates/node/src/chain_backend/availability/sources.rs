//! Durable retention of signed sources before publication, and their
//! bounded inventory announcements.

use neutrin0_consensus_types::signed_artifacts::{
    SignedArtifact, SignedArtifactInventory, SignedArtifactRef,
};
use neutrin0_consensus_types::{BlockProof, FinalityVote};
use neutrin0_network::Topic;
use neutrin0_primitives::{ChunkId, Hash};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use neutrin0_sync::EvidenceProofAcceptance;

use super::verdicts::{ProofVerdict, VerdictToken};
use super::{ChainBackend, block_proof_source_id, storage_error};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Persist before publishing and then replay delayed prior-lock dependencies.
    pub(in crate::chain_backend) async fn retain_availability_vote(
        &self,
        vote: &FinalityVote,
    ) -> bool {
        self.accept_signed_source(SignedArtifact::Vote(vote.clone()))
            .await
            == EvidenceProofAcceptance::Accepted
    }

    /// Authenticate fetched sources through the same signing and evidence boundaries.
    /// Storage exhaustion defers sources; it cannot make an invalid proof valid.
    pub(in crate::chain_backend) async fn accept_signed_source(
        &self,
        artifact: SignedArtifact,
    ) -> EvidenceProofAcceptance {
        use EvidenceProofAcceptance::{Accepted, Deferred, Rejected};
        if self.is_light() || self.bootstrap_pending() {
            return Deferred;
        }
        let Some(chunk_id) =
            self.with_engine(|engine| artifact.chunk_id(engine.chain_spec().consensus.chunk_size))
        else {
            return Rejected;
        };
        if !self.availability_source_known(chunk_id) {
            return Deferred;
        }
        let id = artifact.id();
        if self
            .with_engine(|engine| engine.store().signed_artifact_metadata_by_id(&id))
            .ok()
            .flatten()
            .is_some()
        {
            return Accepted;
        }
        if !self.with_engine(|engine| engine.validate_signed_artifact(&artifact)) {
            return Rejected;
        }
        if let SignedArtifact::BlockProof(proof) = &artifact {
            let Some(verdict) = self.signed_proof_verdict_for(proof, id).await else {
                return Deferred;
            };
            // A rejected envelope matters only as the exact bytes some
            // authenticated precommit accepted. It is stored once a retained
            // vote names it, so unsigned junk never fills the store or spreads.
            // Until then it waits, bounded, where a later precommit accepting
            // it is still detected.
            if let ProofVerdict::Rejected(reason) = verdict
                && !self.proof_named_by_retained_vote(chunk_id, id)
            {
                self.pending_rejections
                    .lock()
                    .expect("pending rejections")
                    .insert(id, proof.clone(), reason);
                return Deferred;
            }
        }
        let retained = self.with_live_engine_mut(|engine| {
            match &artifact {
                SignedArtifact::Vote(vote) => engine.retain_signed_vote(vote),
                SignedArtifact::Quorum(quorum) => engine.retain_signed_quorum(quorum),
                SignedArtifact::BlockProof(proof) => engine.retain_signed_proof(proof),
                other => engine.retain_signed_artifact(other, false),
            }
            .map_err(storage_error)
        });
        if retained.is_err() {
            return Deferred;
        }
        if let SignedArtifact::Vote(vote) = &artifact {
            for claim in &vote.attestations {
                if let Some(quorum) = &claim.unlock_quorum {
                    let _ = self.with_live_engine_mut(|engine| {
                        engine.retain_signed_quorum(quorum).map_err(storage_error)
                    });
                }
            }
        }
        self.observe_signed_source_accountability(&artifact, id, Some(chunk_id))
            .await;
        let reference = SignedArtifactRef {
            id,
            kind: artifact.kind(),
        };
        self.publish_signed_inventory(chunk_id, vec![reference])
            .await;
        Accepted
    }

    /// Retain the exact first accepted receipts before publishing this node's own
    /// proof-acceptance declaration. Availability does not delay received votes.
    pub(in crate::chain_backend) fn ensure_publishable_vote_sources(
        &self,
        vote: &FinalityVote,
    ) -> bool {
        if vote.data.phase != neutrin0_consensus_types::FinalityVotePhase::Precommit {
            return true;
        }
        let Some(manifests) =
            neutrin0_consensus_types::ProofManifestIndex::new(&vote.proof_manifests)
        else {
            return false;
        };
        if !manifests.covers_exact(&vote.attestations) {
            return false;
        }
        let own = self.local_voter().map(|key| key.validator_index());
        self.with_engine_mut(|engine| {
            // The bootstrap barrier is rechecked under the engine lock, as in
            // `with_live_engine_mut`: once fetching begins nothing is retained
            // and the vote is not published.
            if self.bootstrap_pending() {
                return false;
            }
            let branch = Self::publication_candidate_hashes(engine, vote);
            for claim in vote
                .attestations
                .iter()
                .filter(|claim| Some(claim.validator_index) == own)
            {
                let Some(manifest) = claim
                    .proof_acceptance
                    .and_then(|commitment| manifests.get(&commitment))
                else {
                    return false;
                };
                for (offset, expected) in manifest.proof_hashes.iter().enumerate() {
                    if let Some((_, source)) =
                        engine.store().signed_artifact(expected).ok().flatten()
                    {
                        if engine.retain_signed_artifact(&source, true).is_err() {
                            return false;
                        }
                        continue;
                    }
                    let Some(height) = vote
                        .data
                        .chunk_id
                        .checked_mul(engine.chain_spec().consensus.chunk_size)
                        .and_then(|start| start.checked_add(u64::try_from(offset).ok()?))
                        .and_then(|height| height.checked_add(1))
                    else {
                        return false;
                    };
                    let Some(hash) = branch
                        .as_ref()
                        .and_then(|hashes| hashes.get(&height))
                        .copied()
                        .or_else(|| {
                            engine
                                .store()
                                .get_block_hash_by_height(height)
                                .ok()
                                .flatten()
                        })
                    else {
                        return false;
                    };
                    let Some(proof) = engine.store().get_block_proof(&hash).ok().flatten() else {
                        return false;
                    };
                    let source = SignedArtifact::BlockProof(proof);
                    if source.id() != *expected
                        || engine.retain_signed_artifact(&source, true).is_err()
                    {
                        return false;
                    }
                }
            }
            true
        })
    }

    fn publication_candidate_hashes(
        engine: &neutrin0_consensus_engine::Engine<DB>,
        vote: &FinalityVote,
    ) -> Option<std::collections::BTreeMap<u64, Hash>> {
        let chunk = engine
            .bft_session(vote.data.chunk_id)?
            .candidate_by_hash(&vote.data.chunk_hash)?;
        let mut hash = chunk.end_block_hash;
        let mut hashes = std::collections::BTreeMap::new();
        for offset in 0..engine.chain_spec().consensus.chunk_size {
            let header = engine.store().get_header(&hash).ok().flatten()?;
            if header.height != chunk.end_height.checked_sub(offset)? {
                return None;
            }
            hashes.insert(header.height, hash);
            if header.height == chunk.start_height {
                return Some(hashes);
            }
            hash = header.parent_hash;
        }
        None
    }

    /// Retain signed pacemaker, proposal and nil artifacts before their publication.
    pub(in crate::chain_backend) async fn retain_availability_bft_message(
        &self,
        message: &neutrin0_consensus_types::BftMessage,
        local: bool,
    ) -> bool {
        use neutrin0_consensus_types::{BftMessage, BftVote};
        let artifact = match message {
            BftMessage::Proposal(value) => SignedArtifact::Proposal(value.clone()),
            BftMessage::Vote(BftVote::Value(value)) => SignedArtifact::Vote(value.clone()),
            BftMessage::Vote(BftVote::Nil(value)) => SignedArtifact::NilVote(value.clone()),
            BftMessage::RoundChange(value) => SignedArtifact::RoundChange(value.clone()),
            BftMessage::RoundChangeCertificate(value) => {
                SignedArtifact::RoundChangeCertificate(value.clone())
            }
        };
        if local {
            let chunk = self
                .with_engine(|engine| artifact.chunk_id(engine.chain_spec().consensus.chunk_size));
            if self
                .with_live_engine_mut(|engine| {
                    engine
                        .retain_signed_artifact(&artifact, true)
                        .map_err(storage_error)
                })
                .is_err()
            {
                return false;
            }
            let reference = artifact.reference();
            self.observe_signed_source_accountability(&artifact, reference.id, chunk)
                .await;
            if let Some(chunk) = chunk {
                self.publish_signed_inventory(chunk, vec![reference]).await;
            }
            true
        } else {
            self.accept_signed_source(artifact).await == EvidenceProofAcceptance::Accepted
        }
    }

    /// Consume the ordinary import verdict without verifying accepted receipts twice.
    /// Invalid imports still need the backend's exact objective rejection classifier.
    pub(in crate::chain_backend) async fn retain_imported_proof_source(
        &self,
        proof: &BlockProof,
        accepted: bool,
        token: VerdictToken,
    ) {
        if token.source != block_proof_source_id(proof)
            || (accepted && !self.remember_block_verdict(token, ProofVerdict::Valid))
        {
            return;
        }
        // An accepted receipt is recorded under the attributed envelope the
        // store keeps and honest proof manifests hash (design 08). A rejected
        // one has no verified attribution and keeps the receiver's envelope.
        let source = if accepted {
            self.with_engine(|engine| {
                engine
                    .store()
                    .block_receipts(&proof.block_hash)
                    .ok()?
                    .into_iter()
                    .find(|held| held.proof.proof_bytes == proof.proof_bytes)
                    .map(|held| held.proof)
            })
            .unwrap_or_else(|| proof.clone())
        } else {
            proof.clone()
        };
        let _ = self
            .accept_signed_source(SignedArtifact::BlockProof(source.clone()))
            .await;
        if accepted {
            self.compact_available_proof(&source);
        }
    }

    /// Exact pointer replacement after accepted receipt import avoids duplicating
    /// valid compressed proofs in the detached accountability source store.
    pub(super) fn compact_available_proof(&self, proof: &BlockProof) {
        let _ = self.with_live_engine_mut(|engine| {
            engine
                .store_mut()
                .compact_accepted_artifact(proof)
                .map_err(storage_error)
        });
    }

    async fn publish_signed_inventory(
        &self,
        chunk_id: ChunkId,
        mut entries: Vec<SignedArtifactRef>,
    ) {
        entries.sort_by_key(|entry| entry.id);
        entries.dedup_by_key(|entry| entry.id);
        entries.truncate(neutrin0_consensus_types::signed_artifacts::MAX_ARTIFACT_INVENTORY);
        let inventory = SignedArtifactInventory {
            chunk_id,
            entries,
            next: None,
        };
        self.publish(Topic::SignedArtifacts, &inventory).await;
    }
}
