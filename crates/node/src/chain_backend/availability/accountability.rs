//! Delayed offence detection over retained signed sources: proof verdicts,
//! rejected envelopes and the proof-acceptance attestations that name them.

use neutrin0_consensus_types::signed_artifacts::{SignedArtifact, SignedArtifactKind};
use neutrin0_consensus_types::{BlockProof, FinalityVote, SlashingEvidence};
use neutrin0_primitives::{ChunkId, Hash};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;

use super::verdicts::ProofVerdict;
use super::{
    ChainBackend, Rejection, block_proof_source_id, deduplicate_source_votes, reporter_retention,
    storage_error,
};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Cache only exact current-backend proof verdicts. Restart starts with an
    /// empty cache; operational failures never become rejection evidence.
    pub(in crate::chain_backend) async fn signed_proof_verdict(
        &self,
        proof: &BlockProof,
    ) -> Option<ProofVerdict> {
        self.signed_proof_verdict_for(proof, block_proof_source_id(proof))
            .await
    }

    /// [`Self::signed_proof_verdict`] for a proof whose source `id` is known.
    pub(super) async fn signed_proof_verdict_for(
        &self,
        proof: &BlockProof,
        id: Hash,
    ) -> Option<ProofVerdict> {
        let token = self.begin_block_verdict(id);
        if let Some(verdict) = self.cached_block_verdict_at(token) {
            return Some(verdict);
        }
        let prover = std::sync::Arc::clone(&self.proof_system);
        let expected = self.accountability_block_program(proof.height)?;
        let proof = proof.clone();
        let verdict = tokio::task::spawn_blocking(move || {
            match prover.classify_block_rejection(&proof, &expected) {
                Ok(verdict) => Some(ProofVerdict::from(verdict)),
                Err(_) => borsh::from_slice::<P::BlockProof>(&proof.proof_bytes)
                    .ok()
                    .filter(|decoded| prover.verify_block(decoded, &proof.public_inputs).is_ok())
                    .map(|_| ProofVerdict::Valid),
            }
        })
        .await
        .ok()
        .flatten()?;
        self.remember_block_verdict(token, verdict)
            .then_some(verdict)
    }

    /// A rejected proof envelope retained under `hash`, with its reason.
    async fn rejected_signed_proof(&self, hash: Hash) -> Option<(BlockProof, Rejection)> {
        if self.cached_block_verdict(hash) == Some(ProofVerdict::Valid) {
            return None;
        }
        let Some((_, SignedArtifact::BlockProof(proof))) = self
            .with_engine(|engine| engine.store().signed_artifact(&hash))
            .ok()
            .flatten()
        else {
            return self
                .pending_rejections
                .lock()
                .expect("pending rejections")
                .get(&hash);
        };
        match self.signed_proof_verdict(&proof).await {
            Some(ProofVerdict::Rejected(reason)) => Some((proof, reason)),
            _ => None,
        }
    }

    async fn detect_signed_proof_offences(
        &self,
        votes: Vec<FinalityVote>,
    ) -> Vec<SlashingEvidence> {
        // A predecessor specification's receipts are not this verifier's to
        // judge, so proof acceptances signed before the fork lapse with it.
        let first_chunk = self.with_engine(|engine| engine.chain_spec().first_chunk());
        // Authenticate/index each complete dictionary once; missing manifests
        // never establish proof rejection or an offence.
        let indexed: Vec<_> = votes
            .iter()
            .filter(|vote| vote.data.chunk_id >= first_chunk)
            .filter_map(|vote| {
                let manifests =
                    neutrin0_consensus_types::ProofManifestIndex::new(&vote.proof_manifests)?;
                manifests
                    .covers_exact(&vote.attestations)
                    .then_some((vote, manifests))
            })
            .collect();
        let mut ids = std::collections::BTreeSet::new();
        for (_, manifests) in &indexed {
            for commitment in manifests.commitments() {
                if let Some(manifest) = manifests.get(&commitment) {
                    ids.extend(manifest.proof_hashes.iter().copied());
                }
            }
        }
        let mut rejections = std::collections::BTreeMap::<Hash, _>::new();
        for hash in ids {
            rejections.insert(hash, self.rejected_signed_proof(hash).await);
        }
        let mut openings = std::collections::BTreeMap::new();
        let mut evidence = Vec::new();
        for (vote, manifests) in &indexed {
            for claim in &vote.attestations {
                let Some(commitment) = claim.proof_acceptance else {
                    continue;
                };
                let Some(manifest) = manifests.get(&commitment) else {
                    continue;
                };
                for (offset, hash) in manifest.proof_hashes.iter().enumerate() {
                    let Some(Some((proof, reason))) = rejections.get(hash) else {
                        continue;
                    };
                    let Ok(offset) = u64::try_from(offset) else {
                        continue;
                    };
                    let opening = openings
                        .entry((commitment, offset))
                        .or_insert_with(|| manifest.opening(offset));
                    let Some(proof_opening) = opening.as_ref() else {
                        continue;
                    };
                    let indexed = neutrin0_consensus_types::IndexedVote {
                        data: claim.vote.clone(),
                        signature: claim.vote_signature,
                    };
                    let item = SlashingEvidence::InvalidProofSigning {
                        validator_index: claim.validator_index,
                        vote: indexed,
                        attestation: claim.clone(),
                        rejected_proof: proof.clone(),
                        proof_opening: proof_opening.clone(),
                        reason: *reason,
                    };
                    if self
                        .with_engine(|engine| engine.verify_slashing_evidence(&item))
                        .is_ok()
                    {
                        evidence.push(item);
                    }
                }
            }
        }
        evidence
    }

    /// Report offences an accepted source establishes. `id` is the artifact's
    /// identity and `chunk` its source chunk, both already derived by the caller.
    /// Observation records sources (durably on reporters), so it rechecks the
    /// bootstrap barrier under the engine lock like the retention before it.
    pub(in crate::chain_backend) async fn observe_signed_source_accountability(
        &self,
        artifact: &SignedArtifact,
        id: Hash,
        chunk: Option<ChunkId>,
    ) {
        let mut evidence = self
            .with_live_engine_mut(|engine| {
                engine
                    .observe_signed_artifact(artifact)
                    .map_err(storage_error)
            })
            .unwrap_or_default();
        let votes = match (artifact, chunk) {
            (SignedArtifact::Vote(vote), _) => vec![vote.clone()],
            (SignedArtifact::BlockProof(_), Some(chunk)) => {
                let metadata = self
                    .with_engine(|engine| engine.store().signed_artifact_metadata_for_chunk(chunk))
                    .unwrap_or_default();
                let mut votes = Vec::new();
                for item in metadata.into_iter().filter(|item| {
                    item.kind == SignedArtifactKind::Vote && item.proof_hashes.contains(&id)
                }) {
                    if let Some((_, SignedArtifact::Vote(vote))) = self
                        .with_engine(|engine| engine.store().signed_artifact(&item.id))
                        .ok()
                        .flatten()
                    {
                        votes.push(vote);
                    }
                }
                let reporter = self.reporter_source_votes(chunk);
                votes.extend(reporter.into_iter().filter(|vote| {
                    neutrin0_consensus_types::ProofManifestIndex::new(&vote.proof_manifests)
                        .filter(|index| index.covers_exact(&vote.attestations))
                        .is_some_and(|index| {
                            index.commitments().any(|commitment| {
                                index
                                    .get(&commitment)
                                    .is_some_and(|manifest| manifest.proof_hashes.contains(&id))
                            })
                        })
                }));
                deduplicate_source_votes(&mut votes);
                votes
            }
            _ => Vec::new(),
        };
        evidence.extend(self.detect_signed_proof_offences(votes).await);
        for item in evidence {
            self.pool_and_gossip_slashing(item).await;
        }
    }

    /// One startup replay restores authenticated observations and reports every
    /// retained dependency-complete offence through ordinary pool verification.
    pub(in crate::chain_backend) async fn replay_signed_artifact_accountability(&self) {
        let mut evidence = self
            .with_live_engine_mut(|engine| engine.replay_signed_artifacts().map_err(storage_error))
            .unwrap_or_default();
        let metadata = self
            .with_engine(|engine| engine.store().active_signed_artifact_metadata())
            .unwrap_or_default();
        let mut votes = Vec::new();
        for item in metadata
            .into_iter()
            .filter(|item| item.kind == SignedArtifactKind::Vote)
        {
            if let Some((_, SignedArtifact::Vote(vote))) = self
                .with_engine(|engine| engine.store().signed_artifact(&item.id))
                .ok()
                .flatten()
            {
                votes.push(vote);
            }
        }
        deduplicate_source_votes(&mut votes);
        evidence.extend(self.detect_signed_proof_offences(votes).await);
        let reporter_chunks = self.with_engine(|engine| {
            if reporter_retention(engine) {
                engine.store().reporter_history_chunks().unwrap_or_default()
            } else {
                Vec::new()
            }
        });
        // A reporter's retained votes are checked one chunk at a time, so the
        // replay never holds its whole history.
        for chunk in reporter_chunks {
            let mut votes = self.reporter_source_votes(chunk);
            deduplicate_source_votes(&mut votes);
            evidence.extend(self.detect_signed_proof_offences(votes).await);
        }
        for item in evidence {
            self.pool_and_gossip_slashing(item).await;
        }
    }

    /// Whether a retained vote, live or in a reporter's records, lists `id`
    /// in one of its proof manifests.
    pub(super) fn proof_named_by_retained_vote(&self, chunk: ChunkId, id: Hash) -> bool {
        self.with_engine(|engine| engine.store().proof_named_by_declaration(chunk, &id))
            .unwrap_or(false)
            || self.reporter_source_votes(chunk).iter().any(|vote| {
                vote.proof_manifests
                    .iter()
                    .any(|manifest| manifest.proof_hashes.contains(&id))
            })
    }

    fn reporter_source_votes(&self, chunk: ChunkId) -> Vec<FinalityVote> {
        self.with_engine(|engine| {
            if !reporter_retention(engine) {
                return Vec::new();
            }
            engine
                .store()
                .reporter_sources_for_chunk(chunk)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|source| match source {
                    SignedArtifact::Vote(vote) => Some(vote),
                    _ => None,
                })
                .collect()
        })
    }
}
