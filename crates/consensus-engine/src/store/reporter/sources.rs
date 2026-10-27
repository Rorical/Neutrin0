//! Retained signed sources, their dependencies and each owner's bounded
//! statement entries.

use neutrin0_consensus_types::QuorumCertificate;
use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
use neutrin0_primitives::{BlsPublicKey, Hash, Validator};
use neutrin0_storage::{Batch, Column, Database};
use std::collections::{BTreeMap, BTreeSet};

use super::{
    Owned, ReporterContext, SOURCE_LOOKUP, inventory_key, lookup_key, put_owned, signed_statements,
    source_key,
};
use crate::RetentionPolicy;
use crate::store::{ChainStore, StoreError};

impl<DB: Database> ChainStore<DB> {
    /// Exact signed sources for one watched historical chunk, excluding complete block bodies.
    pub fn reporter_sources_for_chunk(
        &self,
        chunk: u64,
    ) -> Result<Vec<SignedArtifact>, StoreError<DB::Error>> {
        self.db
            .iter_prefix(Column::ReporterSources, &chunk.to_be_bytes())
            .map_err(StoreError::Database)?
            .into_iter()
            .map(|(key, bytes)| {
                let entry: Owned<SignedArtifact> = borsh::from_slice(&bytes)?;
                if key.as_slice() != source_key(chunk, entry.value.id()) {
                    return Err(StoreError::Corrupt("reporter source key"));
                }
                Ok(entry.value)
            })
            .collect()
    }

    pub(in crate::store) fn reporter_source_refs(
        &self,
        chunk: u64,
    ) -> Result<
        Vec<neutrin0_consensus_types::signed_artifacts::SignedArtifactRef>,
        StoreError<DB::Error>,
    > {
        let key = inventory_key(chunk, [0; 32]);
        self.db
            .iter_prefix(Column::ReporterIndex, &key[..9])
            .map_err(StoreError::Database)?
            .into_iter()
            .map(|(key, bytes)| {
                let id = key
                    .get(9..)
                    .and_then(|id| id.try_into().ok())
                    .ok_or(StoreError::Corrupt("reporter inventory key"))?;
                Ok(
                    neutrin0_consensus_types::signed_artifacts::SignedArtifactRef {
                        id,
                        kind: borsh::from_slice(&bytes)?,
                    },
                )
            })
            .collect()
    }

    /// Stage `artifact`, whose identity is `id`, and its dependencies for
    /// accountable owners. `policy` is the stored retention policy.
    pub(in crate::store) fn retain_reporter_source_batch(
        &self,
        batch: &mut Batch,
        chunk: u64,
        id: Hash,
        artifact: &SignedArtifact,
        policy: RetentionPolicy,
    ) -> Result<(), StoreError<DB::Error>> {
        if policy != RetentionPolicy::Reporter {
            return Ok(());
        }
        let ReporterContext { validators, owners } = self.reporter_context_batch(batch, chunk)?;
        let source_owners =
            self.reporter_source_owners_batch(batch, chunk, id, artifact, &validators, &owners)?;
        if !owners.is_empty() {
            for quorum in carried_quorums(artifact) {
                let dependency = SignedArtifact::Quorum(quorum.clone());
                self.put_reporter_source_batch(
                    batch,
                    chunk,
                    dependency.id(),
                    &dependency,
                    &owners,
                )?;
            }
        }
        if !source_owners.is_empty() {
            // Copy envelopes: accepted receipt references would dangle after ordinary pruning.
            // Quorums and other signers remain dependencies of a tracked signer's lock claim.
            self.put_reporter_source_batch(batch, chunk, id, artifact, &source_owners)?;
        }
        if let SignedArtifact::Vote(vote) = artifact {
            self.retain_vote_proof_dependencies_batch(batch, chunk, vote, &validators, &owners)?;
        }
        Ok(())
    }

    /// The accountable owners that keep `artifact` itself: every owner for a
    /// quorum, the owners whose precommits accepted a proof envelope, and
    /// otherwise the signers whose statement entries admit it.
    fn reporter_source_owners_batch(
        &self,
        batch: &mut Batch,
        chunk: u64,
        id: Hash,
        artifact: &SignedArtifact,
        validators: &[Validator],
        owners: &[BlsPublicKey],
    ) -> Result<Vec<BlsPublicKey>, StoreError<DB::Error>> {
        match artifact {
            SignedArtifact::Quorum(_) => Ok(owners.to_vec()),
            SignedArtifact::BlockProof(_) => {
                self.reporter_proof_claim_owners(chunk, id, validators, owners)
            }
            _ => {
                let mut admitted = Vec::new();
                for (index, round, step, statement) in signed_statements(artifact) {
                    let Some(owner) = validators
                        .get(index as usize)
                        .map(|v| v.pubkey)
                        .filter(|key| owners.contains(key))
                    else {
                        continue;
                    };
                    if self.admit_statement_batch(
                        batch,
                        chunk,
                        &owner,
                        (round, step, statement),
                        id,
                    )? {
                        admitted.push(owner);
                    }
                }
                Ok(admitted)
            }
        }
    }

    /// Copy the proof envelopes each accountable signer's precommit accepted,
    /// as named by its proof manifest, for that signer.
    fn retain_vote_proof_dependencies_batch(
        &self,
        batch: &mut Batch,
        chunk: u64,
        vote: &neutrin0_consensus_types::FinalityVote,
        validators: &[Validator],
        owners: &[BlsPublicKey],
    ) -> Result<(), StoreError<DB::Error>> {
        let manifests = neutrin0_consensus_types::ProofManifestIndex::new(&vote.proof_manifests)
            .filter(|index| index.covers_exact(&vote.attestations))
            .ok_or(StoreError::Corrupt(
                "invalid reporter proof manifest dictionary",
            ))?;
        let mut dependencies: BTreeMap<Hash, Vec<BlsPublicKey>> = BTreeMap::new();
        for claim in &vote.attestations {
            let Some(owner) = validators
                .get(claim.validator_index as usize)
                .map(|v| v.pubkey)
                .filter(|key| owners.contains(key))
            else {
                continue;
            };
            let Some(commitment) = claim.proof_acceptance else {
                continue;
            };
            let manifest = manifests
                .get(&commitment)
                .ok_or(StoreError::Corrupt("missing reporter proof manifest"))?;
            for proof_id in &manifest.proof_hashes {
                dependencies.entry(*proof_id).or_default().push(owner);
            }
        }
        for (proof_id, users) in dependencies {
            // `signed_artifact` verifies that the source has exactly this identity.
            if let Some((source, dependency @ SignedArtifact::BlockProof(_))) =
                self.signed_artifact(&proof_id)?
                && source == chunk
            {
                self.put_reporter_source_batch(batch, chunk, proof_id, &dependency, &users)?;
            }
        }
        Ok(())
    }

    fn reporter_proof_claim_owners(
        &self,
        chunk: u64,
        id: Hash,
        validators: &[Validator],
        eligible: &[BlsPublicKey],
    ) -> Result<Vec<BlsPublicKey>, StoreError<DB::Error>> {
        let mut votes = Vec::new();
        for source in self.reporter_sources_for_chunk(chunk)? {
            if let SignedArtifact::Vote(vote) = source {
                votes.push(vote);
            }
        }
        if let Some(record) = self.historical_chunk(chunk)? {
            votes.push(record.finality.precommit_vote());
        }
        let mut owners = Vec::new();
        for vote in votes {
            let manifests =
                neutrin0_consensus_types::ProofManifestIndex::new(&vote.proof_manifests)
                    .filter(|index| index.covers_exact(&vote.attestations))
                    .ok_or(StoreError::Corrupt(
                        "invalid reporter proof manifest dictionary",
                    ))?;
            let required: BTreeSet<_> = manifests
                .commitments()
                .filter(|commitment| {
                    manifests
                        .get(commitment)
                        .is_some_and(|manifest| manifest.proof_hashes.contains(&id))
                })
                .collect();
            owners.extend(
                vote.attestations
                    .iter()
                    .filter(|claim| {
                        claim
                            .proof_acceptance
                            .is_some_and(|commitment| required.contains(&commitment))
                    })
                    .filter_map(|claim| validators.get(claim.validator_index as usize))
                    .map(|validator| validator.pubkey)
                    .filter(|key| eligible.contains(key)),
            );
        }
        owners.sort_unstable();
        owners.dedup();
        Ok(owners)
    }

    /// Stage `artifact`, whose identity is `id`, merging its prior owners,
    /// including owners staged earlier in the same batch.
    pub(super) fn put_reporter_source_batch(
        &self,
        batch: &mut Batch,
        chunk: u64,
        id: Hash,
        artifact: &SignedArtifact,
        owners: &[BlsPublicKey],
    ) -> Result<(), StoreError<DB::Error>> {
        let key = source_key(chunk, id);
        let mut all = owners.to_vec();
        if let Some(prior) =
            self.staged_decoded::<Owned<SignedArtifact>>(batch, Column::ReporterSources, &key)?
        {
            all.extend(prior.owners);
        }
        all.sort_unstable();
        all.dedup();
        put_owned(batch, Column::ReporterSources, key, &all, artifact)?;
        batch.put(
            Column::ReporterIndex,
            lookup_key(SOURCE_LOOKUP, &id),
            borsh::to_vec(&chunk)?,
        );
        batch.put(
            Column::ReporterIndex,
            inventory_key(chunk, id),
            borsh::to_vec(&artifact.kind())?,
        );
        if let SignedArtifact::BlockProof(proof) = artifact
            && let Some(header) = self
                .get_header(&proof.block_hash)?
                .or(self.reporter_header(&proof.block_hash)?)
        {
            self.put_reporter_header_batch(batch, chunk, &header, &all)?;
            if let Some(parent) = self
                .get_header(&header.parent_hash)?
                .or(self.reporter_header(&header.parent_hash)?)
            {
                self.put_reporter_header_batch(batch, chunk, &parent, &all)?;
            }
        }
        Ok(())
    }

    pub(in crate::store) fn reporter_source(
        &self,
        id: &Hash,
    ) -> Result<Option<(u64, SignedArtifact)>, StoreError<DB::Error>> {
        let Some(chunk): Option<u64> =
            self.get_decoded(Column::ReporterIndex, &lookup_key(SOURCE_LOOKUP, id))?
        else {
            return Ok(None);
        };
        let entry: Owned<SignedArtifact> = self
            .get_decoded(Column::ReporterSources, &source_key(chunk, *id))?
            .ok_or(StoreError::Corrupt("reporter source lookup dangling"))?;
        if entry.value.id() != *id {
            return Err(StoreError::Corrupt("reporter source id"));
        }
        Ok(Some((chunk, entry.value)))
    }
}

/// The quorum certificates `artifact` carries: signed unlock declarations,
/// a proposal's valid QC and the highest QCs of round-change reports.
fn carried_quorums(artifact: &SignedArtifact) -> Vec<&QuorumCertificate> {
    match artifact {
        SignedArtifact::Vote(value) => value
            .attestations
            .iter()
            .filter_map(|v| v.unlock_quorum.as_ref())
            .collect(),
        SignedArtifact::Proposal(value) => value.valid_quorum.iter().collect(),
        SignedArtifact::RoundChange(value) => value.highest_quorum.iter().collect(),
        SignedArtifact::RoundChangeCertificate(value) => value
            .reports
            .iter()
            .filter_map(|v| v.highest_quorum.as_ref())
            .collect(),
        _ => Vec::new(),
    }
}
