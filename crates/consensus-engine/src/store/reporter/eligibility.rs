//! Tracked identities and their finalized economic eligibility: which owners
//! keep retained material and the release of everything only departed owners needed.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::history_proof::ConsensusBoundary;
use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
use neutrin0_consensus_types::{Header, SlashingEvidence};
use neutrin0_primitives::{BlsPublicKey, Hash, Validator};
use neutrin0_prover_chunk::history::HistoricalChunk;
use neutrin0_storage::{Batch, Column, Database};
use std::collections::{BTreeMap, BTreeSet};

use super::{
    HEADER_LOOKUP, OWNER_PREFIX, Owned, SOURCE_LOOKUP, STATEMENT, chunk_lookup_key, dormant_key,
    inventory_key, lookup_key, reporter_chunk_for_height, validate_addresses,
};
use crate::store::{ChainStore, StoreError};
use crate::{ReporterIdentity, RetentionPolicy};

impl<DB: Database> ChainStore<DB> {
    pub(crate) fn retain_reporter_source(
        &mut self,
        chunk: u64,
        artifact: &SignedArtifact,
    ) -> Result<(), StoreError<DB::Error>> {
        let policy = self.retention_info()?.policy;
        if policy != RetentionPolicy::Reporter {
            return Ok(());
        }
        self.retain_reporter_source_with(chunk, artifact.id(), artifact, policy)
    }

    /// Durably retain one source whose identity and stored retention policy the
    /// caller already read.
    pub(in crate::store) fn retain_reporter_source_with(
        &mut self,
        chunk: u64,
        id: Hash,
        artifact: &SignedArtifact,
        policy: RetentionPolicy,
    ) -> Result<(), StoreError<DB::Error>> {
        if policy != RetentionPolicy::Reporter {
            return Ok(());
        }
        let mut batch = Batch::new();
        self.retain_reporter_source_batch(&mut batch, chunk, id, artifact, policy)?;
        self.write_observed_batch(batch, true)
    }

    pub(crate) fn seed_reporter_tracking(
        &mut self,
        identities: &[(BlsPublicKey, [u8; 32])],
    ) -> Result<(), StoreError<DB::Error>> {
        let mut batch = Batch::new();
        self.merge_reporter_identities_batch(&mut batch, identities)?;
        self.write_observed_batch(batch, true)
    }

    /// Identities with selectively retained material and their historical withdrawal addresses.
    pub fn reporter_tracked_validators(
        &self,
    ) -> Result<Vec<ReporterIdentity>, StoreError<DB::Error>> {
        let mut identities = Vec::new();
        for (key, bytes) in self
            .db
            .iter_column(Column::ReporterValidators)
            .map_err(StoreError::Database)?
        {
            let key = key
                .try_into()
                .map_err(|_| StoreError::Corrupt("reporter identity key"))?;
            let addresses: Vec<[u8; 32]> = borsh::from_slice(&bytes)?;
            validate_addresses::<DB::Error>(&addresses)?;
            identities.extend(addresses.into_iter().map(|address| (key, address)));
        }
        identities.sort_unstable();
        Ok(identities)
    }

    pub(super) fn merge_reporter_identities_batch(
        &self,
        batch: &mut Batch,
        identities: &[ReporterIdentity],
    ) -> Result<(), StoreError<DB::Error>> {
        let mut grouped: BTreeMap<BlsPublicKey, Vec<[u8; 32]>> = BTreeMap::new();
        for (key, address) in identities {
            grouped.entry(*key).or_default().push(*address);
        }
        for (key, mut addresses) in grouped {
            if let Some(previous) =
                self.staged_decoded::<Vec<[u8; 32]>>(batch, Column::ReporterValidators, &key)?
            {
                validate_addresses::<DB::Error>(&previous)?;
                addresses.extend(previous);
            }
            addresses.sort_unstable();
            addresses.dedup();
            batch.put(Column::ReporterValidators, key, borsh::to_vec(&addresses)?);
        }
        Ok(())
    }

    /// Bonded, unslashed memberships that remain accountable for their
    /// signatures, each with the withdrawal account its balance is queried under.
    pub(super) fn accountable_identities(
        &self,
        validators: &[Validator],
    ) -> Result<Vec<ReporterIdentity>, StoreError<DB::Error>> {
        let mut identities = Vec::new();
        for validator in validators {
            if validator.effective_stake > 0 && !self.is_identity_slashed(&validator.pubkey)? {
                identities.push((validator.pubkey, validator.withdrawal_credentials));
            }
        }
        Ok(identities)
    }

    /// Whether switching to a snapshot would skip append data needed by watched openings.
    pub fn reporter_has_history(&self) -> Result<bool, StoreError<DB::Error>> {
        Ok(!self
            .db
            .entries_from(Column::ReporterIndex, &[], 1)
            .map_err(StoreError::Database)?
            .is_empty())
    }

    /// Replace eligibility only from authenticated finalized runtime economics.
    /// Shared material is deleted only after its last slashable owner leaves.
    pub fn set_reporter_eligible(
        &mut self,
        eligible: &[(BlsPublicKey, [u8; 32])],
        chunk_size: u64,
    ) -> Result<Vec<Hash>, StoreError<DB::Error>> {
        if self.retention_info()?.policy != RetentionPolicy::Reporter {
            return Err(StoreError::Corrupt(
                "reporter eligibility outside reporter role",
            ));
        }
        let mut keys = BTreeSet::new();
        let mut batch = Batch::new();
        self.merge_reporter_identities_batch(&mut batch, eligible)?;
        for (key, _) in eligible {
            keys.insert(*key);
        }
        let previous = self.reporter_tracked_validators()?;
        let changed = previous.iter().any(|(key, _)| !keys.contains(key));
        for (key, _) in previous {
            if !keys.contains(&key) {
                batch.delete(Column::ReporterValidators, key);
            }
        }
        let removed_raw =
            self.release_ineligible_raw_reports_batch(&mut batch, &keys, chunk_size)?;
        if changed {
            self.trim_ineligible_owners_batch(&mut batch, &keys)?;
        }
        self.write_observed_batch(batch, true)?;
        Ok(removed_raw)
    }

    /// Drop every pooled raw report whose accused identity is no longer
    /// eligible, returning the dropped report ids.
    fn release_ineligible_raw_reports_batch(
        &self,
        batch: &mut Batch,
        keys: &BTreeSet<BlsPublicKey>,
        chunk_size: u64,
    ) -> Result<Vec<Hash>, StoreError<DB::Error>> {
        let mut removed_raw = Vec::new();
        for (id, evidence) in self.iter_slashing_evidence()? {
            let chunk = raw_report_chunk::<DB::Error>(&evidence, chunk_size)?;
            let validators = if let Some(record) = self.historical_chunk(chunk)? {
                record.validators
            } else if chunk == self.finalized_count()? {
                self.get_validator_set_snapshot(
                    self.get_latest_validator_set_index()?.unwrap_or(0),
                )?
                .unwrap_or_default()
            } else {
                Vec::new()
            };
            let accused = validators
                .get(evidence.offender_index() as usize)
                .map(|v| v.pubkey);
            if accused.is_none_or(|key| !keys.contains(&key)) {
                batch.delete(Column::SlashingPool, id);
                removed_raw.push(id);
            }
        }
        Ok(removed_raw)
    }

    /// Remove departed owners from every statement, record, source, header
    /// and boundary, deleting what no eligible owner holds any more.
    fn trim_ineligible_owners_batch(
        &self,
        batch: &mut Batch,
        keys: &BTreeSet<BlsPublicKey>,
    ) -> Result<(), StoreError<DB::Error>> {
        self.trim_reporter_statements(batch, keys)?;
        self.trim_reporter_owners::<HistoricalChunk>(batch, Column::ReporterHistory, keys)?;
        self.trim_reporter_owners::<SignedArtifact>(batch, Column::ReporterSources, keys)?;
        self.trim_reporter_owners::<Header>(batch, Column::ReporterHeaders, keys)?;
        self.trim_reporter_owners::<ConsensusBoundary>(batch, Column::ReporterBoundaries, keys)
    }

    /// Drop the statement entries of owners that are no longer eligible.
    fn trim_reporter_statements(
        &self,
        batch: &mut Batch,
        eligible: &BTreeSet<BlsPublicKey>,
    ) -> Result<(), StoreError<DB::Error>> {
        self.scan_prefix(Column::ReporterIndex, &[STATEMENT], |key, _| {
            let owner: BlsPublicKey = key
                .get(9..OWNER_PREFIX)
                .and_then(|owner| owner.try_into().ok())
                .ok_or(StoreError::Corrupt("reporter statement key"))?;
            if !eligible.contains(&owner) {
                batch.delete(Column::ReporterIndex, key);
            }
            Ok(())
        })
    }

    fn trim_reporter_owners<T: BorshSerialize + BorshDeserialize>(
        &self,
        batch: &mut Batch,
        column: Column,
        eligible: &BTreeSet<BlsPublicKey>,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut removed_headers: BTreeMap<Hash, Vec<u64>> = BTreeMap::new();
        let mut removed_chunks = BTreeSet::new();
        self.scan_prefix(column, &[], |key, bytes| {
            let mut entry: Owned<T> = borsh::from_slice(&bytes)?;
            let before = entry.owners.len();
            entry.owners.retain(|owner| eligible.contains(owner));
            if entry.owners.is_empty() {
                if column == Column::ReporterHistory {
                    let chunk = crate::store::retention::decode_count(&key)?;
                    batch.delete(Column::ReporterIndex, chunk_lookup_key(chunk));
                    batch.delete(Column::ReporterIndex, dormant_key(chunk));
                    removed_chunks.insert(chunk);
                }
                if column == Column::ReporterSources {
                    let hash: Hash = key[8..]
                        .try_into()
                        .map_err(|_| StoreError::Corrupt("reporter source key"))?;
                    batch.delete(Column::ReporterIndex, lookup_key(SOURCE_LOOKUP, &hash));
                    let chunk = u64::from_be_bytes(key[..8].try_into().expect("eight bytes"));
                    batch.delete(Column::ReporterIndex, inventory_key(chunk, hash));
                } else if column == Column::ReporterHeaders {
                    let hash: Hash = key[8..]
                        .try_into()
                        .map_err(|_| StoreError::Corrupt("reporter header key"))?;
                    let chunk = u64::from_be_bytes(key[..8].try_into().expect("eight bytes"));
                    removed_headers.entry(hash).or_default().push(chunk);
                }
                batch.delete(column, key);
            } else if entry.owners.len() != before {
                // An entry that kept every owner is already stored exactly.
                batch.put(column, key, borsh::to_vec(&entry)?);
            }
            Ok(())
        })?;
        self.release_reporter_subtrees_batch(batch, &removed_chunks)?;
        for (hash, removed) in removed_headers {
            let mut chunks: Vec<u64> = self
                .get_decoded(Column::ReporterIndex, &lookup_key(HEADER_LOOKUP, &hash))?
                .ok_or(StoreError::Corrupt("reporter header lookup missing"))?;
            chunks.retain(|chunk| !removed.contains(chunk));
            if chunks.is_empty() {
                batch.delete(Column::ReporterIndex, lookup_key(HEADER_LOOKUP, &hash));
            } else {
                batch.put(
                    Column::ReporterIndex,
                    lookup_key(HEADER_LOOKUP, &hash),
                    borsh::to_vec(&chunks)?,
                );
            }
        }
        Ok(())
    }

    pub(super) fn reporter_owners(
        &self,
        validators: &[Validator],
    ) -> Result<Vec<BlsPublicKey>, StoreError<DB::Error>> {
        let eligible: BTreeSet<_> = self
            .reporter_tracked_validators()?
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        Ok(validators
            .iter()
            .filter(|v| eligible.contains(&v.pubkey))
            .map(|v| v.pubkey)
            .collect())
    }
}

/// The source chunk of a pooled raw report, from the header height or the
/// vote its first cited message carries.
fn raw_report_chunk<E>(evidence: &SlashingEvidence, chunk_size: u64) -> Result<u64, StoreError<E>> {
    match evidence {
        SlashingEvidence::DoubleProposal { header_a, .. } => {
            reporter_chunk_for_height(header_a.height, chunk_size)
        }
        SlashingEvidence::DaCommitmentFraud { header, .. }
        | SlashingEvidence::InvalidExecutionClaim { header, .. } => {
            reporter_chunk_for_height(header.height, chunk_size)
        }
        SlashingEvidence::DoublePrevote { vote_a, .. }
        | SlashingEvidence::DoublePrecommit { vote_a, .. }
        | SlashingEvidence::LockViolation { vote_a, .. } => Ok(vote_a.data.chunk_id),
        SlashingEvidence::InvalidProofSigning { vote, .. } => Ok(vote.data.chunk_id),
        SlashingEvidence::ConflictingNilVote { value_vote, .. } => Ok(value_vote.data.chunk_id),
        SlashingEvidence::DoubleBftProposal { proposal_a, .. } => Ok(proposal_a.chunk.chunk_id),
    }
}
