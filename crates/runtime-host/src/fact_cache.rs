//! Bounded verified fact receipts, reusable across offences and process restarts.

// Keep cache internals explicitly scoped to the host crate.
#![allow(clippy::redundant_pub_crate)]

use neutrin0_primitives::Hash;
use neutrin0_prover_chunk::{facts::FactStatement, receipt_codec};
use sp1_sdk::{HashableKey, SP1ProofWithPublicValues, SP1VerifyingKey};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};

use crate::bounded_cache::BoundedCache;

/// Most verified fact receipts kept in memory and on disk per fact program.
const FACT_CACHE_ENTRIES: usize = 256;

/// Encoded-size budget of one fact program's receipt cache.
const FACT_CACHE_BYTES: usize = 32 * 1024 * 1024;

pub(super) struct FactReceipt {
    pub(super) bundle: SP1ProofWithPublicValues,
    pub(super) statement: FactStatement,
    id: Hash,
    size: usize,
}

pub(super) struct FactCache {
    entries: BoundedCache<Hash, Arc<FactReceipt>>,
    directory: PathBuf,
}

/// Greedily maximize newly covered exact requests within the receipt budget.
/// Equal coverage favors fewer encoded bytes, then the most recently retained
/// receipt. This is bounded set-cover selection, not a global-optimality claim.
fn covering_indices(
    candidates: &[(&FactStatement, usize)],
    wanted: &mut BTreeSet<Hash>,
    limit: usize,
) -> Vec<usize> {
    let request_ids: Vec<BTreeSet<_>> = candidates
        .iter()
        .map(|(statement, _)| statement.facts.iter().map(|fact| fact.id).collect())
        .collect();
    let mut selected = Vec::with_capacity(limit.min(candidates.len()));
    while selected.len() < limit && !wanted.is_empty() {
        let best = candidates
            .iter()
            .enumerate()
            .filter_map(|(index, (_, bytes))| {
                let covered = request_ids[index].intersection(wanted).count();
                (covered > 0).then_some((index, covered, *bytes))
            })
            .max_by(
                |(left_index, left_covered, left_bytes),
                 (right_index, right_covered, right_bytes)| {
                    left_covered
                        .cmp(right_covered)
                        .then_with(|| right_bytes.cmp(left_bytes))
                        .then_with(|| left_index.cmp(right_index))
                },
            );
        let Some((index, _, _)) = best else {
            break;
        };
        for id in &request_ids[index] {
            wanted.remove(id);
        }
        selected.push(index);
    }
    selected
}

pub(super) fn verify_receipt<T: borsh::BorshSerialize>(
    bundle: &SP1ProofWithPublicValues,
    statement: &T,
    key: &SP1VerifyingKey,
) -> Result<(), neutrin0_proof_system::ProofError> {
    crate::guarded(|| {
        neutrin0_prover_chunk::proof_verification::verify_typed_receipt(
            &bundle.proof,
            bundle.public_values.as_slice(),
            &bundle.sp1_version,
            statement,
            &key.hash_u32(),
        )
    })?
    .map_err(|_| neutrin0_proof_system::ProofError::BackendRejected)
}

impl FactReceipt {
    /// Verify `bundle` against `statement` under `key`. `size` is the length
    /// of the bundle's exact `receipt_codec` encoding, which the caller
    /// already holds.
    pub(super) fn new(
        bundle: SP1ProofWithPublicValues,
        statement: FactStatement,
        key: &SP1VerifyingKey,
        size: usize,
    ) -> Result<Self, neutrin0_proof_system::ProofError> {
        verify_receipt(&bundle, &statement, key)?;
        if statement.facts.is_empty()
            || statement.facts.len() > neutrin0_prover_chunk::facts::MAX_FACTS
        {
            return Err(neutrin0_proof_system::ProofError::MalformedProof);
        }
        if size > neutrin0_consensus_types::evidence::MAX_EVIDENCE_PROOF_BYTES {
            return Err(neutrin0_proof_system::ProofError::MalformedProof);
        }
        let id = neutrin0_consensus_types::evidence::commitment(&statement);
        Ok(Self {
            bundle,
            statement,
            id,
            size,
        })
    }
}

impl FactCache {
    pub(super) fn load(key: &SP1VerifyingKey) -> Self {
        let directory = crate::cache_dir().join(format!(
            "facts-{}-{}",
            sp1_sdk::SP1_CIRCUIT_VERSION,
            key.bytes32()
        ));
        let mut cache = Self {
            entries: BoundedCache::new(FACT_CACHE_ENTRIES, FACT_CACHE_BYTES),
            directory,
        };
        let Ok(files) = std::fs::read_dir(&cache.directory) else {
            return cache;
        };
        let mut files: Vec<_> = files
            .flatten()
            .filter(|file| file.path().extension().is_some_and(|ext| ext == "bin"))
            .filter_map(|file| Some((file.metadata().ok()?.modified().ok()?, file.path())))
            .collect();
        files.sort_unstable();
        // Prune before loading so a restart never admits an unbounded directory.
        let keep_from = files.len().saturating_sub(FACT_CACHE_ENTRIES);
        for (_, path) in files.drain(..keep_from) {
            let _ = std::fs::remove_file(path);
        }
        for (_, path) in files {
            let receipt = (|| {
                if std::fs::metadata(&path).ok()?.len() > 2 * 1024 * 1024 {
                    return None;
                }
                let bytes = std::fs::read(&path).ok()?;
                let bundle = crate::guarded(|| {
                    receipt_codec::decode::<SP1ProofWithPublicValues, { 2 * 1024 * 1024 }>(&bytes)
                })
                .ok()?
                .ok()?;
                let statement = borsh::from_slice(bundle.public_values.as_slice()).ok()?;
                // A persisted receipt never inherits an in-memory verified flag.
                FactReceipt::new(bundle, statement, key, bytes.len()).ok()
            })();
            if let Some(receipt) = receipt
                && path == cache.path(receipt.id)
            {
                cache.retain(Arc::new(receipt));
            } else {
                let _ = std::fs::remove_file(path);
            }
        }
        cache
    }

    pub(super) fn verified(&self) -> BTreeMap<Hash, bool> {
        self.entries
            .values()
            .flat_map(|receipt| {
                receipt
                    .statement
                    .facts
                    .iter()
                    .map(|fact| (fact.id, fact.valid))
            })
            .collect()
    }

    pub(super) fn covering(
        &self,
        ids: &mut std::collections::BTreeSet<Hash>,
    ) -> Vec<Arc<FactReceipt>> {
        self.covering_limited(ids, FACT_CACHE_ENTRIES)
    }

    /// Select only the receipts that can actually fit the consuming Guest.
    /// Requests covered solely by discarded receipts remain in `ids`.
    pub(super) fn covering_limited(
        &self,
        ids: &mut BTreeSet<Hash>,
        limit: usize,
    ) -> Vec<Arc<FactReceipt>> {
        let receipts: Vec<_> = self.entries.values().collect();
        let candidates: Vec<_> = receipts
            .iter()
            .map(|receipt| (&receipt.statement, receipt.size))
            .collect();
        covering_indices(&candidates, ids, limit)
            .into_iter()
            .map(|index| Arc::clone(receipts[index]))
            .collect()
    }

    /// Cache a verified receipt and persist `bytes`, its exact
    /// `receipt_codec` encoding.
    pub(super) fn insert(&mut self, receipt: Arc<FactReceipt>, bytes: &[u8]) {
        if self.entries.contains(&receipt.id) {
            return;
        }
        // Failure to write the optional cache does not invalidate a verified proof.
        if std::fs::create_dir_all(&self.directory).is_ok() {
            let _ = crate::write_atomic(&self.path(receipt.id), bytes);
        }
        self.retain(receipt);
    }

    fn path(&self, id: Hash) -> PathBuf {
        self.directory
            .join(format!("{}.bin", blake3::Hash::from(id).to_hex()))
    }

    fn retain(&mut self, receipt: Arc<FactReceipt>) {
        for (id, _) in self.entries.insert(receipt.id, receipt.size, receipt) {
            let _ = std::fs::remove_file(self.path(id));
        }
    }
}

#[cfg(test)]
mod tests;
