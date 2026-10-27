//! Reserved full proof lists behind precommit attestations, kept exactly
//! while a surviving reservation references them.

use alloc::collections::{BTreeMap, BTreeSet};
use neutrin0_consensus_types::ProofManifest;
use neutrin0_primitives::BlsPublicKey;
use neutrin0_storage::{Batch, BatchOp, Column, Database};

use super::{PROOF_MANIFEST_TAG, VOTE_INTENT_TAG, VoteIntent, manifest_key, vote_key};
use crate::{Engine, EngineError, StoreError};

extern crate alloc;

impl<DB: Database> Engine<DB> {
    pub(super) fn reserved_proof_manifest(
        &self,
        identity: &BlsPublicKey,
        intent: &VoteIntent,
    ) -> Result<Option<ProofManifest>, EngineError<DB::Error>> {
        let Some(acceptance) = intent.proof_acceptance else {
            return Ok(None);
        };
        let bytes = self
            .store()
            .db()
            .get(
                Column::SigningJournal,
                &manifest_key(identity, intent.data.chunk_id, &acceptance),
            )
            .map_err(StoreError::Database)?
            .ok_or(StoreError::Corrupt("reserved proof manifest missing"))?;
        let manifest: ProofManifest = borsh::from_slice(&bytes)?;
        if manifest.commitment() != acceptance
            || acceptance.count != self.chain_spec().consensus.chunk_size
        {
            return Err(StoreError::Corrupt("reserved proof manifest commitment mismatch").into());
        }
        Ok(Some(manifest))
    }

    /// Apply the intent mutations to a small local journal view, then remove
    /// full lists no surviving reservation references. A retained lock keeps
    /// its original precommit intent and manifest across arbitrarily many rounds.
    pub(super) fn compact_signing_manifests(
        &self,
        batch: &mut Batch,
        identity: &BlsPublicKey,
        chunk_id: u64,
    ) -> Result<(), EngineError<DB::Error>> {
        let mut prefix = vote_key(identity, chunk_id);
        prefix[0] = VOTE_INTENT_TAG;
        let mut intents: BTreeMap<_, _> = self
            .store()
            .db()
            .iter_prefix(Column::SigningJournal, &prefix)
            .map_err(StoreError::Database)?
            .into_iter()
            .collect();
        for operation in batch.operations() {
            match operation {
                BatchOp::Put {
                    column: Column::SigningJournal,
                    key,
                    value,
                } if key.starts_with(&prefix) => {
                    intents.insert(key.clone(), value.clone());
                }
                BatchOp::Delete {
                    column: Column::SigningJournal,
                    key,
                } if key.starts_with(&prefix) => {
                    intents.remove(key);
                }
                _ => {}
            }
        }
        let mut required = BTreeSet::new();
        for bytes in intents.values() {
            let intent: VoteIntent = borsh::from_slice(bytes)?;
            if let Some(acceptance) = intent.proof_acceptance {
                required.insert(acceptance);
            }
        }
        prefix[0] = PROOF_MANIFEST_TAG;
        for (key, bytes) in self
            .store()
            .db()
            .iter_prefix(Column::SigningJournal, &prefix)
            .map_err(StoreError::Database)?
        {
            let manifest: ProofManifest = borsh::from_slice(&bytes)?;
            let acceptance = manifest.commitment();
            if key != manifest_key(identity, chunk_id, &acceptance) {
                return Err(
                    StoreError::Corrupt("reserved proof manifest identity mismatch").into(),
                );
            }
            if !required.contains(&acceptance) {
                batch.delete(Column::SigningJournal, key);
            }
        }
        Ok(())
    }
}
