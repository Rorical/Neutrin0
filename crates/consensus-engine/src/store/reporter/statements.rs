//! Each owner's bounded signed-statement entries: two differing statements
//! per chunk, round and step and 256 per chunk, the highest round yielding to
//! a lower one.

use neutrin0_consensus_types::Header;
use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
use neutrin0_primitives::{BlsPublicKey, Hash};
use neutrin0_storage::{Batch, Column, Database};

use super::{
    HEADER_LOOKUP, HEADER_STEP, OWNER_PREFIX, Owned, SOURCE_LOOKUP, STATEMENTS_PER_OWNER,
    STATEMENTS_PER_STEP, STEP_PREFIX, inventory_key, lookup_key, source_key, statement_key,
};
use crate::store::{ChainStore, StoreError};

impl<DB: Database> ChainStore<DB> {
    /// Whether `owner` keeps the signed `(round, step, statement)` under
    /// `holder`, the source or header carrying it, staging its entry. An
    /// identical statement already kept is not kept twice, a full step keeps
    /// what it has, and a full owner gives up its highest-round statement
    /// only for a lower one.
    pub(super) fn admit_statement_batch(
        &self,
        batch: &mut Batch,
        chunk: u64,
        owner: &BlsPublicKey,
        (round, step, statement): (u64, u8, Hash),
        holder: Hash,
    ) -> Result<bool, StoreError<DB::Error>> {
        let key = statement_key(chunk, owner, round, step, &statement);
        if let Some(kept) = self.staged_decoded::<Hash>(batch, Column::ReporterIndex, &key)? {
            return Ok(kept == holder);
        }
        let step_entries = self
            .db
            .iter_prefix(Column::ReporterIndex, &key[..STEP_PREFIX])
            .map_err(StoreError::Database)?;
        if step_entries.len() >= STATEMENTS_PER_STEP {
            return Ok(false);
        }
        let owner_entries = self
            .db
            .iter_prefix(Column::ReporterIndex, &key[..OWNER_PREFIX])
            .map_err(StoreError::Database)?;
        if owner_entries.len() >= STATEMENTS_PER_OWNER {
            let Some((highest, kept)) = owner_entries.into_iter().max() else {
                return Ok(false);
            };
            let rounds = OWNER_PREFIX..STEP_PREFIX - 1;
            if highest.get(rounds.clone()) <= key.get(rounds) {
                return Ok(false);
            }
            self.release_statement_batch(batch, chunk, owner, highest, &kept)?;
        }
        batch.put(Column::ReporterIndex, key, holder);
        Ok(true)
    }

    /// Drop one statement entry and its owner from the source or header
    /// holding it, deleting the holder once nobody owns it.
    fn release_statement_batch(
        &self,
        batch: &mut Batch,
        chunk: u64,
        owner: &BlsPublicKey,
        key: Vec<u8>,
        holder: &[u8],
    ) -> Result<(), StoreError<DB::Error>> {
        let holder: Hash = holder
            .try_into()
            .map_err(|_| StoreError::Corrupt("reporter statement holder"))?;
        let header = key.get(STEP_PREFIX - 1) == Some(&HEADER_STEP);
        batch.delete(Column::ReporterIndex, key);
        let entry_key = source_key(chunk, holder);
        if header {
            let Some(mut entry) =
                self.staged_decoded::<Owned<Header>>(batch, Column::ReporterHeaders, &entry_key)?
            else {
                return Ok(());
            };
            entry.owners.retain(|kept| kept != owner);
            if !entry.owners.is_empty() {
                batch.put(Column::ReporterHeaders, entry_key, borsh::to_vec(&entry)?);
                return Ok(());
            }
            batch.delete(Column::ReporterHeaders, entry_key);
            let lookup = lookup_key(HEADER_LOOKUP, &holder);
            let mut chunks: Vec<u64> = self
                .staged_decoded(batch, Column::ReporterIndex, &lookup)?
                .unwrap_or_default();
            chunks.retain(|kept| *kept != chunk);
            if chunks.is_empty() {
                batch.delete(Column::ReporterIndex, lookup);
            } else {
                batch.put(Column::ReporterIndex, lookup, borsh::to_vec(&chunks)?);
            }
            return Ok(());
        }
        let Some(mut entry) = self.staged_decoded::<Owned<SignedArtifact>>(
            batch,
            Column::ReporterSources,
            &entry_key,
        )?
        else {
            return Ok(());
        };
        entry.owners.retain(|kept| kept != owner);
        if entry.owners.is_empty() {
            batch.delete(Column::ReporterSources, entry_key);
            batch.delete(Column::ReporterIndex, lookup_key(SOURCE_LOOKUP, &holder));
            batch.delete(Column::ReporterIndex, inventory_key(chunk, holder));
        } else {
            batch.put(Column::ReporterSources, entry_key, borsh::to_vec(&entry)?);
        }
        Ok(())
    }
}
