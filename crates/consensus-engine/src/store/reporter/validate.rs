//! Startup recheck of every watched opening and index entry.

use neutrin0_consensus_types::Header;
use neutrin0_consensus_types::signed_artifacts::SignedArtifact;
use neutrin0_primitives::{BlsPublicKey, Hash};
use neutrin0_storage::{Column, Database};

use super::{
    CHUNK_LOOKUP, DORMANT, HEADER_LOOKUP, HEADER_STEP, OWNER_PREFIX, Owned, SOURCE_INVENTORY,
    SOURCE_LOOKUP, STATEMENT, STEP_PREFIX, SUBTREE, lookup_key, source_key,
};
use crate::store::{ChainStore, StoreError};

impl<DB: Database> ChainStore<DB> {
    /// Recheck every watched opening and index entry before resuming from
    /// disk, a page at a time.
    pub(in crate::store) fn validate_reporter_history(&self) -> Result<(), StoreError<DB::Error>> {
        let frontier = self.history_frontier(self.finalized_count()?)?;
        self.scan_prefix(Column::ReporterHistory, &[], |key, _| {
            let chunk = crate::store::retention::decode_count(&key)?;
            // A current opening must verify; a dormant one waits for a refresh.
            self.verified_reporter_opening(chunk, &frontier)?;
            Ok(())
        })?;
        self.scan_prefix(Column::ReporterIndex, &[], |key, bytes| {
            let Some(tag) = key.first() else {
                return Err(StoreError::Corrupt("reporter index empty key"));
            };
            match *tag {
                SOURCE_LOOKUP => {
                    let hash: Hash = key
                        .get(1..)
                        .and_then(|hash| hash.try_into().ok())
                        .ok_or(StoreError::Corrupt("reporter source lookup key"))?;
                    let chunk: u64 = borsh::from_slice(&bytes)?;
                    let (source, _) = self
                        .reporter_source(&hash)?
                        .ok_or(StoreError::Corrupt("reporter source lookup unavailable"))?;
                    if source != chunk {
                        return Err(StoreError::Corrupt("reporter source lookup count"));
                    }
                }
                HEADER_LOOKUP => {
                    let hash: Hash = key
                        .get(1..)
                        .and_then(|hash| hash.try_into().ok())
                        .ok_or(StoreError::Corrupt("reporter header lookup key"))?;
                    let chunks: Vec<u64> = borsh::from_slice(&bytes)?;
                    for chunk in chunks {
                        let header: Owned<Header> = self
                            .get_decoded(Column::ReporterHeaders, &source_key(chunk, hash))?
                            .ok_or(StoreError::Corrupt("reporter header lookup dangling"))?;
                        if header.value.hash() != hash {
                            return Err(StoreError::Corrupt("reporter header lookup hash"));
                        }
                    }
                    self.reporter_header(&hash)?
                        .ok_or(StoreError::Corrupt("reporter header lookup unavailable"))?;
                }
                SOURCE_INVENTORY => {
                    let chunk = key
                        .get(1..9)
                        .and_then(|c| c.try_into().ok())
                        .map(u64::from_be_bytes)
                        .ok_or(StoreError::Corrupt("reporter inventory chunk key"))?;
                    let hash: Hash = key
                        .get(9..)
                        .and_then(|h| h.try_into().ok())
                        .ok_or(StoreError::Corrupt("reporter inventory hash"))?;
                    let lookup = lookup_key(SOURCE_LOOKUP, &hash);
                    if self.get_decoded::<u64>(Column::ReporterIndex, &lookup)? != Some(chunk) {
                        return Err(StoreError::Corrupt("reporter inventory lookup mismatch"));
                    }
                }
                CHUNK_LOOKUP | DORMANT => {
                    let chunk = key
                        .get(1..)
                        .ok_or(StoreError::Corrupt("reporter chunk key"))
                        .and_then(crate::store::retention::decode_count)?;
                    // Every watched opening was already checked above.
                    self.reporter_record(chunk)?
                        .ok_or(StoreError::Corrupt("reporter chunk lookup unavailable"))?;
                }
                SUBTREE => {
                    if key.len() != 10 || bytes.len() != 32 {
                        return Err(StoreError::Corrupt("reporter history subtree"));
                    }
                }
                STATEMENT => self.validate_reporter_statement(&key, &bytes)?,
                _ => return Err(StoreError::Corrupt("reporter index kind")),
            }
            Ok(())
        })
    }

    /// A statement entry must name a source or header its owner still owns.
    fn validate_reporter_statement(
        &self,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<(), StoreError<DB::Error>> {
        let chunk = key
            .get(1..9)
            .and_then(|c| c.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or(StoreError::Corrupt("reporter statement key"))?;
        let owner: BlsPublicKey = key
            .get(9..OWNER_PREFIX)
            .and_then(|owner| owner.try_into().ok())
            .ok_or(StoreError::Corrupt("reporter statement key"))?;
        let holder: Hash = bytes
            .try_into()
            .map_err(|_| StoreError::Corrupt("reporter statement holder"))?;
        let owners = if key.get(STEP_PREFIX - 1) == Some(&HEADER_STEP) {
            self.get_decoded::<Owned<Header>>(Column::ReporterHeaders, &source_key(chunk, holder))?
                .map(|entry| entry.owners)
        } else {
            self.get_decoded::<Owned<SignedArtifact>>(
                Column::ReporterSources,
                &source_key(chunk, holder),
            )?
            .map(|entry| entry.owners)
        };
        if owners.is_some_and(|owners| owners.contains(&owner)) {
            Ok(())
        } else {
            Err(StoreError::Corrupt("reporter statement holder unavailable"))
        }
    }
}
