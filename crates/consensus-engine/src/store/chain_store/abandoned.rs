//! Headers of stale candidates that rooted their stale subtree, kept until
//! abandonment detection can compare them with the finalized chain.

use alloc::vec::Vec;

use neutrin0_consensus_types::Header;
use neutrin0_primitives::Height;
use neutrin0_storage::{Batch, Column, Database};

use super::ChainStore;
use crate::store::StoreError;

extern crate alloc;

/// Most kept headers one detection pass reads: the stale roots of the nine
/// chunks of the liveness window, one per proposer and slot, with room.
const MAX_ABANDONED_HEADERS: usize = 16 * 1024;

fn abandoned_key(header: &Header) -> Vec<u8> {
    let mut key = header.height.to_be_bytes().to_vec();
    key.extend_from_slice(&header.hash());
    key
}

impl<DB: Database> ChainStore<DB> {
    /// Stage keeping `header`, a stale candidate whose parent is not stale,
    /// so a restart before its height finalizes cannot lose it.
    pub(crate) fn keep_abandoned_header_batch(
        batch: &mut Batch,
        header: &Header,
    ) -> Result<(), StoreError<DB::Error>> {
        batch.put(
            Column::AbandonedHeaders,
            abandoned_key(header),
            borsh::to_vec(header)?,
        );
        Ok(())
    }

    /// Kept headers at heights `first..=last`, in height order.
    pub fn abandoned_headers(
        &self,
        first: Height,
        last: Height,
    ) -> Result<Vec<Header>, StoreError<DB::Error>> {
        self.db
            .entries_from(
                Column::AbandonedHeaders,
                &first.to_be_bytes(),
                MAX_ABANDONED_HEADERS,
            )
            .map_err(StoreError::Database)?
            .into_iter()
            .map(|(_, bytes)| borsh::from_slice::<Header>(&bytes))
            .take_while(|header| header.as_ref().is_ok_and(|header| header.height <= last))
            .map(|header| header.map_err(StoreError::from))
            .collect()
    }

    /// Stage dropping the kept headers below `height`, which no liveness
    /// evidence can cite any more.
    pub(crate) fn prune_abandoned_headers_batch(
        &self,
        batch: &mut Batch,
        height: Height,
    ) -> Result<(), StoreError<DB::Error>> {
        for key in self
            .db
            .keys_below(Column::AbandonedHeaders, &height.to_be_bytes())
            .map_err(StoreError::Database)?
        {
            batch.delete(Column::AbandonedHeaders, key);
        }
        Ok(())
    }
}
