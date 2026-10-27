//! Carrying retained history across a hard fork (design 20).
//!
//! A hard fork's successor starts in a new data directory from its
//! predecessor's endpoint, which brings only the recent History records. What
//! the predecessor's directory retained for older chunks stays valid in the
//! successor: the History tree continues across the fork and old signatures
//! verify under the predecessor's domain. A carry file moves it: raw pooled
//! offences for every node, a reporter's retention and an archive's complete
//! History tree and records. Pooled evidence receipts stay behind; their raw
//! reports are proven again under the successor's programs.

use std::io::{Read, Write};

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::history::HISTORY_RETENTION_CHUNKS;
use neutrin0_primitives::Hash;
use neutrin0_storage::{Batch, Column, Database};

use super::{ChainStore, StoreError};
use crate::RetentionPolicy;

/// Leading bytes of every carry file.
const MAGIC: &[u8; 16] = b"NEUTRIN0-FORKCRY";
/// Tag after the last row.
const END: u8 = 0xff;
/// Columns a carry file holds; each row is tagged by its column's position.
const CARRIED: [Column; 9] = [
    Column::SlashingPool,
    Column::ReporterHistory,
    Column::ReporterSources,
    Column::ReporterHeaders,
    Column::ReporterBoundaries,
    Column::ReporterValidators,
    Column::ReporterIndex,
    Column::HistoryNodes,
    Column::HistoricalChunks,
];
/// Metadata key naming the predecessor whose carry this directory imported.
const FORK_CARRY: &[u8] = b"fork_carry";
/// Rows read per page on export.
const PAGE: usize = 1024;
/// Bound on one key, value or header, above any retained row.
const MAX_FIELD: u32 = 64 * 1024 * 1024;
/// Bytes written per import batch.
const BATCH_BYTES: usize = 16 * 1024 * 1024;

#[derive(BorshSerialize, BorshDeserialize)]
struct Header {
    chain_spec_hash: Hash,
    finalized_count: u64,
    policy: RetentionPolicy,
    reporter_gaps: Vec<(u64, u64)>,
}

/// What a carry file holds, or what an import of one wrote.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrySummary {
    /// Specification of the directory it was exported from.
    pub chain_spec_hash: Hash,
    /// Chunks that directory had finalized.
    pub finalized_count: u64,
    /// Rows exported, or imported.
    pub rows: u64,
}

impl<DB: Database> ChainStore<DB> {
    /// Write every row of this stopped node's database that a hard fork's
    /// successor keeps (see the module) to `out`.
    ///
    /// # Errors
    /// Refuses a database that was never initialized and returns storage and
    /// write failures.
    pub fn export_fork_carry(
        &self,
        out: &mut impl Write,
    ) -> Result<CarrySummary, StoreError<DB::Error>> {
        let header = Header {
            chain_spec_hash: self
                .get_chain_spec_hash()?
                .ok_or(StoreError::Corrupt("the database was never initialized"))?,
            finalized_count: self.finalized_count()?,
            policy: self.retention_info()?.policy,
            reporter_gaps: self.reporter_gaps()?,
        };
        out.write_all(MAGIC)?;
        write_field(out, &borsh::to_vec(&header)?)?;
        let mut rows = 0;
        for (tag, column) in (0_u8..).zip(CARRIED) {
            let mut from = Vec::new();
            loop {
                let page = self
                    .db
                    .entries_from(column, &from, PAGE)
                    .map_err(StoreError::Database)?;
                for (key, value) in &page {
                    out.write_all(&[tag])?;
                    write_field(out, key)?;
                    write_field(out, value)?;
                    rows += 1;
                }
                match page.last().filter(|_| page.len() == PAGE) {
                    Some((key, _)) => {
                        from.clone_from(key);
                        from.push(0);
                    }
                    None => break,
                }
            }
        }
        out.write_all(&[END])?;
        out.flush()?;
        Ok(CarrySummary {
            chain_spec_hash: header.chain_spec_hash,
            finalized_count: header.finalized_count,
            rows,
        })
    }

    /// Whether this directory imported a carry file.
    ///
    /// # Errors
    /// Returns storage failures.
    pub fn fork_carry_imported(&self) -> Result<bool, StoreError<DB::Error>> {
        Ok(self.get_raw(Column::Meta, FORK_CARRY)?.is_some())
    }

    /// Import a carry file of `predecessor` into this successor directory,
    /// which started at `fork_count`, once: pooled raw offences always, a
    /// reporter's retention into a reporter and an archive's History into an
    /// archive. Rows already present stay as they are, except that a tracked
    /// identity keeps every withdrawal account either side knew. Watched
    /// chunks are then reopened under the current frontier, as a snapshot
    /// jump reopens them, and chunks between the predecessor's finality and
    /// the successor's first retained record are recorded as a gap. Returns
    /// `None` when this directory already imported a carry.
    ///
    /// # Errors
    /// Refuses a file of another specification, a predecessor that finalized
    /// beyond the fork, a successor that has not started, an archive's import
    /// from a source that kept no complete History, and malformed files. A
    /// failed import leaves no completion marker and may be repeated.
    pub(crate) fn import_fork_carry(
        &mut self,
        input: &mut impl Read,
        predecessor: Hash,
        fork_count: u64,
    ) -> Result<Option<CarrySummary>, StoreError<DB::Error>> {
        if self.get_raw(Column::Meta, FORK_CARRY)?.is_some() {
            return Ok(None);
        }
        let mut magic = [0; 16];
        input.read_exact(&mut magic)?;
        if &magic != MAGIC {
            return Err(StoreError::Corrupt("not a fork carry file"));
        }
        let header: Header = borsh::from_slice(&read_field(input)?)?;
        let count = self.finalized_count()?;
        let policy = self.retention_info()?.policy;
        if header.chain_spec_hash != predecessor {
            return Err(StoreError::Corrupt(
                "carry file is not of this fork's predecessor",
            ));
        }
        if header.finalized_count > fork_count {
            return Err(StoreError::Corrupt(
                "carry predecessor finalized beyond the fork",
            ));
        }
        if count < fork_count {
            return Err(StoreError::Corrupt("the successor has not started"));
        }
        if policy == RetentionPolicy::Archive && header.policy != RetentionPolicy::Archive {
            return Err(StoreError::Corrupt(
                "an archive carries History only from an archive",
            ));
        }
        let rows = self.write_carried_rows(input, policy)?;
        let mut batch = Batch::new();
        if policy == RetentionPolicy::Reporter && self.reporter_has_history()? {
            self.reopen_carried_batch(&mut batch, &header, fork_count, count)?;
        }
        batch.put(Column::Meta, FORK_CARRY, header.chain_spec_hash);
        self.write_observed_batch(batch, true)?;
        Ok(Some(CarrySummary {
            chain_spec_hash: header.chain_spec_hash,
            finalized_count: header.finalized_count,
            rows,
        }))
    }

    /// Write the rows of `input` that a `policy` node keeps, in bounded
    /// batches, and return how many.
    fn write_carried_rows(
        &mut self,
        input: &mut impl Read,
        policy: RetentionPolicy,
    ) -> Result<u64, StoreError<DB::Error>> {
        let mut batch = Batch::new();
        let mut pending = 0;
        let mut rows = 0;
        loop {
            let mut tag = [0];
            input.read_exact(&mut tag)?;
            if tag[0] == END {
                break;
            }
            let column = *CARRIED
                .get(usize::from(tag[0]))
                .ok_or(StoreError::Corrupt("carry row tag"))?;
            let key = read_field(input)?;
            let value = read_field(input)?;
            let kept = match column {
                Column::SlashingPool => true,
                Column::HistoryNodes | Column::HistoricalChunks => {
                    policy == RetentionPolicy::Archive
                }
                _ => policy == RetentionPolicy::Reporter,
            };
            if !kept {
                continue;
            }
            let value = match (column, self.get_raw(column, &key)?) {
                (Column::ReporterValidators, Some(existing)) => {
                    let mut accounts: Vec<[u8; 32]> = borsh::from_slice(&existing)?;
                    accounts.extend(borsh::from_slice::<Vec<[u8; 32]>>(&value)?);
                    accounts.sort_unstable();
                    accounts.dedup();
                    borsh::to_vec(&accounts)?
                }
                (_, Some(_)) => continue,
                (_, None) => value,
            };
            pending += key.len() + value.len();
            batch.put(column, key, value);
            rows += 1;
            if pending >= BATCH_BYTES {
                self.write_observed_batch(core::mem::take(&mut batch), false)?;
                pending = 0;
            }
        }
        self.write_observed_batch(batch, false)?;
        Ok(rows)
    }

    /// Reopen every watched chunk under the frontier at `count`, as a
    /// snapshot jump does, and record the chunks between the predecessor's
    /// finality and the successor's first retained record as a gap.
    fn reopen_carried_batch(
        &self,
        batch: &mut Batch,
        header: &Header,
        fork_count: u64,
        count: u64,
    ) -> Result<(), StoreError<DB::Error>> {
        let mut gaps = self.reporter_gaps()?;
        gaps.extend(&header.reporter_gaps);
        let resumed = fork_count.saturating_sub(HISTORY_RETENTION_CHUNKS);
        if header.finalized_count < resumed {
            gaps.push((header.finalized_count, resumed));
        }
        gaps.sort_unstable();
        gaps.dedup();
        batch.put(
            Column::Meta,
            super::bootstrap::REPORTER_GAPS,
            borsh::to_vec(&gaps)?,
        );
        let recent = (count.saturating_sub(HISTORY_RETENTION_CHUNKS)..count)
            .map(|chunk| self.historical_opening(chunk, count))
            .collect::<Result<Vec<_>, _>>()?;
        self.refresh_reporter_paths_batch(batch, &recent, &self.history_frontier(count)?)
    }
}

fn write_field(out: &mut impl Write, bytes: &[u8]) -> borsh::io::Result<()> {
    let length = u32::try_from(bytes.len())
        .ok()
        .filter(|length| *length <= MAX_FIELD)
        .ok_or_else(|| borsh::io::Error::other("carry row exceeds its bound"))?;
    out.write_all(&length.to_le_bytes())?;
    out.write_all(bytes)
}

fn read_field(input: &mut impl Read) -> borsh::io::Result<Vec<u8>> {
    let mut length = [0; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length);
    if length > MAX_FIELD {
        return Err(borsh::io::Error::other("carry row exceeds its bound"));
    }
    let mut bytes = vec![0; length as usize];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests;
